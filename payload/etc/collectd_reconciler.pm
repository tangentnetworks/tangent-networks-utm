#!/usr/bin/perl -T
# /etc/collectd_reconciler.pm
# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
# SPDX-License-Identifier: BSD-3-Clause
#
# collectd_reconciler.pm - Boot-time RRD map self-healer for TangentNet
#
# Reads /etc/tn-interfaces for interface names and gateway IP,
# walks the live RRD tree for disk/swap/ping/interface discovery,
# then writes /etc/collectd_rrd_map_override.pm which
# collectd_rrd_exporter.pm merges at load time.
#
# Invocation (from /etc/rc.local, after collectd starts):
#   sleep 20 && /usr/bin/perl /etc/collectd_reconciler.pm
#
# Safe to re-run at any time. Fully idempotent. Writes atomically.

package collectd_reconciler;

use strict;
use warnings;
use File::Glob ':glob';
use File::Basename qw(basename dirname);
use Exporter 'import';

our @EXPORT_OK = qw(run_reconciler);

# -----------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------

my $TN_INTERFACES = '/etc/tn-interfaces';
my $RRD_BASE      = '/var/www/htdocs/tn/data/rrd/collectd/tangent';
my $OVERRIDE_FILE = '/etc/collectd_rrd_map_override.pm';
my $LOG_FILE      = '/var/www/htdocs/tn/data/logs/collectd/reconciler.log';
my $HOST          = 'tangent';

# Keys we care about from tn-interfaces
my @WANTED_KEYS = qw(
  EXT_IF
  INT_IF
  EXT_GW4
);

# ps_* metric suffixes that collectd generates for every monitored process
my @PS_METRICS = qw(
  ps_code
  ps_count
  ps_cputime
  ps_data
  ps_pagefaults
  ps_rss
  ps_stacksize
  ps_vm
);

# -----------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------

sub _log {
    my ($msg) = @_;
    my $ts = scalar localtime;
    if ( open my $fh, '>>', $LOG_FILE ) {
        print $fh "[$ts] [reconciler] $msg\n";
        close $fh;
    }
}

# -----------------------------------------------------------------------
# Untaint - allows paths, IPs, interface names
# -----------------------------------------------------------------------

sub _untaint {
    my ($v) = @_;
    return undef unless defined $v && length $v;
    $v =~ /^([\w.\-:\/]+)$/ or die "Tainted value rejected: $v\n";
    return $1;
}

# -----------------------------------------------------------------------
# Parse /etc/tn-interfaces
# Returns hashref of KEY => value for all KEY="value" lines
# -----------------------------------------------------------------------

sub _parse_tn_interfaces {
    my ($path) = @_;
    my %cfg;

    open my $fh, '<', $path
      or die "Cannot read $path: $!\n";

    while (<$fh>) {
        chomp;

        # Match KEY="value" -- value may be empty
        next unless /^([A-Z0-9_]+)="([^"]*)"$/;
        my ( $key, $val ) = ( $1, $2 );
        $cfg{$key} = $val;
    }
    close $fh;

    return \%cfg;
}

# -----------------------------------------------------------------------
# Validate that required keys were substituted (non-empty)
# -----------------------------------------------------------------------

sub _validate_cfg {
    my ($cfg) = @_;
    my @missing;

    for my $key (@WANTED_KEYS) {
        push @missing, $key
          unless defined $cfg->{$key} && length $cfg->{$key};
    }

    if (@missing) {
        _log( "WARNING: tn-interfaces missing or empty keys: "
              . join( ', ', @missing ) );
    }

    return \@missing;
}

# -----------------------------------------------------------------------
# Walk RRD tree and return all .rrd paths grouped by plugin family
# -----------------------------------------------------------------------

sub _walk_rrd_tree {
    my %found = (
        disk      => [],
        swap_dev  => [],
        interface => [],
        ping      => [],
        processes => [],
        other     => [],
    );

    # Untaint RRD_BASE before use under -T
    my $safe_base = _untaint($RRD_BASE)
      or die "RRD_BASE taint check failed\n";

    # Find all .rrd files one level deep (plugin-instance/type.rrd)
    my @rrds = bsd_glob( "$safe_base/*/*.rrd", GLOB_ERR | GLOB_NOSORT );

    for my $rrd (@rrds) {

        # Strip base prefix to get relative path: plugin-instance/type.rrd
        ( my $rel = $rrd ) =~ s{^\Q$safe_base\E/}{};
        my ( $plugin_inst, $type_file ) = split '/', $rel, 2;
        my $type = $type_file;
        $type =~ s/\.rrd$//;

        if    ( $plugin_inst =~ /^disk-/ ) { push @{ $found{disk} }, $rrd }
        elsif ( $plugin_inst =~ /^swap-dev/ ) {
            push @{ $found{swap_dev} }, $rrd;
        }
        elsif ( $plugin_inst =~ /^interface-/ ) {
            push @{ $found{interface} }, $rrd;
        }
        elsif ( $plugin_inst =~ /^ping$/ ) { push @{ $found{ping} }, $rrd }
        elsif ( $plugin_inst =~ /^processes-/ ) {
            push @{ $found{processes} }, $rrd;
        }
        else { push @{ $found{other} }, $rrd }
    }

    return \%found;
}

# -----------------------------------------------------------------------
# Build the override map from live data
#
# Returns hashref: collectd_id => rrd_absolute_path
# -----------------------------------------------------------------------

sub _build_override_map {
    my ( $cfg, $rrd_tree ) = @_;
    my %map;

    my $safe_base = _untaint($RRD_BASE)
      or die "RRD_BASE taint check failed\n";

    # --- Interfaces from tn-interfaces ---
    for my $if_key (qw(EXT_IF INT_IF)) {
        my $if_name = $cfg->{$if_key} or next;
        $if_name = _untaint($if_name) or next;

        for my $metric (qw(if_octets if_packets if_errors)) {
            my $id   = "$HOST/interface-$if_name/$metric";
            my $path = "$safe_base/interface-$if_name/$metric.rrd";
            $map{$id} = $path;
            _log("interface: mapped $id");
        }
    }

   # --- Interfaces discovered in RRD tree (catch extras: lo0, pflog1, etc.) ---
    for my $rrd ( @{ $rrd_tree->{interface} } ) {
        ( my $rel = $rrd ) =~ s{^\Q$safe_base\E/}{};
        my ( $plugin_inst, $type_file ) = split '/', $rel, 2;
        ( my $metric  = $type_file )   =~ s/\.rrd$//;
        ( my $if_name = $plugin_inst ) =~ s/^interface-//;

        my $id = "$HOST/$plugin_inst/$metric";
        unless ( exists $map{$id} ) {
            $map{$id} = $rrd;
            _log("interface: discovered extra $id");
        }
    }

    # --- Disk: discover actual device from RRD tree ---
    my %disk_seen;
    for my $rrd ( @{ $rrd_tree->{disk} } ) {
        ( my $rel = $rrd ) =~ s{^\Q$safe_base\E/}{};
        my ( $plugin_inst, $type_file ) = split '/', $rel, 2;
        ( my $metric = $type_file ) =~ s/\.rrd$//;

        my $id = "$HOST/$plugin_inst/$metric";
        $map{$id}                = $rrd;
        $disk_seen{$plugin_inst} = 1;
        _log("disk: mapped $id");
    }

    if ( !%disk_seen ) {
        _log(
"WARNING: no disk-* RRDs found under $safe_base -- disk metrics will be unavailable"
        );
    }

    # --- Swap device: discover actual device from RRD tree ---
    my %swap_seen;
    for my $rrd ( @{ $rrd_tree->{swap_dev} } ) {
        ( my $rel = $rrd ) =~ s{^\Q$safe_base\E/}{};
        my ( $plugin_inst, $type_file ) = split '/', $rel, 2;
        ( my $metric = $type_file ) =~ s/\.rrd$//;

        my $id = "$HOST/$plugin_inst/$metric";
        $map{$id}                = $rrd;
        $swap_seen{$plugin_inst} = 1;
        _log("swap: mapped $id");
    }

    # --- Ping: 1.1.1.1 is fixed; gateway comes from tn-interfaces ---
    my $gw4 = $cfg->{EXT_GW4};
    $gw4 = _untaint($gw4) if defined $gw4 && length $gw4;

    # First map whatever is actually on disk (authoritative)
    for my $rrd ( @{ $rrd_tree->{ping} } ) {
        ( my $rel = $rrd ) =~ s{^\Q$safe_base\E/}{};
        my ( undef, $type_file ) = split '/', $rel, 2;
        ( my $metric = $type_file ) =~ s/\.rrd$//;

        my $id = "$HOST/ping/$metric";
        $map{$id} = $rrd;
        _log("ping: discovered $id");
    }

    # Now synthesise gateway entries if tn-interfaces has EXT_GW4 and
    # no matching RRD was found on disk yet (handles first-boot gap)
    if ( $gw4 && length $gw4 ) {
        for my $prefix (qw(ping ping_droprate ping_stddev)) {
            my $id   = "$HOST/ping/$prefix-$gw4";
            my $path = "$safe_base/ping/$prefix-$gw4.rrd";
            unless ( exists $map{$id} ) {

                # RRD not on disk yet -- register the expected path anyway
                # so the exporter can emit a graceful unavailable rather
                # than a "No RRD file found" warning.
                $map{$id} = $path;
                _log("ping: pre-registered (not yet on disk) $id");
            }
        }
    }
    else {
        _log("WARNING: EXT_GW4 empty -- gateway ping entries cannot be resolved"
        );
    }

    # --- Processes: walk RRD tree for exact process names ---
    # This handles deployments where optional daemons may not be running
    # (and therefore have no RRD) without generating spurious warnings.
    my %proc_seen;
    for my $rrd ( @{ $rrd_tree->{processes} } ) {
        ( my $rel = $rrd ) =~ s{^\Q$safe_base\E/}{};
        my ( $plugin_inst, $type_file ) = split '/', $rel, 2;
        ( my $metric = $type_file ) =~ s/\.rrd$//;

        my $id = "$HOST/$plugin_inst/$metric";
        $map{$id} = $rrd;
        ( my $proc_name = $plugin_inst ) =~ s/^processes-//;
        $proc_seen{$proc_name} = 1;
    }

    if (%proc_seen) {
        _log(   "processes: mapped "
              . scalar( keys %proc_seen )
              . " processes: "
              . join( ', ', sort keys %proc_seen ) );
    }
    else {
        _log("WARNING: no processes-* RRDs found -- process metrics unavailable"
        );
    }

    return \%map;
}

# -----------------------------------------------------------------------
# Emit the override as a valid Perl module
#
# collectd_rrd_exporter.pm will `do` this file at load time and merge
# the returned hashref into its own map.
# -----------------------------------------------------------------------

sub _write_override {
    my ($map) = @_;

    my $tmp = "$OVERRIDE_FILE.tmp.$$";

    open my $fh, '>', $tmp
      or die "Cannot write $tmp: $!\n";

    my $ts = scalar localtime;
    print $fh <<"HEADER";
# /etc/collectd_rrd_map_override.pm
# AUTO-GENERATED by collectd_reconciler.pm on $ts
# DO NOT EDIT -- re-run collectd_reconciler.pm to regenerate

package collectd_rrd_map_override;

# Returns hashref: collectd_id => absolute_rrd_path
sub get_map {
    return {
HEADER

    for my $id ( sort keys %$map ) {
        my $path = $map->{$id};

      # Escape any single-quotes in key/value (should never happen, but be safe)
        ( my $safe_id   = $id )   =~ s/'/\\'/g;
        ( my $safe_path = $path ) =~ s/'/\\'/g;
        printf $fh "        '%s' => '%s',\n", $safe_id, $safe_path;
    }

    print $fh "    };\n}\n\n1;\n";
    close $fh;

    # Atomic rename
    rename( $tmp, $OVERRIDE_FILE )
      or die "Cannot rename $tmp -> $OVERRIDE_FILE: $!\n";

    _log(   "override written: $OVERRIDE_FILE ("
          . scalar( keys %$map )
          . " entries)" );
}

# -----------------------------------------------------------------------
# Report: log a diff between the static base map and the override
# so operators can see what changed on this hardware
# -----------------------------------------------------------------------

sub _report_diff {
    my ($map) = @_;

    # Entries with no RRD on disk yet (pre-registered paths)
    my @missing_on_disk = sort grep { !-f $map->{$_} } keys %$map;

    if (@missing_on_disk) {
        _log(   "NOTICE: "
              . scalar(@missing_on_disk)
              . " entries registered but RRD not yet on disk (normal at first boot):"
        );
        for my $id (@missing_on_disk) {
            _log("  missing: $id => $map->{$id}");
        }
    }
    else {
        _log(   "all "
              . scalar( keys %$map )
              . " override entries have RRDs on disk" );
    }
}

# -----------------------------------------------------------------------
# Public entry point
# -----------------------------------------------------------------------

sub run_reconciler {
    _log("starting reconciliation");

    # 1. Parse tn-interfaces
    my $cfg = eval { _parse_tn_interfaces($TN_INTERFACES) };
    if ($@) {
        _log("FATAL: cannot parse $TN_INTERFACES: $@");
        die $@;
    }
    _log(
"tn-interfaces: EXT_IF=$cfg->{EXT_IF} INT_IF=$cfg->{INT_IF} EXT_GW4=$cfg->{EXT_GW4}"
    );

    _validate_cfg($cfg);

    # 2. Walk RRD tree
    my $rrd_tree = eval { _walk_rrd_tree() };
    if ($@) {
        _log("FATAL: RRD tree walk failed: $@");
        die $@;
    }

    my $total_rrds = 0;
    $total_rrds += scalar @{ $rrd_tree->{$_} } for keys %$rrd_tree;
    _log("RRD tree: $total_rrds files found across all plugin families");

    # 3. Build override map
    my $map = eval { _build_override_map( $cfg, $rrd_tree ) };
    if ($@) {
        _log("FATAL: map build failed: $@");
        die $@;
    }

    # 4. Report diff
    _report_diff($map);

    # 5. Write override module atomically
    eval { _write_override($map) };
    if ($@) {
        _log("FATAL: write failed: $@");
        die $@;
    }

    _log("reconciliation complete");
    return $map;
}

# -----------------------------------------------------------------------
# Allow direct invocation: perl -T /etc/collectd_reconciler.pm
# -----------------------------------------------------------------------

run_reconciler() unless caller;

1;
