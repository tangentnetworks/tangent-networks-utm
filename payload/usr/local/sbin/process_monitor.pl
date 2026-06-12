#!/usr/bin/perl

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;
use File::Basename;
use File::Path qw(make_path);

my $status_dir = '/var/www/htdocs/tn/data/services/status';

my %programs = (

    # PID-based programs (with PID file)
    'collectd' => {
        pid_file     => "/var/www/htdocs/tn/data/run/collectd/collectd.pid",
        type         => "pid_file",
        display_name => "collectd"
    },

#'symon'  		          => { pid_file => "/var/run/symon.pid", type => "pid_file", display_name => "symon" },
#'symux'		          => { pid_file => "/var/run/symux.pid", type => "pid_file", display_name => "symux" },
    'p3scan' => {
        pid_file     => "/var/www/htdocs/tn/data/run/p3scan/p3scan.pid",
        type         => "pid_file",
        display_name => "p3scan"
    },
    'spamd' => {
        pid_file     => "/var/www/htdocs/tn/data/run/spamd/spamd.pid",
        type         => "pid_file",
        display_name => "spamd"
    },
    'sockd' => {
        pid_file     => "/var/www/htdocs/tn/data/run/sockd/sockd.pid",
        type         => "pid_file",
        display_name => "sockd"
    },
    'sslproxy' => {
        pid_file     => "/var/www/htdocs/tn/data/run/sslproxy/sslproxy.pid",
        type         => "pid_file",
        display_name => "sslproxy"
    },
    'e2guardian' => {
        pid_file     => "/var/www/htdocs/tn/data/run/e2guardian/e2guardian.pid",
        type         => "pid_file",
        display_name => "e2guardian"
    },
    'snortsentry' => {
        pid_file => "/var/www/htdocs/tn/data/run/snortsentry/snortsentry.pid",
        type     => "pid_file",
        display_name => "snortsentry"
    },
    'snort' => {
        pid_file     => "/var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid",
        type         => "pid_file",
        display_name => "snort"
    },
    'snortinline' => {
        pid_file     => "/var/www/htdocs/tn/data/run/snort/snort_.pid",
        type         => "pid_file",
        display_name => "snortinline"
    },
    'clamd' => {
        pid_file     => "/var/www/htdocs/tn/data/run/clamav/clamd.pid",
        type         => "pid_file",
        display_name => "clamd"
    },
    'freshclam' => {
        pid_file     => "/var/www/htdocs/tn/data/run/clamav/freshclam.pid",
        type         => "pid_file",
        display_name => "freshclam"
    },
    'smtp-gated' => {
        pid_file     => "/var/www/htdocs/tn/data/run/smtp-gated/smtp-gated.pid",
        type         => "pid_file",
        display_name => "smtp gated"
    },
    'pmacct_egress_json_mfs' => {
        pid_file =>
          "/var/www/htdocs/tn/data/run/pmacct/pmacct-int_if_json_mfs.pid",
        type         => "pid_file",
        display_name => "pmacct egress json pipe"
    },

#'pmacct_egress_text_pipe'     => { pid_file => "/var/www/htdocs/tn/data/run/pmacct/pmacct-ext_if_text_pipe.pid", type => "pid_file", display_name => "pmacct egress text pipe" },
    'pmacct_egress_json_log' => {
        pid_file =>
          "/var/www/htdocs/tn/data/run/pmacct/pmacct-ext_if_json_log.pid",
        type         => "pid_file",
        display_name => "pmacct egress json log"
    },

#'pmacct_egress_text_log'      => { pid_file => "/var/www/htdocs/tn/data/run/pmacct/pmacct-ext_if_text_log.pid", type => "pid_file", display_name => "pmacct egress text log" },
    'pmacct_ingress_json_mfs ' => {
        pid_file =>
          "/var/www/htdocs/tn/data/run/pmacct/pmacct-int_if_json_mfs.pid",
        type         => "pid_file",
        display_name => "pmacct ingress json pipe"
    },

#'pmacct_ingress_text_pipe'    => { pid_file => "/var/www/htdocs/tn/data/run/pmacct/pmacct-int_if_text_pipe.pid", type => "pid_file", display_name => "pmacct ingress text pipe" },

    # rcctl-managed daemons
    'cron'   => { type => "rcctl", name => "cron",   display_name => "cron" },
    'rad'    => { type => "rcctl", name => "rad",    display_name => "rad" },
    'slaacd' => { type => "rcctl", name => "slaacd", display_name => "slaacd" },
    'dhcpd'  => { type => "rcctl", name => "dhcpd",  display_name => "dhcpd" },
    'unbound' =>
      { type => "rcctl", name => "unbound", display_name => "unbound" },
    'ftpproxy' =>
      { type => "rcctl", name => "ftp-proxy", display_name => "ftp proxy" },
    'httpd'  => { type => "rcctl", name => "httpd",  display_name => "httpd" },
    'ntpd'   => { type => "rcctl", name => "ntpd",   display_name => "ntpd" },
    'pflogd' => { type => "rcctl", name => "pflogd", display_name => "pflogd" },
    'smtpd'  => { type => "rcctl", name => "smtpd",  display_name => "smtpd" },
    'syslogd' =>
      { type => "rcctl", name => "syslogd", display_name => "syslogd" },
);

sub get_pid_from_file {
    my ($pid_file) = @_;
    if ( -f $pid_file ) {
        open( my $fh, '<', $pid_file ) or die "Cannot open $pid_file: $!";
        my $pid = <$fh>;
        chomp($pid);
        close($fh);
        return $pid;
    }
    return undef;
}

sub get_pid_for_rcctl {
    my ($name) = @_;
    my $pgrep_output = `pgrep -n $name 2>/dev/null`;
    chomp($pgrep_output);
    return $pgrep_output if $pgrep_output;
    return undef;
}

sub get_process_info {
    my ($pid) = @_;
    return unless defined $pid;
    my $ps_output =
`ps -o pid,user,pcpu,pmem,rss,vsz,comm,args -p $pid 2>/dev/null | tail -n 1`;
    return unless $ps_output;
    chomp($ps_output);
    $ps_output =~ s/^\s+|\s+$//g;
    my ( $pid_out, $user, $pcpu, $pmem, $rss, $vsz, $comm, $args ) =
      split( /\s+/, $ps_output, 8 );
    return {
        pid  => $pid_out,
        user => $user,
        cpu  => $pcpu,
        mem  => $pmem,
        rss  => $rss,
        vsz  => $vsz,
        comm => $comm,
        args => $args
    };
}

sub get_port_listeners {
    my ($pid) = @_;
    return unless defined $pid;
    my @listeners;
    my $netstat_output = `netstat -an -p tcp 2>/dev/null | grep $pid`;
    foreach my $line ( split( /\n/, $netstat_output ) ) {
        if ( $line =~ /tcp.*\*\.(\d+)/ ) {
            push @listeners, { pid => $pid, address => "0.0.0.0:$1" };
        }
    }
    return @listeners;
}

sub write_status_file {
    my ( $prog, $proc_info, $pid_file_path, $pid_file_contents, $display_name )
      = @_;
    my $prog_status_dir = "$status_dir/$display_name";
    my $status_file     = "$prog_status_dir/status";

    # Create directory if it doesn't exist
    make_path($prog_status_dir) unless -d $prog_status_dir;

    # Truncate and repopulate the status file
    open( my $fh, '>', $status_file ) or die "Cannot open $status_file: $!";
    if ($proc_info) {
        print $fh "Status: Running\n";
        print $fh "PID: $proc_info->{pid}\n";
        print $fh "User: $proc_info->{user}\n";
        print $fh "CPU Usage: $proc_info->{cpu}%\n";
        print $fh "Memory Usage: $proc_info->{mem}%\n";
        print $fh "RSS: $proc_info->{rss} KB\n";
        print $fh "VSZ: $proc_info->{vsz} KB\n";
        print $fh "Command: $proc_info->{comm}\n";
        print $fh "Arguments: $proc_info->{args}\n";
        print $fh "PID File Path: $pid_file_path\n" if $pid_file_path;
        print $fh "PID File Contents: $pid_file_contents\n"
          if $pid_file_contents;

        my @listeners = get_port_listeners( $proc_info->{pid} );
        if (@listeners) {
            print $fh "Port Listeners:\n";
            foreach my $listener (@listeners) {
                print $fh
                  "  PID: $listener->{pid}, Address: $listener->{address}\n";
            }
        }
    }
    else {
        print $fh "Status: Not running\n";
    }
    close($fh);
}

foreach my $prog ( sort keys %programs ) {
    print "=== $prog Status Report ===\n";
    my $info = $programs{$prog};
    my ( $pid, $pid_file_path, $pid_file_contents, @listeners );

    if ( $info->{type} eq "pid_file" ) {
        $pid_file_path     = $info->{pid_file};
        $pid_file_contents = get_pid_from_file($pid_file_path);
        $pid               = $pid_file_contents;
    }
    elsif ( $info->{type} eq "rcctl" ) {
        my $name = $info->{name} || $prog;
        $pid = get_pid_for_rcctl($name);
    }

    my $proc_info = get_process_info($pid);

    # Write status to file (truncate and repopulate)
    write_status_file( $prog, $proc_info, $pid_file_path, $pid_file_contents,
        $info->{display_name} );

    if ($proc_info) {
        print "Status:               Running\n";
        print "PID:                  $proc_info->{pid}\n";
        print "User:                 $proc_info->{user}\n";
        print "CPU Usage:            $proc_info->{cpu}%\n";
        print "Memory Usage:         $proc_info->{mem}%\n";
        print "RSS:                  $proc_info->{rss} KB\n";
        print "VSZ:                  $proc_info->{vsz} KB\n";
        print "Command:              $proc_info->{comm}\n";
        print "Arguments:            $proc_info->{args}\n";
        print "PID File Path:        $pid_file_path\n" if $pid_file_path;
        print "PID File Contents:    $pid_file_contents\n"
          if $pid_file_contents;
    }
    else {
        print "Status:               Not running\n";
    }

    @listeners = get_port_listeners( $proc_info->{pid} ) if $proc_info;
    if (@listeners) {
        print "Port Listeners:\n";
        foreach my $listener (@listeners) {
            print "  PID: $listener->{pid}, Address: $listener->{address}\n";
        }
    }

    print "\n";
}
