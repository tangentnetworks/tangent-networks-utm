#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

#
# e2g_whitelist_update.pl v1.0.0
# Tangent Networks - e2guardian whitelist generator
#
# Fetches, merges, deduplicates and installs domain whitelists for e2guardian.
# Sources: Tranco top list, Umbrella popularity list, static infrastructure
# list, and local operator overrides.
#
# Usage:
#   e2g_whitelist_update.pl [--config /etc/e2guardian/whitelist.conf]
#                           [--dry-run] [--verbose] [--help] [--version]
#
# Cron: 0 09 * * * root /usr/local/sbin/e2g_whitelist_update.pl
# rc.local: /usr/local/sbin/e2g_whitelist_update.pl &
#

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case bundling);
use File::Basename;
use File::Temp qw(tempfile);
use File::Spec;
use Sys::Syslog qw(:standard :macros);
use POSIX       qw(strftime);
use Fcntl       qw(:flock O_WRONLY O_CREAT O_TRUNC);

# Clean environment for taint mode
delete @ENV{qw(IFS CDPATH ENV BASH_ENV PATH LOAD_LIBRARY)};
$ENV{PATH} = '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin';

our $VERSION = '1.0.0';

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

my %config = (
    config_file => '/etc/e2guardian/whitelist.conf',
    log_file    => '/var/www/htdocs/tn/data/logs/cron/e2g_whitelist.log',
    pid_file    => '/var/run/e2g_whitelist_update.pid',
    lock_file   => '/var/run/e2g_whitelist_update.lock',

    # Output files written by this script
    out_exception => '/etc/e2guardian/lists/localexceptionsitelist',
    out_ssl       => '/etc/e2guardian/lists/localgreysslsitelist',

    # Local operator overrides - never overwritten by this script
    local_override => '/etc/e2guardian/lists/whitelist_local.txt',

    # Static infrastructure list bundled with the script
    static_list => '/etc/e2guardian/feeds/whitelist_static.txt',

    # e2guardian PID file for reload signal
    e2g_pid_file => '/var/www/htdocs/tn/data/run/e2guardian/e2guardian.pid',

    # Fetch settings
    fetch_timeout => 60,
    fetch_retries => 3,
    user_agent    => 'Mozilla/5.0 (compatible; TangentNetworks/1.0)',

    # Tranco list - top N domains
    tranco_url     => 'https://tranco-list.eu/download/latest/100K',
    tranco_enabled => 1,
    tranco_top     => 100000,

    # Umbrella popularity list
    umbrella_url =>
      'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip',
    umbrella_enabled => 0,        # disabled by default - large download
    umbrella_top     => 100000,

    # Majestic million
    majestic_url     => 'https://downloads.majestic.com/majestic_million.csv',
    majestic_enabled => 0,        # disabled by default
    majestic_top     => 100000,

    # Work directory for downloads
    work_dir => '/etc/feeds/whitelist',

    # Log level: debug info warn error
    log_level => 'info',

    # Reload e2guardian after update
    reload_e2g => 1,

    dry_run => 0,
    verbose => 0,
);

my %log_levels = ( debug => 0, info => 1, warn => 2, error => 3 );

# ---------------------------------------------------------------------------
# Static infrastructure list - always whitelisted regardless of config
# These are written to the static list file on first run if it does not exist
# ---------------------------------------------------------------------------

my @STATIC_INFRASTRUCTURE = qw(
  detectportal.firefox.com
  firefox.com
  mozilla.org
  mozilla.com
  mozilla.net
  addons.mozilla.org
  services.mozilla.com

  debian.org
  deb.debian.org
  security.debian.org
  ftp.debian.org
  backports.debian.org
  mxrepo.com
  ubuntu.com
  archive.ubuntu.com
  security.ubuntu.com
  launchpad.net
  canonical.com
  fedoraproject.org
  centos.org
  archlinux.org
  opensuse.org
  alpinelinux.org
  freebsd.org
  openbsd.org
  netbsd.org

  pypi.org
  files.pythonhosted.org
  pythonhosted.org
  npmjs.com
  npmjs.org
  registry.npmjs.org
  yarnpkg.com
  rubygems.org
  crates.io
  static.crates.io
  index.crates.io
  packagist.org
  pkg.go.dev
  gopkg.in
  golang.org
  nuget.org

  github.com
  githubusercontent.com
  raw.githubusercontent.com
  github.io
  gitlab.com
  bitbucket.org
  sourceforge.net

  letsencrypt.org
  ocsp.letsencrypt.org
  r3.o.lencr.org
  x1.c.lencr.org
  ocsp.digicert.com
  ocsp.sectigo.com
  ocsp.usertrust.com
  ocsp.comodoca.com
  crl.sectigo.com
  crl.usertrust.com
  crl3.digicert.com
  crl4.digicert.com
  ocsp.globalsign.com
  crl.globalsign.com

  connectivitycheck.gstatic.com
  connectivitycheck.android.com
  clients3.google.com
  captive.apple.com
  www.apple.com
  msftconnecttest.com
  msftncsi.com
  ipv6.msftconnecttest.com

  wikipedia.org
  wikimedia.org
  wikidata.org
  wikisource.org
  wiktionary.org
  mediawiki.org
  wikiversity.org

  google.com
  googleapis.com
  googlesyndication.com
  googleusercontent.com
  gstatic.com
  gvt1.com
  gvt2.com
  bing.com
  microsoftonline.com
  microsoft.com
  live.com
  office.com
  office365.com
  windows.com
  windowsupdate.com
  update.microsoft.com
  download.microsoft.com
  azure.com
  azureedge.net

  apple.com
  icloud.com
  mzstatic.com
  akadns.net
  aaplimg.com

  cloudflare.com
  cloudflare.net
  cloudflareinsights.com
  cdn.cloudflare.net
  cdnjs.cloudflare.com
  1.1.1.1
  1.0.0.1

  akamai.com
  akamaihd.net
  akamaiedge.net
  akamaized.net
  edgesuite.net
  edgekey.net
  akstat.io
  fastly.com
  fastly.net
  fastlylabs.com

  amazon.com
  amazonaws.com
  cloudfront.net
  awsstatic.com

  tranco-list.eu
  s3-us-west-1.amazonaws.com
  downloads.majestic.com

  zohomail.in
  zoho.com
  zohocdn.com
);

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

my $LOG_FH;

sub log_open {
    my $path = $config{log_file};
    open( $LOG_FH, '>>', $path )
      or warn "Cannot open log $path: $!\n";
    if ($LOG_FH) {
        my $oldfh = select $LOG_FH;
        $| = 1;
        select $oldfh;
    }
    openlog( 'e2g_whitelist_update', 'pid', LOG_DAEMON );
}

sub log_close {
    close $LOG_FH if $LOG_FH;
    closelog();
}

sub log_msg {
    my ( $level, $msg ) = @_;
    my $numeric    = $log_levels{$level}               // 1;
    my $configured = $log_levels{ $config{log_level} } // 1;
    return if $numeric < $configured;

    my $ts   = strftime( '%Y-%m-%d %H:%M:%S', localtime );
    my $line = "[$ts] [$level] $msg\n";

    print $LOG_FH $line if $LOG_FH;
    print STDERR $line  if $config{verbose};

    my %syslog_map = (
        debug => LOG_DEBUG,
        info  => LOG_INFO,
        warn  => LOG_WARNING,
        error => LOG_ERR,
    );
    syslog( $syslog_map{$level} // LOG_INFO, '%s', $msg );
}

# ---------------------------------------------------------------------------
# Lock
# ---------------------------------------------------------------------------

my $LOCK_FH;

sub acquire_lock {
    my $lf = $config{lock_file};
    open( $LOCK_FH, '>', $lf )
      or die "Cannot open lock file $lf: $!\n";
    flock( $LOCK_FH, LOCK_EX | LOCK_NB )
      or die "Another instance is running (lock: $lf)\n";
}

sub release_lock {
    flock( $LOCK_FH, LOCK_UN ) if $LOCK_FH;
    close $LOCK_FH             if $LOCK_FH;
    unlink $config{lock_file};
}

# ---------------------------------------------------------------------------
# Config file loader
# ---------------------------------------------------------------------------

sub load_config {
    my $cf = $config{config_file};
    return unless -f $cf;

    open( my $fh, '<', $cf )
      or do { warn "Cannot open config $cf: $!\n"; return };

    while (<$fh>) {
        chomp;
        s/#.*$//;
        s/^\s+//;
        s/\s+$//;
        next unless length $_;

        if (/^(\w+)\s*=\s*(.+)$/) {
            my ( $key, $val ) = ( $1, $2 );
            $val =~ s/^\s+//;
            $val =~ s/\s+$//;
            if ( exists $config{$key} ) {

                # Boolean normalisation
                if    ( $val =~ /^(yes|true|1)$/i ) { $config{$key} = 1 }
                elsif ( $val =~ /^(no|false|0)$/i ) { $config{$key} = 0 }
                else                                { $config{$key} = $val }
            }
        }
    }
    close $fh;
}

# ---------------------------------------------------------------------------
# Fetch a URL using fetch(1) on OpenBSD or curl as fallback
# Returns path to downloaded file or undef on failure
# ---------------------------------------------------------------------------

sub untaint_path {
    my ($val) = @_;

    # Accept only safe filesystem path characters
    if ( $val =~ m{^([\w/.\-]+)$} ) { return $1 }
    die "Tainted path rejected: $val\n";
}

sub untaint_int {
    my ($val) = @_;
    if ( $val =~ /^(\d+)$/ ) { return $1 }
    die "Tainted integer rejected: $val\n";
}

sub untaint_url {
    my ($val) = @_;
    if ( $val =~ m{^(https?://[\w.\-/=?&%+:]+)$} ) { return $1 }
    die "Tainted URL rejected: $val\n";
}

sub fetch_url {
    my ( $url, $dest ) = @_;

    # Validate and untaint
    my $safe_url;
    eval { $safe_url = untaint_url($url) };
    if ($@) { log_msg( 'error', "Invalid URL: $url" ); return undef }

    my $safe_dest;
    eval { $safe_dest = untaint_path($dest) };
    if ($@) { log_msg( 'error', "Invalid dest path: $dest" ); return undef }

    my $safe_timeout = untaint_int( $config{fetch_timeout} );

    log_msg( 'info', "Fetching: $safe_url" );

    my $ret;
    for my $attempt ( 1 .. $config{fetch_retries} ) {

        # Try OpenBSD fetch first, fall back to curl
        if ( -x '/usr/bin/fetch' ) {
            $ret = system( '/usr/bin/fetch', '-q', '-T', $safe_timeout,
                '-o', $safe_dest, '--', $safe_url );
        }
        elsif ( -x '/usr/local/bin/curl' || -x '/usr/bin/curl' ) {
            my $curl =
              -x '/usr/local/bin/curl'
              ? '/usr/local/bin/curl'
              : '/usr/bin/curl';
            $ret = system(
                $curl,         '-sS',      '--max-time',
                $safe_timeout, '-A',       $config{user_agent},
                '-o',          $safe_dest, '--',
                $safe_url
            );
        }
        else {
            log_msg( 'error', 'Neither fetch nor curl found' );
            return undef;
        }

        if ( $ret == 0 && -s $safe_dest ) {
            log_msg( 'debug', "Fetched OK: $safe_url -> $safe_dest" );
            return $safe_dest;
        }

        log_msg( 'warn',
            "Fetch attempt $attempt/$config{fetch_retries} failed for $safe_url"
        );
        sleep 5 if $attempt < $config{fetch_retries};
    }

    log_msg( 'error', "All fetch attempts failed for $safe_url" );
    return undef;
}

# ---------------------------------------------------------------------------
# Parse Tranco CSV: rank,domain
# Returns arrayref of domains up to $limit
# ---------------------------------------------------------------------------

sub parse_tranco {
    my ( $file, $limit ) = @_;
    my @domains;
    open( my $fh, '<', $file ) or do {
        log_msg( 'error', "Cannot open Tranco file $file: $!" );
        return \@domains;
    };

    my $count      = 0;
    my $skipped    = 0;
    my $first_line = 1;
    while (<$fh>) {
        chomp;
        next if /^\s*$/;

        # Show first line in debug to diagnose format issues
        if ($first_line) {
            log_msg( 'debug', "Tranco first line: $_" );
            $first_line = 0;
        }

        # Skip header if present (rank,domain or similar text header)
        next if /^rank[,\s]/i || /^#/;

        # Tranco format: rank,domain
        my ( $rank, $domain );
        if (/^(\d+),(.+)$/) {
            ( $rank, $domain ) = ( $1, $2 );
        }
        elsif (/^([\w][\w.\-]*\.[\w]{2,})$/) {

            # Plain domain list with no rank column
            $domain = $1;
        }
        else {
            $skipped++;
            next;
        }

        next unless defined $domain && length $domain;
        $domain = lc $domain;
        $domain =~ s/^\s+//;
        $domain =~ s/\s+$//;

        # Untaint domain
        next unless $domain =~ /^([\w][\w.\-]*\.[\w]{2,})$/;
        $domain = $1;

        push @domains, $domain;
        last if ++$count >= $limit;
    }
    close $fh;
    log_msg( 'debug', "Tranco: skipped $skipped unparseable lines" )
      if $skipped;
    log_msg( 'info', sprintf( "Tranco: loaded %d domains", scalar @domains ) );
    return \@domains;
}

# ---------------------------------------------------------------------------
# Parse Umbrella CSV: rank,domain (same format as Tranco, zipped)
# ---------------------------------------------------------------------------

sub parse_umbrella {
    my ( $zip_file, $limit ) = @_;
    my @domains;

    # Unzip to temp file
    my ( $tmp_fh, $tmp_path ) = tempfile(
        'umbrella_XXXXXX',
        DIR    => $config{work_dir},
        UNLINK => 1
    );
    close $tmp_fh;

    my $ret =
      system( '/usr/bin/unzip', '-p', $zip_file, 'top-1m.csv', '>', $tmp_path );
    if ( $ret != 0 ) {

        # Try different unzip path
        $ret = system( '/bin/sh', '-c',
            "/usr/local/bin/unzip -p $zip_file top-1m.csv > $tmp_path" );
    }

    unless ( -s $tmp_path ) {
        log_msg( 'error', "Failed to unzip Umbrella archive" );
        return \@domains;
    }

    return parse_tranco( $tmp_path, $limit );
}

# ---------------------------------------------------------------------------
# Parse Majestic CSV: GlobalRank,TldRank,Domain,TLD,...
# ---------------------------------------------------------------------------

sub parse_majestic {
    my ( $file, $limit ) = @_;
    my @domains;
    open( my $fh, '<', $file ) or do {
        log_msg( 'error', "Cannot open Majestic file $file: $!" );
        return \@domains;
    };

    my $count   = 0;
    my $headers = 1;
    while (<$fh>) {
        chomp;
        if ($headers) { $headers = 0; next }
        next if /^\s*$/;
        my @fields = split /,/, $_, 4;
        next unless defined $fields[2] && length $fields[2];
        my $domain = lc $fields[2];
        $domain             =~ s/^\s+//;
        $domain             =~ s/\s+$//;
        next unless $domain =~ /^[\w][\w.\-]*\.[\w]{2,}$/;
        push @domains, $domain;
        last if ++$count >= $limit;
    }
    close $fh;
    log_msg( 'info',
        sprintf( "Majestic: loaded %d domains", scalar @domains ) );
    return \@domains;
}

# ---------------------------------------------------------------------------
# Load a plain domain list (one domain per line, # comments)
# ---------------------------------------------------------------------------

sub load_plain_list {
    my ($file) = @_;
    my @domains;
    return \@domains unless -f $file;

    open( my $fh, '<', $file ) or do {
        log_msg( 'warn', "Cannot open list $file: $!" );
        return \@domains;
    };

    while (<$fh>) {
        chomp;
        s/#.*$//;
        s/^\s+//;
        s/\s+$//;
        next unless length $_;
        next unless /^[\w][\w.\-]*\.[\w]{2,}$/;
        push @domains, lc $_;
    }
    close $fh;
    log_msg( 'info',
        sprintf( "Loaded %d entries from %s", scalar @domains, $file ) );
    return \@domains;
}

# ---------------------------------------------------------------------------
# Write static infrastructure file if it does not exist
# ---------------------------------------------------------------------------

sub ensure_static_list {
    my $path = $config{static_list};
    return if -f $path && -s $path;

    log_msg( 'info', "Writing static infrastructure list: $path" );

    my $dir = dirname($path);
    unless ( -d $dir ) {
        mkdir $dir, 0755
          or log_msg( 'warn', "Cannot create dir $dir: $!" );
    }

    open( my $fh, '>', $path )
      or do { log_msg( 'error', "Cannot write $path: $!" ); return };

    print $fh "# Tangent Networks static whitelist - infrastructure domains\n";
    print $fh "# Auto-generated by e2g_whitelist_update.pl\n";
    print $fh "# Edit this file to add permanent operator whitelistentries\n";
    print $fh "# Lines beginning with # are comments\n\n";
    print $fh "$_\n" for sort @STATIC_INFRASTRUCTURE;
    close $fh;
}

# ---------------------------------------------------------------------------
# Ensure local override file exists with header comment
# ---------------------------------------------------------------------------

sub ensure_local_override {
    my $path = $config{local_override};
    return if -f $path;

    log_msg( 'info', "Creating local override file: $path" );
    open( my $fh, '>', $path )
      or do { log_msg( 'error', "Cannot create $path: $!" ); return };
    print $fh "# Tangent Networks local whitelist overrides\n";
    print $fh "# This file is NEVER overwritten by e2g_whitelist_update.pl\n";
    print $fh "# Add permanent per-deployment exceptions here\n";
    print $fh "# One domain per line, # for comments\n\n";
    close $fh;
}

# ---------------------------------------------------------------------------
# Reload e2guardian
# ---------------------------------------------------------------------------

sub reload_e2guardian {
    return unless $config{reload_e2g};
    return if $config{dry_run};

    my $pid_file = $config{e2g_pid_file};
    unless ( -f $pid_file ) {
        log_msg( 'warn', "e2guardian PID file not found: $pid_file" );
        return;
    }

    open( my $fh, '<', $pid_file )
      or
      do { log_msg( 'warn', "Cannot read e2guardian PID file: $!" ); return };
    my $raw_pid = <$fh>;
    close $fh;
    chomp $raw_pid;

    # Untaint - accept only digits
    my $pid;
    if ( $raw_pid =~ /^(\d+)$/ ) { $pid = $1 }
    else {
        log_msg( 'warn', "Invalid PID in $pid_file" );
        return;
    }

    log_msg( 'info', "Sending HUP to e2guardian PID $pid" );
    kill( 'HUP', $pid )
      or log_msg( 'warn', "Failed to send HUP to PID $pid: $!" );
}

# ---------------------------------------------------------------------------
# Write output list atomically
# ---------------------------------------------------------------------------

sub write_list {
    my ( $path, $domains_ref, $label ) = @_;

    my $safe_path = untaint_path($path);
    my $dir       = dirname($safe_path);
    my ( $tmp_fh, $tmp_path ) = tempfile(
        'e2g_wl_XXXXXX',
        DIR    => $dir,
        UNLINK => 0
    );

    # Untaint tmp_path from File::Temp
    $tmp_path = untaint_path($tmp_path);

    print $tmp_fh "# Tangent Networks $label\n";
    print $tmp_fh "# Generated: "
      . strftime( '%Y-%m-%d %H:%M:%S', localtime ) . "\n";
    print $tmp_fh "# Entries: " . scalar(@$domains_ref) . "\n\n";
    print $tmp_fh "$_\n" for @$domains_ref;
    close $tmp_fh;

    rename( $tmp_path, $safe_path )
      or do {
        log_msg( 'error', "Cannot rename $tmp_path -> $safe_path: $!" );
        unlink $tmp_path;
        return 0;
      };

    log_msg( 'info',
        sprintf( "Wrote %d entries to %s", scalar @$domains_ref, $safe_path ) );
    return 1;
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

sub main {
    my $help    = 0;
    my $version = 0;

    GetOptions(
        'config|c=s'  => \$config{config_file},
        'dry-run|n'   => \$config{dry_run},
        'verbose|v'   => \$config{verbose},
        'log-level=s' => \$config{log_level},
        'help|h'      => \$help,
        'version|V'   => \$version,
    ) or die "Invalid options. Try --help\n";

    if ($version) { print "e2g_whitelist_update.pl v$VERSION\n"; exit 0 }
    if ($help)    { show_help();                                 exit 0 }

    load_config();

    log_open();

    log_msg( 'info',
        "e2g_whitelist_update.pl v$VERSION starting"
          . ( $config{dry_run} ? ' [DRY RUN]' : '' ) );

    acquire_lock();

    # Ensure work directory exists
    unless ( -d $config{work_dir} ) {
        mkdir $config{work_dir}, 0755
          or die "Cannot create work dir $config{work_dir}: $!\n";
    }

    ensure_static_list();
    ensure_local_override();

    # Collect all domains into a single hash for dedup
    my %seen;
    my @all_domains;

    # 1. Static infrastructure - highest priority, always first
    my $static = load_plain_list( $config{static_list} );
    for my $d (@$static) {
        next if $seen{$d}++;
        push @all_domains, $d;
    }
    log_msg( 'info',
        sprintf( "Static infrastructure: %d domains", scalar @$static ) );

    # 2. Local operator overrides
    my $local = load_plain_list( $config{local_override} );
    for my $d (@$local) {
        next if $seen{$d}++;
        push @all_domains, $d;
    }
    log_msg( 'info', sprintf( "Local overrides: %d domains", scalar @$local ) );

    # 3. Tranco
    if ( $config{tranco_enabled} ) {
        my $dest = File::Spec->catfile( $config{work_dir}, 'tranco.csv' );
        my $file = fetch_url( $config{tranco_url}, $dest );
        if ($file) {
            my $domains = parse_tranco( $file, $config{tranco_top} );
            my $added   = 0;
            for my $d (@$domains) {
                next if $seen{$d}++;
                push @all_domains, $d;
                $added++;
            }
            log_msg( 'info', "Tranco: added $added new domains after dedup" );
        }
        else {
            log_msg( 'warn',
                "Tranco fetch failed - continuing with other sources" );
        }
    }

    # 4. Umbrella
    if ( $config{umbrella_enabled} ) {
        my $dest = File::Spec->catfile( $config{work_dir}, 'umbrella.zip' );
        my $file = fetch_url( $config{umbrella_url}, $dest );
        if ($file) {
            my $domains = parse_umbrella( $file, $config{umbrella_top} );
            my $added   = 0;
            for my $d (@$domains) {
                next if $seen{$d}++;
                push @all_domains, $d;
                $added++;
            }
            log_msg( 'info', "Umbrella: added $added new domains after dedup" );
        }
        else {
            log_msg( 'warn', "Umbrella fetch failed - continuing" );
        }
    }

    # 5. Majestic
    if ( $config{majestic_enabled} ) {
        my $dest = File::Spec->catfile( $config{work_dir}, 'majestic.csv' );
        my $file = fetch_url( $config{majestic_url}, $dest );
        if ($file) {
            my $domains = parse_majestic( $file, $config{majestic_top} );
            my $added   = 0;
            for my $d (@$domains) {
                next if $seen{$d}++;
                push @all_domains, $d;
                $added++;
            }
            log_msg( 'info', "Majestic: added $added new domains after dedup" );
        }
        else {
            log_msg( 'warn', "Majestic fetch failed - continuing" );
        }
    }

    log_msg( 'info',
        sprintf( "Total unique domains after dedup: %d", scalar @all_domains )
    );

    unless (@all_domains) {
        log_msg( 'error',
            "No domains collected - aborting to avoid empty whitelist" );
        release_lock();
        log_close();
        exit 1;
    }

    if ( $config{dry_run} ) {
        log_msg( 'info',
                "Dry run - would write "
              . scalar(@all_domains)
              . " domains to $config{out_exception}" );
    }
    else {
        # Write exception site list
        write_list( $config{out_exception}, \@all_domains,
            'exception site list' )
          or do {
            log_msg( 'error', "Failed to write exception list" );
            release_lock();
            log_close();
            exit 1;
          };

      # Write SSL grey list - same domains, allows MITM on whitelisted SSL sites
        write_list( $config{out_ssl}, \@all_domains, 'SSL grey list' );

        reload_e2guardian();
    }

    log_msg( 'info', "e2g_whitelist_update.pl completed successfully" );

    release_lock();
    log_close();
    exit 0;
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

sub show_help {
    print <<'END';
e2g_whitelist_update.pl v1.0.0 - Tangent Networks e2guardian whitelist generator

Usage: e2g_whitelist_update.pl [options]

Options:
  -c, --config FILE    Config file (default: /etc/e2guardian/whitelist.conf)
  -n, --dry-run        Do not write files or reload e2guardian
  -v, --verbose        Print log messages to stderr
      --log-level LVL  Log level: debug info warn error (default: info)
  -V, --version        Print version and exit
  -h, --help           Print this help and exit

Config file format (key = value, # comments):
  tranco_enabled   = yes
  umbrella_enabled = no
  majestic_enabled = no
  tranco_top       = 100000
  reload_e2g       = yes
  log_level        = info

Sources:
  1. Static infrastructure list  (/etc/e2guardian/feeds/whitelist_static.txt)
  2. Local operator overrides    (/etc/e2guardian/lists/whitelist_local.txt)
  3. Tranco top list             (https://tranco-list.eu)
  4. Umbrella popularity list    (disabled by default - large download)
  5. Majestic million            (disabled by default)

Output:
  /etc/e2guardian/lists/localexceptionsitelist
  /etc/e2guardian/lists/localgreysslsitelist

Cron example:
  0 09 * * * root /usr/local/sbin/e2g_whitelist_update.pl

rc.local example:
  /usr/local/sbin/e2g_whitelist_update.pl &
END
}

main();
