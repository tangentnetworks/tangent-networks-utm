#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ---
# Description: e2guardian Feeds List Provider
# Path: ./cgi-bin/e2g_feeds.pl
# ---
use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;
use File::Basename qw(dirname basename);

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/usr/local/bin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

    my $lib_path =
      File::Spec->catdir( $RealBin, File::Spec->updir, 'data', 'lib' );
    unless ( File::Spec->file_name_is_absolute($lib_path) ) {
        $lib_path = File::Spec->rel2abs($lib_path);
    }
    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        unshift @INC, $1;
    }
    else {
        die "FATAL: Invalid lib path\n";
    }

}

use TNEnv;
use TNSecurityCheck;

# Standard level -- no CSRF/session, origin check only
my $session = security_check('standard');

use CGI qw(:standard);
use JSON::PP;

my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

# Pre-compute canonical paths before pledge (RELABS-001)
my $CHILDSAFE_FILE = File::Spec->rel2abs(
    File::Spec->catfile(
        $script_dir, '..', 'data', 'db', 'e2g', 'childsafe.txt'
    )
);
my $GENERAL_FILE = File::Spec->rel2abs(
    File::Spec->catfile(
        $script_dir, '..', 'data', 'db', 'e2g', 'general.txt'
    )
);
my $USER_FEEDS_FILE = File::Spec->rel2abs(
    File::Spec->catfile(
        $script_dir, '..',         'data',     'services',
        'queue',     'e2gfilters', 'userlist', 'userfeeds.txt'
    )
);

for my $ref ( \$CHILDSAFE_FILE, \$GENERAL_FILE, \$USER_FEEDS_FILE ) {
    if ( $$ref =~ m{^([-/\w.]+)$} ) { $$ref = $1 }
    else                            { die "FATAL: Invalid path: $$ref\n" }
}

# =============================================
# RESPONSE HELPERS
# =============================================
sub send_json {
    my ($data) = @_;
    my $out = JSON::PP->new->utf8->encode($data);
    print "Status: 200 OK\r\n";
    print "Content-Type: application/json; charset=UTF-8\r\n";
    print "X-Frame-Options: DENY\r\n";
    print "X-Content-Type-Options: nosniff\r\n";
    print "Cache-Control: no-cache, no-store, must-revalidate, private\r\n";
    print "Connection: close\r\n";
    print "\r\n";
    print $out;
    exit 0;
}

sub send_error {
    my ( $code, $message ) = @_;
    my %st = (
        400 => 'Bad Request',
        403 => 'Forbidden',
        500 => 'Internal Server Error'
    );
    print "Status: $code " . ( $st{$code} || 'Error' ) . "\r\n";
    print "Content-Type: application/json\r\n";
    print "\r\n";
    print JSON::PP->new->utf8->encode( { success => 0, error => $message } );
    exit 0;
}

# =============================================
# OPENBSD PLEDGE + UNVEIL
# =============================================
{
    my $app_root = $script_dir;
    $app_root =~ s{/cgi-bin$}{};
    $app_root =~ s{^/var/www}{};
    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {
            OpenBSD::Unveil::unveil( "$app_root/data/lib", "r" )
              or die "unveil lib: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/config", "r" )
              or die "unveil config: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/db", "r" )
              or die "unveil db: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/keys", "r" )
              or die "unveil keys: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/db/e2g", "r" )
              or die "unveil e2g db: $!";
            OpenBSD::Unveil::unveil(
                "$app_root/data/services/queue/e2gfilters/userlist", "r" )
              or die "unveil userlist: $!";
            OpenBSD::Unveil::unveil() or die "unveil lock: $!";
        }
        if ( eval { require OpenBSD::Pledge; 1 } ) {
            OpenBSD::Pledge::pledge("stdio rpath") or die "pledge: $!";
        }
    };
    if ($@) {
        send_error( 500, "Internal server error" );
    }
}

# =============================================
# MAIN
# =============================================
my $cgi  = CGI->new;
my $mode = $cgi->param('mode') || 'general';

unless ( $mode =~ /^(general|childsafe|custom)$/ ) {
    send_error( 400, "Invalid mode: $mode" );
}
$mode = $1;

my @all_feeds = get_feeds_for_mode($mode);

send_json(
    {
        success => 1,
        feeds   => \@all_feeds,
        count   => scalar(@all_feeds),
        mode    => $mode,
    }
);

# =============================================
# GET FEEDS FOR SPECIFIC MODE
# =============================================
sub get_feeds_for_mode {
    my ($mode) = @_;
    if ( $mode eq 'childsafe' ) {
        return -e $CHILDSAFE_FILE
          ? parse_e2g_file( $CHILDSAFE_FILE, 'ChildSafe' )
          : ();
    }
    elsif ( $mode eq 'general' ) {
        return -e $GENERAL_FILE
          ? parse_e2g_file( $GENERAL_FILE, 'General' )
          : ();
    }
    elsif ( $mode eq 'custom' ) {
        return -e $USER_FEEDS_FILE ? parse_user_feeds($USER_FEEDS_FILE) : ();
    }
    return ();
}

sub parse_e2g_file {
    my ( $file, $filter_type ) = @_;
    my @feeds;
    open my $fh, '<', $file or return ();
    while ( my $line = <$fh> ) {
        chomp $line;
        next if $line =~ /^\s*$/ || $line =~ /^#/;
        if ( $line =~ /^(\w+):\s*(.+)$/ ) {
            my ( $cat, $url ) = ( $1, $2 );
            next unless $cat =~ /^([\w]+)$/;
            $cat = $1;
            next unless $url =~ /^(https?:\/\/[^\s]+)$/;
            $url = $1;
            push @feeds,
              {
                category => $cat,
                url      => $url,
                filter   => $filter_type,
                source   => 'system'
              };
        }
    }
    close $fh;
    return @feeds;
}

sub parse_user_feeds {
    my ($file) = @_;
    my @feeds;
    return () unless -e $file;
    open my $fh, '<', $file or return ();
    while ( my $line = <$fh> ) {
        chomp $line;
        next if $line =~ /^\s*$/ || $line =~ /^#/;
        if ( $line =~ /^(\w+):\s*(.+)$/ ) {
            my ( $cat, $url ) = ( $1, $2 );
            next unless $cat =~ /^([\w]+)$/;
            $cat = $1;
            next unless $url =~ /^(https?:\/\/[^\s]+)$/;
            $url = $1;
            push @feeds,
              {
                category => $cat,
                url      => $url,
                filter   => 'Custom',
                source   => 'user'
              };
        }
    }
    close $fh;
    return @feeds;
}
