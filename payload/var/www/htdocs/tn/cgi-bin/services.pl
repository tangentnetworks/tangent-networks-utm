#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# services.pl - Taint-safe CGI script for Tangent Gateway
# Outputs service status as JSON for the dashboard

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;
use File::Basename qw(dirname);
use Fcntl          qw(:flock);

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/sbin:/usr/sbin';
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

my $session = security_check('standard');

use JSON::PP;

my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

# Pre-compute canonical path before pledge (RELABS-001)
my $DATA_FILE = File::Spec->rel2abs(
    File::Spec->catfile(
        $script_dir, '..', 'data', 'logs', 'bootlog', 'services.json'
    )
);
if ( $DATA_FILE =~ m{^([-/\w.]+)$} ) { $DATA_FILE = $1 }
else                                 { die "FATAL: Invalid data file path\n" }

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
        404 => 'Not Found',
        500 => 'Internal Server Error'
    );
    print "Status: $code " . ( $st{$code} || 'Error' ) . "\r\n";
    print "Content-Type: application/json\r\n";
    print "\r\n";
    print JSON::PP->new->utf8->encode(
        {
            error     => 1,
            message   => $message,
            services  => {},
            timestamp => time() * 1000,
        }
    );
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
            OpenBSD::Unveil::unveil( "$app_root/data/keys", "r" )
              or die "unveil keys: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/logs/bootlog", "r" )
              or die "unveil bootlog: $!";
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
unless ( -e $DATA_FILE ) {
    send_error( 404, "Service data file not found" );
}

my $json_data;
if ( open( my $fh, '<', $DATA_FILE ) ) {
    flock( $fh, LOCK_SH );
    local $/;
    $json_data = <$fh>;
    close($fh);
}
else {
    send_error( 500, "Unable to open data store: $!" );
}

my $data;
eval { $data = decode_json($json_data) };
if ($@) {
    send_error( 500, "JSON parse error: $@" );
}

send_json(
    {
        services  => $data->{services},
        timestamp => ( stat($DATA_FILE) )[9] * 1000,
        system    => "Tangent Networks Firewall",
    }
);
