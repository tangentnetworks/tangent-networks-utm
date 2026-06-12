#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ============================================================================
# SCRIPT: router.pl
# PURPOSE: Front-door CGI dispatcher for all HTTP requests.
# VERSION: 1.0.0
#
# ROLE IN THE STACK:
#   router.pl is the single entry point configured in httpd.conf.
#   Every request to the appliance hits this script first. It loads
#   TNWAF and delegates all routing, SRI tamper detection, rate limiting,
#   CSP header emission, and asset serving to TNWAF::route_request().
#   CGI API calls (/cgi-bin/control.pl) are proxied via TNWAF::proxy_to_cgi().
#
# INTEGRATION:
#   router.pl
#     └── TNWAF::route_request()        # all routing and file serving
#           ├── serve_asset()           # JS/CSS/fonts/images
#           │     └── serve_file()      # SRI tamper check on JS before serve
#           ├── serve_html/view()       # HTML pages and SPA fragments
#           └── proxy_to_cgi()          # forwards /cgi-bin/* to control.pl
#
# DEVEL MODE GUARD:
#   If TNConfig reports DEVEL=1, router.pl enforces loopback-only access
#   (127.0.0.1 / ::1) before passing control to TNWAF. Any non-loopback
#   request in DEVEL mode receives 503 and is logged.
#
# CRASH TRACING:
#   All checkpoints are buffered in @TRACE. On any unclean exit the END
#   block flushes the trace to /tmp/router_debug.log (chroot: /var/www/tmp)
#   for post-mortem diagnosis without needing a live debugger.
#
# DOES NOT TOUCH:
#   Authentication, sessions, CSRF, passwords -- all handled by control.pl.
#   SRI hash generation -- handled at deploy time by TN_SUBSTITUTE.sh.
#
# AUTHOR: DAVID PETER, TANGENT NETWORKS
# ============================================================================

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;

our @TRACE;
our $SUCCESS = 0;

# ============================================================================
# BOOTSTRAP: Memory Buffer Logger
# ============================================================================
BEGIN {
    push @TRACE, sprintf( "[$$] START: %s",  scalar localtime );
    push @TRACE, sprintf( "[$$] URI:    %s", $ENV{REQUEST_URI}    // 'undef' );
    push @TRACE, sprintf( "[$$] METHOD: %s", $ENV{REQUEST_METHOD} // 'undef' );
    push @TRACE, sprintf( "[$$] LEN:    %s", $ENV{CONTENT_LENGTH} // '0' );
}

sub cp { push @TRACE, "[$$] $_[0]" }

END {
    unless ($SUCCESS) {
        if ( open( my $log, '>>', '/tmp/router_debug.log' ) ) {
            chmod 0666, '/tmp/router_debug.log';
            print $log "\n" . ( "!" x 60 ) . "\n";
            print $log "[$$] CRASH DETECTED - FLUSHING TRACE BUFFER\n";
            print $log "$_\n" for @TRACE;
            close $log;
        }
    }
}

$SIG{__WARN__} = sub {
    my $msg = shift;
    chomp $msg;
    push @TRACE, "[$$] WARN: $msg";
};

$SIG{__DIE__} = sub {
    return if $^S;
    my $msg = shift;
    chomp $msg;
    push @TRACE, "[$$] FATAL: $msg";
};

# ============================================================================
# ENVIRONMENT & PATHS
# ============================================================================
BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

    my $lib_path =
      File::Spec->catdir( $RealBin, File::Spec->updir, 'data', 'lib' );
    unless ( File::Spec->file_name_is_absolute($lib_path) ) {
        require Cwd;
        $lib_path = Cwd::abs_path($lib_path);
    }
    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        unshift @INC, $1;
        push @TRACE, "[$$] CP1 - INC set to $1";
    }
    else {
        push @TRACE, "[$$] FATAL - Unsafe lib path: $lib_path";
        print "Status: 500 Internal Server Error\r\n\r\n";
        die "Unsafe characters in lib path";
    }
}

# ============================================================================
# CORE MODULE LOADING
# ============================================================================
use TNEnv;
use TNWAF;
cp("CP2 - TNWAF loaded");

use TNConfig;
cp("CP3 - TNConfig loaded");

# ============================================================================
# DEVEL MODE SECURITY CHECK
# ============================================================================
{
    if ( TNConfig::is_devel_mode() ) {
        my $addr = $ENV{SERVER_ADDR} // $ENV{HTTP_HOST} // '';
        $addr =~ s/:\d+$//;
        my $is_loopback =
          (      $addr eq '127.0.0.1'
              || $addr eq 'localhost'
              || $addr eq '::1'
              || $addr =~ /^127\./ );
        unless ($is_loopback) {
            cp("FATAL: Devel mode on non-loopback: $addr");
            print "Status: 503 Service Unavailable\r\n";
            print "Content-Type: text/plain\r\n\r\n";
            print "503 Service Unavailable\n";
            exit 0;
        }
    }
}
cp("CP4 - Devel check passed");

# ============================================================================
# ROUTING
# ============================================================================
TNWAF::route_request();
cp("CP5 - route_request returned");

$SUCCESS = 1;
exit 0;
