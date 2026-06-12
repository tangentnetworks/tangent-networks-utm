# ============================================================================
# MODULE: TNSecurityCheck.pm
# PURPOSE: Lightweight one-line security gate for CGI scripts.
# VERSION: 2.0.0
#
# ROLE IN THE STACK:
#   TNSecurityCheck wraps the full security validation stack into a single
#   function call: security_check($level). CGI scripts call it at the top
#   and receive a session hashref on success or an error response + exit on
#   failure. It is the enforcer that sits in front of every protected endpoint.
#
# SECURITY LEVELS:
#   'standard'   -- origin check + download protection only. No auth required.
#                   Returns anonymous session { role => 'public' }.
#   'protected'  -- full auth: session + origin + download + POST method + CSRF.
#                   Returns validated session hashref.
#   'restricted' -- same as protected + role must be 'admin'.
#                   Returns validated admin session hashref.
#
# VALIDATION LAYERS (protected/restricted):
#   1. Session    -- cookie extracted, HMAC signature verified, DB validated
#   2. Origin     -- HTTP_ORIGIN or HTTP_REFERER must match HTTP_HOST
#   3. Download   -- blocks octet-stream / x-perl accept headers
#   4. Method     -- enforces POST for state-changing endpoints
#   5. CSRF       -- token from JSON body verified via TNSecurity time-window HMAC
#   6. Role       -- admin check for restricted level
#
# DEVEL MODE:
#   All checks bypassed when TNConfig::is_devel_mode() is true.
#   Returns synthetic admin session { user_id => 'devel', role => 'admin' }.
#
# USAGE:
#   use TNSecurityCheck;
#   my $session = security_check('protected');
#   # $session->{username}, $session->{role}, $session->{user_id} now available
#
# INTEGRATION:
#   Loaded by  : individual CGI scripts that need one-line security validation
#   Depends on : TNEnv, TNConfig, TNSecurity, TNAuth
#   Note       : control.pl does NOT use TNSecurityCheck -- it implements its
#                own equivalent validation inline for finer-grained control
#                over each endpoint's requirements.
#
# AUTHOR: DAVID PETER, TANGENT NETWORKS
# ============================================================================

package TNSecurityCheck;
use strict;
use warnings;

use File::Basename;
use Cwd 'abs_path';

BEGIN {
    my $lib_path = dirname(__FILE__);
    $lib_path = abs_path($lib_path) if -d $lib_path;
    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        unshift @INC, $1 unless grep { $_ eq $1 } @INC;
    }
}

use TNEnv;
use CGI;
use JSON;
use TNSecurity;
use TNAuth;
use TNConfig;

use Exporter 'import';
our @EXPORT = qw(security_check);

# ============================================================
# TNSecurityCheck.pm -- Lightweight Script Validator
# ============================================================
# One-line security validation for CGI scripts.
#
# AUTHOR: David Peter, Tangent Networks
# VERSION: 2.0.0
# ============================================================

our $VERSION = '2.0.0';

# ============================================================
# MAIN SECURITY CHECK FUNCTION
# ============================================================

sub security_check {
    my ($level) = @_;
    $level ||= 'standard';

    my $cgi = CGI->new;

    # DEVEL MODE BYPASS
    if ( TNConfig::is_devel_mode() ) {
        TNSecurity::log_security_event(
            'debug',
            'DEVEL: All security checks bypassed',
            $ENV{SCRIPT_NAME} || ''
        );

        return {
            user_id    => 'devel',
            username   => 'developer',
            role       => 'admin',
            devel_mode => 1,
        };
    }

    # ========================================
    # STANDARD LEVEL: No authentication required
    # ========================================
    if ( $level eq 'standard' ) {

        # Only check origin and download protection
        unless ( _check_origin() ) {
            _error_response(
                403,
                'Invalid origin',
                'Invalid origin for standard endpoint'
            );
        }

        unless ( _check_download() ) {
            _error_response(
                550,
                'Download not permitted',
                'Download attempt on standard endpoint'
            );
        }

        # Return anonymous session
        return {
            user_id    => undef,
            username   => 'anonymous',
            role       => 'public',
            devel_mode => 0,
        };
    }

    # ========================================
    # PROTECTED & RESTRICTED: Authentication required
    # ========================================

    # LAYER 1: SESSION VALIDATION
    my $session = _check_session($cgi);
    unless ($session) {
        _error_response(
            401,
            'Authentication required',
            'Unauthorized API access'
        );
    }

    # LAYER 2: ORIGIN VALIDATION
    unless ( _check_origin() ) {
        _error_response(
            403,
            'Invalid origin',
            "Invalid origin from user: $session->{username}"
        );
    }

    # LAYER 3: DOWNLOAD PROTECTION
    unless ( _check_download() ) {
        _error_response(
            550,
            'Download not permitted',
            "Download attempt by user: $session->{username}"
        );
    }

    # LAYER 4: METHOD VALIDATION (for protected/restricted levels)
    if ( $level eq 'protected' || $level eq 'restricted' ) {
        unless ( _check_method('POST') ) {
            _error_response(
                405,
                'Method not allowed',
                'Non-POST to protected endpoint'
            );
        }
    }

    # LAYER 5: CSRF VALIDATION (for protected/restricted levels)
    if ( $level eq 'protected' || $level eq 'restricted' ) {
        unless ( _check_csrf($cgi) ) {
            _error_response(
                403,
                'Invalid CSRF token',
                "CSRF validation failed for user: $session->{username}"
            );
        }
    }

    # LAYER 6: ROLE CHECK (for restricted level)
    if ( $level eq 'restricted' ) {
        unless ( $session->{role} eq 'admin' ) {
            _error_response(
                403,
                'Admin privileges required',
                "Non-admin access attempt by: $session->{username}"
            );
        }
    }

    # ALL CHECKS PASSED
    return $session;
}

# ============================================================
# SECURITY CHECK LAYERS
# ============================================================

sub _check_session {
    my ($cgi) = @_;

    # Read cookie from environment
    my $cookie_string = $ENV{HTTP_COOKIE};

    # No cookie header at all
    if ( !defined $cookie_string ) {
        return undef;
    }

    # Extract tn_session cookie value
    my $session_cookie = '';
    if ( $cookie_string =~ /tn_session=([a-zA-Z0-9_\-=\.]+)/ ) {
        $session_cookie = $1;    # Untainted
    }

    # Cookie not found in header
    if ( !$session_cookie ) {
        return undef;
    }

    # Verify signature and get session ID
    my $session_id = TNSecurity::verify_session_id($session_cookie);

    # Signature verification failed
    if ( !defined $session_id ) {
        return undef;
    }

    # Validate with database
    my $session = TNAuth::validate_session($session_id);

    # Return session (could be undef if not found/expired)
    return $session;
}

sub _check_origin {
    my $origin  = $ENV{HTTP_ORIGIN}  || '';
    my $referer = $ENV{HTTP_REFERER} || '';
    my $host    = $ENV{HTTP_HOST}    || '';

    # Same-origin requests may not have these headers
    return 1 if ( !$origin && !$referer );

    # Check origin header
    if ($origin) {
        return 1 if ( $origin eq "http://$host" || $origin eq "https://$host" );
    }

    # Check referer header
    if ($referer) {
        return 1 if ( $referer =~ m{^https?://\Q$host\E(/|$)} );
    }

    return 0;
}

sub _check_download {
    my $accept = $ENV{HTTP_ACCEPT} || '';

    # Block suspicious accept headers
    if ( $accept =~
m{application/octet-stream|text/x-perl|application/x-perl|text/plain.*download}i
      )
    {
        return 0;
    }

    return 1;
}

sub _check_method {
    my ($expected) = @_;

    my $method = $ENV{REQUEST_METHOD} || '';
    return ( $method eq $expected );
}

sub _check_csrf {
    my ($cgi) = @_;

    # Try CGI param first, then environment variable (for FastCGI)
    my $json_text = $cgi->param('POSTDATA') || $ENV{POSTDATA} || '';

    my $data = eval { JSON->new->utf8->decode($json_text) };

    return 0 unless $data;

    my $csrf_token = $data->{csrf_token} || '';
    return TNSecurity::validate_csrf_token($csrf_token);
}

# ============================================================
# ERROR RESPONSES
# ============================================================

sub _error_response {
    my ( $status, $message, $log_message ) = @_;

    TNSecurity::log_security_event( 'warning', $log_message, $message );

    print "Status: $status\n";
    TNSecurity::print_secure_headers( 'application/json', 0 );

    my $json = JSON->new->utf8->encode(
        {
            success => 0,
            error   => $message,
        }
    );

    print $json;
    exit;
}

1;

__END__

=head1 NAME

TNSecurityCheck -- Lightweight one-line security validator for CGI scripts

=head1 SYNOPSIS
