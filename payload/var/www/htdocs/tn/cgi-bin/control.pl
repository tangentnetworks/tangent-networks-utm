#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

#
# ============================================================================
# SCRIPT: control.pl
# PURPOSE: JSON API backend --  authentication, session management, user
#          administration, and DEVEL mode control.
# VERSION: 2.1.0
#
# ROLE IN THE STACK:
#   control.pl is the sole CGI script that handles all state-changing API
#   calls from the browser UI. It is invoked directly by OpenBSD slowcgi
#   and never loaded by router.pl --  the two are siblings, not parent/child.
#   TNWAF (via router.pl) proxies /cgi-bin/control.pl requests through to
#   slowcgi which then executes this script fresh per request.
#
# RESPONSIBILITIES:
#   1. Authentication      --  register, login, logout
#   2. Password reset      --  security question flow + recovery code flow,
#                              both gated by short-lived HMAC-signed reset tokens
#   3. Session management  --  issue, validate, and destroy signed session cookies
#   4. CSRF protection     --  all state-changing endpoints require a valid
#                              time-window CSRF token from TNSecurity
#   5. User administration --  user deletion (admin only)
#   6. DEVEL mode          --  enable/disable via password, status query
#   7. Sandbox             --  OpenBSD unveil(2) + pledge(2) applied after
#                              module loading to lock down filesystem access
#                              to only what the request lifecycle needs
#
# REQUEST LIFECYCLE:
#   slowcgi forks control.pl
#     ├── BEGIN: STDERR redirected to /tmp/control-YYYY-MM-DD.log
#     ├── BEGIN: @INC set to data/lib, environment sanitised
#     ├── Modules loaded (TNEnv, TNSecurity, TNAuth, TNConfig, DBD::SQLite)
#     ├── DBD::SQLite pre-loaded before pledge(2) to allow dlopen()
#     ├── unveil(2) applied --  filesystem visibility locked to required paths
#     ├── pledge(2) applied --  syscalls restricted to stdio/rpath/wpath/cpath/flock
#     ├── Origin validated for all non-GET/HEAD methods
#     └── route_request() dispatches to the appropriate handler
#
# SECURITY MODEL:
#   Every handler enforces its own requirements explicitly:
#     require_method()     --  enforces GET or POST, never both
#     require_csrf_token() --  validates time-window HMAC token from JSON body
#     require_session()    --  validates signed cookie + DB session + role
#   There is no global auth gate --  each endpoint is responsible for its own
#   validation. This is intentional: it prevents a single bypass from
#   compromising all endpoints and makes each handler self-documenting.
#
# RESET TOKEN FLOW:
#   Password reset is a two-step challenge/response:
#     Step 1: User provides username → receives security questions
#     Step 2: User answers questions OR provides recovery code
#             → receives a short-lived HMAC-signed reset token (10 min TTL)
#     Step 3: User submits new password + reset token
#             → token verified (HMAC + expiry + username binding) → password updated
#   Reset tokens are never stored --  they are stateless HMAC proofs.
#
# SESSION COOKIE:
#   Cookie value = HMAC-signed session ID (TNSecurity::sign_session_id()).
#   Cookie attributes sourced from security.conf:
#     SESSION_COOKIE_NAME, SESSION_SECURE, SESSION_HTTPONLY, SESSION_SAMESITE
#   Default: HttpOnly=1, SameSite=Strict, Secure=0 (set to 1 for TLS).
#
# SANDBOX PATHS (unveil):
#   Mandatory : data/lib (r), data/config (r), data/db (rwc), /tmp (rwc),
#               /dev/urandom (r)
#   Optional  : data/keys (r), data/logs (rwc), Perl module trees (r),
#               shared libs /usr/local/lib /usr/lib (r)
#   All paths are chroot-internal (/htdocs/tn/... not /var/www/htdocs/tn/...)
#   Existence probed BEFORE first unveil() call --  kernel restricts visibility
#   immediately on first unveil() so -d checks after that return false.
#
# DEVEL MODE:
#   When TNConfig::is_devel_mode() is true:
#     - CSRF validation is bypassed
#     - Origin check is bypassed
#     - require_session() still enforces role (devel is not an auth bypass)
#   DEVEL mode is password-protected (PBKDF2 hash in security.conf) and
#   router.pl enforces loopback-only access when DEVEL=1.
#
# DOES NOT HANDLE:
#   Static file serving, SRI tamper detection, rate limiting, CSP headers
#   --  all of those belong to TNWAF (router.pl). This script is JSON API only.
#
# INTEGRATION:
#   Executed by : OpenBSD slowcgi, proxied via TNWAF
#   Depends on  : TNEnv, TNSecurity, TNAuth, TNConfig
#   Log output  : STDERR → /tmp/control-YYYY-MM-DD.log (chroot /var/www/tmp)
#                 Security events → data/logs/waf/security.log via TNSecurity
#
# AUTHOR: DAVID PETER, TANGENT NETWORKS
#
# ============================================================================

use strict;
use warnings;

# ============================================================================
# BOOTSTRAP
# Runs at BEGIN time before any module is loaded.
# Redirects STDERR to a dated log file (flock'd for slowcgi worker safety),
# sanitises the environment for taint mode, and adds data/lib to @INC.
# ============================================================================

use FindBin qw($RealBin);
use File::Spec;

BEGIN {
    # Redirect STDERR to a date-stamped log file inside the chroot.
    # /tmp/ inside the chroot = /var/www/tmp/ on the host.
    if ( $ENV{GATEWAY_INTERFACE} ) {
        my $log_date = do {
            my @t = localtime;
            sprintf( "%04d-%02d-%02d", $t[5] + 1900, $t[4] + 1, $t[3] );
        };

        # Open a named handle first so we can flock() before duping to STDERR.
        # Under slowcgi, multiple worker processes share the same log file —
        # flock(LOCK_EX) ensures no two processes interleave their startup
        # writes. The lock is released when $log_fh goes out of scope.
        # O_APPEND (>>) provides atomicity for individual write() syscalls;
        # flock covers the open/setup window.
        # LOCK_EX = 2 -- numeric constant used here because Fcntl is not yet
        # loaded at BEGIN time.
        open( my $log_fh, '>>', "/tmp/control-${log_date}.log" )
          or die "Cannot open control log: $!";
        flock( $log_fh, 2 ) or die "Cannot lock control log: $!";
        open( STDERR, '>>&', $log_fh )
          or die "Cannot redirect STDERR to log: $!";
        STDERR->autoflush(1);

        # $log_fh goes out of scope here -- lock released, fd remains open
        # via the STDERR dup above.
    }

    # Clean environment for taint mode
    $ENV{PATH} = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

    # Set up lib path to find TNEnv
    my $lib_path =
      File::Spec->catdir( $RealBin, File::Spec->updir, 'data', 'lib' );

    unless ( File::Spec->file_name_is_absolute($lib_path) ) {
        $lib_path = File::Spec->rel2abs($lib_path);
    }

    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        $lib_path = $1;
    }
    else {
        die "FATAL: Unsafe characters in path: $lib_path\n";
    }

    unless ( -d $lib_path ) {
        die "FATAL: Library directory not found: $lib_path\n";
    }

    unshift @INC, $lib_path;
}

# Timestamp every warn/die that reaches STDERR so control.log entries
# are always traceable. Must be outside BEGIN so $SIG is set at runtime.
$SIG{__WARN__} = sub {
    my $msg = shift;
    chomp $msg;
    printf STDERR "[%s] WARN: %s\n", scalar(localtime), $msg;
};

$SIG{__DIE__} = sub {
    return if $^S;    # ignore die() inside eval blocks
    my $msg = shift;
    chomp $msg;
    printf STDERR "[%s] FATAL: %s\n", scalar(localtime), $msg;
};

use TNEnv;
use CGI;
use JSON;
use TNSecurity;
use TNAuth;
use TNConfig;

# Force DBD::SQLite to load its XS shared library NOW, before pledge(2) is
# applied. DBI loads the DBD driver lazily on the first connect() call -- if
# that call happens after pledge is active, dlopen() needs prot_exec which
# we do not grant. Pre-loading here ensures the .so is mapped before the
# pledge/unveil sandbox is locked down.
use DBD::SQLite;

my $db_path     = get_db_path();
my $config_file = File::Spec->catfile( get_config_path(), 'security.conf' );

# ============================================================================
# CONFIGURATION
# All session cookie attributes sourced from security.conf via TNConfig.
# Invalid SAMESITE values default to Strict and warn to the error log.
# MAX_REQUEST_SIZE enforced before route_request() --  send_error() available
# because modules are already loaded at this point.
# ============================================================================

my $MAX_REQUEST_SIZE    = 1_048_576;    # 1 MB
my $SESSION_COOKIE_PATH = '/';

# Reset tokens are short-lived proof that a user completed the password
# reset identity challenge (security questions or recovery code).
# They are HMAC-signed, single-use, and expire after this many seconds.
my $RESET_TOKEN_TTL = 600;    # 10 minutes

my $SESSION_COOKIE_NAME =
  TNConfig::get_config( 'session', 'SESSION_COOKIE_NAME' ) // 'tn_session';
my $SESSION_COOKIE_SECURE = TNConfig::get_config( 'session', 'SESSION_SECURE' )
  // 0;
my $SESSION_COOKIE_HTTPONLY =
  TNConfig::get_config( 'session', 'SESSION_HTTPONLY' ) // 1;
my $SESSION_COOKIE_SAMESITE =
  TNConfig::get_config( 'session', 'SESSION_SAMESITE' ) // 'Strict';

if ( $SESSION_COOKIE_SAMESITE !~ /^(Strict|Lax|None)$/ ) {
    warn
"Invalid SESSION_SAMESITE value '$SESSION_COOKIE_SAMESITE' in security.conf, defaulting to Strict\n";
    $SESSION_COOKIE_SAMESITE = 'Strict';
}

# =============================================
# REQUEST HANDLING
# =============================================

our $cgi = CGI->new();

# Check request size AFTER modules are loaded so send_error() is available.
if ( $ENV{CONTENT_LENGTH} && $ENV{CONTENT_LENGTH} > $MAX_REQUEST_SIZE ) {
    send_error( 413, 'Request too large' );
}

my $method    = untaint_method( $ENV{REQUEST_METHOD} || 'GET' );
my $path_info = untaint_path_info( $ENV{PATH_INFO}   || '/' );
send_error( 400, 'Invalid path' ) unless defined $path_info;

$path_info =~ s{^/}{};

# =============================================
# OPENBSD PLEDGE + UNVEIL
# =============================================
# The CGI process runs inside the /var/www chroot.
# unveil() paths are chroot-internal.
#
# Perl module paths vary depending on which directories were copied
# into the chroot during setup. We probe each candidate and unveil
# only those that actually exist, so the script works regardless of
# which subset is present. Hard-failing on a missing optional path
# would break the sandbox init entirely -- which is worse than not
# unveiling a non-existent directory.
#
# Typical OpenBSD chroot layout for slowcgi:
#   /usr/lib/perl5/         -- base Perl (if copied in)
#   /usr/libdata/perl5/     -- base Perl on some OpenBSD versions
#   /usr/local/lib/perl5/   -- CPAN / ports Perl modules
#   /usr/local/lib/         -- shared libs (DBD::SQLite, libpthread, etc.)
#   /usr/lib/               -- base shared libs
# =============================================

{
    my $app_root = $db_path;
    $app_root =~ s{/data/db/?.*$}{};    # /htdocs/tn

    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {

      # IMPORTANT: All -d / -f existence checks MUST happen before the first
      # unveil() call. Once any unveil() is issued the kernel begins restricting
      # filesystem visibility -- a -d on an as-yet-unveiled path returns false
      # even if the directory exists, causing it to be silently skipped and then
      # inaccessible after the unveil lock is applied.

        # Resolve the full path list while the filesystem is still unrestricted.

       # Mandatory paths -- die if absent, the app cannot function without them.
            my @to_unveil = (
                [ "$app_root/data/lib",    "r" ],
                [ "$app_root/data/config", "r" ],
                [ "$app_root/data/db",     "rwc" ],
                [ "/tmp",                  "rwc" ],
                [ "/dev/urandom",          "r" ],
            );

            # Optional paths -- probe existence NOW, before any unveil() call.
            for my $entry (
                [ "$app_root/data/keys", "r" ],     # HMAC key files (read-only)
                [ "$app_root/data/logs", "rwc" ],   # application logs
                 # Perl module trees -- layout varies by OpenBSD version / chroot setup.
                [ "/usr/lib/perl5",           "r" ],
                [ "/usr/libdata/perl5",       "r" ],
                [ "/usr/local/lib/perl5",     "r" ],
                [ "/usr/local/libdata/perl5", "r" ],

             # Shared libs for XS modules (DBD::SQLite, libpthread, libm, libz).
                [ "/usr/local/lib", "r" ],
                [ "/usr/lib",       "r" ],
              )
            {
                push @to_unveil, $entry if -d $entry->[0];
            }

            # Now issue all unveil() calls in one pass.
            for my $entry (@to_unveil) {
                OpenBSD::Unveil::unveil( $entry->[0], $entry->[1] )
                  or die "unveil $entry->[0]: $!";
            }

            OpenBSD::Unveil::unveil() or die "unveil lock: $!";
        }
        if ( eval { require OpenBSD::Pledge; 1 } ) {
            OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock")
              or die "pledge: $!";
        }
    };
    if ($@) {
        printf STDERR "[%s] FATAL: sandbox_init_failed: %s\n",
          scalar(localtime), $@;
        send_error( 500, 'Internal server error' );
    }
}

# Origin validation for all state-changing methods
if ( $method ne 'GET' && $method ne 'HEAD' ) {
    unless ( validate_origin() ) {
        send_error( 403, 'Invalid origin' );
    }
}

route_request( $method, $path_info );

# =============================================
# JSON BODY - single read, cached for the request lifetime
# =============================================
my $JSON_BODY_CACHE;

sub get_json_body {
    return $JSON_BODY_CACHE if defined $JSON_BODY_CACHE;
    my $content = $cgi->param('POSTDATA') || '';
    unless ($content) { send_error( 400, 'Empty request body' ) }
    my $data;
    eval { $data = JSON->new->utf8->decode($content) };
    if ( $@ || !defined $data || ref($data) ne 'HASH' ) {
        send_error( 400, 'Invalid JSON' );
    }
    $JSON_BODY_CACHE = $data;
    return $JSON_BODY_CACHE;
}

# =============================================
# TAINT UTILITIES
# =============================================

sub untaint_method {
    my ($val) = @_;
    return 'GET' unless $val;
    if ( $val =~ /^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)$/ ) { return $1 }
    send_error( 400, 'Invalid HTTP method' );
}

sub untaint_path_info {
    my ($path) = @_;
    return '/' unless $path;
    return undef if $path =~ /\.\./;
    if ( $path =~ m{^(/[\w/._-]+)$} ) { return $1 }
    send_error( 400, 'Invalid path' );
}

sub untaint_string {
    my ( $str, $pattern ) = @_;
    return '' unless defined $str;
    $pattern ||= qr/^([\w\s\@\.\-]+)$/;
    if ( $str =~ $pattern ) { return $1 }
    return undef;
}

sub untaint_email {
    my ($email) = @_;
    return undef unless $email;
    if ( $email =~ /^([a-zA-Z0-9._%+-]+\@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/ ) {
        return $1;
    }
    return undef;
}

sub untaint_username {
    my ($username) = @_;
    return undef unless $username;
    if ( $username =~ /^([a-zA-Z0-9_-]{3,32})$/ ) { return $1 }
    return undef;
}

# ============================================================================
# ROUTING
# Flat dispatch table --  path string to handler function.
# Each handler is fully self-contained and enforces its own method, CSRF,
# session, and role requirements. No global auth gate.
#
# Auth routes    --  unauthenticated, CSRF required
# API routes     --  mixed: session/CSRF per handler
# DEVEL routes   --  password-protected enable/disable, loopback-only via router.pl
# ============================================================================

sub route_request {
    my ( $method, $path ) = @_;

    # Authentication routes
    if    ( $path eq 'auth/register' )              { handle_register() }
    elsif ( $path eq 'auth/login' )                 { handle_login() }
    elsif ( $path eq 'auth/logout' )                { handle_logout() }
    elsif ( $path eq 'auth/reset/get_questions' )   { handle_get_questions() }
    elsif ( $path eq 'auth/reset/verify_answers' )  { handle_verify_answers() }
    elsif ( $path eq 'auth/reset/verify_code' )     { handle_verify_code() }
    elsif ( $path eq 'auth/reset/update_password' ) { handle_update_password() }

    # API routes
    elsif ( $path eq 'api/csrf' )      { handle_get_csrf() }
    elsif ( $path eq 'api/session' )   { handle_check_session() }
    elsif ( $path eq 'api/questions' ) { handle_list_questions() }
    elsif ( $path eq 'api/registration/status' ) {
        handle_registration_status();
    }
    elsif ( $path eq 'api/registration/tokens' ) { handle_list_tokens() }
    elsif ( $path eq 'api/user/delete' )         { handle_user_delete() }

    # DEVEL mode routes
    elsif ( $path eq 'devel/status' )  { handle_devel_status() }
    elsif ( $path eq 'devel/enable' )  { handle_devel_enable() }
    elsif ( $path eq 'devel/disable' ) { handle_devel_disable() }

    else { send_error( 404, 'Endpoint not found' ) }
}

# =============================================
# AUTHENTICATION HANDLERS
# =============================================

sub handle_register {
    require_method('POST');
    require_csrf_token();

    my $data = get_json_body();

    my $username = untaint_username( $data->{username} )
      || send_error( 400, 'Invalid username format' );
    my $password = $data->{password} || send_error( 400, 'Password required' );
    my $security_questions = $data->{security_questions}
      || send_error( 400, 'Security questions required' );
    my $token = $data->{token} || '';

    my $email;
    if ( $data->{email} ) {
        $email = untaint_email( $data->{email} );
        unless ($email) { send_error( 400, 'Invalid email format' ) }
        unless ( TNSecurity::validate_email($email) ) {
            send_error( 400, 'Invalid email format' );
        }
    }

    unless ( TNSecurity::validate_username($username) ) {
        send_error( 400, 'Invalid username format' );
    }

    my $result =
      TNAuth::register_user( $username, $password, $email, $security_questions,
        $token );

    if ( $result->{success} ) {
        TNSecurity::log_security_event( 'info', 'User registered', $username );
        send_json(
            {
                success             => 1,
                message             => 'Registration successful',
                recovery_codes      => $result->{recovery_codes}      || [],
                registration_tokens => $result->{registration_tokens} || [],
            }
        );
    }
    else {
        send_error( 400, $result->{error} || 'Registration failed' );
    }
}

sub handle_login {
    require_method('POST');
    require_csrf_token();

    my $data = get_json_body();

    my $username = untaint_username( $data->{username} )
      || send_error( 400, 'Invalid username' );
    my $password = $data->{password} || send_error( 400, 'Password required' );

    my $result = TNAuth::authenticate_user( $username, $password );

    if ( $result->{success} ) {
        my $ip =
          untaint_string( $ENV{REMOTE_ADDR}, qr/^([\d\.]+)$/ ) || 'unknown';
        my $user_agent =
          untaint_string( $ENV{HTTP_USER_AGENT}, qr/^(.{0,255})$/ )
          || 'unknown';

        my $session =
          TNAuth::create_session( $result->{user_id}, $ip, $user_agent );

        if ( $session->{success} ) {
            my $signed_session =
              TNSecurity::sign_session_id( $session->{session_id} );

            my $cookie = sprintf(
                "Set-Cookie: %s=%s; Path=%s%s%s; SameSite=%s",
                $SESSION_COOKIE_NAME,
                $signed_session,
                $SESSION_COOKIE_PATH,
                $SESSION_COOKIE_HTTPONLY ? '; HttpOnly' : '',
                $SESSION_COOKIE_SECURE   ? '; Secure'   : '',
                $SESSION_COOKIE_SAMESITE
            );

            TNSecurity::log_security_event( 'info', 'User logged in',
                $username );

            send_json(
                {
                    success  => 1,
                    message  => 'Login successful',
                    username => $username,
                    role     => $result->{role},
                },
                [$cookie]
            );
        }
        else {
            send_error( 500, 'Failed to create session' );
        }
    }
    else {
        TNSecurity::log_security_event( 'warning', 'Failed login attempt',
            $username );
        send_error( 401, $result->{error} || 'Authentication failed' );
    }
}

sub handle_logout {
    require_method('POST');
    require_csrf_token();

    my $session_id = get_session_id();

    if ($session_id) {
        TNAuth::destroy_session($session_id);
        TNSecurity::log_security_event( 'info', 'User logged out', '' );
    }

    clear_session_cookie();
    send_json( { success => 1, message => 'Logged out' } );
}

sub handle_get_questions {
    require_method('POST');
    require_csrf_token();

    my $data     = get_json_body();
    my $username = untaint_username( $data->{username} )
      || send_error( 400, 'Invalid username' );

    my $rate = TNAuth::check_reset_attempts($username);
    unless ( $rate->{allowed} ) {
        TNSecurity::log_security_event( 'warning', 'RESET_RATE_LIMITED',
            $username );
        send_error( 429, 'Too many reset attempts -- try again later' );
    }

    my $questions = TNAuth::get_security_questions($username);

    if ( $questions && @$questions ) {
        send_json( { success => 1, questions => $questions } );
    }
    else {
        send_error( 404, 'User not found or no questions set' );
    }
}

sub handle_verify_answers {
    require_method('POST');
    require_csrf_token();

    my $data     = get_json_body();
    my $username = untaint_username( $data->{username} )
      || send_error( 400, 'Invalid username' );
    my $answers = $data->{answers} || send_error( 400, 'Answers required' );

    my $result = TNAuth::verify_security_answers( $username, $answers );

    if ( $result->{success} ) {
        my $reset_token = _issue_reset_token($username);
        send_json(
            {
                success     => 1,
                message     => 'Answers verified',
                reset_token => $reset_token
            }
        );
    }
    else {
        TNSecurity::log_security_event( 'warning', 'RESET_ANSWERS_FAILED',
            $username );
        send_error( 401, 'Incorrect answers' );
    }
}

sub handle_verify_code {
    require_method('POST');
    require_csrf_token();

    my $data     = get_json_body();
    my $username = untaint_username( $data->{username} )
      || send_error( 400, 'Invalid username' );
    my $code = untaint_string( $data->{code}, qr/^([0-9a-f]{64})$/ )
      || send_error( 400, 'Invalid recovery code format' );

    my $result = TNAuth::verify_recovery_code( $username, $code );

    if ( $result->{success} ) {
        my $reset_token = _issue_reset_token($username);
        send_json(
            {
                success     => 1,
                message     => 'Code verified',
                reset_token => $reset_token
            }
        );
    }
    else {
        TNSecurity::log_security_event( 'warning', 'RESET_CODE_FAILED',
            $username );
        send_error( 401, 'Invalid recovery code' );
    }
}

sub handle_update_password {
    require_method('POST');
    require_csrf_token();

    my $data     = get_json_body();
    my $username = untaint_username( $data->{username} )
      || send_error( 400, 'Invalid username' );
    my $new_password =
      $data->{new_password} || send_error( 400, 'New password required' );
    my $reset_token =
      $data->{reset_token} || send_error( 403, 'Reset token required' );

    unless ( _verify_reset_token( $reset_token, $username ) ) {
        TNSecurity::log_security_event( 'warning', 'RESET_TOKEN_REJECTED',
            $username );
        send_error( 403, 'Invalid or expired reset token' );
    }

    my $user = TNAuth::get_user_by_username($username);
    unless ($user) { send_error( 404, 'User not found' ) }

    my $result = TNAuth::update_password( $user->{id}, $new_password );

    if ( $result->{success} ) {
        TNAuth::clear_reset_attempts($username);
        TNSecurity::log_security_event( 'info', 'Password reset completed',
            $username );
        send_json( { success => 1, message => 'Password updated' } );
    }
    else {
        send_error( 500, 'Failed to update password' );
    }
}

# ============================================================================
# RESET TOKEN HELPERS
# Stateless HMAC-signed tokens used as proof that a user completed the
# password reset identity challenge (security questions or recovery code).
#
# Token format: base64(username:expiry).hmac_hex(payload:reset)
#   - Payload is base64 to avoid : ambiguity in the split
#   - HMAC keyed with named key 'reset_token' via TNSecurity::hmac_hex()
#   - Expiry bound to $RESET_TOKEN_TTL seconds (default 600 / 10 minutes)
#   - Username bound inside the token --  a token for user A cannot reset user B
#   - Verified with timing-safe compare to prevent HMAC oracle attacks
# ============================================================================

sub _issue_reset_token {
    my ($username) = @_;
    my $expiry     = time() + $RESET_TOKEN_TTL;
    my $payload    = _b64("$username:$expiry");
    my $sig        = TNSecurity::hmac_hex( "$payload:reset", 'reset_token' );
    return "$payload.$sig";
}

sub _verify_reset_token {
    my ( $token, $expected_username ) = @_;
    return 0 unless $token && $expected_username;

    unless ( $token =~ /^([A-Za-z0-9+\/=]+)\.([0-9a-f]+)$/ ) {
        return 0;
    }
    my ( $payload, $sig ) = ( $1, $2 );

    my $expected_sig = TNSecurity::hmac_hex( "$payload:reset", 'reset_token' );
    return 0 unless TNSecurity::timing_safe_compare( $sig, $expected_sig );

    my $decoded = _b64d($payload);
    return 0 unless defined $decoded;

    my ( $username, $expiry ) = split /:/, $decoded, 2;
    return 0 unless defined $username && defined $expiry;
    return 0 unless $expiry =~ /^\d+$/;
    return 0 unless $username eq $expected_username;
    return 0 unless time() <= $expiry;

    return 1;
}

sub _b64 {
    require MIME::Base64;
    return MIME::Base64::encode_base64( $_[0], '' );
}

sub _b64d {
    require MIME::Base64;
    my $decoded = eval { MIME::Base64::decode_base64( $_[0] ) };
    return $@ ? undef : $decoded;
}

# =============================================
# API HANDLERS
# =============================================

sub handle_get_csrf {
    require_method('GET');
    my $token = TNSecurity::generate_csrf_token();
    send_json( { success => 1, token => $token } );
}

sub handle_check_session {
    require_method('GET');

    my $session_id = get_session_id();

    if ($session_id) {
        my $session = TNAuth::validate_session($session_id);
        if ($session) {
            send_json(
                {
                    authenticated => 1,
                    username      => $session->{username},
                    user_id       => $session->{user_id},
                    role          => $session->{role},
                    session_age   => $session->{session_age},
                    devel_mode    => TNConfig::is_devel_mode() ? 1 : 0,
                }
            );
        }
    }

    send_json( { authenticated => 0 } );
}

sub handle_list_questions {
    require_method('GET');
    my @questions = TNAuth::get_available_questions();
    send_json( { success => 1, questions => \@questions } );
}

sub handle_registration_status {
    require_method('GET');
    my $status = TNAuth::check_registration_status();
    send_json($status);
}

sub handle_list_tokens {
    require_method('GET');
    my $session = require_session('admin');
    my $tokens  = TNAuth::get_unused_tokens();
    send_json( { success => 1, tokens => $tokens } );
}

# =============================================
# DEVEL MODE HANDLERS
# =============================================

sub handle_devel_status {
    require_method('GET');
    my $devel_mode = TNConfig::is_devel_mode();
    send_json( { devel_mode => $devel_mode ? 1 : 0, version => '2.1.0' } );
}

sub handle_devel_enable {
    require_method('POST');
    require_csrf_token();

    my $data     = get_json_body();
    my $password = $data->{password} || send_error( 400, 'Password required' );

    if ( TNConfig::enable_devel_mode($password) ) {
        TNSecurity::log_security_event( 'warning', 'DEVEL mode enabled', '' );
        send_json( { success => 1, message => 'DEVEL mode enabled' } );
    }
    else {
        send_error( 401, 'Invalid password' );
    }
}

sub handle_devel_disable {
    require_method('POST');
    require_csrf_token();
    TNConfig::disable_devel_mode();
    TNSecurity::log_security_event( 'info', 'DEVEL mode disabled', '' );
    send_json( { success => 1, message => 'DEVEL mode disabled' } );
}

sub handle_user_delete {
    require_method('POST');
    my $session = require_session('admin');
    require_csrf_token();

    if ( $session->{role} ne 'admin' ) {
        send_error( 403, 'Administrative privileges required' );
    }

    my $json       = get_json_body();
    my $target_uid = untaint_string( $json->{user_id}, qr/^([a-f0-9]{64})$/ );
    unless ($target_uid) { send_error( 400, 'Invalid user_id' ) }

    my $result = TNAuth::delete_user($target_uid);

    if ( $result->{success} ) {
        TNSecurity::log_security_event( 'info', 'USER_DELETED',
            "Admin $session->{username} deleted user $target_uid" );
        send_json(
            {
                success => 1,
                message => "User $target_uid deleted successfully"
            }
        );
    }
    else {
        send_error( 500, "Deletion failed: $result->{error}" );
    }
}

# ============================================================================
# UTILITY FUNCTIONS
#
# require_method()      --  enforces a single HTTP method, 405 on mismatch
# require_csrf_token()  --  reads csrf_token from JSON body, validates via
#                           TNSecurity time-window HMAC. Skipped if ENABLE_CSRF=0.
# require_session()     --  extracts signed cookie, verifies HMAC, validates DB
#                           session, enforces role. 401 on missing/expired session.
# get_session_id()      --  extracts and verifies the signed session cookie value
# set_session_cookie()  --  emits Set-Cookie header with configured attributes
# clear_session_cookie()--  emits expired Set-Cookie to destroy client cookie
# validate_origin()     --  checks HTTP_ORIGIN or HTTP_REFERER matches HTTP_HOST.
#                           Skipped in DEVEL mode and if ENABLE_ORIGIN_CHECK=0.
# send_json()           --  emits Status 200 + JSON body + security headers + exit
# send_error()          --  emits Status N + JSON error body + exit.
#                           500+ errors also logged to security.log.
# untaint_*()           --  taint-mode safe extractors for method, path, string,
#                           email, username. Return undef or call send_error on fail.
# ============================================================================

sub require_method {
    my ($required) = @_;
    unless ( $method eq $required ) {
        send_error( 405, "Method not allowed. Expected $required" );
    }
}

sub require_csrf_token {
    return 1 unless TNConfig::get_config( 'security', 'ENABLE_CSRF' ) // 1;

    my $data  = get_json_body();
    my $token = $data ? $data->{csrf_token} : undef;

    unless ( TNSecurity::validate_csrf_token($token) ) {
        send_error( 403, 'Invalid or missing CSRF token' );
    }
    return 1;
}

sub require_session {
    my ($required_role) = @_;

    my $session_id = get_session_id();
    unless ($session_id) { send_error( 401, 'Authentication required' ) }

    my $session = TNAuth::validate_session($session_id);
    unless ($session) { send_error( 401, 'Invalid session' ) }

    if ( $required_role && $session->{role} ne $required_role ) {
        send_error( 403, 'Insufficient permissions' );
    }

    return $session;
}

sub get_session_id {
    my $cookie = $ENV{HTTP_COOKIE} || '';
    if ( $cookie =~ /\Q$SESSION_COOKIE_NAME\E=([a-zA-Z0-9_\-=\.]+)/ ) {
        my $signed_session = $1;
        return TNSecurity::verify_session_id($signed_session);
    }
    return undef;
}

sub set_session_cookie {
    my ($session_id) = @_;
    my $cookie = sprintf(
        "%s=%s; Path=%s%s%s; SameSite=%s",
        $SESSION_COOKIE_NAME,
        $session_id,
        $SESSION_COOKIE_PATH,
        $SESSION_COOKIE_HTTPONLY ? '; HttpOnly' : '',
        $SESSION_COOKIE_SECURE   ? '; Secure'   : '',
        $SESSION_COOKIE_SAMESITE
    );
    print "Set-Cookie: $cookie\n";
}

sub clear_session_cookie {
    my $cookie = sprintf(
        "%s=; Path=%s; Expires=Thu, 01 Jan 1970 00:00:00 GMT%s; SameSite=%s",
        $SESSION_COOKIE_NAME, $SESSION_COOKIE_PATH,
        $SESSION_COOKIE_HTTPONLY ? '; HttpOnly' : '',
        $SESSION_COOKIE_SAMESITE
    );
    print "Set-Cookie: $cookie\n";
}

sub validate_origin {
    my $origin  = $ENV{HTTP_ORIGIN}  || '';
    my $referer = $ENV{HTTP_REFERER} || '';
    my $host    = $ENV{HTTP_HOST}    || '';

    return 1 if TNConfig::is_devel_mode();
    return 1
      unless TNConfig::get_config( 'security', 'ENABLE_ORIGIN_CHECK' ) // 1;

    $host = untaint_string( $host, qr/^([\w\.\-:]+)$/ ) || '';

    if ( $origin && $host ) {
        return 1 if $origin =~ m{^https?://\Q$host\E(?::\d+)?$};
    }
    if ( $referer && $host ) {
        return 1 if $referer =~ m{^https?://\Q$host\E(?::\d+)?/};
    }

    return 0;
}

sub send_json {
    my ( $data, $extra_headers ) = @_;

    my $json_output = JSON->new->utf8->encode($data);

    print "Status: 200 OK\n";
    print "Content-Type: application/json; charset=UTF-8\n";
    print "Content-Length: " . length($json_output) . "\n";
    print "X-Frame-Options: DENY\n";
    print "X-Content-Type-Options: nosniff\n";
    print "Cache-Control: no-cache, no-store, must-revalidate, private\n";
    print "Connection: close\n";

    if ( $extra_headers && ref($extra_headers) eq 'ARRAY' ) {
        print "$_\n" for @$extra_headers;
    }

    print "\n";
    print $json_output;

    exit 0;
}

sub send_error {
    my ( $code, $message ) = @_;

    my %status_messages = (
        400 => 'Bad Request',
        401 => 'Unauthorized',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        413 => 'Payload Too Large',
        429 => 'Too Many Requests',
        500 => 'Internal Server Error',
    );

    my $status = $status_messages{$code} || 'Error';

    print "Status: $code $status\n";
    print "Content-Type: application/json\n";
    print "\n";
    print JSON->new->utf8->encode(
        {
            success => 0,
            error   => $message,
            code    => $code,
        }
    );

    if ( $code >= 500 ) {
        eval {
            TNSecurity::log_security_event( 'error', "HTTP $code: $message",
                '' );
        };
    }

    exit 0;
}

1;
