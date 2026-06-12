# ============================================================================
# MODULE: TNWAF.pm
# PURPOSE: Web Application Firewall -- routing, asset serving, SRI enforcement.
# VERSION: 1.0.2
#
# ROLE IN THE STACK:
#   TNWAF is the HTTP layer. It is loaded by router.pl and owns everything
#   between the raw HTTP request and the filesystem or CGI backend.
#
# RESPONSIBILITIES:
#   1. Request validation   -- URI length, method whitelist, block patterns
#   2. Rate limiting        -- per-IP request counter with lockout
#   3. Routing              -- maps URIs to serve_* handlers
#   4. Asset serving        -- JS, CSS, fonts, images, HTML, SPA views
#   5. SRI tamper detection -- sha384 of JS file content verified against
#                              %CONFIG{sri_hashes} before every serve.
#                              A hash mismatch returns 500 and logs SRI_TAMPER.
#                              Hashes are written by TN_SUBSTITUTE.sh at deploy
#                              time and must not be regenerated at runtime.
#   6. Security headers     -- CSP, HSTS, X-Frame-Options, etc. on all responses
#   7. CGI proxying         -- /cgi-bin/*.pl forwarded to control.pl via exec()
#
# SRI HASH FLOW:
#   TN_SUBSTITUTE.sh (deploy)
#     +---- computes sha384 for each JS asset
#           +---- writes sri_hashes block into TNWAF.pm
#   TNWAF::serve_file() (runtime)
#     +---- recomputes sha384 of file bytes on disk
#           +---- compares against %CONFIG{sri_hashes} -- refuses to serve on mismatch
#
# PATH RESOLUTION:
#   BASE_DIR = TNEnv::get_app_root() = /htdocs/tn  (inside chroot)
#   Assets are served from BASE_DIR/assets/{js,css,fonts,img}/
#   serve_asset() passes the canonical relative path (/assets/js/foo.js)
#   directly to serve_file() -- no stripping of BASE_DIR needed.
#
# INTEGRATION:
#   Loaded by  : router.pl
#   Depends on : TNEnv (path resolution), TNConfig (rate limit config)
#   Does NOT load TNAuth or TNSecurity -- auth is exclusively control.pl's domain.
#
# AUTHOR: DAVID PETER, TANGENT NETWORKS
# ============================================================================

package TNWAF;

use strict;
use warnings;
use Time::HiRes qw(time);
use File::Spec;
use File::Basename;
use Cwd 'abs_path';
use Digest::SHA  qw(sha384);
use MIME::Base64 qw(encode_base64);

our $VERSION = '1.0.2';

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/sbin:/usr/sbin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

 # Self-bootstrap: resolve lib path from this file's own location.
 # TNWAF.pm lives in data/lib alongside TNAuth, TNSecurity, TNConfig, TNEnv.
 # dirname(__FILE__) resolves to data/lib directly -- no path arithmetic needed.
 # This matches the pattern used by TNAuth, TNSecurity, TNConfig, and TNEnv.
    my $lib_path = dirname(__FILE__);
    $lib_path = abs_path($lib_path) if -d $lib_path;
    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        unshift @INC, $1 unless grep { $_ eq $1 } @INC;
    }
    else {
        die "FATAL: Unsafe characters in lib path: $lib_path\n";
    }
}

use TNEnv;
use TNConfig;

# BASE_DIR via TNEnv::get_app_root() -- same resolution used by TNSecurity
# and TNConfig. TNEnv derives app_root from its own __FILE__ location:
#   data/lib/../.. = app root (/var/www/htdocs/tn inside the chroot).
# This replaces the previous FindBin/$RealBin approach and ensures TNWAF
# is environment-aware and chroot-safe regardless of invocation context.
our $BASE_DIR = do {
    my $path = TNEnv::get_app_root();
    if ( $path =~ m{^([-/\w.]+)$} ) {
        $1;
    }
    else {
        die "FATAL: Unsafe characters in BASE_DIR: $path\n";
    }
};

our %CONFIG = (
    docroot => $BASE_DIR,

    sri_hashes => {
        '/assets/js/auth.js' => 'sha384-zxVXOdCbp5CF2QfNoz+nbGhpNTQl/P6AzaGhSTQMXhWOQZERnBpdrHWUghEmWlkq',
        '/assets/js/doc.js' => 'sha384-I2PJ8+c+uSGlbPHxv0FF0KRX6/MMHEg0y1rn2xYqNdUz1FESQ5xVmir6Y6/zdoV8',
        '/assets/js/e2g.js' => 'sha384-KJq6lgB9xu1Nw54DPRwKTYjzBiugFX6/Ek8JJ9MKJ9Be0EdAoYBNuWkqjzwoWoY5',
        '/assets/js/firewall.js' => 'sha384-71YcxLfb3fIMLqpdRyjl0ZH3FvkM2V3yXG/fxLzBux7PIvj7q+h/9RKpz8nWtRVJ',
        '/assets/js/integrity.js' => 'sha384-l+j7ayZ+ZSbLj396aMzsM1xywEPglbpyQdfmNJbFvxxybGPsk4MGKcI+dMucp8pf',
        '/assets/js/integrity_list.js' => 'sha384-51vmC55zsZHmRZ5jqfrEFfu4PF283sBH0K1VrtFf7D8CXa39SpAjZQ/joNiVsA33',
        '/assets/js/lan.js' => 'sha384-Mc8kMNUWUhh0caNS2craZWPPGR2cEGUVKC3ErR+nqIQj7OeYqyKGlRBhfvIH4KSv',
        '/assets/js/logs.js' => 'sha384-7s+HLrshxHLZy85Pm7/5jbvmjsv8E1YQ6tzLNXMOlOjcgf7Muk6wCYSRVqg/l0tK',
        '/assets/js/mail.js' => 'sha384-xHP7x+Q4CJRUUzzn/NjuFHIiiJK/5TO85mu1GXaCNjbnL1649qxGRBJ33AeRkSjp',
        '/assets/js/maintenance.js' => 'sha384-fUVAs/Oy0oZNh9oTDBQctm4VRVtp9gvDX0Cv30dQyOpSOFiDZHcTbsisd2nNSS1f',
        '/assets/js/managenav.js' => 'sha384-z/EwQt3P73H/XsHAQGanUFlE83238NaG4QeZXniyBeF2HaM+ROYfArf+VoOlsDBH',
        '/assets/js/metrics.js' => 'sha384-uN8xl5rx4jIqHH2zQoJZ0S4lpE9/x6F6VsJwgRn/xnS3DM0XlJZJ/fosrYWNm2Q5',
        '/assets/js/pf.js' => 'sha384-YfzcLQxHJzii9xWssnP7fZlfZbzzvKUSBkpMvDSoiaYHozGzkOItzF741r49KST2',
        '/assets/js/pfstats.js' => 'sha384-W0WdOQn8IaqflzZH0bZSns/PxwwZqgWv4sbWxKtSHQIUiafHexi8xr/+6B6cWp67',
        '/assets/js/powermgmt.js' => 'sha384-R5M1hBrZDZHG97qxU1/mafaf6X7tO+JiUlTow2fIy+fv0n0wWoTeqFoBDKzf5CY+',
        '/assets/js/register-sw.js' => 'sha384-02PFGWnvDB3qAPOlnw1ZrSp7XD7EBa01mKDEcOMvutz3jvWFWQzkmY8aAeCsDrHS',
        '/assets/js/servicemonitor.js' => 'sha384-M2J/VRxDSAJcIM++4uXQy+Q+czVjRdJKgPLE68xNFT9abARixDchVKYDgOsCNycV',
        '/assets/js/services.js' => 'sha384-8LXtnc8vDV+UBvLTq8UDbhr3P0M2Fl4BR+aD6AKugj8bmfCyMt+ulNaYI0/X4SvD',
        '/assets/js/session.js' => 'sha384-QWdWaO8Dk8DeqJLutTFPv3TyuqxWqwNnRXz1t4VR9y+V22AZj4ZifSgZtLl3cxCw',
        '/assets/js/token.js' => 'sha384-klUKP7N3iOfziRPsL6XrgPgO3JQbkMUofalL1p+6OQ5SG/UOWlgH79KnPTaqHeUn',
        '/assets/js/ts.js' => 'sha384-TH4RWg6PiUgp3X5p0KFpJPI48AYQL3BjUGLmYsswiOPb3uRy6AfJ0OawHKaN2lmo',
        '/assets/js/ui.js' => 'sha384-+Y8m2Uyky1CH8VYb9O4k8mYFuaN6t0m3pUNP+g4na/ROg2LuMAnQSeH8LGG5psRh',
        '/assets/js/unbound.js' => 'sha384-slyQ3T0GITgO7qjxyo4sNUf9hAYPj8f5oFdPNwXjJnAWe6ynZz5rDCzsR11RVkhS',
        '/assets/js/view.js' => 'sha384-0yKOeVPneHsG7gC2FrpA7AjJKnBXvW2MukKNMQDHQejFqLMT6ad8F/Ge9lAL1JCF',
        '/assets/js/wan.js' => 'sha384-ASRSQNd6tbZJQ5Ooe3ihVfOfF73nGH0SzfyuuCJDJ/1AbmVbjfbLcTKMdH8D1cYp',
    },

    csp => {
        default_src => "'self'",

# script-src: 'self' only -- all JS is external files with SRI enforcement.
# unsafe-inline and unsafe-eval removed -- server-side SRI tamper detection
# in serve_file() ensures only known-good JS is ever served.
# style-src:  'self' only -- CSS is self-hosted, no inline styles.
# img-src:    'self' + data: -- data: required for inline SVG data URIs from
#             Tailwind/Flowbite CSS (custom selects, checkboxes, form elements).
# font-src:   'self' only -- fonts are self-hosted, no data: URI fonts.
# object-src: 'none' -- blocks Flash/plugins/object tag entirely.
# No blob:, no unsafe-inline, no unsafe-eval -- no legitimate use in this codebase.
        script_src                => "'self'",
        style_src                 => "'self' 'unsafe-inline'",
        img_src                   => "'self' data:",
        font_src                  => "'self'",
        connect_src               => "'self'",
        object_src                => "'none'",
        form_action               => "'self'",
        base_uri                  => "'self'",
        frame_ancestors           => "'none'",
        upgrade_insecure_requests => '',
    },

    security_headers => {
        'X-Frame-Options'        => 'DENY',
        'X-Content-Type-Options' => 'nosniff',
        'X-XSS-Protection'       => '1; mode=block',
        'Referrer-Policy'        => 'strict-origin-when-cross-origin',
        'Permissions-Policy'     =>
          'geolocation=(), microphone=(), camera=(), payment=()',
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
    },

    cache_headers => {
        'Cache-Control' => 'no-cache, no-store, must-revalidate, private',
        'Pragma'        => 'no-cache',
        'Expires'       => '0',
    },

    rate_limit => {
        enabled => 1,

        # Read from security.conf [rate_limit] at startup.
        # Floors prevent the appliance being misconfigured into no protection.
        max_rpm => do {
            my $v =
              TNConfig::get_config( 'rate_limit', 'MAX_REQUESTS_PER_MINUTE' )
              // 60;
            $v = 10 if $v < 10;    # floor: below 10 req/min is unusable
            $v;
        },
        lockout => do {
            my $v = TNConfig::get_config( 'rate_limit', 'LOCKOUT_DURATION' )
              // 1800;
            $v = 60 if $v < 60;    # floor: below 60 s lockout is no deterrent
            $v;
        },
    },

    filtering => {
        max_uri_length    => 2048,
        max_header_length => 8192,
        block_patterns    => [
            qr/\.\./,           qr/[<>'"]/,
            qr/union.*select/i, qr/script.*src/i,
            qr/javascript:/i,   qr/data:text\/html/i,
        ],
    },

    log_file     => 'data/logs/waf/access.log',
    security_log => 'data/logs/waf/security.log',
    error_log    => 'data/logs/waf/error.log',
);

our %RATE_LIMITS = ();
our %IP_BLOCKS   = ();

sub route_request {
    my ($uri) = @_;
    $uri ||= $ENV{REQUEST_URI} || '/';
    $uri =~ s/\?.*$//;
    return error_response( 400, 'Bad Request' ) unless validate_request($uri);
    my $client_ip = $ENV{REMOTE_ADDR} || 'unknown';
    return error_response( 429, 'Too Many Requests' )
      unless check_rate_limit($client_ip);
    log_access( $uri, $client_ip );
    if ( $uri =~ m{^/cgi-bin/(\w+\.pl)(/.*)?$} ) {
        return proxy_to_cgi( $1, $2 || '' );
    }
    if    ( $uri eq '/index.html' ) { return serve_static_html('index.html') }
    elsif ( $uri eq '/' || $uri eq '/view.html' ) { return serve_html() }
    elsif ( $uri eq '/documentation.html' ) {
        return serve_static_html('documentation.html');
    }
    elsif ( $uri eq '/pwreset.html' ) {
        return serve_static_html('pwreset.html');
    }
    elsif ( $uri eq '/register.html' ) {
        return serve_static_html('register.html');
    }
    elsif ( $uri eq '/privacy.html' ) {
        return serve_static_html('privacy.html');
    }
    elsif ( $uri eq '/legal.html' ) { return serve_static_html('legal.html') }
    elsif ( $uri eq '/license.html' ) {
        return serve_static_html('license.html');
    }
    elsif ( $uri =~ m{^/view/(\w+)$} ) { return serve_view($1) }
    elsif ( $uri =~ m{^/docs/([\w-]+\.html)$} ) {
        return serve_doc_fragment($1);
    }
    elsif ( $uri =~ m{^/assets/(js|css|fonts|img|images)/([\w./-]+)$} ) {
        return serve_asset( $1, $2 );
    }
    elsif ( $uri =~ m{^/data/(.+)$} ) { return serve_data($1) }
    elsif ( $uri =~ m{^/(favicon(?:-\d+x\d+)?\.ico)$} ) {
        return serve_root_file( $1, 'image/x-icon' );
    }
    elsif ( $uri =~ m{^/(favicon(?:-\d+x\d+)?\.png)$} ) {
        return serve_root_file( $1, 'image/png' );
    }
    elsif ( $uri =~ m{^/(apple-(?:icon|touch-icon)(?:-\d+x\d+)?\.png)$} ) {
        return serve_root_file( $1, 'image/png' );
    }
    elsif ( $uri eq '/manifest.json' ) {
        return serve_root_file( 'manifest.json', 'application/json' );
    }
    elsif ( $uri eq '/sw.js' ) {
        return serve_root_file( 'sw.js', 'application/javascript' );
    }
    else { return error_response( 404, 'Not Found' ) }
}

sub proxy_to_cgi {
    my ( $script, $path_info ) = @_;
    my $script_path = File::Spec->catfile( $BASE_DIR, 'cgi-bin', $script );
    unless ( -f $script_path && -x $script_path ) {
        return error_response( 404, 'Not Found' );
    }
    local $ENV{PATH_INFO} = $path_info;
    exec($script_path) or return error_response( 500, 'Internal Server Error' );
}

sub serve_html {
    my $file_path = File::Spec->catfile( $BASE_DIR, 'view.html' );
    return serve_file( $file_path, 'text/html; charset=UTF-8', 1 );
}

sub serve_static_html {
    my ($filename) = @_;
    return error_response( 400, 'Invalid file' )
      unless $filename =~ /^([\w.-]+\.html)$/;
    $filename = $1;
    my $file_path = File::Spec->catfile( $BASE_DIR, $filename );
    return serve_file( $file_path, 'text/html; charset=UTF-8', 1 );
}

sub serve_root_file {
    my ( $filename, $content_type ) = @_;
    return error_response( 400, 'Invalid file' )
      unless $filename =~ /^([\w.-]+)$/;
    $filename = $1;
    my $file_path = File::Spec->catfile( $BASE_DIR, $filename );
    return serve_file( $file_path, $content_type, 0 );
}

sub serve_view {
    my ($view_name) = @_;
    return error_response( 400, 'Invalid view' ) unless $view_name =~ /^(\w+)$/;
    $view_name = $1;
    my $file_path = File::Spec->catfile( $BASE_DIR, 'view', $view_name );
    return serve_file( $file_path, 'text/html; charset=UTF-8', 1 );
}

sub serve_doc_fragment {
    my ($filename) = @_;
    return error_response( 400, 'Invalid file' )
      unless $filename =~ /^([\w-]+\.html)$/;
    $filename = $1;
    my $file_path = File::Spec->catfile( $BASE_DIR, 'docs', $filename );
    return serve_file( $file_path, 'text/html; charset=UTF-8', 1 );
}

sub serve_asset {
    my ( $type, $file ) = @_;
    return error_response( 400, 'Invalid file' )
      unless $file =~ m{^([\w./-]+)$};
    $file = $1;
    return error_response( 403, 'Forbidden' ) if $file =~ /\.\./;
    my $file_path    = File::Spec->catfile( $BASE_DIR, 'assets', $type, $file );
    my $content_type = get_content_type( $file, $type );
    return serve_file( $file_path, $content_type, 0 );
}

sub serve_data {
    my ($file) = @_;

    # Validate path characters -- no traversal, no special chars.
    return error_response( 400, 'Invalid file' )
      unless $file =~ m{^([\w./-]+)$};
    $file = $1;
    return error_response( 403, 'Forbidden' ) if $file =~ /\.\./;

    # Denylist: block subdirectories that contain secrets.
    my ($top_dir) = ( $file =~ m{^([\w-]+)/} );
    if ($top_dir) {
        my %blocked = map { $_ => 1 } qw(
          keys config lib lib-bak scripts session run queue
        );
        return error_response( 403, 'Forbidden' ) if $blocked{$top_dir};

        # db/ is partially blocked: SQLite database files must never be served,
        # but subdirectories (GeoIP/, pf/) contain UI-readable lookup data.
        if ( $top_dir eq 'db' ) {
            return error_response( 403, 'Forbidden' )
              if $file =~ m{^db/[^/]+\.db(?:-wal|-shm)?$};
        }
    }

    my $file_path    = File::Spec->catfile( $BASE_DIR, 'data', $file );
    my $content_type = $file =~ /\.json$/ ? 'application/json' : 'text/plain';
    return serve_file( $file_path, $content_type, 0 );
}

sub serve_file {
    my ( $file_path, $content_type, $include_csp ) = @_;
    unless ( -f $file_path && -r $file_path ) {
        return error_response( 404, 'Not Found' );
    }
    open( my $fh, '<', $file_path )
      or return error_response( 500, 'Internal Server Error' );
    binmode($fh);
    local $/;
    my $content = <$fh>;
    close($fh);

   # ---Server-side SRI tamper detection
   # For JS assets: compute SHA-384 of file content and compare against the
   # known-good hash table. If the file has been tampered with on disk the
   # hash will not match and we refuse to serve it -- the browser never sees
   # the compromised file regardless of what the HTML integrity= attribute says.
    if ( $content_type =~ /javascript/ ) {
        my $relative_path = $file_path;
        $relative_path =~ s{^\Q$BASE_DIR\E}{};
        if ( my $expected = $CONFIG{sri_hashes}{$relative_path} ) {
            my $actual = 'sha384-' . encode_base64( sha384($content), '' );
            unless ( $actual eq $expected ) {
                log_security( 'SRI_TAMPER',
                        "Hash mismatch for $relative_path -- "
                      . "expected=$expected actual=$actual -- refusing to serve"
                );
                return error_response( 500, 'Internal Server Error' );
            }
        }
    }

    print_headers( $content_type, $include_csp, $file_path );
    binmode(STDOUT);
    print $content;
    return 1;
}

sub print_headers {
    my ( $content_type, $include_csp, $file_path ) = @_;
    print "Content-Type: $content_type\n";
    if ($include_csp) { print "Content-Security-Policy: " . build_csp() . "\n" }
    if ( $file_path && $content_type =~ /javascript/ ) {
        my $relative_path = $file_path;
        $relative_path =~ s{^\Q$BASE_DIR\E}{};
        if ( my $sri = $CONFIG{sri_hashes}{$relative_path} ) {
            print "X-Content-Digest: $sri\n";
        }
    }
    foreach my $header ( keys %{ $CONFIG{security_headers} } ) {
        print "$header: $CONFIG{security_headers}{$header}\n";
    }
    foreach my $header ( keys %{ $CONFIG{cache_headers} } ) {
        print "$header: $CONFIG{cache_headers}{$header}\n";
    }
    print "\n";
}

sub build_csp {
    my @directives;
    foreach my $directive ( sort keys %{ $CONFIG{csp} } ) {
        my $value = $CONFIG{csp}{$directive};
        next unless defined $value;
        my $name = $directive;
        $name =~ s/_/-/g;
        push @directives, $value ? "$name $value" : $name;
    }
    return join( '; ', @directives );
}

sub get_content_type {
    my ( $file, $asset_type ) = @_;
    my %types = (
        'js'    => 'application/javascript',
        'mjs'   => 'application/javascript',
        'css'   => 'text/css',
        'woff'  => 'font/woff',
        'woff2' => 'font/woff2',
        'ttf'   => 'font/ttf',
        'otf'   => 'font/otf',
        'eot'   => 'application/vnd.ms-fontobject',
        'png'   => 'image/png',
        'jpg'   => 'image/jpeg',
        'jpeg'  => 'image/jpeg',
        'gif'   => 'image/gif',
        'svg'   => 'image/svg+xml',
        'webp'  => 'image/webp',
        'ico'   => 'image/x-icon',
        'json'  => 'application/json',
        'xml'   => 'application/xml',
        'txt'   => 'text/plain',
    );
    my $ext = ( $file =~ /\.([^.]+)$/ )[0] || '';
    return $types{$ext}                    || 'application/octet-stream';
}

sub validate_request {
    my ($uri) = @_;
    return 0 if length($uri) > $CONFIG{filtering}{max_uri_length};
    foreach my $pattern ( @{ $CONFIG{filtering}{block_patterns} } ) {
        if ( $uri =~ $pattern ) {
            log_security( 'BLOCKED',
                "Malicious pattern detected in URI: $uri" );
            return 0;
        }
    }
    my $method = $ENV{REQUEST_METHOD} || 'GET';
    unless ( $method =~ /^(GET|POST|HEAD|OPTIONS)$/ ) {
        log_security( 'BLOCKED', "Invalid HTTP method: $method" );
        return 0;
    }
    return 1;
}

sub check_rate_limit {
    my ($ip) = @_;
    return 1 unless $CONFIG{rate_limit}{enabled};
    my $now = time();
    if ( exists $IP_BLOCKS{$ip} ) {
        my $block_until = $IP_BLOCKS{$ip};
        if ( $now < $block_until ) {
            log_security( 'RATE_LIMIT', "Blocked IP: $ip" );
            return 0;
        }
        else {
            delete $IP_BLOCKS{$ip};
        }
    }
    unless ( exists $RATE_LIMITS{$ip} ) {
        $RATE_LIMITS{$ip} = { count => 0, window_start => $now };
    }
    my $limit = $RATE_LIMITS{$ip};
    if ( $now - $limit->{window_start} >= 60 ) {
        $limit->{count}        = 0;
        $limit->{window_start} = $now;
    }
    $limit->{count}++;
    if ( $limit->{count} > $CONFIG{rate_limit}{max_rpm} ) {
        $IP_BLOCKS{$ip} = $now + $CONFIG{rate_limit}{lockout};
        log_security( 'RATE_LIMIT',
            "IP blocked for exceeding rate limit: $ip" );
        return 0;
    }
    return 1;
}

sub error_response {
    my ( $code, $message ) = @_;
    my %codes = (
        400 => 'Bad Request',
        403 => 'Forbidden',
        404 => 'Not Found',
        429 => 'Too Many Requests',
        500 => 'Internal Server Error',
    );
    my $status = $codes{$code} || 'Error';

# Dual logging: waf/error.log (TNWatch source) + httpd/httpd_error.log (UI viewer)
    {
        my $timestamp = scalar( localtime( time() ) );
        my $ip        = $ENV{REMOTE_ADDR} || 'unknown';
        my $uri       = $ENV{REQUEST_URI} || '-';
        my $line      = sprintf "[%s] HTTP %d %s - IP=%s URI=%s\n",
          $timestamp, $code, $status, $ip, $uri;

        my $waf_log = File::Spec->catfile( $BASE_DIR, $CONFIG{error_log} );
        my $waf_dir = File::Spec->catdir( $BASE_DIR, 'data', 'logs', 'waf' );
        mkdir( $waf_dir, 0755 ) unless -d $waf_dir;
        if ( open( my $fh, '>>', $waf_log ) ) { print $fh $line; close($fh) }

        my $httpd_log = File::Spec->catfile( $BASE_DIR, 'data', 'logs', 'httpd',
            'httpd_error.log' );
        my $httpd_dir =
          File::Spec->catdir( $BASE_DIR, 'data', 'logs', 'httpd' );
        mkdir( $httpd_dir, 0755 ) unless -d $httpd_dir;
        if ( open( my $fh, '>>', $httpd_log ) ) { print $fh $line; close($fh) }
    }

    print "Status: $code $status\n";
    print_headers( 'text/html; charset=UTF-8', 0 );
    print qq{<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$code $status</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
               min-height: 100vh; display: flex; align-items: center;
               justify-content: center; padding: 20px; }
        .error-container { background: white; border-radius: 16px;
               box-shadow: 0 20px 60px rgba(0,0,0,0.3); padding: 60px 40px;
               text-align: center; max-width: 500px; }
        .error-code { font-size: 96px; font-weight: 900; color: #dc2626;
               line-height: 1; margin-bottom: 20px; }
        .error-message { font-size: 24px; color: #374151; margin-bottom: 30px; }
        .back-link { display: inline-block; padding: 12px 30px; background: #667eea;
               color: white; text-decoration: none; border-radius: 8px;
               font-weight: 600; transition: background 0.2s; }
        .back-link:hover { background: #5568d3; }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-code">$code</div>
        <div class="error-message">$message</div>
        <a href="/" class="back-link">Return Home</a>
    </div>
</body>
</html>};
    return 0;
}

sub log_access {
    my ( $uri, $ip ) = @_;
    my $timestamp  = scalar( localtime( time() ) );
    my $method     = $ENV{REQUEST_METHOD}  || '-';
    my $user_agent = $ENV{HTTP_USER_AGENT} || '-';
    my $log_file   = File::Spec->catfile( $BASE_DIR, $CONFIG{log_file} );
    my $log_dir    = File::Spec->catdir( $BASE_DIR, 'data', 'logs', 'waf' );
    mkdir( $log_dir, 0755 ) unless -d $log_dir;
    if ( open( my $fh, '>>', $log_file ) ) {
        printf $fh "[%s] %s %s %s \"%s\"\n", $timestamp, $ip, $method, $uri,
          $user_agent;
        close($fh);
    }
}

sub log_security {
    my ( $event, $details ) = @_;
    my $timestamp = scalar( localtime( time() ) );
    my $ip        = $ENV{REMOTE_ADDR} || 'unknown';
    my $log_file  = File::Spec->catfile( $BASE_DIR, $CONFIG{security_log} );
    my $log_dir   = File::Spec->catdir( $BASE_DIR, 'data', 'logs', 'waf' );
    mkdir( $log_dir, 0755 ) unless -d $log_dir;
    if ( open( my $fh, '>>', $log_file ) ) {
        printf $fh "[%s] %s IP=%s %s\n", $timestamp, $event, $ip, $details;
        close($fh);
    }
    my $logger = '/usr/bin/logger';
    if ( $logger =~ /^([-\/\w]+)$/ ) {
        $logger = $1;
        system( $logger, '-t', 'tnwaf', '-p', 'security.warning',
            "[$event] IP=$ip $details" );
    }
}

sub get_sri_tag {
    my ($asset_path) = @_;
    my $sri = $CONFIG{sri_hashes}{$asset_path};
    return '' unless $sri;
    return qq{ integrity="$sri" crossorigin="anonymous"};
}

sub get_client_ip {
    return $ENV{HTTP_X_FORWARDED_FOR} || $ENV{REMOTE_ADDR} || 'unknown';
}

sub sanitize {
    my ($text) = @_;
    return '' unless defined $text;
    $text =~ s/[\x00-\x1F\x7F]//g;
    $text =~ s/^\s+|\s+$//g;
    return $text;
}

1;
