# ============================================================================
# MODULE: TNEnv.pm
# PURPOSE: Environment bootstrap -- must be loaded first by all TN* modules.
# VERSION: 1.0.0
#
# ROLE IN THE STACK:
#   TNEnv is the foundation layer. Every other TN* module and every CGI
#   script loads TNEnv first. It runs at BEGIN time and is therefore
#   guaranteed to execute before any other application code.
#
# RESPONSIBILITIES:
#   1. Environment sanitisation -- sets PATH, deletes dangerous env vars,
#                                  configures binmode on STDIN/STDOUT/STDERR.
#   2. @INC bootstrap           -- adds data/lib to @INC using __FILE__ so
#                                  all TN* modules find each other regardless
#                                  of invocation context (CGI, cron, CLI).
#   3. Path utilities           -- get_app_root(), get_data_dir(), get_db_path(),
#                                  get_keys_path(), get_config_path(), get_logs_path().
#                                  All paths are derived from __FILE__ location
#                                  and are chroot-safe (no FindBin, no hardcoding).
#   4. Taint utilities          -- untaint_path(), untaint_filename(),
#                                  untaint_identifier() used throughout the stack.
#   5. Environment verification -- verify_environment() checks all required
#                                  directories and files exist at startup.
#
# CHROOT PATH RESOLUTION:
#   TNEnv.pm lives at: {APP_ROOT}/data/lib/TNEnv.pm
#   get_app_root()  →  data/lib/../.. = {APP_ROOT}
#   get_data_dir()  →  data/lib/..    = {APP_ROOT}/data
#   Inside chroot:  {APP_ROOT} = /htdocs/tn
#   Outside chroot: {APP_ROOT} = /var/www/htdocs/tn
#
# LOAD ORDER (mandatory):
#   1. TNEnv       ← this module, always first
#   2. TNConfig    ← reads security.conf, depends on TNEnv paths
#   3. TNSecurity  ← crypto/session/CSRF, depends on TNConfig
#   4. TNAuth      ← DB auth, depends on TNSecurity
#   5. TNWAF       ← HTTP layer, depends on TNEnv + TNConfig only
#
# INTEGRATION:
#   Loaded by  : router.pl, control.pl, TNWAF.pm, TNSecurity.pm,
#                TNConfig.pm, TNAuth.pm, TNSecurityCheck.pm
#   Depends on : nothing (foundation module)
#
# AUTHOR: DAVID PETER, TANGENT NETWORKS
# ============================================================================
package TNEnv;
use strict;
use warnings;

# ============================================================================
# TNEnv.pm -- Tangent Networks Environment Bootstrap
# ============================================================================
# This module MUST be loaded first in all scripts and modules.
# It sets up the library path, environment, and taint safety.
#
# USAGE:
#   #!/usr/bin/perl -T
#   use strict;
#   use warnings;
#   use FindBin;
#   use lib "$FindBin::RealBin/../data/lib";
#   use TNEnv;  # <-- FIRST, before any other TN* modules
#   use TNSecurity;
#   use TNAuth;
# ============================================================================

our $VERSION = '1.0.0';

# ============================================================================
# ENVIRONMENT SETUP (runs at compile time)
# ============================================================================

BEGIN {
    # Clean environment for taint mode
    $ENV{PATH} = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

    # Set LD_LIBRARY_PATH for chroot environments
    $ENV{LD_LIBRARY_PATH} = '/usr/local/lib:/usr/lib';

    # STDIN and STDERR use the UTF-8 encoding layer for safe text I/O.
    # STDOUT is intentionally left without an encoding layer: the JSON
    # serialiser (JSON->new->utf8->encode) produces raw UTF-8 octets, and
    # adding a :encoding(UTF-8) layer on top would cause Perl to treat those
    # octets as Latin-1 and double-encode them, corrupting non-ASCII output.
    binmode( STDIN,  ':encoding(UTF-8)' );
    binmode( STDOUT, ':raw' );
    binmode( STDERR, ':encoding(UTF-8)' );
}

# ============================================================================
# LIBRARY PATH SETUP
# ============================================================================
# This ensures all TN* modules can find each other, regardless of where
# they're loaded from (CGI script, command-line tool, cron job, etc.)

use FindBin;
use File::Spec;
use Cwd 'abs_path';

BEGIN {
    # Find the lib directory -- use this module's own location
    use File::Basename;
    my $module_file = __FILE__;
    my $lib_path    = dirname($module_file);

    # Make absolute
    $lib_path = abs_path($lib_path) if -d $lib_path;

    # Untaint the path for taint mode
    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        $lib_path = $1;
    }
    else {
        die "TNEnv: Unsafe characters in library path: $lib_path\n";
    }

    # Verify directory exists
    unless ( -d $lib_path ) {
        die "TNEnv: Library directory not found: $lib_path\n";
    }

    # Add to @INC if not already present
    unless ( grep { $_ eq $lib_path } @INC ) {
        unshift @INC, $lib_path;
    }

    # Store for other modules to reference
    $TNEnv::LIB_PATH = $lib_path;
}

# ============================================================================
# PATH UTILITIES
# ============================================================================
# Helper functions for finding application paths in a portable way

# _resolve_path: collapse .. segments in a path without relying on the
# filesystem being fully accessible (chroot safe).
# abs_path() is tried first -- it's authoritative when the path exists.
# If it returns undef (path doesn't exist yet, or chroot context), we
# fall back to a pure-string segment-by-segment collapse.
sub _resolve_path {
    my ($path) = @_;
    my $resolved = Cwd::abs_path($path);
    return $resolved if defined $resolved;

    # Manual collapse: split on /, process each segment
    my @out;
    for my $seg ( split m{/}, $path ) {
        if    ( $seg eq '..' )              { pop @out }
        elsif ( $seg ne '' && $seg ne '.' ) { push @out, $seg }
    }
    return '/' . join( '/', @out );
}

# Get the application root directory
sub get_app_root {
    my $lib_path = $TNEnv::LIB_PATH;

    # lib path is: /htdocs/tn/data/lib  (inside chroot)
    #           or: /var/www/htdocs/tn/data/lib  (outside chroot)
    # app root = two levels up from lib
    my $raw =
      File::Spec->catdir( $lib_path, File::Spec->updir, File::Spec->updir );
    return _resolve_path($raw);
}

# Get path to data directory
#sub get_data_dir {
#    my $lib_path = $TNEnv::LIB_PATH;
#    my $data_dir = File::Spec->catdir($lib_path, File::Spec->updir);
#
#    unless (File::Spec->file_name_is_absolute($data_dir)) {
#        $data_dir = File::Spec->rel2abs($data_dir);
#    }
#
#    return $data_dir;
#}

sub get_data_dir {
    my $lib_path = $TNEnv::LIB_PATH;
    my $raw      = File::Spec->catdir( $lib_path, File::Spec->updir );
    return _resolve_path($raw);
}

# Get path to specific data subdirectory
sub get_data_path {
    my ($subdir) = @_;
    my $data_dir = get_data_dir();
    my $path     = File::Spec->catdir( $data_dir, $subdir );

    unless ( File::Spec->file_name_is_absolute($path) ) {
        $path = File::Spec->rel2abs($path);
    }

    return $path;
}

# Common paths as convenience functions
sub get_db_path     { return get_data_path('db'); }
sub get_keys_path   { return get_data_path('keys'); }
sub get_config_path { return get_data_path('config'); }
sub get_logs_path   { return get_data_path('logs'); }

# ============================================================================
# ENVIRONMENT INFO
# ============================================================================

sub get_environment_info {
    return {
        lib_path     => $TNEnv::LIB_PATH,
        app_root     => get_app_root(),
        data_dir     => get_data_dir(),
        db_path      => get_db_path(),
        keys_path    => get_keys_path(),
        config_path  => get_config_path(),
        logs_path    => get_logs_path(),
        perl_version => $],
        is_tainted   => ${^TAINT} ? 1 : 0,
        inc_paths    => [@INC],
    };
}

# ============================================================================
# TAINT UTILITIES
# ============================================================================
# Common untainting patterns used throughout the application

sub untaint_path {
    my ($path) = @_;
    return undef unless defined $path;

    # Reject parent-directory traversal before the pattern match.
    return undef if $path =~ /\.\./;

    # Allow: alphanumeric, forward slash, underscore, hyphen, dot
    if ( $path =~ m{^([-/\w.]+)$} ) {
        return $1;
    }
    return undef;
}

sub untaint_filename {
    my ($filename) = @_;
    return undef unless defined $filename;

    # Reject path separators and parent-directory references explicitly
    # before the pattern match -- belt-and-suspenders against crafted inputs.
    return undef if $filename =~ m{[/\\]|\.\.};

    # Alphanumeric, underscore, hyphen, dot only
    if ( $filename =~ m{^([\w.-]+)$} ) {
        return $1;
    }
    return undef;
}

sub untaint_identifier {
    my ($id) = @_;
    return undef unless defined $id;

    # Alphanumeric and underscore only (database IDs, usernames, etc.)
    if ( $id =~ m{^([a-zA-Z0-9_]+)$} ) {
        return $1;
    }
    return undef;
}

# ============================================================================
# INITIALIZATION CHECK
# ============================================================================
# Verify the environment is properly set up

sub verify_environment {
    my @errors;

    # Check critical directories exist
    my @required_dirs = (
        [ 'Library',  $TNEnv::LIB_PATH ],
        [ 'Database', get_db_path() ],
        [ 'Keys',     get_keys_path() ],
        [ 'Config',   get_config_path() ],
    );

    foreach my $check (@required_dirs) {
        my ( $name, $path ) = @$check;
        unless ( -d $path ) {
            push @errors, "$name directory not found: $path";
        }
    }

    # Check critical files exist
    my @required_files = (
        [
            'Config file',
            File::Spec->catfile( get_config_path(), 'security.conf' )
        ],
    );

    foreach my $check (@required_files) {
        my ( $name, $path ) = @$check;
        unless ( -f $path ) {
            push @errors, "$name not found: $path";
        }
    }

    # Check device nodes (in chroot environments)
    if ( -e '/dev/urandom' ) {
        unless ( -r '/dev/urandom' ) {
            push @errors, '/dev/urandom not readable';
        }
    }

    return @errors ? \@errors : undef;
}

# ============================================================================
# EXPORT
# ============================================================================

# Make common functions available
our @EXPORT_OK = qw(
  get_app_root
  get_data_dir
  get_data_path
  get_db_path
  get_keys_path
  get_config_path
  get_logs_path
  get_environment_info
  untaint_path
  untaint_filename
  untaint_identifier
  verify_environment
);

our %EXPORT_TAGS = (
    all   => \@EXPORT_OK,
    paths => [
        qw(get_app_root get_data_dir get_data_path get_db_path get_keys_path get_config_path get_logs_path)
    ],
    taint => [qw(untaint_path untaint_filename untaint_identifier)],
);

# Auto-export commonly used functions
sub import {
    my $package = shift;
    my $caller  = caller;

    # Export common functions by default
    no strict 'refs';
    foreach my $func (
        qw(get_data_path get_db_path get_keys_path get_config_path untaint_path)
      )
    {
        *{"${caller}::${func}"} = \&{$func};
    }
}

1;

__END__

=head1 NAME

TNEnv - Tangent Networks Environment Bootstrap

=head1 SYNOPSIS

    #!/usr/bin/perl -T
    use strict;
    use warnings;
    use FindBin;
    use lib "$FindBin::RealBin/../data/lib";
    use TNEnv;  # FIRST - sets up environment
    
    # Now safe to load other TN* modules
    use TNSecurity;
    use TNAuth;
    use TNConfig;
    
    # Use TNEnv functions
    my $db_path = get_db_path();
    my $config = File::Spec->catfile(get_config_path(), 'security.conf');

=head1 DESCRIPTION

TNEnv is the environment bootstrap module for the Tangent Networks security
suite. It MUST be loaded before any other TN* modules to ensure proper
library path setup, environment configuration, and taint mode compliance.

=head2 What TNEnv Does

=over 4

=item * Sets up @INC with the correct library path

=item * Cleans environment variables for taint mode

=item * Configures UTF-8 binmode for STDIN/STDOUT/STDERR

=item * Provides portable path utilities

=item * Offers common untainting patterns

=item * Verifies environment is properly configured

=back

=head2 Path Resolution

TNEnv automatically finds the application root and data directories
regardless of where the script is executed from:

    /var/www/htdocs/tn/              (app root)
    ├── cgi-bin/                     (CGI scripts load TNEnv)
    │   └── control.pl
    ├── data/
    │   ├── lib/                     (TNEnv.pm location)
    │   │   ├── TNEnv.pm
    │   │   ├── TNSecurity.pm
    │   │   └── TNAuth.pm
    │   ├── db/                      (get_db_path())
    │   ├── keys/                    (get_keys_path())
    │   ├── config/                  (get_config_path())
    │   └── logs/                    (get_logs_path())
    └── scripts/                     (CLI tools load TNEnv)

=head1 FUNCTIONS

=head2 Path Functions

=over 4

=item B<get_app_root()>

Returns the application root directory.

=item B<get_data_dir()>

Returns the data directory.

=item B<get_data_path($subdir)>

Returns path to a subdirectory within data/.

=item B<get_db_path()>

Returns the database directory.

=item B<get_keys_path()>

Returns the encryption keys directory.

=item B<get_config_path()>

Returns the configuration directory.

=item B<get_logs_path()>

Returns the logs directory.

=back

=head2 Taint Utilities

=over 4

=item B<untaint_path($path)>

Untaints a file system path. Returns undef if path contains unsafe characters.

=item B<untaint_filename($filename)>

Untaints a filename (no path separators allowed).

=item B<untaint_identifier($id)>

Untaints an alphanumeric identifier (usernames, IDs, etc.).

=back

=head2 Utilities

=over 4

=item B<get_environment_info()>

Returns a hashref with complete environment information.

=item B<verify_environment()>

Checks that all required directories and files exist. Returns arrayref of
errors or undef if everything is OK.

=back

=head1 USAGE IN OTHER MODULES

All TN* modules should use TNEnv:

    package TNSecurity;
    use strict;
    use warnings;
    use TNEnv;  # Sets up environment
    
    # Now safe to use other modules
    use TNConfig;
    
    # Use TNEnv functions
    my $keys_dir = get_keys_path();

=head1 USAGE IN CGI SCRIPTS

    #!/usr/bin/perl -T
    use strict;
    use warnings;
    use FindBin;
    use lib "$FindBin::RealBin/../data/lib";
    use TNEnv;
    use TNSecurity;
    use TNAuth;
    
    # Environment is now properly configured

=head1 CHROOT COMPATIBILITY

TNEnv is designed to work correctly in OpenBSD httpd's chroot environment
at /var/www. It uses absolute path resolution to ensure libraries are
found regardless of the chroot state.

=head1 AUTHOR

Tangent Networks

=head1 VERSION

1.0.0

=cut
