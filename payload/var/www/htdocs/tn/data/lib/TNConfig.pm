# ============================================================================
# MODULE: TNConfig.pm
# PURPOSE: Chroot-aware configuration manager. Single source of truth for
#          all runtime settings read from data/config/security.conf.
# VERSION: 2.1.0
#
# ROLE IN THE STACK:
#   TNConfig sits between TNEnv (paths) and TNSecurity (crypto). It parses
#   security.conf once at first use and caches the result for the request
#   lifetime. All other modules call TNConfig::get_config() rather than
#   reading the file themselves.
#
# RESPONSIBILITIES:
#   1. Config loading    --  parses [section] / KEY = VALUE ini-style file.
#                            Fails closed on missing, unreadable, or malformed
#                            config (DEVEL=0, all security features on).
#   2. DEVEL mode        --  is_devel_mode(), enable_devel_mode(),
#                            disable_devel_mode(). DEVEL mode is password-
#                            protected via PBKDF2 hash stored in security.conf.
#                            enable/disable_devel_mode() do targeted in-place
#                            rewrites of the DEVEL line only --  preserving all
#                            operator comments and other settings.
#   3. Config access     --  get_config($section, $key) for all other modules.
#   4. Fail-closed       --  _fail_closed() sets safe defaults and logs loudly
#                            to STDERR (appears in httpd error log) if config
#                            cannot be loaded.
#
# SECURITY NOTE:
#   set_defaults() is install-path only --  called exclusively by
#   create_default_config() during init_db.pl setup. It must never be
#   called from load_config() as it would expose known credentials if
#   security.conf goes missing in production.
#
# INTEGRATION:
#   Loaded by  : control.pl, TNWAF.pm, TNSecurity.pm, TNAuth.pm,
#                TNSecurityCheck.pm
#   Depends on : TNEnv (get_app_root for config file path)
#   Used for   : rate limits, session config, CSRF config, DEVEL flag,
#                logging config, DEVEL password verification
#
# AUTHOR: DAVID PETER, TANGENT NETWORKS
# ============================================================================
package TNConfig;
use strict;
use warnings;

use File::Basename;
use Cwd 'abs_path';
use Fcntl qw(:flock);

BEGIN {
    # Use this module's own location
    my $lib_path = dirname(__FILE__);
    $lib_path = abs_path($lib_path) if -d $lib_path;

    # Untaint
    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        unshift @INC, $1 unless grep { $_ eq $1 } @INC;
    }
}

use TNEnv;

# =============================================
# CHROOT-AWARE PATHS
# Detects if running in chroot and adjusts paths
# =============================================

our $VERSION = '2.1.0';

# Detect base directory
sub get_base_dir {

    # Use TNEnv helper
    return TNEnv::get_app_root();
}

# Configuration paths relative to base
sub get_config_file {
    my $base = get_base_dir();
    my $path = File::Spec->catfile( $base, 'data', 'config', 'security.conf' );
    return undef if $path =~ /\.\./;
    if ( $path =~ m{^([-/\w.]+)$} ) { return $1 }
    return undef;
}

sub get_config_dir {
    my $base = get_base_dir();
    my $path = File::Spec->catdir( $base, 'data', 'config' );
    return undef if $path =~ /\.\./;
    if ( $path =~ m{^([-/\w.]+)$} ) { return $1 }
    return undef;
}

# Configuration cache
my %CONFIG        = ();
my $CONFIG_LOADED = 0;

# =============================================
# PUBLIC FUNCTIONS
# =============================================

sub is_devel_mode {
    load_config() unless $CONFIG_LOADED;
    return ( $CONFIG{mode}{DEVEL} || 0 ) == 1;
}

sub get_config {
    my ( $section, $key ) = @_;
    load_config() unless $CONFIG_LOADED;

    return undef unless exists $CONFIG{$section};
    return undef unless exists $CONFIG{$section}{$key};

    return $CONFIG{$section}{$key};
}

sub enable_devel_mode {
    my ($password) = @_;
    load_config() unless $CONFIG_LOADED;

    return 0 unless check_devel_password($password);

    $CONFIG{mode}{DEVEL} = 1;
    return write_config();
}

sub disable_devel_mode {
    load_config() unless $CONFIG_LOADED;

    # Update config in memory
    $CONFIG{mode}{DEVEL} = 0;

    # Write to file
    return write_config();
}

sub check_devel_password {
    my ($password) = @_;
    load_config() unless $CONFIG_LOADED;

    my $stored_hash = $CONFIG{mode}{DEVEL_PASSWORD_HASH} || '';
    my $stored_salt = $CONFIG{mode}{DEVEL_PASSWORD_SALT} || '';

    # No hash configured means DEVEL password has not been set at install time.
    # Treat as disabled -- never grant access on an empty credential.
    return 0 unless $stored_hash && $stored_salt;

    # Delegate to TNSecurity::verify_password() so the hashing contract
    # lives in one place and benefits from the PBKDF2 upgrade path.
    require TNSecurity;
    return TNSecurity::verify_password( $password, $stored_hash, $stored_salt );
}

# =============================================
# INTERNAL FUNCTIONS
# =============================================

sub load_config {
    return if $CONFIG_LOADED;

    my $config_file = get_config_file();

    # Missing or unreadable config
    # Do NOT call set_defaults() here. set_defaults() contains a known
    # DEVEL_PASSWORD and historically set DEVEL=1 -- falling back to it
    # when the config file is absent or unreadable in production would
    # expose a known credential. Fail closed instead: DEVEL=0, all
    # security features on, no password set.
    unless ( -e $config_file ) {
        _fail_closed("security.conf not found: $config_file");
        return;
    }
    unless ( -f $config_file && -r $config_file ) {
        _fail_closed("security.conf not readable: $config_file");
        return;
    }

    # Parse config file
    open( my $fh, '<', $config_file ) or do {
        _fail_closed("security.conf open failed: $!");
        return;
    };

    my $current_section = '';

    while ( my $line = <$fh> ) {
        chomp $line;

        next if $line =~ /^\s*#/;
        next if $line =~ /^\s*$/;

        if ( $line =~ /^\[(\w+)\]/ ) {
            $current_section = $1;
            $CONFIG{$current_section} = {}
              unless exists $CONFIG{$current_section};
            next;
        }

        if ( $line =~ /^\s*(\w+)\s*=\s*(.+)$/ ) {
            my ( $key, $value ) = ( $1, $2 );
            $value =~ s/^["']|["']$//g;
            $value =~ s/^\s+|\s+$//g;
            $CONFIG{$current_section}{$key} = $value if $current_section;
        }
    }

    close $fh;

    # Parsed but [mode] section absent
    # A partially written or corrupted config. Fail closed -- do not
    # silently activate set_defaults() which contains a known credential.
    unless ( exists $CONFIG{mode} && exists $CONFIG{mode}{DEVEL} ) {
        _fail_closed("security.conf parsed but [mode] section missing");
        return;
    }

    # Fill in non-critical defaults for optional sections
    # Only sections that carry no credentials and no security bypass.
    $CONFIG{security} = {
        ENABLE_CSRF          => 1,
        ENABLE_SRI           => 1,
        ENABLE_RATE_LIMIT    => 1,
        ENABLE_SESSION_CHECK => 1,
        ENABLE_ORIGIN_CHECK  => 1,
      }
      unless exists $CONFIG{security};

    $CONFIG{logging} = {
        LOG_LEVEL     => 'info',
        LOG_TO_FILE   => 1,
        LOG_TO_SYSLOG => 0,
      }
      unless exists $CONFIG{logging};

    $CONFIG_LOADED = 1;
}

# Fail-closed state: DEVEL=0, all security on, no password.
# Called whenever config is absent, unreadable, or unparseable.
# Logs loudly to STDERR so the error appears in the web server log.
sub _fail_closed {
    my ($reason) = @_;
    warn
"TNConfig CRITICAL: $reason -- failing closed (DEVEL=0, full security enforced)\n";
    $CONFIG{mode} =
      { DEVEL => 0, DEVEL_PASSWORD_HASH => '', DEVEL_PASSWORD_SALT => '' };
    $CONFIG{security} = {
        ENABLE_CSRF          => 1,
        ENABLE_SRI           => 1,
        ENABLE_RATE_LIMIT    => 1,
        ENABLE_SESSION_CHECK => 1,
        ENABLE_ORIGIN_CHECK  => 1,
    };
    $CONFIG{logging} =
      { LOG_LEVEL => 'info', LOG_TO_FILE => 1, LOG_TO_SYSLOG => 0 };
    $CONFIG_LOADED = 1;
}

sub write_config {

    # Only the DEVEL flag ever changes at runtime (enable/disable_devel_mode).
    # Targeted in-place replacement of the single DEVEL = N line preserves
    # comments, the [paths] section, and any operator edits.
    my $config_file = get_config_file();
    my $devel_value = ( $CONFIG{mode}{DEVEL} || 0 ) ? '1' : '0';

    open( my $in, '<', $config_file ) or do {
        warn "Failed to read config file for update: $!\n";
        return 0;
    };
    flock( $in, LOCK_EX )
      or do { close $in; warn "write_config: flock failed: $!\n"; return 0 };
    my @lines = <$in>;
    close $in;    # releases shared lock

    my $found = 0;
    for my $line (@lines) {
        if ( $line =~ s/^(DEVEL\s*=\s*)\d+/$1$devel_value/ ) {
            $found = 1;
        }
    }
    unless ($found) {
        warn "write_config: DEVEL line not found in $config_file\n";
        return 0;
    }

    open( my $out, '>', $config_file ) or do {
        warn "Failed to write config file: $!\n";
        return 0;
    };
    flock( $out, LOCK_EX )
      or
      do { close $out; warn "write_config: flock(out) failed: $!\n"; return 0 };
    print $out @lines;
    close $out;

    chmod 0640, $config_file;
    return 1;
}

# set_defaults: INSTALL PATH ONLY.
# Called exclusively by create_default_config() during initial setup.
# Must never be called from load_config() -- doing so on a missing/unreadable
# security.conf would expose a known credential in production.
#
# DEVEL_PASSWORD is intentionally left empty here. It must be set by
# init_db.pl at install time: prompt operator → hash via TNSecurity::hash_password()
# → write DEVEL_PASSWORD_HASH = pbkdf2:<hex> into security.conf.
# TNConfig::check_devel_password() then verifies against the stored hash.
#
sub set_defaults {
    $CONFIG{mode} = {
        DEVEL               => 0,
        DEVEL_PASSWORD_HASH => '',
        DEVEL_PASSWORD_SALT => '',
    };
    $CONFIG{security} = {
        ENABLE_CSRF          => 1,
        ENABLE_SRI           => 1,
        ENABLE_RATE_LIMIT    => 1,
        ENABLE_SESSION_CHECK => 1,
        ENABLE_ORIGIN_CHECK  => 1,
    };
    $CONFIG{logging} = {
        LOG_LEVEL     => 'info',
        LOG_TO_FILE   => 1,
        LOG_TO_SYSLOG => 0,
    };
}

sub create_default_config {
    my $config_dir = get_config_dir();

    # Create directory if missing
    unless ( -d $config_dir ) {
        mkdir $config_dir, 0755 or return;
    }

    set_defaults();
    write_config();
}

# =============================================
# HELPER FUNCTIONS
# =============================================

sub get_all_config {
    load_config() unless $CONFIG_LOADED;
    return \%CONFIG;
}

sub reload_config {
    $CONFIG_LOADED = 0;
    %CONFIG        = ();
    load_config();
}

# =============================================
# LOCAL UTILITY
# =============================================
# Inlined to avoid circular dependency: TNSecurity uses TNConfig,
# so TNConfig cannot use TNSecurity.
sub _timing_safe_compare {
    my ( $a, $b ) = @_;
    return 0 unless defined $a && defined $b;
    return 0 unless length($a) == length($b);
    my $result = 0;
    for my $i ( 0 .. length($a) - 1 ) {
        $result |= ord( substr( $a, $i, 1 ) ) ^ ord( substr( $b, $i, 1 ) );
    }
    return $result == 0;
}

1;

__END__

=head1 NAME

TNConfig -- Chroot-aware configuration manager for TNSecurity

=head1 DESCRIPTION

Uses relative paths from FindBin to work in chroot environments.

=cut
