#!/usr/bin/perl

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# =============================================================================
# TN_PERL_TRACER.pl - CGI Perl Module Dependency Tracer
# =============================================================================
# Scans CGI scripts and TN lib modules, resolves 'use' statements to actual
# files on disk using the correct OpenBSD @INC order, walks transitive deps,
# and writes:
#
#   tn_perl_modules.txt    - full .pm + .so path list for review
#   tn_perl_allowlist.txt  - top-level names for TN_CHROOT_SETUP.sh Step 3
#
# USAGE:
#   perl TN_PERL_TRACER.pl [CGI_DIR] [LIB_DIR]
#
# Run on the gateway host. Re-run when CGI scripts change.
# =============================================================================

use strict;
use warnings;
use File::Find;
use File::Basename;
use Config;
use Cwd 'abs_path';

# =============================================================================
# PATHS
# =============================================================================

my $script_dir = abs_path( dirname(__FILE__) );

my $cgi_dir = $ARGV[0] || "/var/www/htdocs/tn/cgi-bin";
my $lib_dir = $ARGV[1] || "/var/www/htdocs/tn/data/lib";

my $out_modules   = "$script_dir/tn_perl_modules.txt";
my $out_allowlist = "$script_dir/tn_perl_allowlist.txt";

my $perl_arch = $Config{archname};    # e.g. amd64-openbsd

# OpenBSD site_perl layout:
#   /usr/local/libdata/perl5/site_perl/amd64-openbsd/   <- arch XS modules
#   /usr/local/libdata/perl5/site_perl/                  <- pure-perl modules
#   /usr/local/libdata/perl5/amd64-openbsd/auto/         <- XS .so files
my $perl5site_src = "/usr/local/libdata/perl5";
my $site_arch_dir = "$perl5site_src/site_perl/$perl_arch";   # DBI, DBD, JSON/XS
my $site_perl_dir = "$perl5site_src/site_perl";              # CGI, Mail, etc.
my $site_auto_dir = "$perl5site_src/site_perl/$perl_arch/auto";    # .so files

# OpenBSD core layout (already copied by CHROOT_SETUP Step 2  -- skip these):
#   /usr/libdata/perl5/amd64-openbsd/   <- OpenBSD::Pledge, OpenBSD::Unveil etc.
#   /usr/libdata/perl5/                 <- strict, POSIX, Fcntl etc.
my $perl5core_src = "/usr/libdata/perl5";
my $core_arch_dir = "$perl5core_src/$perl_arch";

# =============================================================================
# HELPERS
# =============================================================================

sub info  { printf "  [.] %s\n", $_[0] }
sub ok    { printf "  [+] %s\n", $_[0] }
sub warn_ { printf "  [!] %s\n", $_[0] }

sub header {
    my $sep = '=' x 60;
    printf "\n%s\n  %s\n%s\n", $sep, $_[0], $sep;
}

# =============================================================================
# STEP 1: Verify paths
# =============================================================================

header("Step 1: Environment");
info("perl_arch     : $perl_arch");
info("CGI dir       : $cgi_dir");
info("LIB dir       : $lib_dir");
info( "site_arch_dir : $site_arch_dir "
      . ( -d $site_arch_dir ? "(OK)" : "(MISSING)" ) );
info( "site_perl_dir : $site_perl_dir "
      . ( -d $site_perl_dir ? "(OK)" : "(MISSING)" ) );
info( "site_auto_dir : $site_auto_dir "
      . ( -d $site_auto_dir ? "(OK)" : "(MISSING)" ) );
info( "core_arch_dir : $core_arch_dir "
      . ( -d $core_arch_dir ? "(OK)" : "(MISSING)" ) );

die "CGI dir not found: $cgi_dir\n"  unless -d $cgi_dir;
warn_("LIB dir not found: $lib_dir") unless -d $lib_dir;

# =============================================================================
# STEP 2: Build resolution @INC matching OpenBSD's actual order
# =============================================================================

# Mirrors OpenBSD perl @INC exactly:
#   site_perl/amd64-openbsd  (arch XS)
#   site_perl                (pure perl)
#   /usr/libdata/perl5/amd64-openbsd  (core arch  -- OpenBSD::*, etc.)
#   /usr/libdata/perl5                (core pure)
# Plus our own lib_dir for TN* resolution.

my @search_inc = grep { -d $_ }
  ( $lib_dir, $site_arch_dir, $site_perl_dir, $core_arch_dir, $perl5core_src, );

sub find_module_path {
    my ($mod) = @_;
    ( my $rel = $mod ) =~ s{::}{/}g;
    $rel .= '.pm';
    for my $dir (@search_inc) {
        my $full = "$dir/$rel";
        return $full if -f $full;
    }
    return undef;
}

sub is_site_perl {
    my ($path) = @_;
    return defined $path && $path =~ m{^\Q$perl5site_src\E};
}

sub is_core {
    my ($path) = @_;
    return defined $path && $path =~ m{^\Q$perl5core_src\E};
}

# Extract use/require statements safely from a file.
# $strict=1 when scanning third-party .pm files during transitive walk:
#   - skip POD sections
#   - require the module name to look like a real installed module
#     (starts with capital, no trailing ::, no spaces, resolves on disk)
# $strict=0 for our own CGI/lib files where we want everything.
sub extract_uses {
    my ( $file, $strict ) = @_;
    my @mods;
    my $in_pod = 0;
    open( my $fh, '<', $file ) or return @mods;
    while ( my $line = <$fh> ) {

        # Track POD sections  -- skip them entirely in strict mode
        if ( $line =~ /^=(pod|head|over|item|back|begin|end|for|encoding|cut)/ )
        {
            $in_pod = ( $line =~ /^=cut/ ) ? 0 : 1;
            next;
        }
        next if $in_pod && $strict;
        next if $line =~ /^\s*#/;     # skip comment lines

        next unless $line =~ /^\s*(?:use|require)\s+([A-Za-z][A-Za-z0-9:]+)/;
        my $mod = $1;

        if ($strict) {

            # In strict mode (scanning installed .pm deps):
            # - must be a valid module name (letters/digits/colons only)
            # - must not end with :: (partial/example names like "Moo::")
            # - must be at least 3 chars
            # - must actually resolve to a file on disk -- this is the real
            #   filter; prose words and example names never resolve.
            # NOTE: do NOT require uppercase first letter -- legitimate
            # lowercase modules exist (strictures, namespace::clean, etc.)
            next unless $mod =~ /^[A-Za-z][A-Za-z0-9:]+$/;
            next if $mod =~ /::$/;
            next if length($mod) < 3;
            my $path = find_module_path($mod);
            next unless defined $path;    # if it doesn't exist, skip silently
        }

        push @mods, $mod;
    }
    close $fh;
    return @mods;
}

# =============================================================================
# STEP 3: Collect source files
# =============================================================================

header("Step 2: Collecting source files");

my @source_files;
for my $dir ( $cgi_dir, $lib_dir ) {
    next unless -d $dir;
    find(
        sub {
            push @source_files, $File::Find::name
              if /\.(pl|pm)$/ && -f $_;
        },
        $dir
    );
}
info( "Source files found: " . scalar(@source_files) );

# =============================================================================
# STEP 4: Extract 'use' statements
# =============================================================================

# These are always available in the chroot via Step 2 (core) or are
# pragmas  -- no need to resolve or copy them.
my %always_skip = map { $_ => 1 } qw(
  strict warnings vars constant feature utf8 overload
  POSIX Fcntl Carp Scalar::Util List::Util Storable
  File::Spec File::Basename File::Path File::Copy
  File::Find File::Temp File::stat
  FindBin Cwd Exporter base parent
  MIME::Base64 Digest::MD5 Digest::SHA
  IO::File IO::Handle IO::Select
  Socket Time::HiRes Time::Local
  Data::Dumper Symbol
  IPC::Open3
);

my %seen_mods;
for my $file (@source_files) {

    # strict=0: scan our own files fully, warn on unresolvable
    for my $mod ( extract_uses( $file, 0 ) ) {
        next if $always_skip{$mod};
        next if $mod =~ /^\d/;
        $seen_mods{$mod} = 1;
    }
}

header("Step 3: Resolving modules");
info( "Unique 'use' statements to resolve: " . scalar( keys %seen_mods ) );

# =============================================================================
# STEP 5: Resolve + walk transitive deps (BFS)
# Only track site_perl modules  -- core is handled by CHROOT_SETUP Step 2.
# Core modules (OpenBSD::Pledge, OpenBSD::Unveil) are noted but not copied.
# =============================================================================

my %resolved_site;    # site_perl paths we need to copy
my %resolved_core;    # core paths  -- informational only
my @queue  = keys %seen_mods;
my %queued = %seen_mods;

my $pass = 0;
while (@queue) {
    $pass++;
    my @next;

    for my $mod (@queue) {
        my $path = find_module_path($mod);

        unless ( defined $path ) {

            # Warn only for modules from our own source files  -- transitive
            # deps from installed .pm files use strict mode which skips
            # unresolvable entries silently before they reach the queue.
            warn_("Cannot resolve: $mod")
              if exists $seen_mods{$mod} && $mod !~ /^TN/;
            next;
        }

        if ( is_site_perl($path) ) {
            next if $resolved_site{$path};
            $resolved_site{$path} = 1;

            # Scan for further deps  -- strict=1 skips POD/comments/unresolvable
            for my $dep ( extract_uses( $path, 1 ) ) {
                next if $always_skip{$dep};
                next if $queued{$dep};
                $queued{$dep} = 1;
                push @next, $dep;
            }
        }
        elsif ( is_core($path) ) {
            $resolved_core{$path} = 1;
        }
    }

    @queue = @next;
    last if $pass > 20;
}

info( "site_perl .pm files to copy: " . scalar( keys %resolved_site ) );
info( "core modules noted (already in chroot): "
      . scalar( keys %resolved_core ) );

# =============================================================================
# STEP 6: Find paired XS .so files
# OpenBSD layout: site_perl/amd64-openbsd/DBI.pm
#              -> amd64-openbsd/auto/DBI/DBI.so
#                 (note: auto/ is under perl5site_src, not site_perl/)
# =============================================================================

header("Step 4: Resolving XS .so files");

my %so_files;
for my $pm ( keys %resolved_site ) {

    # Get path relative to site_arch_dir (XS modules live there)
    my $rel;
    if ( $pm =~ m{^\Q$site_arch_dir\E/(.+)\.pm$} ) {
        $rel = $1;    # e.g. DBI  or  DBD/SQLite  or  JSON/XS
    }
    elsif ( $pm =~ m{^\Q$site_perl_dir\E/(.+)\.pm$} ) {
        $rel = $1;    # pure-perl modules rarely have .so but check anyway
    }
    else {
        next;
    }

    my $leaf = ( split m{/}, $rel )[-1];

    # OpenBSD layout: site_perl/amd64-openbsd/auto/Module/SubMod/SubMod.so
    my $so = "$site_auto_dir/$rel/$leaf.so";
    $so_files{$so} = 1 if -f $so;
}

info( "XS .so files found: " . scalar( keys %so_files ) );

# =============================================================================
# STEP 7: Write tn_perl_modules.txt
# =============================================================================

header("Step 5: Writing output files");

my @all_paths = sort( keys %resolved_site, keys %so_files );

open( my $mod_fh, '>', $out_modules ) or die "Cannot write $out_modules: $!\n";
print $mod_fh "$_\n" for @all_paths;
close $mod_fh;

ok( "tn_perl_modules.txt: " . scalar(@all_paths) . " paths" );

# =============================================================================
# STEP 8: Derive allowlist
# Top-level name = first path component after site_perl/ or site_arch_dir/
# Strip .pm for single-file top-level modules (e.g. CGI.pm -> CGI)
# =============================================================================

my %top_level;
for my $path (@all_paths) {
    my $rel;

    # auto/ is under site_arch_dir  -- match it first (more specific)
    if ( $path =~ m{^\Q$site_auto_dir\E/(.+)$} ) {
        $rel = $1;    # e.g. Sub/Name/Name.so -> top = Sub
    }
    elsif ( $path =~ m{^\Q$site_arch_dir\E/(.+)$} ) {
        $rel = $1;    # e.g. DBI.pm or DBD/SQLite.pm -> top = DBI or DBD
    }
    elsif ( $path =~ m{^\Q$site_perl_dir\E/(.+)$} ) {
        $rel = $1;    # e.g. CGI.pm -> top = CGI
    }
    else {
        next;
    }
    my $top = ( split m{/}, $rel )[0];
    $top =~ s{\.pm$}{};
    $top =~ s{\.so$}{};
    $top_level{$top} = 1;
}

open( my $allow_fh, '>', $out_allowlist )
  or die "Cannot write $out_allowlist: $!\n";
print $allow_fh "$_\n" for sort keys %top_level;
close $allow_fh;

ok(     "tn_perl_allowlist.txt: "
      . scalar( keys %top_level )
      . " top-level modules" );
print "\nAllowlist:\n";
printf "  %s\n", $_ for sort keys %top_level;

# =============================================================================
# STEP 9: Sanity check
# =============================================================================

header("Step 6: Sanity check");

# DBI/DBD/JSON::XS are in site_arch_dir; CGI is in site_perl_dir;
# OpenBSD::Pledge is core  -- should appear in resolved_core, not allowlist
# OpenBSD::Pledge/Unveil are loaded via eval { require } in CGI scripts,
# not bare 'use', so they don't appear in %resolved_core from scanning.
# Verify them directly on disk instead.
my %sanity_site = (
    'DBI'  => 'allowlist',
    'DBD'  => 'allowlist',
    'JSON' => 'allowlist',
    'CGI'  => 'allowlist',
);

my %sanity_core_files = (
    'OpenBSD::Pledge' => "$core_arch_dir/OpenBSD/Pledge.pm",
    'OpenBSD::Unveil' => "$core_arch_dir/OpenBSD/Unveil.pm",
);

my $all_ok = 1;

for my $req ( sort keys %sanity_site ) {
    my $found = grep { /^\Q$req\E/ } keys %top_level;
    if ($found) {
        ok("$req found in allowlist");
    }
    else {
        warn_("$req NOT FOUND in allowlist");
        $all_ok = 0;
    }
}

for my $mod ( sort keys %sanity_core_files ) {
    my $path = $sanity_core_files{$mod};
    if ( -f $path ) {
        ok("$mod found in core (already in chroot via Step 2): $path");
    }
    else {
        warn_("$mod NOT FOUND at expected core path: $path");
        $all_ok = 0;
    }
}

# Warn if SpamAssassin crept in
if ( grep { /Mail\/SpamAssassin|spamassassin/i } @all_paths ) {
    warn_("SpamAssassin detected in output  -- check 'use' statements");
    $all_ok = 0;
}
else {
    ok("SpamAssassin not present (correct)");
}

$all_ok
  ? ok("All checks passed")
  : warn_("Some checks failed  -- review above");

my $sep = '=' x 60;
print "\n$sep\n";
print "  Done.\n";
print "  Commit tn_perl_allowlist.txt alongside TN_CHROOT_SETUP.sh\n";
print "$sep\n\n";
