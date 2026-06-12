#!/usr/bin/perl

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ============================================================================
# SCRIPT: TN_TEST_CHROOT.pl
# PURPOSE: Audits TNAuth DNA and Environment Vitality.
#
# RATIONALE:
#   This script runs on the HOST machine but validates the CHROOT environment.
#   All system paths (like /usr/local/lib/perl5) must exist under the chroot
#   base (e.g. /var/www/usr/local/lib/perl5) to be considered valid.
#
#   We check two things:
#     1. "Physics"  — Devices and binaries (sqlite3, /dev/urandom, etc.)
#     2. "Logic"    — Perl modules (.pm files) required by TN codebase
# ============================================================================

use strict;
use warnings;
use File::Find;
use File::Spec;

# ----------------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------------

# The chroot jail root as seen from the host filesystem.
# All system paths will be prefixed with this when validating chroot contents.
my $chroot_base = '/var/www';

# The TN application directories inside the chroot.
# These are where our own .pl/.pm source files live.
my $cgi_dir = '/var/www/htdocs/tn/cgi-bin';
my $lib_dir = '/var/www/htdocs/tn/data/lib';

# Inject our sovereign TN library path into @INC so the auditor
# can find TN::* modules when checking what is installed.
if ( -d $lib_dir ) { unshift @INC, $lib_dir; }

# ----------------------------------------------------------------------------
# STATE
# ----------------------------------------------------------------------------

# %required : module name => { count => N, found_in => { file => 1, ... } }
#   Populated by scanning all .pl/.pm source files for use/require statements.
my %required;

# %installed : module name => full chroot-rebased path on disk
#   Populated by scanning @INC paths rebased under $chroot_base.
my %installed;

# @vitality_errors : list of plain-text error strings for Physics failures.
my @vitality_errors;

# ============================================================================
# 1. VITALITY CHECK — Environmental Physics
#    Validates that critical devices and binaries exist inside the chroot.
#    These are checked as host paths (chroot_base + original path).
# ============================================================================
sub check_vitality {
    print
      "[INFO] Auditing Environmental Vitality (chroot base: $chroot_base)...\n";

    # Entropy Devices --
    # These character devices must exist inside the chroot for crypto to work.
    # Ed25519 key generation and HMAC operations depend on /dev/urandom.
    foreach my $dev (qw(/dev/random /dev/urandom /dev/null)) {
        my $chroot_dev = $chroot_base . $dev;    # e.g. /var/www/dev/urandom
        if ( -r $chroot_dev && -c $chroot_dev ) {
            print "  OK  Device : $chroot_dev\n";
        }
        else {
            push @vitality_errors,
              "MISSING DEVICE: $chroot_dev (required for crypto/nulling)";
        }
    }

    # Chroot /bin inventory --
    # On this chroot, executables live in /var/www/bin/ (not /usr/local/bin/).
    # We report everything present so missing tools are immediately visible.
    my $chroot_bin = $chroot_base . '/bin';
    if ( -d $chroot_bin ) {
        opendir( my $dh, $chroot_bin )
          or warn "[WARN] Cannot open $chroot_bin: $!\n";
        my @bins = grep { !/^\./ && -f "$chroot_bin/$_" && -x "$chroot_bin/$_" }
          readdir($dh);
        closedir($dh);

        if (@bins) {
            print "  OK  Binaries in $chroot_bin:\n";
            print "        $_\n" for sort @bins;
        }
        else {
            push @vitality_errors, "EMPTY: $chroot_bin (no executables found)";
        }
    }
    else {
        push @vitality_errors, "MISSING DIRECTORY: $chroot_bin";
    }

    # SQLite3 shared library check --
    # We do NOT need the sqlite3 binary in the chroot — only the shared library
    # is required so that our Perl DBD::SQLite module can link against it at
    # runtime. Verify the .so file is present under /var/www/usr/local/lib/.
    my $chroot_lib = $chroot_base . '/usr/local/lib';
    if ( -d $chroot_lib ) {

       # Use glob to find any libsqlite3.so* variant (versioned or unversioned).
        my @sqlite_libs = glob("$chroot_lib/libsqlite3.so*");
        if (@sqlite_libs) {
            print "  OK  SQLite3 lib in $chroot_lib:\n";
            print "        $_\n" for sort @sqlite_libs;
        }
        else {
            push @vitality_errors,
              "MISSING LIBRARY: libsqlite3.so* not found in $chroot_lib";
        }
    }
    else {
        push @vitality_errors, "MISSING DIRECTORY: $chroot_lib";
    }
}

# ============================================================================
# 2. SCAN INSTALLED — The Physical Audit
#    Walks every directory in @INC, rebased under $chroot_base, and records
#    every .pm file found. This tells us what is actually present in the chroot.
#
#    Example: @INC contains /usr/local/lib/perl5/5.36
#             We scan   /var/www/usr/local/lib/perl5/5.36
#             A file at /var/www/usr/local/lib/perl5/5.36/JSON/PP.pm
#             is recorded as installed{ 'JSON::PP' } = '/var/www/usr/local/...'
# ============================================================================
sub scan_installed {

    # Scan system @INC paths rebased into the chroot --
    # e.g. /usr/local/lib/perl5 becomes /var/www/usr/local/lib/perl5
    foreach my $inc_path (@INC) {
        my $chroot_path = $chroot_base . $inc_path;
        next unless -d $chroot_path;

        find(
            {
                wanted => sub {
                    return unless -f $_ && $_ =~ /\.pm$/;
                    my $rel =
                      File::Spec->abs2rel( $File::Find::name, $chroot_path );
                    $rel =~ s/\.pm$//;
                    $rel =~ s/[\\\/]/::/g;
                    $installed{$rel} = $File::Find::name;
                },
                no_chdir => 1,
            },
            $chroot_path
        );
    }

    # Scan sovereign TN lib dir directly --
    # This path is already fully qualified on the host (it IS inside /var/www),
    # so we must NOT rebase it again. TN::* modules live here.
    if ( -d $lib_dir ) {
        find(
            {
                wanted => sub {
                    return unless -f $_ && $_ =~ /\.pm$/;
                    my $rel =
                      File::Spec->abs2rel( $File::Find::name, $lib_dir );
                    $rel =~ s/\.pm$//;
                    $rel =~ s/[\\\/]/::/g;
                    $installed{$rel} = $File::Find::name;
                },
                no_chdir => 1,
            },
            $lib_dir
        );
    }
}

# ============================================================================
# 3. EXTRACT REQUIRED — The Code Audit
#    Scans every .pl and .pm in our TN source directories and collects every
#    module name that appears in a use/require/use base statement.
#    Skips pragmas and core modules that are always available.
# ============================================================================
sub extract_required {
    my $file = $File::Find::name;
    return unless -f $file && $file =~ /\.(pl|pm)$/i;

    open( my $fh, '<', $file ) or do {
        warn "[WARN] Cannot open $file: $!\n";
        return;
    };

    while (<$fh>) {

        # Match:  use Foo::Bar;
        #         require Foo::Bar;
        #         use base 'Foo::Bar';
        if (   /^\s*(?:use|require)\s+([\w:]+)/
            || /^\s*use\s+base\s+['"]([\w:]+)['"]/ )
        {
            my $mod = $1;

            # Skip core pragmas and modules — they are always present.
            next
              if $mod =~
/^(strict|warnings|vars|Exporter|utf8|base|parent|lib|constant|FindBin|File::Spec|File::Find)$/;

           # Skip version numbers that Perl allows after 'use' (e.g. use 5.010).
            next if $mod =~ /^[0-9._]+$/;

            # Record the module and which source file requires it.
            $required{$mod}{count}++;
            $required{$mod}{found_in}{$file} = 1;
        }
    }

    close($fh);
}

# ============================================================================
# EXECUTION
# ============================================================================

check_vitality();
scan_installed();

# Scan our TN source trees for all use/require dependencies.
find( \&extract_required, $cgi_dir ) if -d $cgi_dir;
find( \&extract_required, $lib_dir ) if -d $lib_dir;

# ============================================================================
# REPORT
# ============================================================================

print "\n" . "=" x 70 . "\n";
print "TNAuth INFRASTRUCTURE AUDIT REPORT\n";
print "Chroot Base : $chroot_base\n";
print "CGI Dir     : $cgi_dir\n";
print "Lib Dir     : $lib_dir\n";
print "=" x 70 . "\n";

# -- Vitality Alerts (Physics) --
if (@vitality_errors) {
    print "\nVITALITY ALERTS:\n";
    print "  - $_\n" for @vitality_errors;
    print "-" x 70 . "\n";
}

# -- Module Status (Logic) --
# -- Module Status (Logic) --
print "\nMODULE AUDIT:\n";
print "-" x 50 . "\n";

foreach my $mod ( sort keys %required ) {
    my $status    = $installed{$mod}  ? "OK"        : "MISSING";
    my $type      = ( $mod =~ /^TN/ ) ? "Sovereign" : "System";
    my $inst_path = $installed{$mod} // "(not found in chroot)";
    my @src_files = sort keys %{ $required{$mod}{found_in} };

    print "Module  : $mod\n";
    print "Status  : $status ($type)\n";
    print "Path    : $inst_path\n";
    print "Needed  : $_\n" for @src_files;
    print "-" x 50 . "\n";
}

# -- Final Summary --
my @missing_mods = grep { !$installed{$_} } keys %required;

print "\n" . "=" x 70 . "\n";
if ( @missing_mods || @vitality_errors ) {
    printf(
        "[!] WRECKAGE DETECTED: %d missing module(s), %d vitality error(s).\n",
        scalar @missing_mods,
        scalar @vitality_errors
    );
    print "    Infrastructure is NOT ready for qcow2 replication.\n";
    exit 1;
}
else {
    print "[SUCCESS] DNA and Environment are healthy.\n";
}
