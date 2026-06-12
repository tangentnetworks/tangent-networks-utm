#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ============================================================
# init_db.pl - Automated Database Initialisation Only
# ============================================================
# Location: /usr/local/sbin/create_tn_auth_db.pl
#
# PURPOSE:
#   Initialises a fresh database using a targeted SQL schema.
#   Does NOT provision users or interact with stdin.
#
# USAGE:
#   perl -T /usr/local/sbin/create_tn_auth_db.pl \
#       --schema /var/www/htdocs/tn/data/db/schema.sql
#
# Must be run as root. Sets ownership to www:www 0600.
#
# Use this utility only if you are unable to regain access to
# the system after attempting recovery with
#   `/usr/local/sbin/user_rescue.pl` or
#   `/usr/local/sbin/create_user.pl`.
#
# This script will create the `/var/www/htdocs/tn/data/db/auth.db`
# file and prepare a new authentication database. Please purge the
# existing database before running the program.
#
# ============================================================

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;

# ============================================================
# TAINT-SAFE BOOTSTRAP
# ============================================================

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/sbin:/usr/sbin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

    my $lib_path;

    if ( $FindBin::RealBin =~ m{^([-/\w.]+/data)/scripts$} ) {
        $lib_path = File::Spec->catdir( $1, 'lib' );
    }
    elsif ( -d '/var/www/htdocs/tn/data/lib' ) {
        $lib_path = '/var/www/htdocs/tn/data/lib';
    }
    else {
        die "FATAL: Could not determine library path from: $FindBin::RealBin\n";
    }

    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        $lib_path = $1;
        unshift @INC, $lib_path;
    }
    else {
        die "FATAL: Library path contains unsafe characters: $lib_path\n";
    }
}

use IPC::Open3;
use Symbol qw(gensym);
use TNEnv;

# ============================================================
# PRIVILEGE CHECK -- must run as root
# ============================================================

unless ( $> == 0 ) {
    print "ERROR: This script must be run as root.\n\n";
    print "  perl -T $0 --schema /path/to/schema.sql\n\n";
    exit 1;
}

# ============================================================
# ARGUMENT PARSING -- `--schema` flag is mandatory
# ============================================================

my $schema_file;

{
    my @argv = @ARGV;
    while (@argv) {
        my $arg = shift @argv;
        if ( $arg eq '--schema' ) {
            $schema_file = shift @argv;
        }
        elsif ( $arg =~ /^--schema=(.+)$/ ) {
            $schema_file = $1;
        }
        else {
            print "ERROR: Unknown argument: $arg\n\n";
            _usage();
            exit 1;
        }
    }

    unless ( defined $schema_file && $schema_file ne '' ) {
        print "ERROR: --schema is required.\n\n";
        _usage();
        exit 1;
    }
}

# Untaint and validate schema file path
my $schema_safe;
if ( $schema_file =~ m{^([-/\w.]+\.sql)$} ) {
    $schema_safe = $1;
}
else {
    die
"ERROR: Schema path contains unsafe characters or wrong extension: $schema_file\n";
}

unless ( -f $schema_safe ) {
    print "ERROR: Schema file not found: $schema_safe\n\n";
    exit 1;
}

unless ( -r $schema_safe ) {
    print "ERROR: Schema file is not readable: $schema_safe\n\n";
    exit 1;
}

# ============================================================
# INITIALISE DATABASE FROM SCHEMA
# ============================================================

my $db_path;
{
    my $db_dir_raw = TNEnv::get_db_path();
    my ($db_dir) = ( $db_dir_raw =~ m{^([-/\w.]+)$} )
      or die "ERROR: TNEnv::get_db_path() returned unsafe path: $db_dir_raw\n";

    $db_path = File::Spec->catfile( $db_dir, 'auth.db' );

    # Re-untaint the assembled path
    ($db_path) = ( $db_path =~ m{^([-/\w./]+\.db)$} )
      or die "ERROR: Could not untaint assembled db path: $db_path\n";
}

if ( -e $db_path ) {
    print "ERROR: Database already exists: $db_path\n";
    print "        Aborting to protect active database instance.\n\n";
    exit 1;
}

print "Initialising database from schema...\n";
print "  Schema : $schema_safe\n";
print "  DB     : $db_path\n\n";

{
    open( my $schema_fh, '<', $schema_safe )
      or die "ERROR: Could not open schema file: $!\n";

    my ( $in_fh, $out_fh, $err_fh );
    $err_fh = gensym;

    my $pid = open3( $in_fh, $out_fh, $err_fh,
        '/usr/local/bin/sqlite3', '-batch', $db_path );

    # Pump schema into sqlite3 then close to signal EOF safely without deadlocks
    while ( my $line = <$schema_fh> ) {
        print $in_fh $line;
    }
    close $in_fh;
    close $schema_fh;

    my $stderr_output = do { local $/; <$err_fh> };
    waitpid( $pid, 0 );
    my $rc = $? >> 8;

    if ( $rc != 0 ) {
        $stderr_output //= '';
        die "ERROR: sqlite3 failed to initialise database (exit $rc).\n"
          . ( $stderr_output
            ? "       sqlite3 said: $stderr_output"
            : "       Check schema file for syntax errors.\n" );
    }
}

unless ( -e $db_path ) {
    die "ERROR: sqlite3 ran but db file was not created: $db_path\n";
}

ok("Database initialised successfully from schema baseline.");

# ============================================================
# SET OWNERSHIP -- root creates, www:www owns at runtime
# ============================================================

{
    my ($db_path_safe) = ( $db_path =~ m{^([-/\w./]+)$} )
      or die "ERROR: Unsafe characters in db path: $db_path\n";
    my ($db_dir_safe) = ( $db_path_safe =~ m{^([-/\w./]+)/[^/]+$} )
      or die "ERROR: Could not derive directory from: $db_path_safe\n";

    my $www_uid_raw = getpwnam('www');
    my $www_gid_raw = getgrnam('www');

    unless ( defined $www_uid_raw ) {
        print "ERROR: 'www' user not found on this system.\n";
        exit 1;
    }

    my ($www_uid) = ( $www_uid_raw =~ /^(\d+)$/ )
      or die "ERROR: Could not untaint www uid\n";
    my ($www_gid) = ( $www_gid_raw =~ /^(\d+)$/ )
      or die "ERROR: Could not untaint www gid\n";

    chown $www_uid, $www_gid, $db_dir_safe;
    chown $www_uid, $www_gid, $db_path_safe;
    chmod 0750, $db_dir_safe;
    chmod 0600, $db_path_safe;

    printf "  Ownership set : %s (www:www 0600)\n", $db_path_safe;
}

print "\nDatabase creation routine complete.\n";
exit 0;

# ============================================================
# HELPERS
# ============================================================

sub ok {
    printf "  [+] %s\n", $_[0];
}

sub _usage {
    print "USAGE:\n";
    print
"  perl -T /usr/local/sbin/create_tn_auth_db.pl --schema /var/www/htdocs/tn/data/db/schema.sql\n\n";
    print
"  --schema   Path to the SQL schema file (DDL) used to initialise the database.\n";
    print "             Must be run as root.\n\n";
}
