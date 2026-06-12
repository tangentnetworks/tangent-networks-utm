#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;
use Fcntl qw(:flock);

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin';
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

    # Pre-read JSON POST body before TNSecurityCheck drains STDIN
    # TNSecurityCheck::_check_csrf reads $ENV{POSTDATA} via CGI->new internally
    if (   $ENV{CONTENT_TYPE}
        && $ENV{CONTENT_TYPE} =~ /application\/json/
        && $ENV{CONTENT_LENGTH} )
    {
        read( STDIN, my $json_body, $ENV{CONTENT_LENGTH} );
        $ENV{POSTDATA} = $json_body;
    }
}

use TNEnv;
use TNSecurityCheck;

# Pre-load before pledge locks down dlopen()
use DBD::SQLite;
use DBI;

# Security check - RESTRICTED level (admin only)
my $session = security_check('restricted');

use CGI qw(:standard);
use JSON::PP;
use File::Basename;

my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

# Pre-compute canonical paths before pledge (RELABS-001)
my $OUTPUT_FILE = File::Spec->rel2abs(
    File::Spec->catfile(
        $script_dir, '..', 'data', 'db', 'TNAuditFilesList.json'
    )
);
my $DB_PATH = File::Spec->rel2abs(
    File::Spec->catfile( $script_dir, '..', 'data', 'db', 'TNAudit.db' ) );

for my $ref ( \$OUTPUT_FILE, \$DB_PATH ) {
    if ( $$ref =~ m{^([-/\w.]+)$} ) { $$ref = $1 }
    else                            { die "FATAL: Invalid path: $$ref\n" }
}

# =============================================
# RESPONSE HELPERS (power_mgmt.pl pattern)
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
    my %status_text = (
        400 => 'Bad Request',
        401 => 'Unauthorized',
        403 => 'Forbidden',
        500 => 'Internal Server Error'
    );
    my $status = $status_text{$code} || 'Error';
    print "Status: $code $status\r\n";
    print "Content-Type: application/json\r\n";
    print "\r\n";
    print JSON::PP->new->utf8->encode( { success => 0, message => $message } );
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
            OpenBSD::Unveil::unveil( "$app_root/data/db", "rwc" )
              or die "unveil db: $!";
            OpenBSD::Unveil::unveil( "/tmp", "rwc" ) or die "unveil tmp: $!";
            OpenBSD::Unveil::unveil()                or die "unveil lock: $!";
        }
        if ( eval { require OpenBSD::Pledge; 1 } ) {
            OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock")
              or die "pledge: $!";
        }
    };
    if ($@) {
        send_error( 500, "Internal server error" );
    }
}

# =============================================
# MAIN
# =============================================

my $postdata = $ENV{POSTDATA} || '';

unless ($postdata) {
    send_error( 400, "Empty request body" );
}

my $json_data;
eval { $json_data = decode_json($postdata) };
if ($@) {
    send_error( 400, "Invalid JSON" );
}

my $check = $json_data->{check} || 'all';
if ( $check =~ /^([a-zA-Z0-9_-]+)$/ ) { $check = $1 }
else {
    send_error( 400, "Invalid check name" );
}

my $CLEAN_STATES = "'ok', 'verified', 'baseline', 'retired'";

unless ( -f $DB_PATH ) {
    send_error( 500, "Database not found" );
}

my $dbh = DBI->connect(
    "dbi:SQLite:dbname=$DB_PATH",
    "", "",
    {
        RaiseError        => 0,
        PrintError        => 0,
        AutoCommit        => 1,
        sqlite_open_flags => 0x00000001,
    }
);

unless ($dbh) {
    send_error( 500, "Cannot connect to database" );
}

$dbh->do("PRAGMA foreign_keys = ON");
$dbh->do("PRAGMA journal_mode = WAL");

my ( $sql, @params );
if ( $check eq 'all' ) {
    $sql = qq{
        SELECT check_name, filepath, size_bytes, mode, uid, gid,
               sha256, mtime, last_checked, status, change_count
        FROM files
        WHERE status NOT IN ($CLEAN_STATES)
        ORDER BY check_name, filepath
    };
}
else {
    $sql = qq{
        SELECT check_name, filepath, size_bytes, mode, uid, gid,
               sha256, mtime, last_checked, status, change_count
        FROM files
        WHERE check_name = ?
          AND status NOT IN ($CLEAN_STATES)
        ORDER BY filepath
    };
    @params = ($check);
}

my $sth = $dbh->prepare($sql);
unless ( $sth && $sth->execute(@params) ) {
    $dbh->disconnect();
    send_error( 500, "Query failed" );
}

my ( @files, %grouped );
while ( my $row = $sth->fetchrow_hashref ) {
    my $file_data = {
        check_name   => $row->{check_name},
        filepath     => $row->{filepath},
        size         => format_size( $row->{size_bytes} ),
        size_bytes   => $row->{size_bytes},
        mode         => $row->{mode},
        uid          => $row->{uid},
        gid          => $row->{gid},
        sha256       => $row->{sha256},
        sha256_short => substr( $row->{sha256}, 0, 16 ) . '...',
        mtime        => $row->{mtime},
        last_checked => $row->{last_checked},
        status       => $row->{status},
        change_count => $row->{change_count} || 0,
    };
    if ( $check eq 'all' ) {
        push @{ $grouped{ $row->{check_name} } }, $file_data;
    }
    else {
        push @files, $file_data;
    }
}
$dbh->disconnect();

my %output_data;
$output_data{success}      = 1;
$output_data{check}        = $check;
$output_data{generated_at} = time();

if ( $check eq 'all' ) {
    $output_data{total_files} = 0;
    $output_data{groups}      = \%grouped;
    $output_data{total_files} += scalar( @{ $grouped{$_} } ) for keys %grouped;
}
else {
    $output_data{total_files} = scalar(@files);
    $output_data{files}       = \@files;
}

if ( open( my $out_fh, '>', $OUTPUT_FILE ) ) {
    flock( $out_fh, LOCK_EX );
    print $out_fh encode_json( \%output_data );
    close($out_fh);
    chmod( 0644, $OUTPUT_FILE );

    # Return the full data inline so the JS can render immediately
    # without a second round-trip to fetch the static file.
    my %response = (
        success         => 1,
        file_generated  => 1,
        total_files     => $output_data{total_files},
        violation_count => $output_data{total_files},
        message         => $output_data{total_files}
        ? sprintf( "%d integrity violation(s) found",
            $output_data{total_files} )
        : "No integrity violations",
    );
    if ( $check eq 'all' ) {
        $response{groups} = $output_data{groups};
    }
    else {
        $response{files} = $output_data{files};
    }
    send_json( \%response );
}
else {
    send_error( 500, "Failed to write output file: $!" );
}

sub format_size {
    my ($bytes) = @_;
    return '0 B' unless $bytes;
    my @units = qw(B KB MB GB TB);
    my ( $unit, $size ) = ( 0, $bytes );
    while ( $size >= 1024 && $unit < $#units ) { $size /= 1024; $unit++ }
    return $unit == 0
      ? sprintf( "%d %s",   $size, $units[$unit] )
      : sprintf( "%.2f %s", $size, $units[$unit] );
}

__END__

=head1 SECURITY

Requires 'restricted' level access (admin only).
OpenBSD pledge/unveil hardened. BEGIN STDIN pre-read pattern (power_mgmt.pl).

=cut
