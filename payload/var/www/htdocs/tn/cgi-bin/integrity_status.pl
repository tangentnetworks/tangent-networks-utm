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

    if ( $ENV{GATEWAY_INTERFACE} ) {
        my $log_date = do {
            my @t = localtime;
            sprintf( "%04d-%02d-%02d", $t[5] + 1900, $t[4] + 1, $t[3] );
        };
        open( STDERR, '>>', "/tmp/integrity-${log_date}.log" )
          or die "Cannot open integrity log: $!";
        STDERR->autoflush(1);
    }

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
# DBI must be here -- 'require DBI' inside eval after pledge = SIGABRT
use DBD::SQLite;
use DBI;

# Security check - RESTRICTED level (admin only)
my $session = security_check('restricted');

use CGI qw(:standard);
use JSON::PP;
use POSIX qw(strftime);
use File::Basename;

my $script_dir = dirname(__FILE__);
if ( $script_dir =~ m{^([-/\w.]+)$} ) { $script_dir = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

# Pre-compute canonical paths before pledge (RELABS-001)
my $QUEUE_OUT_DIR =
  File::Spec->catdir( $script_dir, '..', 'data', 'queue', 'integrity',
    'outcome' );
my $STATUS_DIR =
  File::Spec->catdir( $script_dir, '..', 'data', 'services', 'status',
    'integrity' );
my $CANONICAL_OUT    = File::Spec->rel2abs($QUEUE_OUT_DIR);
my $CANONICAL_STATUS = File::Spec->rel2abs($STATUS_DIR);
my $CONF_PATH        = File::Spec->rel2abs(
    File::Spec->catfile(
        $script_dir, '..', 'data', 'config', 'integrity_checks.conf'
    )
);
my $DB_PATH = File::Spec->rel2abs(
    File::Spec->catfile( $script_dir, '..', 'data', 'db', 'TNAudit.db' ) );

for my $ref ( \$CANONICAL_OUT, \$CANONICAL_STATUS, \$CONF_PATH, \$DB_PATH ) {
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
            OpenBSD::Unveil::unveil( $CANONICAL_OUT, "rwc" )
              or die "unveil out: $!";
            OpenBSD::Unveil::unveil( "/tmp", "rwc" ) or die "unveil tmp: $!";
            OpenBSD::Unveil::unveil( $CANONICAL_STATUS, "r" )
              or die "unveil status: $!"
              if -d $CANONICAL_STATUS;
            OpenBSD::Unveil::unveil() or die "unveil lock: $!";
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

if ($postdata) {
    my $json_data;
    eval { $json_data = decode_json($postdata) };

    if ($json_data) {
        my $action       = $json_data->{action}       || '';
        my $check        = $json_data->{check}        || '';
        my $request_time = $json_data->{request_time} || '';

        if ( $action eq 'summary' ) {
            send_json( get_summary() );
        }

        if ( $request_time =~ /^(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})$/ ) {
            $request_time = $1;
        }
        else {
            send_error( 400, "Invalid request time format" );
        }

        if ( $check =~ /^([a-zA-Z0-9_-]+)$/ ) { $check = $1 }
        else {
            send_error( 400, "Invalid check type" );
        }

        my $outcome_file = "$CANONICAL_OUT/out-$request_time";
        if ( $outcome_file =~ m{^([-/\w.]+)$} ) { $outcome_file = $1 }
        else {
            send_error( 500, "Invalid outcome file path" );
        }

        if ( -f $outcome_file ) {
            if ( open( my $fh, '<', $outcome_file ) ) {
                local $/;
                my $json_content = <$fh>;
                close($fh);
                my $outcome;
                eval { $outcome = decode_json($json_content) };
                if ($outcome) {
                    unlink($outcome_file);
                    send_json($outcome);
                }
            }
        }

        send_json(
            {
                success => 0,
                pending => 1,
                message => "Verification in progress"
            }
        );
    }
}

send_error( 400, "No request data" );

# ============================================================
# GET SUMMARY
# ============================================================
sub get_summary {
    my %summary = ( success => 1, checks => {} );

    if ( open( my $cfg_fh, '<', $CONF_PATH ) ) {
        while ( my $line = <$cfg_fh> ) {
            next if $line =~ /^\s*#/;
            next if $line =~ /^\s*$/;
            chomp $line;
            my @fields = split /\|/, $line, 6;
            next unless @fields >= 2;

            my $check_name = $fields[1];
            $check_name =~ s/^\s+|\s+$//g;
            my $display_name = $fields[2] // '';
            $display_name =~ s/^\s+|\s+$//g;
            my $path = $fields[3] // '';
            $path =~ s/^\s+|\s+$//g;
            my $description = $fields[4] // '';
            $description =~ s/^\s+|\s+$//g;
            next unless $check_name;

            $summary{checks}{$check_name} = {
                files        => 0,
                status       => 'pending',
                changes      => 0,
                last_check   => undef,
                display_name => $display_name,
                path         => $path,
                description  => $description,
            };
        }
        close($cfg_fh);
    }

    unless ( -f $DB_PATH ) { return \%summary }

    # DBI already loaded at top -- no require DBI here (SIGABRT after pledge)
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

    if ($dbh) {
        $dbh->do("PRAGMA foreign_keys = ON");
        $dbh->do("PRAGMA journal_mode = WAL");

        my $sql = q{
            SELECT check_name,
                   COUNT(CASE WHEN status != 'retired' THEN 1 END) as total_files,
                   SUM(CASE WHEN status='verified' THEN 1 ELSE 0 END) as verified,
                   SUM(CASE WHEN status='modified' THEN 1 ELSE 0 END) as modified,
                   SUM(CASE WHEN status='missing'  THEN 1 ELSE 0 END) as missing,
                   MAX(CASE WHEN status != 'retired' THEN last_checked END) as last_check,
                   CASE
                       WHEN SUM(CASE WHEN status='modified' OR status='missing' THEN 1 ELSE 0 END) > 0
                           THEN 'failed'
                       WHEN MAX(CASE WHEN status != 'retired' THEN last_checked END) IS NULL
                           THEN 'baseline'
                       ELSE 'verified'
                   END as overall_status
            FROM files
            GROUP BY check_name
        };

        my $sth = $dbh->prepare($sql);
        if ( $sth && $sth->execute() ) {
            while ( my $row = $sth->fetchrow_hashref ) {
                my $cn = $row->{check_name};
                next unless exists $summary{checks}{$cn};
                my $changes =
                  ( $row->{modified} || 0 ) + ( $row->{missing} || 0 );
                $summary{checks}{$cn}{files} = $row->{total_files} || 0;
                $summary{checks}{$cn}{status} =
                  $row->{overall_status} || 'pending';
                $summary{checks}{$cn}{changes}    = $changes;
                $summary{checks}{$cn}{last_check} = $row->{last_check};
            }
        }
        $dbh->disconnect();
    }

    return \%summary;
}

sub get_summary_from_cache {
    my %summary = ( success => 1, checks => {} );
    opendir( my $dh, $CANONICAL_STATUS ) or return \%summary;
    my @check_files = grep { !/^\./ && -f "$CANONICAL_STATUS/$_" } readdir($dh);
    closedir($dh);
    foreach my $check (@check_files) {
        my $status_file = "$CANONICAL_STATUS/$check";
        if ( open( my $fh, '<', $status_file ) ) {
            local $/;
            my $json_content = <$fh>;
            close($fh);
            eval {
                my $data = decode_json($json_content);
                $summary{checks}{$check} = $data;
            };
        }
    }
    return \%summary;
}

__END__

=head1 SECURITY

Requires 'restricted' level access (admin only).
OpenBSD pledge/unveil hardened. BEGIN STDIN pre-read pattern (power_mgmt.pl).

=cut
