#!/usr/bin/perl
package TNAuditDatabase;

use strict;
use warnings;
use DBI;
use JSON::PP;

use Exporter 'import';
our @EXPORT_OK = qw(
  init_db
  get_db_handle
  baseline_file
  update_file_status
  update_baseline_hash
  query_check_status
  query_all_status
  get_file_count
  log_change
  get_changes
  cleanup_old_changes
  get_file_by_path
  get_all_files
);

our $VERSION = '1.0.0';

# Module-level database handle cache
my $DBH;

# ============================================================
# DATABASE INITIALIZATION
# ============================================================

sub init_db {
    my ($db_path) = @_;

    # Validate path
    unless ($db_path) {
        die "ERROR: Database path required\n";
    }

    # Connect to SQLite
    my $dbh = DBI->connect(
        "dbi:SQLite:dbname=$db_path",
        "", "",
        {
            RaiseError     => 1,
            AutoCommit     => 1,
            PrintError     => 0,
            sqlite_unicode => 1,
        }
    ) or die "Cannot connect to database: $DBI::errstr\n";

    # Enable WAL mode for concurrent reads
    $dbh->do("PRAGMA journal_mode=WAL");
    $dbh->do("PRAGMA synchronous=NORMAL");
    $dbh->do("PRAGMA temp_store=MEMORY");
    $dbh->do("PRAGMA cache_size=-64000");    # 64MB cache

    # Create tables if they don't exist
    _create_tables($dbh);

    # Cache handle
    $DBH = $dbh;

    return $dbh;
}

sub _create_tables {
    my ($dbh) = @_;

    # Files table - stores all monitored files
    $dbh->do(
        q{
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            check_name TEXT NOT NULL,
            filepath TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            mode TEXT NOT NULL,
            uid INTEGER NOT NULL,
            gid INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            mtime INTEGER NOT NULL,
            baseline_time INTEGER NOT NULL,
            last_checked INTEGER,
            check_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'baseline',
            change_count INTEGER DEFAULT 0,
            UNIQUE(check_name, filepath)
        )
    }
    );

    # Changes table - tracks modification history
    $dbh->do(
        q{
        CREATE TABLE IF NOT EXISTS changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            changed_at INTEGER NOT NULL,
            old_sha256 TEXT,
            new_sha256 TEXT,
            old_size INTEGER,
            new_size INTEGER,
            old_mode TEXT,
            new_mode TEXT,
            change_type TEXT NOT NULL,
            FOREIGN KEY(file_id) REFERENCES files(id)
        )
    }
    );

    # Checks table - stores check definitions
    $dbh->do(
        q{
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            check_name TEXT UNIQUE NOT NULL,
            check_type TEXT NOT NULL,
            path TEXT NOT NULL,
            display_name TEXT NOT NULL,
            description TEXT,
            exclude_patterns TEXT,
            enabled INTEGER DEFAULT 1,
            last_scan INTEGER,
            file_count INTEGER DEFAULT 0
        )
    }
    );

    # Create indexes
    $dbh->do("CREATE INDEX IF NOT EXISTS idx_check_name ON files(check_name)");
    $dbh->do("CREATE INDEX IF NOT EXISTS idx_status ON files(status)");
    $dbh->do("CREATE INDEX IF NOT EXISTS idx_filepath ON files(filepath)");
    $dbh->do("CREATE INDEX IF NOT EXISTS idx_file_id ON changes(file_id)");
    $dbh->do(
        "CREATE INDEX IF NOT EXISTS idx_changed_at ON changes(changed_at)");
}

# ============================================================
# DATABASE HANDLE
# ============================================================

sub get_db_handle {
    my ($db_path) = @_;

    # Return cached handle if available
    return $DBH if $DBH;

    # Otherwise initialize
    return init_db($db_path);
}

# ============================================================
# BASELINE OPERATIONS
# ============================================================

sub baseline_file {
    my ( $dbh, $check_name, $file_info ) = @_;

    # Validate inputs
    unless ( $check_name && $file_info && ref($file_info) eq 'HASH' ) {
        warn "Invalid baseline_file arguments\n";
        return 0;
    }

    # Required fields
    my @required = qw(filepath size_bytes mode uid gid sha256 mtime);
    foreach my $field (@required) {
        unless ( exists $file_info->{$field} ) {
            warn "Missing required field: $field\n";
            return 0;
        }
    }

    # Insert or replace file record
    my $sql = q{
        INSERT OR REPLACE INTO files (
            check_name, filepath, size_bytes, mode, uid, gid, sha256, 
            mtime, baseline_time, last_checked, check_count, status, change_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, 'baseline', 0)
    };

    my $baseline_time = time();

    eval {
        $dbh->do(
            $sql,                     undef,
            $check_name,              $file_info->{filepath},
            $file_info->{size_bytes}, $file_info->{mode},
            $file_info->{uid},        $file_info->{gid},
            $file_info->{sha256},     $file_info->{mtime},
            $baseline_time
        );
    };

    if ($@) {
        warn "Failed to baseline file $file_info->{filepath}: $@\n";
        return 0;
    }

    return 1;
}

# ============================================================
# UPDATE BASELINE HASH
# Called when an operator deliberately accepts a changed file.
# Updates the stored SHA256, size, and mtime to the current
# on-disk values, resets status to 'baseline', resets
# change_count to 0, and stamps a new baseline_time.
# The caller is responsible for logging the 'accepted' change
# event via log_change() before or after calling this.
# ============================================================

sub update_baseline_hash {
    my ( $dbh, $file_id, $new_sha256, $new_size, $new_mtime ) = @_;

    unless ( $file_id && $new_sha256 ) {
        warn "update_baseline_hash: file_id and new_sha256 required\n";
        return 0;
    }

    my $now = time();

    my $sql = q{
        UPDATE files
        SET sha256        = ?,
            size_bytes    = ?,
            mtime         = ?,
            baseline_time = ?,
            status        = 'baseline',
            change_count  = 0,
            last_checked  = ?
        WHERE id = ?
    };

    eval {
        $dbh->do(
            $sql, undef, $new_sha256,
            $new_size  || 0,
            $new_mtime || $now,
            $now, $now, $file_id
        );
    };

    if ($@) {
        warn "update_baseline_hash: failed for file_id $file_id: $@\n";
        return 0;
    }

    return 1;
}

sub update_file_status {
    my ( $dbh, $file_id, $status, $new_info ) = @_;

    unless ( $file_id && $status ) {
        warn "Invalid update_file_status arguments\n";
        return 0;
    }

    my $now = time();

    # Update file record
    my $sql = q{
        UPDATE files 
        SET status = ?,
            last_checked = ?,
            check_count = check_count + 1
        WHERE id = ?
    };

    eval { $dbh->do( $sql, undef, $status, $now, $file_id ); };

    if ($@) {
        warn "Failed to update file status: $@\n";
        return 0;
    }

    # If file was modified, update change count
    if ( $status eq 'modified' && $new_info ) {
        $dbh->do(
            "UPDATE files SET change_count = change_count + 1 WHERE id = ?",
            undef, $file_id );
    }

    return 1;
}

# ============================================================
# STATUS QUERIES
# ============================================================

sub query_check_status {
    my ( $dbh, $check_name ) = @_;

    unless ($check_name) {
        warn "Check name required\n";
        return undef;
    }

    my $sql = q{
        SELECT
            COUNT(CASE WHEN status != 'retired' THEN 1 END) as total_files,
            SUM(CASE WHEN status='verified' THEN 1 ELSE 0 END) as verified,
            SUM(CASE WHEN status='modified' THEN 1 ELSE 0 END) as modified,
            SUM(CASE WHEN status='missing'  THEN 1 ELSE 0 END) as missing,
            MAX(CASE WHEN status != 'retired' THEN last_checked END) as last_check,
            CASE
                WHEN SUM(CASE WHEN status='modified' OR status='missing' THEN 1 ELSE 0 END) > 0
                    THEN 'failed'
                WHEN MAX(CASE WHEN status != 'retired' THEN last_checked END) IS NULL
                    THEN 'pending'
                ELSE 'verified'
            END as overall_status
        FROM files
        WHERE check_name = ?
    };

    my $row = $dbh->selectrow_hashref( $sql, undef, $check_name );

    return {
        check      => $check_name,
        files      => $row->{total_files} || 0,
        verified   => $row->{verified}    || 0,
        modified   => $row->{modified}    || 0,
        missing    => $row->{missing}     || 0,
        changes    => ( $row->{modified} || 0 ) + ( $row->{missing} || 0 ),
        last_check => $row->{last_check},
        status     => $row->{overall_status} || 'pending',
    };
}

sub query_all_status {
    my ($dbh) = @_;

    my $sql = q{
        SELECT
            check_name,
            COUNT(CASE WHEN status != 'retired' THEN 1 END) as total_files,
            SUM(CASE WHEN status='verified' THEN 1 ELSE 0 END) as verified,
            SUM(CASE WHEN status='modified' THEN 1 ELSE 0 END) as modified,
            SUM(CASE WHEN status='missing'  THEN 1 ELSE 0 END) as missing,
            MAX(CASE WHEN status != 'retired' THEN last_checked END) as last_check,
            CASE
                WHEN SUM(CASE WHEN status='modified' OR status='missing' THEN 1 ELSE 0 END) > 0
                    THEN 'failed'
                WHEN MAX(CASE WHEN status != 'retired' THEN last_checked END) IS NULL
                    THEN 'pending'
                ELSE 'verified'
            END as overall_status
        FROM files
        GROUP BY check_name
    };

    my $sth = $dbh->prepare($sql);
    $sth->execute();

    my %result = ( success => 1, checks => {} );

    while ( my $row = $sth->fetchrow_hashref ) {
        $result{checks}{ $row->{check_name} } = {
            files      => $row->{total_files} || 0,
            verified   => $row->{verified}    || 0,
            modified   => $row->{modified}    || 0,
            missing    => $row->{missing}     || 0,
            changes    => ( $row->{modified} || 0 ) + ( $row->{missing} || 0 ),
            last_check => $row->{last_check},
            status     => $row->{overall_status} || 'pending',
        };
    }

    return \%result;
}

sub get_file_count {
    my ( $dbh, $check_name ) = @_;

    my $sql = "SELECT COUNT(*) FROM files WHERE check_name = ?";
    my ($count) = $dbh->selectrow_array( $sql, undef, $check_name );

    return $count || 0;
}

# ============================================================
# CHANGE TRACKING
# ============================================================

sub log_change {
    my ( $dbh, $file_id, $change_data ) = @_;

    unless ( $file_id && $change_data && ref($change_data) eq 'HASH' ) {
        warn "Invalid log_change arguments\n";
        return 0;
    }

    my $sql = q{
        INSERT INTO changes (
            file_id, changed_at, old_sha256, new_sha256,
            old_size, new_size, old_mode, new_mode, change_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    };

    my $now = time();

    eval {
        $dbh->do(
            $sql,
            undef,
            $file_id,
            $now,
            $change_data->{old_sha256},
            $change_data->{new_sha256},
            $change_data->{old_size},
            $change_data->{new_size},
            $change_data->{old_mode},
            $change_data->{new_mode},
            $change_data->{change_type} || 'modified'
        );
    };

    if ($@) {
        warn "Failed to log change: $@\n";
        return 0;
    }

    return 1;
}

sub get_changes {
    my ( $dbh, $check_name, $limit ) = @_;

    $limit ||= 50;

    my $sql = q{
        SELECT 
            c.changed_at,
            c.change_type,
            c.old_sha256,
            c.new_sha256,
            c.old_size,
            c.new_size,
            f.filepath
        FROM changes c
        JOIN files f ON c.file_id = f.id
        WHERE f.check_name = ?
        ORDER BY c.changed_at DESC
        LIMIT ?
    };

    my $sth = $dbh->prepare($sql);
    $sth->execute( $check_name, $limit );

    my @changes;
    while ( my $row = $sth->fetchrow_hashref ) {
        push @changes,
          {
            filepath    => $row->{filepath},
            changed_at  => $row->{changed_at},
            change_type => $row->{change_type},
            old_sha256  => $row->{old_sha256},
            new_sha256  => $row->{new_sha256},
            old_size    => $row->{old_size},
            new_size    => $row->{new_size},
          };
    }

    return \@changes;
}

sub cleanup_old_changes {
    my ( $dbh, $days ) = @_;

    $days ||= 90;    # Default 90 day retention

    my $cutoff = time() - ( $days * 86400 );

    my $sql = "DELETE FROM changes WHERE changed_at < ?";

    my $deleted = $dbh->do( $sql, undef, $cutoff );

    return $deleted || 0;
}

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

sub get_file_by_path {
    my ( $dbh, $check_name, $filepath ) = @_;

    my $sql = "SELECT * FROM files WHERE check_name = ? AND filepath = ?";
    return $dbh->selectrow_hashref( $sql, undef, $check_name, $filepath );
}

sub get_all_files {
    my ( $dbh, $check_name ) = @_;

    my $sql = "SELECT * FROM files WHERE check_name = ? ORDER BY filepath";
    my $sth = $dbh->prepare($sql);
    $sth->execute($check_name);

    my @files;
    while ( my $row = $sth->fetchrow_hashref ) {
        push @files, $row;
    }

    return \@files;
}

1;

__END__

=head1 NAME

TAuditDatabase - SQLite database operations for TAudit

=head1 SYNOPSIS

    use lib '/var/www/htdocs/tn/data/lib';
    use TAuditDatabase qw(init_db baseline_file query_check_status);
    
    my $dbh = init_db('/var/www/htdocs/tn/data/db/TAudit.db');
    
    baseline_file($dbh, 'cgi', {
        filepath => '/var/www/htdocs/tn/cgi-bin/control.pl',
        size_bytes => 21206,
        mode => '0755',
        uid => 67,
        gid => 67,
        sha256 => 'abc123...',
        mtime => 1234567890,
    });
    
    my $status = query_check_status($dbh, 'cgi');

=head1 DESCRIPTION

Provides SQLite database operations for the TAudit file integrity system.
Located in /var/www/htdocs/tn/data/lib/ with other TN modules.

=head1 FUNCTIONS

=head2 init_db($db_path)

Initialize database, create tables, enable WAL mode. Returns database handle.

=head2 baseline_file($dbh, $check_name, $file_info)

Insert or replace file record in baseline.

=head2 update_baseline_hash($dbh, $file_id, $new_sha256, $new_size, $new_mtime)

Accept a legitimately changed file. Updates sha256, size_bytes, mtime, resets
status to 'baseline' and change_count to 0. Caller must log the 'accepted'
change event via log_change() separately.

=head2 update_file_status($dbh, $file_id, $status, $new_info)

Update file verification status.

=head2 query_check_status($dbh, $check_name)

Get status summary for a check. Returns hashref.

=head2 query_all_status($dbh)

Get status summary for all checks. Returns hashref.

=head2 log_change($dbh, $file_id, $change_data)

Record file change in history.

=head2 get_changes($dbh, $check_name, $limit)

Get recent changes for a check.

=head1 AUTHOR

Tangent Networks

=cut
