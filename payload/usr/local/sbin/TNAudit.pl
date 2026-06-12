#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

#
# TNAudit.pl - File Integrity Monitoring System
# Part of Tangent Networks Security Suite
#

use strict;
use warnings;
use Getopt::Long;
use JSON::PP;
use Time::HiRes qw(time);

# Load TNAudit modules
use lib '/etc/TNAudit';
use TNAuditDatabase qw(
  init_db get_db_handle baseline_file update_file_status update_baseline_hash
  query_check_status query_all_status get_file_count
  log_change get_changes get_file_by_path get_all_files
);
use TNAuditScanner qw(scan_directory scan_file calculate_sha256 get_file_stats);
use TNAuditConfig  qw(load_checks load_global_excludes merge_excludes);
use TNAuditExcludes qw(should_exclude);

# Configuration defaults
use constant {
    DEFAULT_DB_PATH     => '/var/www/htdocs/tn/data/db/TNAudit.db',
    DEFAULT_CONFIG_PATH =>
      '/var/www/htdocs/tn/data/config/integrity_checks.conf',
    DEFAULT_EXCLUDE_PATH =>
      '/var/www/htdocs/tn/data/config/integrity_excludes.conf',
};

our $VERSION = '1.0.0';

# ============================================================
# MAIN
# ============================================================

sub main {

    # Parse command line options
    my %opts = parse_options();

    # Get paths (allow override via options)
    my $db_path = $opts{db} || $ENV{TAUDIT_DB} || DEFAULT_DB_PATH;
    my $config_path =
      $opts{config} || $ENV{TAUDIT_CONFIG} || DEFAULT_CONFIG_PATH;
    my $exclude_path =
      $opts{exclude} || $ENV{TAUDIT_EXCLUDE} || DEFAULT_EXCLUDE_PATH;

    # Initialize database
    my $dbh = init_db($db_path);

    # Execute command
    my $result;

    if ( $opts{action} eq 'init-db' ) {
        $result = {
            success => 1,
            message => "Database initialized at $db_path",
        };
    }
    elsif ( $opts{action} eq 'create-baseline' ) {
        $result =
          create_baseline( $dbh, $config_path, $exclude_path, $opts{check} );
    }
    elsif ( $opts{action} eq 'update-baseline' ) {
        $result =
          update_baseline( $dbh, $config_path, $exclude_path, $opts{check} );
    }
    elsif ( $opts{action} eq 'verify' ) {
        $result =
          verify_integrity( $dbh, $config_path, $exclude_path, $opts{check} );
    }
    elsif ( $opts{action} eq 'status' ) {
        $result = get_status( $dbh, $opts{check} );
    }
    elsif ( $opts{action} eq 'list-files' ) {
        $result = list_files( $dbh, $opts{check} );
    }
    elsif ( $opts{action} eq 'history' ) {
        $result = show_history( $dbh, $opts{check}, $opts{limit} );
    }
    else {
        die "Unknown action: $opts{action}\n";
    }

    # Output result
    if ( $opts{json} ) {
        print encode_json($result) . "\n";
    }
    else {
        print_text_output($result);
    }

    exit( $result->{success} ? 0 : 1 );
}

# ============================================================
# COMMAND LINE PARSING
# ============================================================

sub parse_options {
    my %opts = (
        action  => '',
        check   => undef,
        json    => 0,
        db      => undef,
        config  => undef,
        exclude => undef,
        limit   => 50,
    );

    GetOptions(
        'create-baseline' => sub { $opts{action} = 'create-baseline' },
        'update-baseline' => sub { $opts{action} = 'update-baseline' },
        'verify'          => sub { $opts{action} = 'verify' },
        'status'          => sub { $opts{action} = 'status' },
        'list-files'      => sub { $opts{action} = 'list-files' },
        'history'         => sub { $opts{action} = 'history' },
        'init-db'         => sub { $opts{action} = 'init-db' },
        'check=s'         => \$opts{check},
        'action=s'        => \$opts{action},
        'json'            => \$opts{json},
        'db=s'            => \$opts{db},
        'config=s'        => \$opts{config},
        'exclude=s'       => \$opts{exclude},
        'limit=i'         => \$opts{limit},
        'help'    => sub { print_help();                       exit 0; },
        'version' => sub { print "TNAudit version $VERSION\n"; exit 0; },
    ) or die "Error parsing options. Use --help for usage.\n";

    # Validate action specified
    unless ( $opts{action} ) {
        die "No action specified. Use --help for usage.\n";
    }

    return %opts;
}

# ============================================================
# CREATE BASELINE
# ============================================================

sub create_baseline {
    my ( $dbh, $config_path, $exclude_path, $check_filter ) = @_;

    my $start_time = time();

    # Load configuration
    my @checks          = load_checks($config_path);
    my @global_excludes = load_global_excludes($exclude_path);

    # Filter to specific check if requested
    if ($check_filter) {
        @checks = grep { $_->{check_name} eq $check_filter } @checks;
        unless (@checks) {
            return {
                success => 0,
                error   => "Check not found: $check_filter",
            };
        }
    }

    my $total_files = 0;
    my %check_results;

    # Full baseline (no --check filter): wipe the entire files table and the
    # checks metadata table before re-scanning. This guarantees that check
    # names removed from the conf don't leave stale rows behind that would
    # show as ghost cards in the UI or inflate file counts.
    # The changes table (audit history) is intentionally preserved.
    #
    # Per-check baseline (--check <name>): the targeted DELETE below is
    # sufficient -- we only replace that check's rows.
    unless ($check_filter) {
        $dbh->do("DELETE FROM files");
        $dbh->do("DELETE FROM checks");
        print
          "[Baseline] Cleared files and checks tables for full re-baseline\n";
    }

    # Process each check
    foreach my $check (@checks) {
        my $check_name = $check->{check_name};

    # Per-check DELETE: no-op on a full baseline (table already empty above),
    # but essential for --check <name> runs to remove stale rows for that check.
        $dbh->do( "DELETE FROM files WHERE check_name = ?", undef,
            $check_name );

        # Merge excludes
        my @excludes = merge_excludes( \@global_excludes, $check->{excludes} );

        my $files;

        if ( $check->{type} eq 'dir' ) {

            # Scan directory
            $files = scan_directory( $check->{path}, \@excludes );
        }
        elsif ( $check->{type} eq 'file' ) {

            # Scan single file
            my $file_info = scan_file( $check->{path} );
            $files = $file_info ? [$file_info] : [];
        }

        # Baseline each file
        my $count = 0;
        foreach my $file (@$files) {
            if ( baseline_file( $dbh, $check_name, $file ) ) {
                $count++;
            }
        }

        $check_results{$check_name} = {
            files => $count,
            path  => $check->{path},
        };

        $total_files += $count;
    }

    my $duration = sprintf( "%.2f", time() - $start_time );

    return {
        success     => 1,
        action      => 'create-baseline',
        checks      => scalar(@checks),
        total_files => $total_files,
        results     => \%check_results,
        duration    => "${duration}s",
    };
}

# ============================================================
# UPDATE BASELINE (Accept Changes)
#
# For each file in the targeted check(s) with status=modified:
#   - Re-hash the current file
#   - Call update_baseline_hash() to update sha256/size/mtime
#     and reset status to 'baseline' with change_count=0
#   - Log an 'accepted' event in the changes table
#
# Files with status=missing are NOT silently accepted — they are
# reported back so the operator can investigate. A missing file
# may indicate deletion by an attacker; accepting it blindly
# would erase the audit record.
# ============================================================

sub update_baseline {
    my ( $dbh, $config_path, $exclude_path, $check_filter ) = @_;

    my $start_time = time();

    # Load configuration to validate check_filter
    my @checks = load_checks($config_path);

    if ($check_filter) {
        @checks = grep { $_->{check_name} eq $check_filter } @checks;
        unless (@checks) {
            return {
                success => 0,
                error   => "Check not found: $check_filter",
            };
        }
    }

    my $accepted        = 0;
    my $baselined_new   = 0;
    my $skipped_missing = 0;
    my $errors          = 0;
    my @missing_files;
    my @error_files;

    foreach my $check (@checks) {
        my $check_name     = $check->{check_name};
        my $baseline_files = get_all_files( $dbh, $check_name );

        # ----------------------------------------
        # Pass 1: re-hash files marked 'modified'
        # ----------------------------------------
        foreach my $file (@$baseline_files) {
            my $filepath = $file->{filepath};
            my $file_id  = $file->{id};
            my $status   = $file->{status} || '';

            # Only act on modified files
            next unless $status eq 'modified';

            # File must still exist on disk
            unless ( -f $filepath ) {
                $skipped_missing++;
                push @missing_files, $filepath;
                next;
            }

            # Re-hash the file
            my $new_sha256 = calculate_sha256($filepath);
            unless ($new_sha256) {
                $errors++;
                push @error_files,
                  {
                    filepath => $filepath,
                    reason   => 'Cannot read file for hashing',
                  };
                next;
            }

            # Get current size and mtime
            my ( $new_size, undef, undef, undef, $new_mtime ) =
              get_file_stats($filepath);

            # Log the acceptance event before updating (preserves old hash)
            log_change(
                $dbh, $file_id,
                {
                    change_type => 'accepted',
                    old_sha256  => $file->{sha256},
                    new_sha256  => $new_sha256,
                    old_size    => $file->{size_bytes},
                    new_size    => $new_size || 0,
                }
            );

            # Update baseline with new hash — resets status to 'baseline'
            if (
                update_baseline_hash(
                    $dbh, $file_id, $new_sha256, $new_size, $new_mtime
                )
              )
            {
                $accepted++;
            }
            else {
                $errors++;
                push @error_files,
                  {
                    filepath => $filepath,
                    reason   => 'Database update failed',
                  };
            }
        }

        # ----------------------------------------
        # Pass 2: baseline files marked 'new'
        #
        # verify_integrity writes a DB row with status='new' for every
        # file found on disk that is absent from baseline_lookup.
        # Accept them by calling baseline_file() to upsert a clean
        # baseline row -- same path as create-baseline.
        # ----------------------------------------
        foreach my $new_file (@$baseline_files) {
            next unless ( $new_file->{status} || '' ) eq 'new';

            my $filepath = $new_file->{filepath};

            # File may have vanished between verify and accept -- skip silently
            next unless -f $filepath;

            my $file_info = scan_file($filepath);
            unless ($file_info) {
                $errors++;
                push @error_files,
                  {
                    filepath => $filepath,
                    reason   => 'Cannot scan new file for baselining',
                  };
                next;
            }

            if ( baseline_file( $dbh, $check_name, $file_info ) ) {
                $baselined_new++;
            }
            else {
                $errors++;
                push @error_files,
                  {
                    filepath => $filepath,
                    reason   => 'Database insert failed for new file',
                  };
            }
        }

        # ----------------------------------------
        # Pass 3: retire files marked 'missing'
        #
        # A missing file means it was in the baseline but is no longer
        # on disk -- renamed, deleted, or moved. Rather than leaving the
        # row flagged forever (blocking the card from clearing), we log a
        # 'deleted' event to preserve the audit trail and then mark the
        # row as status='retired' so verify no longer checks it.
        #
        # We do NOT delete the files row because the changes table has no
        # ON DELETE CASCADE -- deleting would orphan change history rows
        # and break the audit join. A 'retired' tombstone keeps everything
        # intact; create-baseline --check <name> will do a full rescan and
        # clean up retired rows as part of a deliberate re-baseline.
        #
        # The rename case (mv a b) produces one 'missing' (old name) and
        # one 'new' (new name). Pass 2 baselines the new name; Pass 3
        # retires the old name. Both clear in a single accept cycle.
        # ----------------------------------------
        my $deleted_accepted = 0;
        foreach my $file (@$baseline_files) {
            next unless ( $file->{status} || '' ) eq 'missing';

            my $filepath = $file->{filepath};
            my $file_id  = $file->{id};

            # Confirm it is genuinely gone -- not a transient read error
            if ( -f $filepath ) {

                # File reappeared between verify and accept (e.g. race with
                # a daemon that recreates it). Treat as modified; re-hash.
                my $new_sha256 = calculate_sha256($filepath);
                if ($new_sha256) {
                    my ( $new_size, undef, undef, undef, $new_mtime ) =
                      get_file_stats($filepath);
                    log_change(
                        $dbh, $file_id,
                        {
                            change_type => 'accepted',
                            old_sha256  => $file->{sha256},
                            new_sha256  => $new_sha256,
                            old_size    => $file->{size_bytes},
                            new_size    => $new_size || 0,
                        }
                    );
                    update_baseline_hash( $dbh, $file_id, $new_sha256,
                        $new_size, $new_mtime );
                    $accepted++;
                }
                next;
            }

            # Log the deletion event -- preserves old hash/size in history
            log_change(
                $dbh, $file_id,
                {
                    change_type => 'deleted',
                    old_sha256  => $file->{sha256},
                    new_sha256  => undef,
                    old_size    => $file->{size_bytes},
                    new_size    => undef,
                }
            );

            # Mark as 'retired' -- verify_integrity skips non-baseline/verified
            # rows when building baseline_lookup, so this file will no longer
            # be checked. Row is retained for audit history.
            $dbh->do(
                q{UPDATE files SET status = 'retired', last_checked = ?
                  WHERE id = ?},
                undef, time(), $file_id
            );

            $deleted_accepted++;
        }

        $accepted += $deleted_accepted;
    }

    my $duration = sprintf( "%.2f", time() - $start_time );

    # Overall status: only errors block a clean baseline result.
    # skipped_missing are files that vanished between verify and accept
    # (genuine race) -- not operator error, but worth reporting.
    # Missing files that were still absent are now retired (Pass 3).
    my $status = ( $errors > 0 ) ? 'failed' : 'baseline';

    my $result = {
        success         => 1,
        action          => 'update-baseline',
        check           => $check_filter || 'all',
        status          => $status,
        accepted        => $accepted,
        baselined_new   => $baselined_new,
        skipped_missing => $skipped_missing,
        errors          => $errors,
        changes         => $errors,
        duration        => "${duration}s",
    };

    $result->{missing_files} = \@missing_files if @missing_files;
    $result->{error_files}   = \@error_files   if @error_files;

    return $result;
}

sub verify_integrity {
    my ( $dbh, $config_path, $exclude_path, $check_filter ) = @_;

    my $start_time = time();

    # Load configuration
    my @checks          = load_checks($config_path);
    my @global_excludes = load_global_excludes($exclude_path);

    # Filter to specific check if requested
    if ($check_filter) {
        @checks = grep { $_->{check_name} eq $check_filter } @checks;
        unless (@checks) {
            return {
                success => 0,
                error   => "Check not found: $check_filter",
            };
        }
    }

    my %totals = (
        files    => 0,
        verified => 0,
        modified => 0,
        missing  => 0,
        new      => 0,
    );

    my @changed_files;

    # Process each check
    foreach my $check (@checks) {
        my $check_name = $check->{check_name};

        # Get all files in baseline for this check.
        # Filter out 'retired' rows -- these are files the operator has
        # accepted as deleted (Pass 3 of update_baseline). They are kept
        # in the DB for audit history but must not be checked for existence
        # or included in the baseline_lookup, otherwise verify would
        # re-flag them as missing on every subsequent run.
        my $all_files = get_all_files( $dbh, $check_name );
        my $baseline_files =
          [ grep { ( $_->{status} || '' ) ne 'retired' } @$all_files ];

        # Create lookup hash -- retired files are already excluded above
        my %baseline_lookup = map { $_->{filepath} => $_ } @$baseline_files;

        # Verify each active (non-retired) file in baseline
        foreach my $baseline (@$baseline_files) {
            my $filepath = $baseline->{filepath};
            my $file_id  = $baseline->{id};

            $totals{files}++;

            # Check if file still exists
            unless ( -f $filepath ) {

                # File missing
                update_file_status( $dbh, $file_id, 'missing' );
                log_change(
                    $dbh, $file_id,
                    {
                        change_type => 'deleted',
                        old_sha256  => $baseline->{sha256},
                        old_size    => $baseline->{size_bytes},
                    }
                );
                $totals{missing}++;
                push @changed_files,
                  {
                    filepath => $filepath,
                    status   => 'missing',
                  };
                next;
            }

            # Calculate current SHA256
            my $current_sha256 = calculate_sha256($filepath);

            unless ($current_sha256) {

                # Cannot read file
                update_file_status( $dbh, $file_id, 'error' );
                next;
            }

            # Compare hashes
            if ( $current_sha256 eq $baseline->{sha256} ) {

                # File verified
                update_file_status( $dbh, $file_id, 'verified' );
                $totals{verified}++;
            }
            else {
                # File modified
                my ( $size, $mode, $uid, $gid, $mtime ) =
                  get_file_stats($filepath);

                update_file_status( $dbh, $file_id, 'modified' );
                log_change(
                    $dbh, $file_id,
                    {
                        change_type => 'modified',
                        old_sha256  => $baseline->{sha256},
                        new_sha256  => $current_sha256,
                        old_size    => $baseline->{size_bytes},
                        new_size    => $size,
                    }
                );
                $totals{modified}++;
                push @changed_files,
                  {
                    filepath   => $filepath,
                    status     => 'modified',
                    old_sha256 => $baseline->{sha256},
                    new_sha256 => $current_sha256,
                  };
            }
        }

        # Check for new files (not in baseline)
        my @excludes = merge_excludes( \@global_excludes, $check->{excludes} );

        my $current_files;
        if ( $check->{type} eq 'dir' ) {
            $current_files = scan_directory( $check->{path}, \@excludes );
        }
        elsif ( $check->{type} eq 'file' ) {

            # Single file check - no new files possible
            $current_files = [];
        }

        foreach my $file (@$current_files) {
            unless ( exists $baseline_lookup{ $file->{filepath} } ) {

                # New file found -- write to DB with status='new' so that
                # update_baseline (accept changes) can find and act on it.
                # Without this the accept loop has no DB row to process and
                # verify flags the same file as new on every subsequent run.
                $totals{new}++;
                push @changed_files,
                  {
                    filepath => $file->{filepath},
                    status   => 'new',
                    sha256   => $file->{sha256},
                  };
                $dbh->do(
                    q{
                    INSERT OR IGNORE INTO files (
                        check_name, filepath, size_bytes, mode, uid, gid,
                        sha256, mtime, baseline_time, last_checked,
                        check_count, status, change_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'new', 0)
                }, undef,
                    $check->{check_name},
                    $file->{filepath},
                    $file->{size_bytes},
                    $file->{mode},
                    $file->{uid},
                    $file->{gid},
                    $file->{sha256},
                    $file->{mtime},
                    time(),
                    time(),
                );
            }
        }
    }

    my $duration = sprintf( "%.2f", time() - $start_time );
    my $changes  = $totals{modified} + $totals{missing} + $totals{new};

    # Determine overall status
    my $status = $changes > 0 ? 'failed' : 'verified';

    my $result = {
        success  => 1,
        action   => 'verify',
        check    => $check_filter || 'all',
        status   => $status,
        files    => $totals{files},
        verified => $totals{verified},
        modified => $totals{modified},
        missing  => $totals{missing},
        new      => $totals{new},
        changes  => $changes,
        duration => "${duration}s",
    };

    # Add changed files if any
    if (@changed_files) {
        $result->{changed_files} = \@changed_files;
    }

    return $result;
}

# ============================================================
# GET STATUS
# ============================================================

sub get_status {
    my ( $dbh, $check_filter ) = @_;

    if ($check_filter) {

        # Single check status
        my $status = query_check_status( $dbh, $check_filter );
        return {
            success => 1,
            %$status,
        };
    }
    else {
        # All checks status
        my $status = query_all_status($dbh);
        return $status;
    }
}

# ============================================================
# LIST FILES
# ============================================================

sub list_files {
    my ( $dbh, $check_name ) = @_;

    unless ($check_name) {
        return {
            success => 0,
            error   => "Check name required for list-files",
        };
    }

    my $files = get_all_files( $dbh, $check_name );

    return {
        success => 1,
        check   => $check_name,
        files   => $files,
    };
}

# ============================================================
# SHOW HISTORY
# ============================================================

sub show_history {
    my ( $dbh, $check_name, $limit ) = @_;

    unless ($check_name) {
        return {
            success => 0,
            error   => "Check name required for history",
        };
    }

    my $changes = get_changes( $dbh, $check_name, $limit );

    return {
        success => 1,
        check   => $check_name,
        changes => $changes,
    };
}

# ============================================================
# TEXT OUTPUT
# ============================================================

sub print_text_output {
    my ($result) = @_;

    if ( $result->{error} ) {
        print "ERROR: $result->{error}\n";
        return;
    }

    my $action = $result->{action} || '';

    if ( $action eq 'create-baseline' ) {
        print "Baseline created successfully\n";
        print "Checks: $result->{checks}\n";
        print "Total files: $result->{total_files}\n";
        print "Duration: $result->{duration}\n";
    }
    elsif ( $action eq 'verify' ) {
        print "Verification complete\n";
        print "Status: $result->{status}\n";
        print "Files: $result->{files}\n";
        print "Verified: $result->{verified}\n";
        print "Modified: $result->{modified}\n";
        print "Missing: $result->{missing}\n";
        print "New: $result->{new}\n";
        print "Changes: $result->{changes}\n";
        print "Duration: $result->{duration}\n";
    }
    else {
        # Generic output
        print "Success: " . ( $result->{success} ? "yes" : "no" ) . "\n";
        if ( $result->{message} ) {
            print "$result->{message}\n";
        }
    }
}

# ============================================================
# HELP
# ============================================================

sub print_help {
    print <<"EOF";
TNAudit - File Integrity Monitoring System
Version $VERSION

USAGE:
    TNAudit.pl <action> [options]

ACTIONS:
    --create-baseline       Create or update file baselines
    --update-baseline       Accept changes — update baseline for modified files
    --verify                Verify file integrity
    --status                Query verification status
    --list-files            List monitored files
    --history               Show change history
    --init-db               Initialize database

OPTIONS:
    --check <name>          Limit to specific check
    --json                  Output JSON format
    --db <path>             Database path (default: ${\DEFAULT_DB_PATH})
    --config <path>         Config file (default: ${\DEFAULT_CONFIG_PATH})
    --exclude <path>        Exclude file (default: ${\DEFAULT_EXCLUDE_PATH})
    --limit <n>             Limit history results (default: 50)
    --help                  Show this help
    --version               Show version

EXAMPLES:
    # Create baseline for all checks
    TNAudit.pl --create-baseline

    # Create baseline for specific check
    TNAudit.pl --create-baseline --check cgi

    # Verify integrity
    TNAudit.pl --verify --check cgi --json

    # Get status
    TNAudit.pl --status --json

    # Show history
    TNAudit.pl --history --check cgi --limit 20

ENVIRONMENT:
    TAUDIT_DB              Override database path
    TAUDIT_CONFIG          Override config file path
    TAUDIT_EXCLUDE         Override exclude file path

EOF
}

# ============================================================
# RUN
# ============================================================

main() unless caller;

1;

__END__

=head1 NAME

TNAudit.pl - File Integrity Monitoring System

=head1 DESCRIPTION

TNAudit monitors file integrity by creating SHA256 baselines and detecting
modifications, deletions, and new files.

=head1 AUTHOR

Tangent Networks

=cut
