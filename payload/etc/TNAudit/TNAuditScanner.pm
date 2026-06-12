#!/usr/bin/perl
package TNAuditScanner;

use strict;
use warnings;
use File::Find;
use File::stat;
use Digest::SHA;
use Fcntl ':mode';

use Exporter 'import';
our @EXPORT_OK = qw(
  scan_directory
  scan_file
  calculate_sha256
  get_file_stats
  format_mode
  is_readable
);

our $VERSION = '1.0.0';

# ============================================================
# DIRECTORY SCANNING
# ============================================================

sub scan_directory {
    my ( $path, $exclude_patterns ) = @_;

    unless ( $path && -d $path ) {
        warn "Invalid or non-existent directory: $path\n";
        return [];
    }

    $exclude_patterns ||= [];

    my @files;

    # Use File::Find to walk directory tree
    find(
        {
            wanted => sub {
                my $file = $File::Find::name;

                # Skip directories and symlinks.
                # -d follows symlinks so catches symlinks-to-dirs.
                # -l catches symlinks to regular files, which -f also
                # resolves as true -- meaning they would be counted and
                # hashed, but `find -type f` does not count them, causing
                # a discrepancy between the card file count and find output.
                return if -d $file;
                return if -l $file;

                # Skip if matches exclude pattern
                my $basename = $_;
                foreach my $pattern (@$exclude_patterns) {
                    if ( _match_pattern( $basename, $pattern ) ) {
                        return;
                    }
                }

                # Get file info
                my $info = scan_file($file);
                push @files, $info if $info;
            },
            follow   => 0,    # Don't follow symlinks
            no_chdir => 1,
        },
        $path
    );

    return \@files;
}

# ============================================================
# SINGLE FILE SCANNING
# ============================================================

sub scan_file {
    my ($filepath) = @_;

    unless ( $filepath && -f $filepath ) {
        warn "File does not exist or is not a regular file: $filepath\n";
        return undef;
    }

    # Check if readable
    unless ( is_readable($filepath) ) {
        warn "Cannot read file: $filepath\n";
        return undef;
    }

    # Get file stats
    my ( $size, $mode, $uid, $gid, $mtime ) = get_file_stats($filepath);

    return undef unless defined $size;

    # Calculate SHA256
    my $sha256 = calculate_sha256($filepath);

    return undef unless $sha256;

    # Return file info
    return {
        filepath   => $filepath,
        size_bytes => $size,
        mode       => format_mode($mode),
        uid        => $uid,
        gid        => $gid,
        mtime      => $mtime,
        sha256     => $sha256,
    };
}

# ============================================================
# SHA256 HASHING
# ============================================================

sub calculate_sha256 {
    my ($filepath) = @_;

    unless ( $filepath && -f $filepath ) {
        warn "Cannot hash non-existent file: $filepath\n";
        return undef;
    }

    # Open file for reading
    my $fh;
    unless ( open $fh, '<', $filepath ) {
        warn "Cannot open file for hashing: $filepath: $!\n";
        return undef;
    }

    binmode($fh);

    # Calculate SHA256
    my $sha = Digest::SHA->new('256');
    eval { $sha->addfile($fh); };

    close($fh);

    if ($@) {
        warn "Error calculating SHA256 for $filepath: $@\n";
        return undef;
    }

    return $sha->hexdigest;
}

# ============================================================
# FILE STATS
# ============================================================

sub get_file_stats {
    my ($filepath) = @_;

    unless ( $filepath && -e $filepath ) {
        warn "Cannot stat non-existent file: $filepath\n";
        return ();
    }

    # Use File::stat for better error handling
    my $st = stat($filepath);

    unless ($st) {
        warn "Cannot stat file: $filepath: $!\n";
        return ();
    }

    return (
        $st->size,     # size in bytes
        $st->mode,     # mode (raw)
        $st->uid,      # owner uid
        $st->gid,      # group gid
        $st->mtime,    # modification time (unix timestamp)
    );
}

# ============================================================
# MODE FORMATTING
# ============================================================

sub format_mode {
    my ($mode) = @_;

    unless ( defined $mode ) {
        return '0000';
    }

    # Extract permission bits (last 12 bits)
    my $perms = $mode & 07777;

    # Format as 4-digit octal string
    return sprintf( '%04o', $perms );
}

# ============================================================
# FILE READABILITY CHECK
# ============================================================

sub is_readable {
    my ($filepath) = @_;

    return 0 unless -e $filepath;
    return 0 unless -f $filepath;
    return 0 unless -r $filepath;

    # Try to actually open it
    if ( open my $fh, '<', $filepath ) {
        close($fh);
        return 1;
    }

    return 0;
}

# ============================================================
# PATTERN MATCHING (Internal)
# ============================================================

sub _match_pattern {
    my ( $filename, $pattern ) = @_;

    # Simple glob pattern matching
    # Convert shell glob to regex
    my $regex = quotemeta($pattern);
    $regex =~ s/\\\*/.*?/g;    # * → .*?
    $regex =~ s/\\\?/./g;      # ? → .

    return $filename =~ /^$regex$/;
}

1;

__END__

=head1 NAME

TNAuditScanner - File system scanning and hashing for TAudit

=head1 SYNOPSIS

    use lib '/etc/TNAudit';
    use TNAuditScanner qw(scan_directory scan_file calculate_sha256);
    
    # Scan entire directory
    my $files = scan_directory('/var/www/htdocs/tn/cgi-bin', ['*.backup', '*.old']);
    
    foreach my $file (@$files) {
        print "$file->{filepath}: $file->{sha256}\n";
    }
    
    # Scan single file
    my $info = scan_file('/etc/pf.conf');
    print "SHA256: $info->{sha256}\n";
    print "Size: $info->{size_bytes} bytes\n";
    print "Mode: $info->{mode}\n";

=head1 DESCRIPTION

Provides file system scanning and SHA256 hashing operations for TAudit.

Uses File::Find for recursive directory scanning, Digest::SHA for hashing,
and File::stat for file metadata.

=head1 FUNCTIONS

=head2 scan_directory($path, $exclude_patterns)

Recursively scan directory and return array of file info hashrefs.
Excludes files matching patterns in $exclude_patterns arrayref.

Returns arrayref of hashrefs with keys: filepath, size_bytes, mode, uid, gid, mtime, sha256.

=head2 scan_file($filepath)

Scan single file and return info hashref.

Returns hashref with keys: filepath, size_bytes, mode, uid, gid, mtime, sha256.

=head2 calculate_sha256($filepath)

Calculate SHA256 hash of file contents.

Returns hex string (64 characters).

=head2 get_file_stats($filepath)

Get file metadata using stat().

Returns list: ($size, $mode, $uid, $gid, $mtime).

=head2 format_mode($mode)

Convert numeric mode to 4-digit octal string.

Example: 33261 → '0755'

=head2 is_readable($filepath)

Check if file exists and is readable.

Returns 1 if readable, 0 otherwise.

=head1 AUTHOR

Tangent Networks

=cut
