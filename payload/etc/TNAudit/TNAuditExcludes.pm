#!/usr/bin/perl
package TNAuditExcludes;

use strict;
use warnings;

use Exporter 'import';
our @EXPORT_OK = qw(
  should_exclude
  compile_pattern
  match_glob
  match_regex
  match_exact
);

our $VERSION = '1.0.0';

# ============================================================
# MAIN EXCLUSION CHECK
# ============================================================

sub should_exclude {
    my ( $filename, $patterns ) = @_;

    return 0 unless $filename;
    return 0 unless $patterns && ref($patterns) eq 'ARRAY';
    return 0 unless @$patterns;

    # Test filename against each pattern
    foreach my $pattern (@$patterns) {
        next unless $pattern;

        # Determine pattern type and test
        if ( $pattern =~ m{^/(.+)/$} ) {

            # Regex pattern: /pattern/
            my $regex = $1;
            return 1 if match_regex( $filename, $regex );
        }
        elsif ( $pattern =~ /^exact:(.+)$/ ) {

            # Exact match: exact:filename
            my $exact = $1;
            return 1 if match_exact( $filename, $exact );
        }
        else {
            # Shell glob pattern (default)
            return 1 if match_glob( $filename, $pattern );
        }
    }

    return 0;
}

# ============================================================
# GLOB PATTERN MATCHING
# ============================================================

sub match_glob {
    my ( $filename, $pattern ) = @_;

    return 0 unless defined $filename && defined $pattern;

    # Convert shell glob to regex
    my $regex = compile_pattern($pattern);

    # Match against filename
    return $filename =~ /^$regex$/;
}

# ============================================================
# REGEX PATTERN MATCHING
# ============================================================

sub match_regex {
    my ( $filename, $regex ) = @_;

    return 0 unless defined $filename && defined $regex;

    # Try to match regex
    eval { return $filename =~ /$regex/; };

    if ($@) {
        warn "Invalid regex pattern: $regex: $@\n";
        return 0;
    }

    return 0;
}

# ============================================================
# EXACT STRING MATCHING
# ============================================================

sub match_exact {
    my ( $filename, $exact ) = @_;

    return 0 unless defined $filename && defined $exact;

    return $filename eq $exact;
}

# ============================================================
# COMPILE GLOB TO REGEX
# ============================================================

sub compile_pattern {
    my ($pattern) = @_;

    return '' unless defined $pattern;

    # Escape special regex characters
    my $regex = quotemeta($pattern);

    # Convert glob wildcards to regex
    $regex =~ s/\\\*/.*?/g;    # * → .*? (non-greedy)
    $regex =~ s/\\\?/./g;      # ? → .

    # Handle character classes [abc] and ranges [a-z]
    # These are already in the pattern, just unescape the brackets
    $regex =~ s/\\\[/[/g;
    $regex =~ s/\\\]/]/g;
    $regex =~ s/\\\-/-/g;

    return $regex;
}

1;

__END__

=head1 NAME

TNAuditExcludes - Pattern matching for file exclusion in TAudit

=head1 SYNOPSIS

    use lib '/etc/TNAudit';
    use TNAuditExcludes qw(should_exclude);
    
    my @patterns = (
        '*.backup',                              # Shell glob
        '*-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]',  # Date pattern
        '/^temp_/',                              # Regex
        'exact:file.txt',                        # Exact match
    );
    
    if (should_exclude('file-2026-02-15.pl', \@patterns)) {
        print "File excluded\n";
    }

=head1 DESCRIPTION

Provides pattern matching for excluding files from TAudit monitoring.

Supports three pattern types:

1. Shell glob (default): *.backup, temp*, file-????.txt
   - * matches any characters
   - ? matches single character
   - [abc] matches character class
   - [0-9] matches digit range

2. Regex: /^pattern$/
   - Patterns wrapped in forward slashes
   - Full Perl regex syntax

3. Exact match: exact:filename.txt
   - Matches exact string only

=head1 FUNCTIONS

=head2 should_exclude($filename, $patterns)

Test if filename matches any pattern in arrayref.

Returns 1 if excluded, 0 otherwise.

=head2 match_glob($filename, $pattern)

Match filename against shell glob pattern.

Returns 1 if matches, 0 otherwise.

=head2 match_regex($filename, $regex)

Match filename against regex pattern.

Returns 1 if matches, 0 otherwise.

=head2 match_exact($filename, $exact)

Match filename against exact string.

Returns 1 if matches, 0 otherwise.

=head2 compile_pattern($pattern)

Convert shell glob pattern to regex.

Returns regex string.

=head1 PATTERN EXAMPLES

    *.backup           → matches: file.backup, test.backup
    *-????-??-??       → matches: file-2026-02-15, backup-2025-12-31
    temp*              → matches: temp123, tempfile.txt
    test-[0-9]         → matches: test-1, test-5
    /^backup_\d+$/     → matches: backup_123, backup_999
    exact:file.txt     → matches: file.txt only

=head1 AUTHOR

Tangent Networks

=cut
