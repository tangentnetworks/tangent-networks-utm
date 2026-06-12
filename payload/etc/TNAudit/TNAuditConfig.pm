#!/usr/bin/perl
package TNAuditConfig;

use strict;
use warnings;

use Exporter 'import';
our @EXPORT_OK = qw(
  load_checks
  parse_check_line
  validate_check
  load_global_excludes
  merge_excludes
);

our $VERSION = '1.0.0';

# ============================================================
# LOAD CHECKS FROM CONFIG FILE
# ============================================================

sub load_checks {
    my ($config_file) = @_;

    unless ( $config_file && -f $config_file ) {
        die "Config file not found: $config_file\n";
    }

    my @checks;

    open my $fh, '<', $config_file
      or die "Cannot open config file: $config_file: $!\n";

    while ( my $line = <$fh> ) {
        chomp $line;

        # Skip blank lines
        next if $line =~ /^\s*$/;

        # Skip comments
        next if $line =~ /^\s*#/;

        # Parse check line
        my $check = parse_check_line($line);

        if ($check) {

            # Validate check
            if ( validate_check($check) ) {
                push @checks, $check;
            }
            else {
                warn "Invalid check configuration (skipping): $line\n";
            }
        }
        else {
            warn "Cannot parse check line (skipping): $line\n";
        }
    }

    close $fh;

    return @checks;
}

# ============================================================
# PARSE SINGLE CHECK LINE
# ============================================================

sub parse_check_line {
    my ($line) = @_;

    return undef unless $line;

    # Remove leading/trailing whitespace
    $line =~ s/^\s+//;
    $line =~ s/\s+$//;

    # Split by pipe
    my @fields = split /\|/, $line;

    # Need at least 5 fields: type|check_name|display_name|path|description
    unless ( @fields >= 5 ) {
        return undef;
    }

    # Extract fields
    my ( $type, $check_name, $display_name, $path, $description, $excludes ) =
      @fields;

    # Clean up fields
    $type         = _trim($type);
    $check_name   = _trim($check_name);
    $display_name = _trim($display_name);
    $path         = _trim($path);
    $description  = _trim($description);
    $excludes     = _trim( $excludes || '' );

    # Parse excludes into array
    my @exclude_patterns;
    if ($excludes) {
        @exclude_patterns = split /,/, $excludes;
        @exclude_patterns = map { _trim($_) } @exclude_patterns;
    }

    return {
        type         => $type,
        check_name   => $check_name,
        display_name => $display_name,
        path         => $path,
        description  => $description,
        excludes     => \@exclude_patterns,
    };
}

# ============================================================
# VALIDATE CHECK CONFIGURATION
# ============================================================

sub validate_check {
    my ($check) = @_;

    return 0 unless $check && ref($check) eq 'HASH';

    # Check required fields
    return 0 unless $check->{type};
    return 0 unless $check->{check_name};
    return 0 unless $check->{path};

    # Validate type
    unless ( $check->{type} eq 'dir' || $check->{type} eq 'file' ) {
        warn "Invalid check type: $check->{type} (must be 'dir' or 'file')\n";
        return 0;
    }

    # Validate path exists
    if ( $check->{type} eq 'dir' ) {
        unless ( -d $check->{path} ) {
            warn "Directory does not exist: $check->{path}\n";
            return 0;
        }
    }
    elsif ( $check->{type} eq 'file' ) {
        unless ( -f $check->{path} ) {
            warn "File does not exist: $check->{path}\n";
            return 0;
        }
    }

    return 1;
}

# ============================================================
# LOAD GLOBAL EXCLUDES
# ============================================================

sub load_global_excludes {
    my ($exclude_file) = @_;

    my @patterns;

    # If no file provided or doesn't exist, return empty list
    return @patterns unless $exclude_file && -f $exclude_file;

    open my $fh, '<', $exclude_file or do {
        warn "Cannot open exclude file: $exclude_file: $!\n";
        return @patterns;
    };

    while ( my $line = <$fh> ) {
        chomp $line;

        # Skip blank lines
        next if $line =~ /^\s*$/;

        # Skip comments
        next if $line =~ /^\s*#/;

        # Clean and add pattern
        my $pattern = _trim($line);
        push @patterns, $pattern if $pattern;
    }

    close $fh;

    return @patterns;
}

# ============================================================
# MERGE EXCLUDE PATTERNS
# ============================================================

sub merge_excludes {
    my ( $global, $local ) = @_;

    my @merged;

    # Add global patterns
    if ( $global && ref($global) eq 'ARRAY' ) {
        push @merged, @$global;
    }

    # Add local patterns
    if ( $local && ref($local) eq 'ARRAY' ) {
        push @merged, @$local;
    }

    # Remove duplicates
    my %seen;
    @merged = grep { !$seen{$_}++ } @merged;

    return @merged;
}

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

sub _trim {
    my ($str) = @_;
    return '' unless defined $str;
    $str =~ s/^\s+//;
    $str =~ s/\s+$//;
    return $str;
}

1;

__END__

=head1 NAME

TNAuditConfig - Configuration file parsing for TAudit

=head1 SYNOPSIS

    use lib '/etc/TNAudit';
    use TNAuditConfig qw(load_checks load_global_excludes merge_excludes);
    
    # Load check definitions
    my @checks = load_checks('/var/www/htdocs/tn/data/config/integrity_checks.conf');
    
    foreach my $check (@checks) {
        print "Check: $check->{check_name}\n";
        print "  Type: $check->{type}\n";
        print "  Path: $check->{path}\n";
        print "  Display: $check->{display_name}\n";
    }
    
    # Load global excludes
    my @global = load_global_excludes('/var/www/htdocs/tn/data/config/integrity_excludes.conf');
    
    # Merge with check-specific excludes
    my @all_excludes = merge_excludes(\@global, $check->{excludes});

=head1 DESCRIPTION

Parses configuration files for the TAudit file integrity system.

Reads integrity_checks.conf with pipe-delimited format:
type|check_name|display_name|path|description|excludes

Where:
- type: 'dir' or 'file'
- check_name: Unique identifier (e.g., 'cgi', 'lib')
- display_name: Human-readable name
- path: Full path to directory or file
- description: Description text
- excludes: Comma-separated exclude patterns (optional)

=head1 FUNCTIONS

=head2 load_checks($config_file)

Load and parse check definitions from config file.

Returns array of check hashrefs.

=head2 parse_check_line($line)

Parse a single pipe-delimited config line.

Returns hashref with keys: type, check_name, display_name, path, description, excludes.

=head2 validate_check($check)

Validate check configuration (type valid, path exists).

Returns 1 if valid, 0 otherwise.

=head2 load_global_excludes($exclude_file)

Load global exclude patterns from file (one per line).

Returns array of patterns.

=head2 merge_excludes($global, $local)

Merge global and check-specific exclude patterns, removing duplicates.

Returns array of patterns.

=head1 AUTHOR

Tangent Networks

=cut
