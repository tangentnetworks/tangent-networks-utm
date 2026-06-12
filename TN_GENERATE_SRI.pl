#!/usr/bin/perl

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ============================================================================
# TN_GENERATE_SRI.pl - SRI Hash Generator for Tangent Networks
# ============================================================================
# Generates SHA-384 SRI hashes for JavaScript assets and outputs paste-ready
# Perl hash lines for TNWAF.pm %CONFIG{sri_hashes}.
#
# THREE DISCOVERY MODES:
#
#   1. DIRECTORY SCAN (default):
#      Walks assets/js/ and hashes every .js file on disk.
#      Most complete — catches everything, including files not yet referenced.
#
#   2. SCRIPT TAG PARSE (--from-tags):
#      Parses <script src="..."> tags from all HTML files and view fragments.
#      Handles relative paths (./assets/...) and absolute (/assets/...).
#      Hashes files on disk — ignores any existing integrity= attributes.
#
#   3. INTEGRITY HARVEST (--from-integrity):
#      Reads existing integrity="sha384-..." attributes directly from HTML
#      and view fragments. No disk hashing — extracts what the browser already
#      validates. Fastest and most precise for keeping TNWAF.pm in sync after
#      an SRI regeneration pass on the HTML side.
#      Warns on conflicts (same file, different hashes across sources).
#
#   --all: runs modes 1 + 2 + 3, deduplicated. Mode 3 wins on conflict
#          (integrity= in HTML is the ground truth for what browsers validate).
#
# USAGE:
#   perl TN_GENERATE_SRI.pl                        # directory scan
#   perl TN_GENERATE_SRI.pl --from-tags            # script tag parse
#   perl TN_GENERATE_SRI.pl --from-integrity       # harvest existing integrity=
#   perl TN_GENERATE_SRI.pl --all                  # all three, deduplicated
#   perl TN_GENERATE_SRI.pl --list-only            # show files, no hashes
#   perl TN_GENERATE_SRI.pl --verify               # compare disk hashes vs TNWAF.pm
#   perl TN_GENERATE_SRI.pl --base /path/to/tn     # custom base dir
#
# AUTHOR: David Peter, Tangent Networks
# VERSION: 3.0.0
# ============================================================================

use strict;
use warnings;
use Digest::SHA qw(sha384_hex);
use File::Find;
use File::Spec;
use File::Basename;
use MIME::Base64 qw(encode_base64);
use Getopt::Long qw(:config no_ignore_case bundling);

our $VERSION = '3.0.0';

# ============================================================================
# OPTION PARSING
# ============================================================================

my $base_dir       = '/var/www/htdocs/tn';
my $from_tags      = 0;
my $from_integrity = 0;
my $all_mode       = 0;
my $list_only      = 0;
my $verify_mode    = 0;
my $help           = 0;
my $quiet          = 0;

GetOptions(
    'base=s'         => \$base_dir,
    'from-tags'      => \$from_tags,
    'from-integrity' => \$from_integrity,
    'all'            => \$all_mode,
    'list-only'      => \$list_only,
    'verify'         => \$verify_mode,
    'quiet'          => \$quiet,
    'help|h'         => \$help,
) or usage(1);

usage(0) if $help;

# --all enables all discovery modes
if ($all_mode) {
    $from_tags      = 1;
    $from_integrity = 1;
}

# --verify implies directory scan for disk hashes
$verify_mode = 1 if $verify_mode;

# ============================================================================
# VALIDATE BASE DIR
# ============================================================================

$base_dir =~ s{/$}{};    # strip trailing slash

unless ( -d $base_dir ) {
    die "ERROR: Base directory not found: $base_dir\n";
}

my $assets_js_dir = "$base_dir/assets/js";
my $view_dir      = "$base_dir/view";

# ============================================================================
# HEADER
# ============================================================================

my $mode_label =
    $all_mode       ? 'all (directory + tags + integrity)'
  : $from_integrity ? 'from-integrity'
  : $from_tags      ? 'from-tags'
  : $verify_mode    ? 'verify'
  :                   'directory-scan';

unless ($quiet) {
    print "# ============================================================\n";
    print "# TN SRI Hash Generator v$VERSION\n";
    print "# Generated : " . scalar(localtime) . "\n";
    print "# Base      : $base_dir\n";
    print "# Mode      : $mode_label\n";
    print "# ============================================================\n";
    print "# CSS is protected by CSP style-src 'self' -- no SRI needed\n";
    print "# ============================================================\n\n";
}

# ============================================================================
# COLLECT HTML SOURCES
# ============================================================================
# Returns all HTML files and view fragments to parse.
# Handles:
#   $base_dir/*.html  -- top-level pages (login, register, etc.)
#   $base_dir/docs/*.html -- documentation fragments
#   $base_dir/view/*  -- SPA view swaps (no .html extension by design)

sub collect_html_sources {
    my ($base) = @_;
    my @files;
    my %seen;

    # Recursive find across all likely HTML-containing directories
    my @search_dirs;
    for my $d ( $base, "$base/view", "$base/docs", "$base/splash_screens" ) {
        push @search_dirs, $d if -d $d;
    }

    File::Find::find(
        {
            wanted => sub {
                return unless -f $_;
                my $path = $File::Find::name;

                # Skip binary and asset files by extension
                return
                  if $path =~
/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|otf|eot|json|xml|map|gz|zip|db|pl|pm|sh|conf|key|crt|pem|log|txt|md)$/i;

                # Skip dot-files and editor artifacts
                return if basename($path) =~ /^\./;
                return if $path           =~ /\.(bak|orig|stale|swp|tmp)$/i;

                # Skip data/, lib/, keys/, config/, db/ -- no HTML there
                return
                  if $path =~
m{/data/(lib|keys|config|db|run|queue|session|sockets|pipes|spool|logs|archive|tmp)/};

                return if $seen{$path}++;
                push @files, $path;
            },
            no_chdir => 1,
        },
        @search_dirs
    );

    return sort @files;
}

# ============================================================================
# NORMALISE SCRIPT SRC PATH
# ============================================================================
# Converts any relative or absolute src value to /assets/js/filename.js form.
# Handles:
#   ./assets/js/foo.js
#   /assets/js/foo.js
#   assets/js/foo.js
#   ../assets/js/foo.js  (warn and skip)

sub normalise_src {
    my ($src) = @_;

    # Strip query strings and fragments
    $src =~ s{[?#].*$}{};

    # Collapse leading ./ or bare relative
    $src =~ s{^\./}{/};
    $src =~ s{^assets/}{/assets/};

    # Warn on parent traversal -- do not process
    if ( $src =~ /\.\./ ) {
        warn "WARNING: Skipping src with parent traversal: $src\n";
        return undef;
    }

    # Must resolve to /assets/js/*.js
    return undef unless $src =~ m{^/assets/js/[\w./-]+\.js$};

    return $src;
}

# ============================================================================
# EXTRACT SCRIPT SRCS FROM HTML
# ============================================================================
# Returns list of normalised /assets/js/*.js paths found in <script src=...>

sub extract_script_srcs {
    my ($file) = @_;
    my @srcs;

    open( my $fh, '<:raw', $file ) or do {
        warn "WARNING: Cannot read $file: $!\n";
        return ();
    };

    local $/;
    my $content = <$fh>;
    close $fh;

    # Match all <script ...> opening tags (handles multi-line, any attr order)
    while ( $content =~ m{<script\b([^>]*?)>}gis ) {
        my $attrs = $1;

        # src= with single or double quotes
        if ( $attrs =~ m{\bsrc\s*=\s*["']([^"']+)["']}i ) {
            my $norm = normalise_src($1);
            push @srcs, $norm if defined $norm;
        }
    }

    return @srcs;
}

# ============================================================================
# EXTRACT INTEGRITY HASHES FROM HTML
# ============================================================================
# Returns hashref { '/assets/js/foo.js' => 'sha384-...' }
# Extracts src + integrity pairs from <script> tags.
# Warns if the same src appears with conflicting hashes.

sub extract_integrity_hashes {
    my ($file) = @_;
    my %hashes;

    open( my $fh, '<:raw', $file ) or do {
        warn "WARNING: Cannot read $file: $!\n";
        return {};
    };

    local $/;
    my $content = <$fh>;
    close $fh;

    while ( $content =~ m{<script\b([^>]*?)>}gis ) {
        my $attrs = $1;

        my $src       = '';
        my $integrity = '';

        if ( $attrs =~ m{\bsrc\s*=\s*["']([^"']+)["']}i ) { $src = $1 }
        if ( $attrs =~ m{\bintegrity\s*=\s*["']([^"']+)["']}i ) {
            $integrity = $1;
        }

        next unless $src && $integrity;

        my $norm = normalise_src($src);
        next unless defined $norm;

        # Validate integrity format
        unless ( $integrity =~ m{^sha384-[A-Za-z0-9+/]+=*$} ) {
            warn
"WARNING: Malformed integrity value for $norm in $file: $integrity\n";
            next;
        }

        if ( exists $hashes{$norm} && $hashes{$norm} ne $integrity ) {
            warn "WARNING: Hash conflict for $norm\n"
              . "  existing : $hashes{$norm}\n"
              . "  in $file : $integrity\n"
              . "  Keeping existing value -- verify manually.\n";
        }
        else {
            $hashes{$norm} = $integrity;
        }
    }

    return \%hashes;
}

# ============================================================================
# GENERATE SHA-384 SRI HASH FROM FILE
# ============================================================================

sub generate_sri {
    my ($file_path) = @_;

    unless ( -f $file_path ) {
        warn "WARNING: File not found: $file_path\n";
        return undef;
    }
    unless ( -r $file_path ) {
        warn "WARNING: File not readable: $file_path\n";
        return undef;
    }

    open( my $fh, '<', $file_path ) or do {
        warn "WARNING: Cannot open $file_path: $!\n";
        return undef;
    };
    binmode($fh);
    local $/;
    my $content = <$fh>;
    close $fh;

    my $hex    = sha384_hex($content);
    my $binary = pack( 'H*', $hex );
    my $b64    = encode_base64( $binary, '' );    # no newline

    return "sha384-$b64";
}

# ============================================================================
# COLLECT FILES -- DIRECTORY SCAN
# ============================================================================

sub collect_from_directory {
    my ( $dir, $base ) = @_;
    my %found;    # rel_path => abs_path

    unless ( -d $dir ) {
        warn "WARNING: assets/js directory not found: $dir\n";
        return %found;
    }

    File::Find::find(
        {
            wanted => sub {
                return unless -f $_ && /\.js$/;
                my $abs = $File::Find::name;
                my $rel = $abs;
                $rel =~ s{^\Q$base\E}{};
                $found{$rel} = $abs;
            },
            no_chdir => 1,
        },
        $dir
    );

    return %found;
}

# ============================================================================
# VERIFY MODE
# ============================================================================
# Reads existing TNWAF.pm, extracts sri_hashes, recomputes from disk,
# reports matches, mismatches, and missing files.

sub run_verify {
    my ($base) = @_;

    my $waf_pm = "$base/data/lib/TNWAF.pm";
    unless ( -f $waf_pm ) {
        die "ERROR: TNWAF.pm not found at $waf_pm\n";
    }

    # Extract existing sri_hashes from TNWAF.pm
    open( my $fh, '<', $waf_pm ) or die "ERROR: Cannot read $waf_pm: $!\n";
    my %existing;
    while ( my $line = <$fh> ) {
        if ( $line =~
            m{^\s*'(/assets/js/[\w./-]+\.js)'\s*=>\s*'(sha384-[^']+)'} )
        {
            $existing{$1} = $2;
        }
    }
    close $fh;

    if ( !%existing ) {
        die "ERROR: No sri_hashes entries found in $waf_pm\n"
          . "       Check that the keys have no trailing spaces (see TN_GENERATE_SRI.pl docs)\n";
    }

    printf "# Verifying %d entries from TNWAF.pm against disk\n\n",
      scalar keys %existing;

    my ( $ok, $fail, $missing ) = ( 0, 0, 0 );

    for my $rel ( sort keys %existing ) {
        my $abs = $base . $rel;
        unless ( -f $abs ) {
            printf "  MISSING  %s\n", $rel;
            $missing++;
            next;
        }
        my $actual = generate_sri($abs);
        unless ( defined $actual ) {
            printf "  ERROR    %s (could not hash)\n", $rel;
            $fail++;
            next;
        }
        if ( $actual eq $existing{$rel} ) {
            printf "  OK       %s\n", $rel unless $quiet;
            $ok++;
        }
        else {
            printf "  TAMPERED %s\n",          $rel;
            printf "           stored : %s\n", $existing{$rel};
            printf "           actual : %s\n", $actual;
            $fail++;
        }
    }

    print "\n";
    printf "# Result: %d OK, %d TAMPERED/ERROR, %d MISSING\n", $ok, $fail,
      $missing;
    exit( ( $fail || $missing ) ? 1 : 0 );
}

# ============================================================================
# MAIN
# ============================================================================

run_verify($base_dir) if $verify_mode;

my %to_hash;      # rel_path => abs_path  (for modes 1 + 2)
my %harvested;    # rel_path => sri_hash  (for mode 3)
my @warnings;

# ---- MODE 1: Directory scan -----------------------------------------
if ( !$from_tags && !$from_integrity || $all_mode ) {
    my %found = collect_from_directory( $assets_js_dir, $base_dir );
    if ( !%found ) {
        push @warnings, "Directory scan: no .js files found in $assets_js_dir";
    }
    else {
        for my $rel ( keys %found ) {
            $to_hash{$rel} = $found{$rel};
        }
        printf "# Directory scan: %d file(s) found\n", scalar keys %found
          unless $quiet;
    }
}

# ---- MODE 2: Script tag parse ---------------------------------------
if ( $from_tags || $all_mode ) {
    my @sources = collect_html_sources($base_dir);
    if ( !@sources ) {
        push @warnings, "Tag parse: no HTML/view sources found under $base_dir";
    }

    my %tag_srcs;    # rel_path => source_file
    for my $html_file (@sources) {
        for my $src ( extract_script_srcs($html_file) ) {
            $tag_srcs{$src} ||= $html_file;
        }
    }

    if ( !%tag_srcs ) {
        push @warnings,
            "Tag parse: no /assets/js/*.js src values found in "
          . scalar(@sources)
          . " source file(s)";
    }
    else {
        printf
"# Tag parse: %d unique script src(s) found across %d source file(s)\n",
          scalar keys %tag_srcs, scalar @sources
          unless $quiet;
    }

    if ( $list_only && %tag_srcs ) {
        print "# Discovered script src paths:\n";
        for my $src ( sort keys %tag_srcs ) {
            my $rel_src = $tag_srcs{$src};
            $rel_src =~ s{^\Q$base_dir\E/?}{};
            printf "#   %-50s  (from %s)\n", $src, $rel_src;
        }
        print "#\n";
    }

    for my $src ( sort keys %tag_srcs ) {
        my $abs = $base_dir . $src;
        if ( -f $abs ) {
            $to_hash{$src} = $abs;
        }
        else {
            push @warnings, "Tag parse: referenced JS not on disk: $abs";
        }
    }
}

# ---- MODE 3: Integrity harvest --------------------------------------
if ( $from_integrity || $all_mode ) {
    my @sources = collect_html_sources($base_dir);
    if ( !@sources ) {
        push @warnings,
          "Integrity harvest: no HTML/view sources found under $base_dir";
    }

    my $total_found = 0;
    for my $html_file (@sources) {
        my $pairs = extract_integrity_hashes($html_file);
        for my $rel ( keys %$pairs ) {
            if ( exists $harvested{$rel} && $harvested{$rel} ne $pairs->{$rel} )
            {
                push @warnings,
"Integrity harvest: conflict for $rel in $html_file -- keeping first value";
            }
            else {
                $harvested{$rel} = $pairs->{$rel};
                $total_found++;
            }
        }
    }

    if ( !%harvested ) {
        push @warnings,
            "Integrity harvest: no integrity= attributes found in "
          . scalar(@sources)
          . " source file(s)";
    }
    else {
        printf "# Integrity harvest: %d unique hash(es) extracted\n",
          scalar keys %harvested
          unless $quiet;
    }
}

# Print any accumulated warnings before output
if (@warnings) {
    print "\n" unless $quiet;
    for my $w (@warnings) {
        print "# WARN: $w\n";
    }
    print "\n" unless $quiet;
}

exit 0 if $list_only;

# ---- Merge: mode 3 (harvested) wins over modes 1+2 on conflict -----
# In --all mode: disk hashes from modes 1+2 are computed and stored in
# %to_hash. Harvested integrity= values from mode 3 override because
# they are what the browser actually validates.

my %final;    # rel_path => sri_hash

# First pass: compute disk hashes for modes 1+2
for my $rel ( sort keys %to_hash ) {
    my $sri = generate_sri( $to_hash{$rel} );
    if ( defined $sri ) {
        $final{$rel} = $sri;
    }
    else {
        push @warnings, "Could not hash: $to_hash{$rel}";
    }
}

# Second pass: harvested values override (mode 3 is ground truth)
for my $rel ( sort keys %harvested ) {
    if ( exists $final{$rel} && $final{$rel} ne $harvested{$rel} ) {
        warn "# NOTE: $rel -- disk hash differs from integrity= in HTML\n"
          . "#       disk    : $final{$rel}\n"
          . "#       html    : $harvested{$rel}\n"
          . "#       Using HTML value (ground truth for browser validation)\n";
    }
    $final{$rel} = $harvested{$rel};
}

# ---- OUTPUT ---------------------------------------------------------
if ( !%final ) {
    print "# No hashes generated. Check warnings above.\n";
    exit 1;
}

print "\n" unless $quiet;
print "sri_hashes => {\n";
for my $rel ( sort keys %final ) {
    printf "    '%s' => '%s',\n", $rel, $final{$rel};
}
print "},\n\n";
printf "# %d hash(es) generated.\n", scalar keys %final;
print "# Paste the sri_hashes => { ... } block into TNWAF.pm\n";

# ============================================================================
# USAGE
# ============================================================================

sub usage {
    my ($exit_code) = @_;
    print <<'USAGE';
TN_GENERATE_SRI.pl v3.0.0 - Tangent Networks SRI Hash Generator

USAGE:
  perl TN_GENERATE_SRI.pl [OPTIONS]

DISCOVERY MODES (can be combined with --all):
  (default)         Walk assets/js/ and hash every .js file on disk
  --from-tags       Parse <script src="..."> from HTML files and view swaps
  --from-integrity  Extract existing integrity="sha384-..." from HTML/views
  --all             All three modes combined, deduplicated

OTHER OPTIONS:
  --verify          Compare TNWAF.pm sri_hashes against current disk hashes
  --list-only       Show discovered files without generating hashes
  --base DIR        Application root (default: /var/www/htdocs/tn)
  --quiet           Suppress comments, output hash block only
  --help, -h        This help

EXAMPLES:
  # Recommended after editing JS -- recompute all hashes from disk:
  perl TN_GENERATE_SRI.pl

  # Recommended after editing HTML integrity= attributes -- sync TNWAF.pm:
  perl TN_GENERATE_SRI.pl --from-integrity

  # Verify current TNWAF.pm hashes match files on disk:
  perl TN_GENERATE_SRI.pl --verify

  # See what script tags exist without generating hashes:
  perl TN_GENERATE_SRI.pl --from-tags --list-only

  # Full audit: all discovery modes, see any conflicts:
  perl TN_GENERATE_SRI.pl --all

  # Custom deployment path:
  perl TN_GENERATE_SRI.pl --base /srv/tn

OUTPUT:
  Paste-ready sri_hashes => { ... } block for TNWAF.pm %%CONFIG
  Use --quiet to get clean output suitable for scripted replacement.

NOTES:
  - No padding in hash keys -- avoids the lookup bug from padded string keys
  - --from-integrity wins over disk hashes on conflict in --all mode
  - --verify exits 0 on clean, 1 if any tampered or missing files found
  - Relative src paths (./assets/...) are normalised automatically

USAGE
    exit $exit_code;
}
