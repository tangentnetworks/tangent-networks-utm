#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_rule_parser.pl
#
# PURPOSE:
#   Parse pf-addons.conf into a dependency graph (DAG) and write
#   parsed-rules.json for consumption by pf_active_rules.pl (CGI)
#   and the WebUI deletion flow.
#
# CALLED BY:
#   pf_anchor_sync.sh -- after writing active-addons.json
#
# OUTPUT:
#   /var/www/htdocs/tn/data/services/queue/pf-rules/parsed-rules.json
#
# PRIVILEGE: runs as root
# TAINT:     enabled (-T)

use strict;
use warnings;
use JSON::PP;
use Digest::MD5 qw(md5_hex);
use POSIX       qw(strftime);

# ============================================================
# ENVIRONMENT
# ============================================================
$ENV{PATH} = '/sbin:/bin:/usr/sbin:/usr/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

# ============================================================
# CONFIGURATION
# ============================================================
my $ADDONS_CONF = '/etc/pf/pf-addons.conf';
my $OUTPUT_JSON =
  '/var/www/htdocs/tn/data/services/queue/pf-rules/parsed-rules.json';
my $LOG_FILE = '/var/www/tmp/pf_rule_parser.log';

# ============================================================
# LOGGING
# ============================================================
sub log_msg {
    my ( $level, $msg ) = @_;
    my $ts = strftime( '%Y-%m-%d %H:%M:%S', localtime );
    open my $fh, '>>', $LOG_FILE or return;
    print $fh "[$ts] [$level] $msg\n";
    close $fh;
}

# ============================================================
# UNTAINT HELPERS
# ============================================================
sub untaint_path {
    my ($path) = @_;
    if ( $path =~ m{^([-/\w.]+)$} ) { return $1; }
    return undef;
}

# ============================================================
# STEP 1 -- READ AND JOIN LINE CONTINUATIONS
#
# pf_validator.pl writes tables with \ continuations:
#   table <geoip_vn> persist { \
#       31.25.10.0/24, \
#       109.70.236.0/24 \
#   }
# Join these into single logical lines before parsing.
# ============================================================
sub read_logical_lines {
    my ($file) = @_;

    my $safe = untaint_path($file);
    unless ( $safe && -f $safe && -r $safe ) {
        log_msg( 'ERROR', "Cannot read conf: $file" );
        return [];
    }

    open my $fh, '<', $safe or do {
        log_msg( 'ERROR', "Open failed: $file: $!" );
        return [];
    };
    my @physical = <$fh>;
    close $fh;

    my @logical;
    my $buffer = '';
    my @buf_lines;
    my $phys_idx = 0;

    for my $raw (@physical) {
        $phys_idx++;
        chomp $raw;

        push @buf_lines, $phys_idx;

        if ( $raw =~ /\\\s*$/ ) {

            # Continuation -- strip the backslash, accumulate
            ( my $stripped = $raw ) =~ s/\\\s*$//;

            # Collapse leading whitespace on continuation lines
            # but preserve one space for readability
            $stripped =~ s/^\s+/ / if $buffer;
            $buffer .= $stripped;
        }
        else {
            $buffer .= $raw;
            push @logical,
              {
                raw   => $buffer,
                lines => [@buf_lines],
              };
            $buffer    = '';
            @buf_lines = ();
        }
    }

    # Flush any unterminated buffer
    if ( $buffer =~ /\S/ ) {
        push @logical, { raw => $buffer, lines => [@buf_lines] };
    }

    return \@logical;
}

# ============================================================
# STEP 2 -- DETECT PF CONTEXT TYPE
#
# Returns one of:
#   macro   -- name = value
#   table   -- table <name> ...
#   queue   -- queue name ...
#   altq    -- altq on ...
#   nat     -- nat-to / binat-to
#   rdr     -- rdr-to
#   filter  -- pass / block / match
#   comment -- section header or inline comment
#   other   -- anything else (set, antispoof, etc.)
# ============================================================
sub detect_type {
    my ($clean) = @_;

    return 'comment' if $clean =~ /^#/;
    return 'macro'   if $clean =~ /^[\w_]+\s*=/;
    return 'table'   if $clean =~ /^table\s+</;
    return 'queue'   if $clean =~ /^queue\s+[\w_]/;
    return 'altq'    if $clean =~ /^altq\s+/;
    return 'nat'     if $clean =~ /^(nat|binat)-to\s+/;
    return 'rdr'     if $clean =~ /^rdr(-to)?\s+/;
    return 'filter'  if $clean =~ /^(pass|block|match)\s+/;
    return 'other';
}

# ============================================================
# STEP 3 -- EXTRACT DEPENDENCIES WITH TOKEN CONTEXT
#
# Returns arrayref of:
#   { name => 'foo', token => '$foo',    type => 'macro' }
#   { name => 'bar', token => '<bar>',   type => 'table' }
#   { name => 'baz', token => 'baz',     type => 'queue' }
# ============================================================
sub extract_deps {
    my ($clean) = @_;
    my @deps;
    my %seen;    # deduplicate within same line

    # Macro references: $name
    while ( $clean =~ /\$([\w_]+)/g ) {
        my $name = $1;
        next if $seen{"macro:$name"}++;
        push @deps, { name => $name, token => "\$$name", type => 'macro' };
    }

    # Table references: <name>
    while ( $clean =~ /<([\w_]+)>/g ) {
        my $name = $1;
        next if $seen{"table:$name"}++;
        push @deps, { name => $name, token => "<$name>", type => 'table' };
    }

    # Queue usage: queue name or queue (name, priority)
    # Handles: queue ssh_q  and  queue (ssh_q, bulk_q)
    if ( $clean =~ /\bqueue\s+\(([^)]+)\)/ ) {
        for my $q ( split /\s*,\s*/, $1 ) {
            $q =~ s/^\s+|\s+$//g;
            next unless $q =~ /^[\w_]+$/;
            next if $seen{"queue:$q"}++;
            push @deps, { name => $q, token => $q, type => 'queue' };
        }
    }
    elsif ( $clean =~ /\bqueue\s+([\w_]+)/ ) {
        my $q = $1;

        # Skip the keyword 'queue' itself appearing in a definition line
        unless ( $seen{"queue:$q"}++ ) {
            push @deps, { name => $q, token => $q, type => 'queue' };
        }
    }

    return \@deps;
}

# ============================================================
# STEP 4 -- DETECT SECTION HEADER
#
# pf_validator.pl writes section headers as:
#   # ============================================================
#   # SECTION TITLE
#   # ============================================================
# We track the current section label from the title line.
# ============================================================
sub is_section_separator { return $_[0] =~ /^#\s*=+\s*$/; }

sub is_section_title {
    my ($clean) = @_;
    return $1 if $clean =~ /^#\s+([A-Z][A-Z0-9 _&()\/\-]+)\s*$/;
    return undef;
}

# ============================================================
# MAIN PARSER
# ============================================================
sub smart_parse {
    my $logical_lines = read_logical_lines($ADDONS_CONF);

    unless (@$logical_lines) {
        return {
            generated => time(),
            sections  => [],
            objects   => {},
            graph     => {},
        };
    }

    my %dag = (
        generated => time(),
        objects   => {},       # name -> uid of its definition node
        graph     => {},       # name -> [uid, uid, ...] of nodes that use it
        sections  => [],       # ordered array of section objects
    );

    my $current_section = {
        label => 'preamble',
        rules => [],
    };
    my $in_separator  = 0;
    my $pending_title = undef;

    foreach my $entry (@$logical_lines) {
        my $raw   = $entry->{raw};
        my $lines = $entry->{lines};

        # Strip comments and whitespace for analysis
        my $clean = $raw;
        $clean =~ s/#.*$//;
        $clean =~ s/^\s+|\s+$//g;

        # ── Section header detection ──
        if ( is_section_separator( $raw =~ s/^\s+//r ) ) {
            $in_separator++;
            if ( $in_separator == 1 ) {

                # First separator -- next title line names the section
            }
            elsif ( $in_separator >= 2 && defined $pending_title ) {

                # Second separator after title -- section starts
                # Save current section if it has content
                if ( @{ $current_section->{rules} } ) {
                    push @{ $dag{sections} }, $current_section;
                }
                $current_section = {
                    label => $pending_title,
                    rules => [],
                };
                $pending_title = undef;
                $in_separator  = 0;
            }
            next;
        }

        # Check for title between separators
        if ( $in_separator == 1 ) {
            my $title = is_section_title($raw);
            if ($title) {
                $pending_title = $title;
                next;
            }
            $in_separator = 0;    # Not a title -- reset
        }

        # Skip pure comment lines and blank lines
        next unless $clean =~ /\S/;

        my $uid  = md5_hex( $raw . join( ',', @$lines ) );
        my $type = detect_type($clean);
        my $deps = extract_deps($clean);

        my $node = {
            id      => $uid,
            raw     => $raw,
            lines   => $lines,
            type    => $type,
            section => $current_section->{label},
            deps    => $deps,
        };

        # ── Record definition (what this node provides) ──
        if ( $type eq 'macro' ) {
            if ( $clean =~ /^([\w_]+)\s*=/ ) {
                $node->{provides} = $1;
                $dag{objects}{$1} = $uid;
            }
        }
        elsif ( $type eq 'table' ) {
            if ( $clean =~ /^table\s+<([\w_]+)>/ ) {
                $node->{provides} = $1;
                $dag{objects}{$1} = $uid;

              # Remove self-referential dep -- the table name appears
              # in its own definition line e.g. table <geoip_vn> persist { ... }
                @{ $node->{deps} } =
                  grep { $_->{name} ne $1 } @{ $node->{deps} };
            }
        }
        elsif ( $type eq 'queue' ) {
            if ( $clean =~ /^queue\s+([\w_]+)/ ) {
                $node->{provides} = $1;
                $dag{objects}{$1} = $uid;

                # Remove self-referential dep
                @{ $node->{deps} } =
                  grep { $_->{name} ne $1 } @{ $node->{deps} };
            }
        }
        elsif ( $type eq 'altq' ) {

            # altq itself doesn't provide a named object but is
            # the root of the queue tree -- record it for reference
            if ( $clean =~ /^altq\s+on\s+(\S+)/ ) {
                $node->{provides} = "altq:$1";
                $dag{objects}{"altq:$1"} = $uid;
            }
        }

        # ── Build reverse graph (who uses me) ──
        foreach my $dep (@$deps) {

            # Skip self-reference -- definition nodes reference their own name
            next if $node->{provides} && $dep->{name} eq $node->{provides};
            $dag{graph}{ $dep->{name} } //= [];
            push @{ $dag{graph}{ $dep->{name} } }, $uid;
        }

        push @{ $current_section->{rules} }, $node;
    }

    # Save the last section
    if ( @{ $current_section->{rules} } ) {
        push @{ $dag{sections} }, $current_section;
    }

    return \%dag;
}

# ============================================================
# CASCADE RESOLVER
#
# Given a target name (macro/table/queue), returns all rule IDs
# that would become dangling if that object were deleted.
# Uses iterative BFS with %visited to prevent infinite loops
# on any circular references.
# ============================================================
sub resolve_cascade {
    my ( $dag, $target_name ) = @_;

    my %visited;
    my %reasons;
    my @queue = ($target_name);

    while (@queue) {
        my $name = shift @queue;
        next unless exists $dag->{graph}{$name};

        foreach my $child_id ( @{ $dag->{graph}{$name} } ) {
            next if $visited{$child_id}++;

            # Find the child node -- build lookup if needed
            my $child_rule = $dag->{_lookup}{$child_id};
            next unless $child_rule;

            $reasons{$child_id} = "Depends on '$name' via "
              . join( ', ',
                map { $_->{token} }
                grep { $_->{name} eq $name } @{ $child_rule->{deps} } );

            # If child is itself a definition, cascade further
            if ( $child_rule->{provides} ) {
                push @queue, $child_rule->{provides};
            }
        }
    }

    return \%reasons;
}

# ============================================================
# BUILD ID LOOKUP MAP
# Flattens all rules across all sections into a hash by ID.
# Attached to the DAG as _lookup (underscore = internal, not
# serialised to JSON).
# ============================================================
sub build_lookup {
    my ($dag) = @_;
    my %lookup;
    for my $section ( @{ $dag->{sections} } ) {
        for my $rule ( @{ $section->{rules} } ) {
            $lookup{ $rule->{id} } = $rule;
        }
    }
    $dag->{_lookup} = \%lookup;
}

# ============================================================
# BUILD PROPOSED NEW CONF
# Given a set of IDs to purge, returns the conf text with
# those rules omitted. Preserves section comments.
# ============================================================
sub build_new_conf {
    my ( $dag, $purge_ids_ref ) = @_;
    my %purge = map { $_ => 1 } @$purge_ids_ref;
    my @output_lines;

    for my $section ( @{ $dag->{sections} } ) {
        my @kept = grep { !$purge{ $_->{id} } } @{ $section->{rules} };
        next unless @kept;

        # Re-emit section header
        push @output_lines,
          '# ' . ( '=' x 60 ),
          '# ' . $section->{label},
          '# ' . ( '=' x 60 );

        for my $rule (@kept) {
            push @output_lines, $rule->{raw};
        }
        push @output_lines, '';
    }

    push @output_lines, '# --- End of pf-addons.conf ---';
    return join( "\n", @output_lines ) . "\n";
}

# ============================================================
# WRITE OUTPUT -- atomic temp + rename
# ============================================================
sub write_output {
    my ($dag) = @_;

    my $safe_out = untaint_path($OUTPUT_JSON);
    unless ($safe_out) {
        log_msg( 'ERROR', "Invalid output path: $OUTPUT_JSON" );
        return 0;
    }

    my $tmp      = "${safe_out}.tmp";
    my $safe_tmp = untaint_path($tmp);
    unless ($safe_tmp) {
        log_msg( 'ERROR', "Invalid tmp path: $tmp" );
        return 0;
    }

    # Remove internal lookup before serialising
    my $serialise = {%$dag};
    delete $serialise->{_lookup};

    open my $fh, '>', $safe_tmp or do {
        log_msg( 'ERROR', "Cannot write tmp: $safe_tmp: $!" );
        return 0;
    };

    print $fh encode_json($serialise);
    close $fh;

    rename( $safe_tmp, $safe_out ) or do {
        log_msg( 'ERROR', "Cannot rename to output: $!" );
        unlink $safe_tmp;
        return 0;
    };

    chown( scalar getpwnam('www'), scalar getgrnam('www'), $safe_out );
    chmod( 0644, $safe_out );

    return 1;
}

# ============================================================
# MAIN
# ============================================================
log_msg( 'INFO', '=== pf_rule_parser.pl started ===' );

unless ( -f $ADDONS_CONF && -s $ADDONS_CONF ) {
    log_msg( 'INFO',
        'pf-addons.conf absent or empty -- writing empty parsed-rules.json' );
    my $empty = {
        generated => time(),
        sections  => [],
        objects   => {},
        graph     => {},
    };
    write_output($empty);
    exit 0;
}

my $dag = smart_parse();
build_lookup($dag);

my $section_count = scalar @{ $dag->{sections} };
my $rule_count    = 0;
$rule_count += scalar @{ $_->{rules} } for @{ $dag->{sections} };
my $object_count = scalar keys %{ $dag->{objects} };

log_msg( 'INFO',
    "Parsed: $section_count sections, $rule_count rules, $object_count objects"
);

unless ( write_output($dag) ) {
    log_msg( 'ERROR', 'Failed to write parsed-rules.json' );
    exit 1;
}

log_msg( 'INFO', '=== pf_rule_parser.pl complete ===' );
exit 0;
