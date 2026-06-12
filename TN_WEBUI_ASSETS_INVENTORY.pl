#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ============================================================
# tn_inventory.pl - Tangent UTM Professional Asset Discovery
# ============================================================

use strict;
use warnings;
use File::Find;
use File::Basename;
use Cwd 'abs_path';
use POSIX qw(strftime);

$ENV{PATH} = '/bin:/usr/bin:/usr/local/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

my $UNTAINT_PATH_RE = qr{^([/a-zA-Z0-9_.=+:@, -]+)$};

# -- Configuration -------------------------------------------------------------
my $APP_ROOT   = $ARGV[0] // '/var/www/htdocs/tn';
my $HTTPD_CONF = $ARGV[1] // '/etc/httpd.conf';
my $DEBUG      = ( $ARGV[2] && $ARGV[2] eq '--debug' ) ? 1 : 0;

$APP_ROOT = abs_path($APP_ROOT) if -d $APP_ROOT;
if ( $APP_ROOT =~ $UNTAINT_PATH_RE ) { $APP_ROOT = $1 }
else { die "ERROR: Unsafe APP_ROOT path: $APP_ROOT\n" }

if ( $HTTPD_CONF =~ $UNTAINT_PATH_RE ) { $HTTPD_CONF = $1 }
else { die "ERROR: Unsafe HTTPD_CONF path: $HTTPD_CONF\n" }

# -- Data stores ---------------------------------------------------------------
my %html_files;          # rel_path => 1
my %all_js_on_disk;      # rel_path => 1
my %js_file_sizes;       # rel_path => bytes
my %loaded_js;           # rel_path => 1  (referenced via <script src>)
my %devel_js_loaders;    # html_rel => 1  (pages that load devel.js)
my $devel_js_on_disk = 0;

my %all_css_on_disk;     # rel_path => 1
my %css_file_sizes;      # rel_path => bytes
my %loaded_css;          # rel_path => 1  (referenced via <link rel=stylesheet>)

my %cgi_files;           # basename => full_path
my %active_cgi;          # basename => { sources=>[], via_js=>0, via_html=>0,
                         #               via_docs=>0, via_httpd=>0 }
my %blocked_paths;       # path_pattern => 1
my %httpd_rewrites;      # basename => 1  (CGI seen in httpd.conf)

# -- Helpers -------------------------------------------------------------------
sub is_backup {
    return $_[0] =~ /\.orig$|\.bak$|-bak$|\.backup$|~$/i;
}

sub register_cgi {
    my ( $script, $source, $type ) = @_;
    $active_cgi{$script} //= {
        sources   => [],
        via_js    => 0,
        via_html  => 0,
        via_docs  => 0,
        via_httpd => 0
    };
    push @{ $active_cgi{$script}{sources} }, $source
      unless grep { $_ eq $source } @{ $active_cgi{$script}{sources} };
    $active_cgi{$script}{"via_$type"} = 1;
}

sub fmt_size {
    my ($sz) = @_;
    return
        $sz > 1_048_576 ? sprintf( "%.2f MB", $sz / 1_048_576 )
      : $sz > 1_024     ? sprintf( "%.2f KB", $sz / 1_024 )
      :                   "$sz B";
}

# -- Step 1: collect disk inventory -------------------------------------------
find( { wanted => \&collect_files, no_chdir => 1 }, $APP_ROOT );

sub collect_files {
    my $f = $File::Find::name;
    return if $f =~ m{/\.};
    return if is_backup($f);
    return unless -f $f;

    my $rel = $f;
    $rel =~ s{^\Q$APP_ROOT\E/?}{};

    if ( $f =~ /\.js$/i ) {
        $all_js_on_disk{$rel} = 1;
        $js_file_sizes{$rel}  = ( stat($f) )[7] // 0;
        if ( basename($f) eq 'devel.js' ) {
            $devel_js_on_disk = 1;
            print "DEBUG: devel.js found on disk at $rel\n" if $DEBUG;
        }
    }
    elsif ( $f =~ /\.css$/i ) {
        $all_css_on_disk{$rel} = 1;
        $css_file_sizes{$rel}  = ( stat($f) )[7] // 0;
    }
    elsif ( $f =~ m{/cgi-bin/.*\.pl$}i ) {
        $cgi_files{ basename($f) } = $f;
    }
    elsif ($f =~ m{\Q$APP_ROOT\E/[^/]+\.html?$}i
        || $f =~ m{\Q$APP_ROOT\E/view/[^/]+$}
        || $f =~ m{\Q$APP_ROOT\E/docs/[^/]+\.html?$}i )
    {
        $html_files{$rel} = 1;
    }
}

# -- Step 2: parse HTML/view for <script src> and <link> to build asset lists --
for my $rel ( sort keys %html_files ) {
    next if $rel =~ m{^docs/};    # docs do not load app JS or CSS
    my $full = "$APP_ROOT/$rel";
    open my $fh, '<', $full or do { warn "Cannot open $full: $!\n"; next };
    while ( my $line = <$fh> ) {

        # JavaScript
        while ( $line =~ m{src=["'][./]*(assets/js/[\w.-]+\.js)["']}gi ) {
            my $js_rel = $1;
            $loaded_js{$js_rel} = 1;
            if ( basename($js_rel) eq 'devel.js' ) {
                $devel_js_loaders{$rel} = 1;
                print "DEBUG: $rel loads devel.js\n" if $DEBUG;
            }
            print "DEBUG: $rel loads JS $js_rel\n" if $DEBUG;
        }

        # CSS
        while ( $line =~ m{href=["'][./]*(assets/css/[\w.-]+\.css)["']}gi ) {
            my $css_rel = $1;
            $loaded_css{$css_rel} = 1;
            print "DEBUG: $rel loads CSS $css_rel\n" if $DEBUG;
        }
    }
    close $fh;
}

# -- Step 3: parse httpd.conf for CGI rewrites and blocked paths ---------------
if ( -f $HTTPD_CONF ) {
    open my $fh, '<', $HTTPD_CONF or warn "Cannot open $HTTPD_CONF: $!\n";
    if ($fh) {
        while ( my $line = <$fh> ) {
            if ( $line =~
                m{request\s+rewrite\s+["']/cgi-bin/([\w.-]+\.pl)["']}i )
            {
                my $script = $1;
                $httpd_rewrites{$script} = 1;
                register_cgi( $script, $HTTPD_CONF, 'httpd' );
                print "DEBUG: httpd.conf rewrites to $script\n" if $DEBUG;
            }
            if ( $line =~ m{location\s+["']([^"']+)["'][^{]*\{[^}]*block}i ) {
                $blocked_paths{$1} = 1;
            }
        }
        close $fh;
    }
}
else {
    warn "WARNING: httpd.conf not found at $HTTPD_CONF\n";
}

# -- Step 4: scan loaded JS files for CGI refs --------------------------------
sub scan_for_cgi {
    my ( $full_path, $source_label, $type ) = @_;
    open my $fh, '<', $full_path
      or do { warn "Cannot open $full_path: $!\n"; return };
    while ( my $line = <$fh> ) {

        # Pattern 1 & 2: /cgi-bin/name.pl  or  cgi-bin/name.pl
        while ( $line =~ m{(?:/)?cgi-bin/([\w.-]+\.pl)}gi ) {
            register_cgi( $1, $source_label, $type );
            print "DEBUG [cgi-bin] $1 in $source_label\n"
              if $DEBUG && $1 eq 'logs.pl';
        }

        # Pattern 3: bare quoted .pl names - skipped for docs (prose examples)
        if ( $type ne 'docs' ) {
            while ( $line =~ m{['"]([\w.-]+\.pl)['"]}g ) {
                my $s = $1;
                if (
                    $s =~
                    /^(?:logs?|get|fetch|status|control|mail|firewall|router
                               |pf_|e2g_|integrity_|unbound_|power_|manage_
                               |search_|services)/x
                  )
                {
                    register_cgi( $s, $source_label, $type );
                }
            }
        }

        # Pattern 4: template literals
        while ( $line =~ m{`[^`]*(?:/)?cgi-bin/([\w.-]+\.pl)[^`]*`}g ) {
            register_cgi( $1, $source_label, $type );
        }
    }
    close $fh;
}

for my $rel ( sort keys %loaded_js ) {
    my $full = "$APP_ROOT/$rel";
    next unless -f $full;
    scan_for_cgi( $full, $rel, 'js' );
}

# -- Step 5: scan view/*, tn/*.html, and docs/*.html for inline CGI refs ------
for my $rel ( sort keys %html_files ) {
    my $full = "$APP_ROOT/$rel";
    next unless -f $full;
    my $type = $rel =~ m{^docs/} ? 'docs' : 'html';
    scan_for_cgi( $full, $rel, $type );
}

# -- Step 6: classify CGI status ----------------------------------------------
sub cgi_status {
    my ($script) = @_;
    my $info     = $active_cgi{$script};
    my $on_disk  = exists $cgi_files{$script} ? 1 : 0;
    my $via_real = $info->{via_js} || $info->{via_html} || $info->{via_httpd};
    my $via_docs = $info->{via_docs};

    if ( $script eq 'router.pl' && !$on_disk ) { return '[MISSING - CRITICAL]' }
    if ( $via_real              && $on_disk )  { return '[ACTIVE]' }
    if ( $via_real && !$on_disk )  { return '[ACTIVE - NOT ON DISK]' }
    if ( $via_docs && !$via_real ) { return '[UNVERIFIED]' }
    return '[UNKNOWN]';
}

# -- Statistics ----------------------------------------------------------------
my @loaded_js_list    = sort keys %loaded_js;
my @unloaded_js_list  = sort grep { !$loaded_js{$_} } keys %all_js_on_disk;
my @loaded_css_list   = sort keys %loaded_css;
my @unloaded_css_list = sort grep { !$loaded_css{$_} } keys %all_css_on_disk;
my @active_cgi_list   = sort keys %active_cgi;
my @orphaned_cgi_list = sort grep { !$active_cgi{$_} } keys %cgi_files;
my @blocked_list      = sort keys %blocked_paths;

my $js_disk_count      = scalar keys %all_js_on_disk;
my $js_loaded_count    = scalar keys %loaded_js;
my $js_unloaded_count  = scalar @unloaded_js_list;
my $css_disk_count     = scalar keys %all_css_on_disk;
my $css_loaded_count   = scalar keys %loaded_css;
my $css_unloaded_count = scalar @unloaded_css_list;
my $html_count         = scalar keys %html_files;
my $cgi_total          = scalar keys %cgi_files;
my $cgi_active_count   = scalar @active_cgi_list;
my $cgi_orphaned       = scalar @orphaned_cgi_list;
my $blocked_count      = scalar @blocked_list;

# -- Report --------------------------------------------------------------------
my $TIMESTAMP   = strftime( '%Y%m%d_%H%M%S', localtime );
my $REPORT_FILE = "tn_inventory_${TIMESTAMP}.txt";
open my $rep_fh, '>', $REPORT_FILE or die "Cannot write report: $!\n";

sub out {
    my ( $fh, $line ) = @_;
    print $line;
    print $fh $line;
}

my $HR  = "-" x 80 . "\n";
my $HDR = "+" x 80 . "\n";

out( $rep_fh, "\n" );
out( $rep_fh, $HDR );
out( $rep_fh, "  TANGENT UTM - PROFESSIONAL ASSET INVENTORY REPORT\n" );
out(
    $rep_fh,
    sprintf(
        "  Generated  : %s\n", strftime( '%Y-%m-%d %H:%M:%S', localtime )
    )
);
out( $rep_fh, sprintf( "  App Root   : %s\n", $APP_ROOT ) );
out( $rep_fh, sprintf( "  httpd.conf : %s\n", $HTTPD_CONF ) );
out( $rep_fh, $HDR . "\n" );

# -- Executive Summary ---------------------------------------------------------
out( $rep_fh, "EXECUTIVE SUMMARY\n" );
out( $rep_fh, $HR );
out( $rep_fh,
    sprintf( "  %-38s : %3d\n", "HTML / View / Docs pages", $html_count ) );
out( $rep_fh,
    sprintf( "  %-38s : %3d\n", "JS files on disk", $js_disk_count ) );
out( $rep_fh,
    sprintf( "  %-38s : %3d\n", "JS files actually loaded", $js_loaded_count )
);
out(
    $rep_fh,
    sprintf( "  %-38s : %3d\n",
        "JS files not loaded (unused)",
        $js_unloaded_count )
);
out( $rep_fh,
    sprintf( "  %-38s : %3d\n", "CSS files on disk", $css_disk_count ) );
out(
    $rep_fh,
    sprintf(
        "  %-38s : %3d\n", "CSS files actually loaded", $css_loaded_count
    )
);
out(
    $rep_fh,
    sprintf( "  %-38s : %3d\n",
        "CSS files not loaded (unused)",
        $css_unloaded_count )
);
out( $rep_fh,
    sprintf( "  %-38s : %3d\n", "CGI endpoints on disk", $cgi_total ) );
out( $rep_fh,
    sprintf( "  %-38s : %3d\n", "CGI endpoints referenced", $cgi_active_count )
);
out( $rep_fh,
    sprintf( "  %-38s : %3d\n", "CGI endpoints orphaned", $cgi_orphaned ) );
out( $rep_fh,
    sprintf( "  %-38s : %3d\n", "httpd.conf protected paths", $blocked_count )
);
out(
    $rep_fh,
    sprintf( "  %-38s : %s\n",
        "router.pl",
        exists $cgi_files{'router.pl'}
        ? "ON DISK"
        : "*** MISSING FROM DISK ***" )
);
out(
    $rep_fh,
    sprintf(
        "  %-38s : %s\n",
        "devel.js",
        $devel_js_on_disk
        ? (
            keys %devel_js_loaders
            ? "ON DISK + LOADED by: "
              . join( ', ', sort keys %devel_js_loaders )
            : "ON DISK (not loaded by any page)"
          )
        : "not present"
    )
);
out( $rep_fh, "\n" );

# -- Dev Mode Notice -----------------------------------------------------------
if ($devel_js_on_disk) {
    out( $rep_fh, "DEV MODE NOTICE\n" );
    out( $rep_fh, $HR );
    out( $rep_fh,
        "  devel.js is present on disk. Intentional during UI development;\n" );
    out( $rep_fh, "  review before production deployment.\n" );
    if ( keys %devel_js_loaders ) {
        out( $rep_fh, "  Currently loaded by:\n" );
        out( $rep_fh, "    $_\n" ) for sort keys %devel_js_loaders;
    }
    else {
        out( $rep_fh, "  Not loaded by any HTML or view page.\n" );
    }
    out( $rep_fh, "\n" );
}

# -- router.pl critical warning ------------------------------------------------
unless ( exists $cgi_files{'router.pl'} ) {
    out( $rep_fh, "CRITICAL WARNING\n" );
    out( $rep_fh, $HR );
    out( $rep_fh, "  router.pl is NOT present in cgi-bin.\n" );
    out( $rep_fh,
"  This script is the TNWAF traffic funnel - all requests route through it.\n"
    );
    out( $rep_fh,
        "  The application will not function correctly without it.\n\n" );
}

# -- HTML / View / Docs pages --------------------------------------------------
out( $rep_fh, "HTML / VIEW / DOCS PAGES SCANNED\n" );
out( $rep_fh, $HR );
out( $rep_fh, "  $_\n" ) for sort keys %html_files;
out( $rep_fh, sprintf( "\n  Total: %d pages\n\n", $html_count ) );

# -- JS files actually loaded --------------------------------------------------
out( $rep_fh, "JAVASCRIPT FILES ACTUALLY LOADED (via <script src>)\n" );
out( $rep_fh, $HR );
out( $rep_fh, sprintf( "  %-10s %-50s %10s\n", "Flag", "File", "Size" ) );
out( $rep_fh, "  " . "-" x 72 . "\n" );
for my $rel (@loaded_js_list) {
    my $flag = basename($rel) eq 'devel.js' ? '[DEV MODE]' : '         ';
    out(
        $rep_fh,
        sprintf(
            "  %-10s %-50s %10s\n",
            $flag, $rel, fmt_size( $js_file_sizes{$rel} // 0 )
        )
    );
}
out( $rep_fh,
    sprintf( "\n  Total: %d loaded JS files\n\n", $js_loaded_count ) );

# -- JS files on disk but never loaded ----------------------------------------
if ( $js_unloaded_count > 0 ) {
    out( $rep_fh, "JAVASCRIPT FILES ON DISK BUT NEVER LOADED\n" );
    out( $rep_fh, $HR );
    out( $rep_fh, sprintf( "  %-10s %-50s %10s\n", "Flag", "File", "Size" ) );
    out( $rep_fh, "  " . "-" x 72 . "\n" );
    for my $rel (@unloaded_js_list) {
        my $flag = basename($rel) eq 'devel.js' ? '[DEV MODE]' : '         ';
        out(
            $rep_fh,
            sprintf(
                "  %-10s %-50s %10s\n",
                $flag, $rel, fmt_size( $js_file_sizes{$rel} // 0 )
            )
        );
    }
    out( $rep_fh,
        sprintf( "\n  Total: %d unloaded JS files\n\n", $js_unloaded_count ) );
}

# -- CSS files actually loaded -------------------------------------------------
out( $rep_fh, "CSS FILES ACTUALLY LOADED (via <link rel=stylesheet>)\n" );
out( $rep_fh, $HR );
out( $rep_fh, sprintf( "  %-55s %10s\n", "File", "Size" ) );
out( $rep_fh, "  " . "-" x 67 . "\n" );
for my $rel (@loaded_css_list) {
    out(
        $rep_fh,
        sprintf( "  %-55s %10s\n",
            $rel, fmt_size( $css_file_sizes{$rel} // 0 ) )
    );
}
out( $rep_fh,
    sprintf( "\n  Total: %d loaded CSS files\n\n", $css_loaded_count ) );

# -- CSS files on disk but never loaded ---------------------------------------
if ( $css_unloaded_count > 0 ) {
    out( $rep_fh, "CSS FILES ON DISK BUT NEVER LOADED\n" );
    out( $rep_fh, $HR );
    out( $rep_fh, sprintf( "  %-55s %10s\n", "File", "Size" ) );
    out( $rep_fh, "  " . "-" x 67 . "\n" );
    for my $rel (@unloaded_css_list) {
        out(
            $rep_fh,
            sprintf( "  %-55s %10s\n",
                $rel, fmt_size( $css_file_sizes{$rel} // 0 ) )
        );
    }
    out( $rep_fh,
        sprintf( "\n  Total: %d unloaded CSS files\n\n", $css_unloaded_count )
    );
}

# -- httpd.conf CGI rewrites ---------------------------------------------------
out( $rep_fh, "HTTPD.CONF CGI REWRITES\n" );
out( $rep_fh, $HR );
for my $script ( sort keys %httpd_rewrites ) {
    my $disk = exists $cgi_files{$script} ? 'on disk' : '*** NOT ON DISK ***';
    out( $rep_fh, sprintf( "  %-40s %s\n", $script, $disk ) );
}
out(
    $rep_fh,
    sprintf( "\n  Total: %d CGI rewrites in httpd.conf\n\n",
        scalar keys %httpd_rewrites )
);

# -- Protected paths -----------------------------------------------------------
if ( $blocked_count > 0 ) {
    out( $rep_fh, "HTTPD.CONF PROTECTED PATHS (block return 403)\n" );
    out( $rep_fh, $HR );
    out( $rep_fh, "  $_\n" ) for @blocked_list;
    out( $rep_fh,
        sprintf( "\n  Total: %d protected paths\n\n", $blocked_count ) );
}

# -- CGI endpoints referenced --------------------------------------------------
out( $rep_fh, "CGI ENDPOINTS REFERENCED\n" );
out( $rep_fh, $HR );
out(
    $rep_fh,
    sprintf(
        "  %-35s %-22s %-5s %-5s %-5s %-5s %s\n",
        "Script", "Status", "JS", "HTML", "DOCS", "HTTPD", "First Seen In"
    )
);
out( $rep_fh, "  " . "-" x 78 . "\n" );
for my $cgi (@active_cgi_list) {
    my $info   = $active_cgi{$cgi};
    my $status = cgi_status($cgi);
    my $first  = @{ $info->{sources} } ? $info->{sources}[0] : 'unknown';
    out(
        $rep_fh,
        sprintf(
            "  %-35s %-22s %-5s %-5s %-5s %-5s %s\n",
            $cgi,
            $status,
            $info->{via_js}    ? 'Y' : '-',
            $info->{via_html}  ? 'Y' : '-',
            $info->{via_docs}  ? 'Y' : '-',
            $info->{via_httpd} ? 'Y' : '-',
            $first
        )
    );
}
out( $rep_fh,
    sprintf( "\n  Total Referenced: %d CGI scripts\n\n", $cgi_active_count ) );

# -- Orphaned CGI --------------------------------------------------------------
if ( $cgi_orphaned > 0 ) {
    out( $rep_fh, "ORPHANED CGI ENDPOINTS (on disk, never referenced)\n" );
    out( $rep_fh, $HR );
    out( $rep_fh, "  $_\n" ) for @orphaned_cgi_list;
    out( $rep_fh,
        sprintf( "\n  Total Orphaned: %d CGI scripts\n\n", $cgi_orphaned ) );
}

# -- Debug ---------------------------------------------------------------------
if ($DEBUG) {
    out( $rep_fh, "DEBUG: logs.pl check\n" );
    out( $rep_fh, $HR );
    if ( $active_cgi{'logs.pl'} ) {
        my $info = $active_cgi{'logs.pl'};
        out( $rep_fh, "  logs.pl ACTIVE\n" );
        out( $rep_fh,
            "  Sources: " . join( ', ', @{ $info->{sources} } ) . "\n" );
    }
    else {
        out( $rep_fh,
            "  logs.pl NOT ACTIVE - raw scan of all loaded files:\n" );
        for my $rel ( sort( keys %loaded_js, keys %html_files ) ) {
            my $full = "$APP_ROOT/$rel";
            next unless -f $full;
            open my $fh, '<', $full or next;
            while ( my $line = <$fh> ) {
                out( $rep_fh, "    In $rel: $line" ) if $line =~ /logs\.pl/;
            }
            close $fh;
        }
    }
    out( $rep_fh, "\n" );
}

# -- Footer --------------------------------------------------------------------
out( $rep_fh, $HDR );
out( $rep_fh, "  END OF REPORT\n" );
out( $rep_fh, sprintf( "  Report saved to: %s\n", $REPORT_FILE ) );
out( $rep_fh, $HDR . "\n" );
close $rep_fh;

# -- Terminal summary ----------------------------------------------------------
print "\n$HDR";
print "  TANGENT UTM - ASSET INVENTORY COMPLETE\n";
print $HDR;
printf "  Report file    : %s\n",               $REPORT_FILE;
printf "  HTML/view/docs : %d pages scanned\n", $html_count;
printf "  JS on disk     : %d  (loaded: %d  unused: %d)\n",
  $js_disk_count, $js_loaded_count, $js_unloaded_count;
printf "  CSS on disk    : %d  (loaded: %d  unused: %d)\n",
  $css_disk_count, $css_loaded_count, $css_unloaded_count;
printf "  CGI referenced : %d\n", $cgi_active_count;
printf "  CGI orphaned   : %d\n", $cgi_orphaned;
printf "  router.pl      : %s\n",
  exists $cgi_files{'router.pl'} ? "OK - on disk" : "*** MISSING ***";
printf "  devel.js       : %s\n",
  $devel_js_on_disk
  ? ( keys %devel_js_loaders ? "on disk + LOADED" : "on disk (not loaded)" )
  : "not present";
print $HDR . "\n";

exit 0;
