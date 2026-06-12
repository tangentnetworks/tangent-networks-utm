package TNWatchMail;

# TNWatch - Email Delivery Module
# /etc/TNWatch/TNWatchMail.pm
#
# Sends HTML + plain text multipart emails via local sendmail.
# Two templates:
#   send_digest(\%stats)                  daily digest
#   send_alert($rule_name, \%detail)      immediate alert

use strict;
use warnings;
use POSIX qw(strftime);
use JSON::PP;

#
# CONSTANTS
#

# Taint mode: explicit safe PATH required for qx{} / system() calls
BEGIN {
    $ENV{PATH} = '/usr/bin:/usr/sbin:/bin:/sbin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
}

my $FROM     = 'TNWatch <root@localhost>';
my $TO       = 'root';
my $SENDMAIL = '/usr/sbin/sendmail';

# Severity colours (inline CSS     email client safe)
my %SEV_COLOR = (
    critical => '#ef4444',    # red-500
    warning  => '#f59e0b',    # amber-500
    info     => '#3b82f6',    # blue-500
    ok       => '#22c55e',    # green-500
);

my %SEV_BG = (
    critical => '#fef2f2',
    warning  => '#fffbeb',
    info     => '#eff6ff',
    ok       => '#f0fdf4',
);

#
# PUBLIC API
#

sub send_digest {
    my ($stats) = @_;
    my $date    = $stats->{date} // strftime( "%Y-%m-%d", localtime );
    my $subject = "TNWatch Daily Digest - $date";
    $subject .= " [!] CHANGES DETECTED" if _digest_has_issues($stats);

    my $html = _render_digest_html($stats);
    my $text = _render_digest_text($stats);

    return _send( $subject, $html, $text );
}

sub send_alert {
    my ( $rule_name, $detail ) = @_;
    my $rule  = $detail->{rule}   // {};
    my $sev   = $rule->{severity} // 'warning';
    my $emoji = $sev eq 'critical' ? '[!]' : '[!]';

    # Human-friendly rule name
    my $display = _rule_display_name($rule_name);
    my $subject = "$emoji TNWatch Alert: $display";

    my $html = _render_alert_html( $rule_name, $detail );
    my $text = _render_alert_text( $rule_name, $detail );

    return _send( $subject, $html, $text );
}

#
# EMAIL DELIVERY
#

# Strip any non-ASCII bytes from a string.
# OpenBSD mail stack without X11/locale support passes raw bytes through
# unchanged, and viewers decode as Latin-1, mangling UTF-8 sequences.
# All TNWatch output must be 7-bit ASCII clean.
sub _ascii {
    my ($s) = @_;

    # Keep only printable ASCII (32-126) plus tab (9) and newline (10).
    # Written as literal characters in the tr range to avoid any escape
    # interpretation issues across different Perl/editor combinations.
    $s =~ s/[^\t\n\x20-\x7e]//g;
    return $s;
}

sub _send {
    my ( $subject, $html, $text ) = @_;
    my $date_str = strftime( "%a, %d %b %Y %H:%M:%S %z", localtime );

    # Scrub subject and body through ASCII filter before sending.
    # This is the last line of defence -- all literals in this file
    # should already be ASCII-only, but _ascii() catches anything
    # that slips through (e.g. data from log files or DB fields).
    $subject = _ascii($subject);
    $text    = _ascii($text);

    open( my $mail, '|-', $SENDMAIL, '-t', '-f', 'root' )
      or do { warn "Cannot open sendmail: $!\n"; return 0 };

    print $mail "To: $TO\n";
    print $mail "From: $FROM\n";
    print $mail "Subject: $subject\n";
    print $mail "Date: $date_str\n";
    print $mail "Content-Type: text/plain; charset=US-ASCII\n";
    print $mail "X-Mailer: TNWatch/1.0\n";
    print $mail "\n";
    print $mail $text;

    close($mail);
    return ( $? == 0 ) ? 1 : 0;
}

#
# SHARED HTML SKELETON
#
# All inline CSS     no external resources, works in
# any mail client including the Tangent Networks viewer.
# Dark/light mode via \@media prefers-color-scheme.

sub _html_head {
    my ($title) = @_;
    return <<HTML;
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$title</title>
<style>
/* Reset */
*{box-sizing:border-box}
body,table,td,th{margin:0;padding:0;border-collapse:collapse}

/* Mobile-first base */
body{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,
    'Helvetica Neue',Arial,sans-serif;
  font-size:14px;
  line-height:1.55;
  background:#f3f4f6;
  color:#111827;
  -webkit-text-size-adjust:100%;
}
/* Full-width on mobile, max 700px on desktop */
.wrapper{
  width:100%;
  max-width:700px;
  margin:0 auto;
  background:#ffffff;
}
/* Give breathing room on larger screens */
\@media screen and (min-width:600px){
  body{padding:16px 8px}
  .wrapper{border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12)}
}

/* Header */
.header{
  padding:16px 16px 14px;
  border-bottom:3px solid #e5e7eb;
}
\@media screen and (min-width:480px){
  .header{padding:20px 24px 16px}
}
.header-title{
  font-size:17px;
  font-weight:700;
  color:#111827;
  margin:0 0 2px;
  line-height:1.3;
}
.header-sub{
  font-size:12px;
  color:#6b7280;
  margin:0;
}

/* Body */
.body{padding:0 12px 20px}
\@media screen and (min-width:480px){
  .body{padding:0 20px 24px}
}

/* Sections */
.section{
  margin-top:16px;
  border:1px solid #e5e7eb;
  border-radius:6px;
  overflow:hidden;
}
.section-head{
  padding:8px 12px;
  background:#f9fafb;
  border-bottom:1px solid #e5e7eb;
  font-size:11px;
  font-weight:700;
  letter-spacing:.07em;
  text-transform:uppercase;
  color:#374151;
}
.section-body{padding:10px 12px}
\@media screen and (min-width:480px){
  .section-body{padding:12px 14px}
}

/* Key-value rows */
.kv-row{
  display:flex;
  justify-content:space-between;
  align-items:baseline;
  gap:8px;
  padding:5px 0;
  border-bottom:1px solid #f3f4f6;
  font-size:13px;
  flex-wrap:nowrap;
}
.kv-row:last-child{border-bottom:none}
.kv-label{color:#6b7280;flex-shrink:0}
.kv-val{font-weight:600;color:#111827;text-align:right;word-break:break-word}
.kv-val.ok  {color:#16a34a}
.kv-val.warn{color:#d97706}
.kv-val.crit{color:#dc2626}
.kv-val.info{color:#2563eb}
.kv-val.zero{color:#9ca3af;font-weight:400}

/* Tables: scroll on mobile */
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;margin-top:10px}
table.data-table{
  width:100%;
  min-width:320px;
  font-size:12px;
  border-collapse:collapse;
}
table.data-table th{
  text-align:left;
  padding:6px 8px;
  background:#f9fafb;
  border-bottom:2px solid #e5e7eb;
  color:#6b7280;
  font-weight:700;
  font-size:11px;
  text-transform:uppercase;
  letter-spacing:.04em;
  white-space:nowrap;
}
table.data-table td{
  padding:6px 8px;
  border-bottom:1px solid #f3f4f6;
  color:#374151;
  vertical-align:top;
  word-break:break-all;
}
table.data-table tr:last-child td{border-bottom:none}

/* Badges */
.badge{
  display:inline-block;
  padding:2px 7px;
  border-radius:9999px;
  font-size:10px;
  font-weight:700;
  text-transform:uppercase;
  letter-spacing:.03em;
  white-space:nowrap;
}
.badge-critical{background:#fee2e2;color:#b91c1c}
.badge-warning {background:#fef3c7;color:#92400e}
.badge-info    {background:#dbeafe;color:#1d4ed8}
.badge-ok      {background:#dcfce7;color:#15803d}
.badge-new     {background:#ede9fe;color:#6d28d9}

/* Status bar */
.status-bar{
  padding:10px 12px;
  border-radius:5px;
  font-weight:700;
  font-size:14px;
  margin-bottom:10px;
  border-width:1px;
  border-style:solid;
}
.status-ok  {background:#f0fdf4;color:#15803d;border-color:#bbf7d0}
.status-warn{background:#fffbeb;color:#92400e;border-color:#fde68a}
.status-crit{background:#fef2f2;color:#b91c1c;border-color:#fecaca}
.status-unk {background:#f9fafb;color:#6b7280;border-color:#e5e7eb}

/* Mono */
.mono{
  font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
  font-size:11px;
}

/* Footer */
.footer{
  padding:12px 16px;
  border-top:1px solid #e5e7eb;
  font-size:11px;
  color:#9ca3af;
  text-align:center;
  line-height:1.6;
}

/* Alert header accent */
.alert-accent-crit{border-top:4px solid #ef4444}
.alert-accent-warn{border-top:4px solid #f59e0b}

/*                                                                                                 
   DARK MODE
                                                                                                    */
\@media (prefers-color-scheme:dark){
  body{background:#0f172a;color:#e2e8f0}
  .wrapper{background:#1e293b}
  \@media screen and (min-width:600px){
    .wrapper{box-shadow:0 1px 4px rgba(0,0,0,.5)}
  }
  .header{border-color:#334155}
  .header-title{color:#f1f5f9}
  .header-sub{color:#94a3b8}
  .section{border-color:#334155}
  .section-head{background:#0f172a;border-color:#334155;color:#94a3b8}
  .section-body{background:#1e293b}
  .kv-row{border-color:#0f172a}
  .kv-label{color:#94a3b8}
  .kv-val{color:#f1f5f9}
  .kv-val.zero{color:#475569}
  table.data-table th{background:#0f172a;border-color:#334155;color:#64748b}
  table.data-table td{border-color:#0f172a;color:#cbd5e1}
  .footer{border-color:#334155;color:#475569;background:#1e293b}
  .status-ok  {background:#052e16;color:#4ade80;border-color:#166534}
  .status-warn{background:#1c1400;color:#fbbf24;border-color:#78350f}
  .status-crit{background:#1c0000;color:#f87171;border-color:#7f1d1d}
  .status-unk {background:#1e293b;color:#64748b;border-color:#334155}
  .badge-critical{background:#450a0a;color:#fca5a5}
  .badge-warning {background:#1c1400;color:#fde68a}
  .badge-info    {background:#0c1a33;color:#93c5fd}
  .badge-ok      {background:#052e16;color:#86efac}
  .badge-new     {background:#2e1065;color:#c4b5fd}
}
</style>
</head>
<body>
<div class="wrapper">
HTML
}

sub _html_foot {
    my ($generated) = @_;
    $generated //= strftime( "%Y-%m-%d %H:%M:%S", localtime );
    return <<HTML;
<div class="footer">
  TNWatch &mdash; Tangent Networks &bull; Generated $generated &bull; Delivered to root\@localhost
</div>
</div><!-- /wrapper -->
</body></html>
HTML
}

#
# DIGEST HTML TEMPLATE
#

sub _render_digest_html {
    my ($stats) = @_;

    my $date      = $stats->{date} // strftime( "%Y-%m-%d", localtime );
    my $generated = $stats->{generated}
      // strftime( "%Y-%m-%d %H:%M:%S", localtime );
    my $is_test =
      $stats->{_test} ? ' <span style="color:#f59e0b">[TEST]</span>' : '';

    my $html = _html_head("TNWatch Daily Digest - $date");

    #        Header
    $html .= <<HTML;
<div class="header">
  <p class="header-title"> TNWatch Daily Digest$is_test</p>
  <p class="header-sub">$date &bull; Last 24 hours &bull; Tangent Networks</p>
</div>
<div class="body">
HTML

    #        File Integrity
    $html .= _section_tnaudit( $stats->{tnaudit} // {} );

    #        Services
    $html .= _section_services( $stats->{services} // {} );

    #        PF
    $html .= _section_pf( $stats->{pf} // {} );

    #        HTTPD
    $html .= _section_httpd( $stats->{httpd} // {} );

    #        TNWAF
    $html .= _section_tnwaf( $stats->{tnwaf} // {} );

    #        Snort
    $html .= _section_snort( $stats->{snort} // {} );

    #        E2Guardian
    $html .= _section_e2guardian( $stats->{e2guardian} // {} );

    #        Unbound
    $html .= _section_unbound( $stats->{unbound} // {} );

    #        Auth
    $html .= _section_auth( $stats->{auth} // {} );

    $html .= "</div><!-- /body -->\n";
    $html .= _html_foot($generated);

    return $html;
}

#        Section renderers

sub _section_tnaudit {
    my ($t)     = @_;
    my $status  = $t->{status}        // 'UNKNOWN';
    my $total   = $t->{total}         // 0;
    my $ok      = $t->{ok}            // 0;
    my $changed = $t->{changed}       // 0;
    my $last    = $t->{last_check}    // '-';
    my $summary = $t->{summary}       // {};
    my $files   = $t->{changed_files} // [];

    my ( $bar_class, $icon ) =
        $changed > 0         ? ( 'status-crit', '' )
      : $status eq 'UNKNOWN' ? ( 'status-unk',  '[?]' )
      :                        ( 'status-ok', '' );

    my $html = _section_open('File Integrity (TNAudit)');
    $html .= qq{<div class="status-bar $bar_class">$icon &nbsp;$status</div>};

    $html .= _kv( 'Total Files', _num($total) );
    $html .=
      _kv( 'Verified OK', _num($ok), $ok == $total && $total > 0 ? 'ok' : '' );
    $html .= _kv( 'Issues', _num($changed), $changed > 0 ? 'crit' : 'zero' );

    # Status breakdown from summary hash
    for my $st ( sort keys %$summary ) {
        next if $st eq 'ok';
        my $cls = $st =~ /modified|missing|corrupt/i ? 'crit' : 'warn';
        $html .= _kv( ucfirst($st), _num( $summary->{$st} ), $cls );
    }

    $html .= _kv( 'Last Check', $last );

    # Changed file detail table
    if (@$files) {
        $html .= <<'HTML';
<div style="margin-top:12px">
<div class="table-wrap"><table class="data-table">
<tr><th>File</th><th>Status</th><th>SHA256 (new)</th></tr>
HTML
        for my $f (@$files) {
            my $d    = ref( $f->{details} ) eq 'HASH' ? $f->{details} : {};
            my $path = _esc( $f->{message} // '' );

            # Strip the "TNAudit: STATUS     " prefix to get just the path
            $path =~ s/^TNAudit:\s+\S+\s+--\s+//;
            my $fstatus =
              uc( $d->{status} // ( $f->{message} =~ /(\w+)/ ? $1 : '?' ) );
            my $sha = substr( $d->{new_sha256} // '-', 0, 16 );
            my $badge =
                $fstatus =~ /MODIFIED|MISSING|CORRUPT/ ? 'badge-critical'
              : $fstatus =~ /NEW/                      ? 'badge-new'
              :                                          'badge-warning';
            $html .=
                "<tr><td class=\"mono\">$path</td>"
              . "<td><span class=\"badge $badge\">$fstatus</span></td>"
              . "<td class=\"mono\">$sha&hellip;</td></tr>\n";
        }
        $html .= "</table></div></div>\n";
    }

    return $html . _section_close();
}

sub _section_services {
    my ($s)      = @_;
    my $status   = $s->{status}      // 'UNKNOWN';
    my $total    = $s->{total}       // 0;
    my $running  = $s->{running}     // 0;
    my $down     = $s->{down}        // 0;
    my $degraded = $s->{degraded}    // 0;
    my $last     = $s->{last_check}  // '-';
    my $down_ev  = $s->{down_events} // [];

    my ( $bar_class, $icon ) =
        $down > 0            ? ( 'status-crit', '' )
      : $degraded > 0        ? ( 'status-warn', '[!]' )
      : $status eq 'UNKNOWN' ? ( 'status-unk',  '[?]' )
      :                        ( 'status-ok', '' );

    my $html = _section_open('Services');
    $html .= qq{<div class="status-bar $bar_class">$icon &nbsp;$status</div>};

    $html .= _kv( 'Total Services', _num($total) );
    $html .= _kv( 'Running', _num($running),
        $running == $total && $total > 0 ? 'ok' : '' );
    $html .= _kv( 'Down', _num($down), $down > 0 ? 'crit' : 'zero' );
    $html .=
      _kv( 'Degraded', _num($degraded), $degraded > 0 ? 'warn' : 'zero' );
    $html .= _kv( 'Last Check', $last );

    if (@$down_ev) {
        $html .= <<'HTML';
<div style="margin-top:12px">
<div class="table-wrap"><table class="data-table">
<tr><th>Service</th><th>Status</th><th>Command</th><th>User</th></tr>
HTML
        for my $e (@$down_ev) {
            my $d     = ref( $e->{details} ) eq 'HASH' ? $e->{details} : {};
            my $name  = _esc( $d->{display} // $d->{service} // '?' );
            my $st    = uc( $d->{status}    // '?' );
            my $cmd   = _esc( $d->{command} // '?' );
            my $user  = _esc( $d->{user}    // '?' );
            my $badge = $st =~ /STOP|DEAD/ ? 'badge-critical' : 'badge-warning';
            $html .=
                "<tr><td><strong>$name</strong></td>"
              . "<td><span class=\"badge $badge\">$st</span></td>"
              . "<td class=\"mono\">$cmd</td>"
              . "<td>$user</td></tr>\n";
        }
        $html .= "</table></div></div>\n";
    }

    return $html . _section_close();
}

sub _section_pf {
    my ($p)         = @_;
    my $status      = $p->{pf_status}    // 'unknown';
    my $since       = $p->{pf_since}     // '';
    my $states      = $p->{states}       // 0;
    my $inserts_ps  = $p->{inserts_ps}   // 0;
    my $removals_ps = $p->{removals_ps}  // 0;
    my $churn       = $p->{churn}        // 0;
    my $spikes      = $p->{block_spikes} // 0;

    my $html = _section_open('Packet Filter (PF)');

    my $status_class = lc($status) eq 'enabled' ? 'status-ok' : 'status-warn';
    $html .= qq{<div class="status-bar $status_class">$status</div>};
    $html .= _kv( 'Since', $since ) if $since;
    $html .=
      _kv( 'Active States', _num($states), $states > 0 ? 'info' : 'zero' );
    $html .=
      _kv( 'Inserts/s', _num($inserts_ps), $inserts_ps > 10 ? 'warn' : '' );
    $html .= _kv( 'Removals/s', _num($removals_ps) );
    $html .= _kv(
        'Churn/s',
        ( $churn >= 0 ? '+' : '' ) . _num($churn),
        $churn > 50 ? 'warn' : ''
    );
    $html .=
      _kv( 'Spike Events (24h)', _num($spikes), $spikes > 0 ? 'warn' : 'zero' );

    return $html . _section_close();
}

sub _section_httpd {
    my ($h)  = @_;
    my $e4   = $h->{errors_4xx} // 0;
    my $e5   = $h->{errors_5xx} // 0;
    my $tips = $h->{top_ips}    // [];

    my $html = _section_open('HTTPD Error Log');
    $html .= _kv( '4xx Errors', _num($e4), $e4 > 0 ? 'warn' : 'zero' );
    $html .= _kv( '5xx Errors', _num($e5), $e5 > 0 ? 'crit' : 'zero' );

    if (@$tips) {
        $html .= _top_ip_table( $tips, 'Top Error IPs' );
    }

    return $html . _section_close();
}

sub _section_tnwaf {
    my ($w) = @_;
    my $rl  = $w->{rate_limits}    // 0;
    my $pb  = $w->{pattern_blocks} // 0;
    my $xss = $w->{xss}            // 0;
    my $sql = $w->{sqli}           // 0;
    my $sus = $w->{suspicious}     // 0;

    my $html = _section_open('TNWAF Security');
    $html .= _kv( 'Rate Limits',     _num($rl),  $rl > 0  ? 'warn' : 'zero' );
    $html .= _kv( 'Pattern Blocks',  _num($pb),  $pb > 0  ? 'warn' : 'zero' );
    $html .= _kv( 'XSS Attempts',    _num($xss), $xss > 0 ? 'crit' : 'zero' );
    $html .= _kv( 'SQLi Attempts',   _num($sql), $sql > 0 ? 'crit' : 'zero' );
    $html .= _kv( 'Suspicious Reqs', _num($sus), $sus > 0 ? 'warn' : 'zero' );

    return $html . _section_close();
}

sub _section_snort {
    my ($s)  = @_;
    my $crit = $s->{critical} // 0;
    my $high = $s->{high}     // 0;
    my $low  = $s->{low}      // 0;

    my $html = _section_open('Snort IDS');
    $html .= _kv( 'Critical Alerts', _num($crit), $crit > 0 ? 'crit' : 'zero' );
    $html .= _kv( 'High Alerts',     _num($high), $high > 0 ? 'warn' : 'zero' );
    $html .= _kv( 'Low Alerts',      _num($low),  $low > 0  ? 'info' : 'zero' );

    return $html . _section_close();
}

sub _section_e2guardian {
    my ($e) = @_;
    my $blocked = $e->{blocked} // 0;

    my $html = _section_open('E2Guardian Web Filter');
    $html .=
      _kv( 'Blocked Domains', _num($blocked), $blocked > 0 ? 'warn' : 'zero' );

    return $html . _section_close();
}

sub _section_unbound {
    my ($u) = @_;
    my $nx  = $u->{nxdomain} // 0;
    my $ref = $u->{refused}  // 0;

    my $html = _section_open('Unbound DNS');
    $html .= _kv( 'NXDOMAIN', _num($nx),
        $nx > 100 ? 'warn' : ( $nx > 0 ? 'info' : 'zero' ) );
    $html .= _kv( 'DNS Refused', _num($ref), $ref > 0 ? 'warn' : 'zero' );

    return $html . _section_close();
}

sub _section_auth {
    my ($a)  = @_;
    my $fail = $a->{failures}      // 0;
    my $succ = $a->{successes}     // 0;
    my $doas = $a->{doas}          // 0;
    my $root = $a->{root_attempts} // 0;
    my $tips = $a->{top_ips}       // [];

    my $html = _section_open('Authentication');
    $html .= _kv( 'Failed Logins',
        _num($fail), $fail > 5 ? 'crit' : ( $fail > 0 ? 'warn' : 'zero' ) );
    $html .= _kv( 'Successful Logins', _num($succ) );
    $html .= _kv( 'doas Executions',   _num($doas) );
    $html .=
      _kv( 'Root Login Attempts', _num($root), $root > 0 ? 'crit' : 'zero' );

    if (@$tips) {
        $html .= _top_ip_table( $tips, 'Top Attacker IPs' );
    }

    return $html . _section_close();
}

#
# ALERT HTML TEMPLATE
#

sub _render_alert_html {
    my ( $rule_name, $detail ) = @_;

    my $rule    = $detail->{rule}         // {};
    my $count   = $detail->{count}        // 0;
    my $events  = $detail->{events}       // [];
    my $sev     = $rule->{severity}       // 'warning';
    my $source  = $rule->{source}         // '?';
    my $window  = $rule->{window_seconds} // 300;
    my $thresh  = $rule->{threshold}      // 1;
    my $display = _rule_display_name($rule_name);
    my $now     = strftime( "%Y-%m-%d %H:%M:%S", localtime );

    my $bar_class = $sev eq 'critical' ? 'status-crit'    : 'status-warn';
    my $icon      = $sev eq 'critical' ? '[!]'            : '[!]';
    my $badge_cls = $sev eq 'critical' ? 'badge-critical' : 'badge-warning';

    my $html = _html_head("TNWatch Alert: $display");

    $html .= <<HTML;
<div class="header" style="border-left:4px solid $SEV_COLOR{$sev};padding-left:24px">
  <p class="header-title">$icon TNWatch Alert</p>
  <p class="header-sub">$now &bull; Tangent Networks</p>
</div>
<div class="body">

<div class="section">
<div class="section-head">Alert Details</div>
<div class="section-body">
  <div class="status-bar $bar_class">$icon &nbsp;$display</div>
HTML

    $html .= _kv( 'Rule', _esc($rule_name) );
    $html .= _kv( 'Severity',
        qq{<span class="badge $badge_cls">} . uc($sev) . '</span>' );
    $html .= _kv( 'Source',     _esc($source) );
    $html .= _kv( 'Event Type', _esc( $rule->{event_type} // '?' ) );
    $html .= _kv( 'Count',      "$count events" );
    $html .= _kv( 'Window',     _fmt_window($window) );
    $html .= _kv( 'Threshold',  "$thresh events" );
    $html .= _kv( 'Triggered',  $now );

    $html .= "</div></div>\n";

    #        Event table
    if (@$events) {
        my $show = @$events > 20 ? 20 : scalar @$events;
        my $more = @$events - $show;

        $html .= _section_open("Recent Events (showing $show of $count)");
        $html .= <<'HTML';
<div class="table-wrap"><table class="data-table">
<tr><th>Time</th><th>Src IP</th><th>Event</th><th>Message</th></tr>
HTML
        for my $i ( 0 .. $show - 1 ) {
            my $e = $events->[$i];
            my $ts =
              strftime( "%H:%M:%S", localtime( $e->{timestamp} // time() ) );
            my $ip    = _esc( $e->{src_ip}     // '-' );
            my $et    = _esc( $e->{event_type} // '?' );
            my $msg   = _esc( substr( $e->{message} // '', 0, 80 ) );
            my $sev_e = $e->{severity} // 'info';
            my $bc    = "badge-$sev_e";
            $bc = 'badge-info' unless $bc =~ /critical|warning|info|ok/;

            $html .= "<tr>"
              . "<td class=\"mono\">$ts</td>"
              . "<td class=\"mono\">$ip</td>"
              . "<td><span class=\"badge $bc\">$et</span></td>"
              . "<td>$msg</td>"
              . "</tr>\n";
        }

        $html .= "</table></div>\n";
        if ( $more > 0 ) {
            $html .=
                qq{<p style="margin:8px 0 0;font-size:12px;color:#6b7280">}
              . qq{&hellip; and $more more events. Run: }
              . qq{<code class="mono">TNWatch.pl --query --source $source --since }
              . _fmt_window($window)
              . qq{</code></p>\n};
        }
        $html .= _section_close();
    }

    #        Rule-specific detail blocks
    $html .= _alert_detail_block( $rule_name, $events );

    $html .= "</div><!-- /body -->\n";
    $html .= _html_foot($now);

    return $html;
}

sub _alert_detail_block {
    my ( $rule_name, $events ) = @_;
    return '' unless @$events;

    # TNAudit     show file paths prominently
    if ( $rule_name eq 'tnaudit_change' ) {
        my $html = _section_open('Changed Files');
        $html .= <<'HTML';
<div class="table-wrap"><table class="data-table">
<tr><th>File Path</th><th>Status</th><th>Details</th></tr>
HTML
        for my $e (@$events) {
            my $d    = ref( $e->{details} ) eq 'HASH' ? $e->{details} : {};
            my $path = $e->{message} // '';
            $path =~ s/^TNAudit:\s+\S+\s+--\s+//;
            my $status = uc( $d->{status}
                  // ( $e->{severity} eq 'critical' ? 'MODIFIED' : 'NEW' ) );
            my $sha = substr( $d->{new_sha256} // '-', 0, 24 );
            my $badge =
              $status =~ /MODIFIED|MISSING/ ? 'badge-critical' : 'badge-new';
            $html .= "<tr>"
              . "<td class=\"mono\">"
              . _esc($path) . "</td>"
              . "<td><span class=\"badge $badge\">$status</span></td>"
              . "<td class=\"mono\">"
              . _esc($sha)
              . "&hellip;</td>"
              . "</tr>\n";
        }
        return $html . "</table></div>" . _section_close();
    }

    # Port scan     show scanned ports
    if ( $rule_name eq 'pf_port_scan' ) {
        my $html = _section_open('Port Scan Details');
        for my $e (@$events) {
            my $d     = ref( $e->{details} ) eq 'HASH' ? $e->{details} : {};
            my $ip    = _esc( $e->{src_ip} // '?' );
            my $cnt   = $d->{count} // '?';
            my $ports = join( ', ', sort { $a <=> $b } @{ $d->{ports} // [] } );
            $html .=
qq{<p style="margin:4px 0"><strong>$ip</strong>: $cnt ports scanned</p>};
            $html .=
qq{<p class="mono" style="font-size:12px;color:#6b7280;margin:0 0 8px">$ports</p>};
        }
        return $html . _section_close();
    }

    # Service down     show service details
    if ( $rule_name eq 'service_down' ) {
        my $html = _section_open('Affected Services');
        $html .= <<'HTML';
<div class="table-wrap"><table class="data-table">
<tr><th>Service</th><th>Status</th><th>PID</th><th>Mem %</th><th>CPU %</th></tr>
HTML
        for my $e (@$events) {
            my $d    = ref( $e->{details} ) eq 'HASH' ? $e->{details} : {};
            my $name = _esc( $d->{display} // $d->{service} // '?' );
            my $st   = uc( $d->{status}    // '?' );
            my $pid  = $d->{pid}     // '-';
            my $mem  = $d->{mem_pct} // '-';
            my $cpu  = $d->{cpu_pct} // '-';
            $html .=
                "<tr><td><strong>$name</strong></td>"
              . "<td><span class=\"badge badge-critical\">$st</span></td>"
              . "<td class=\"mono\">$pid</td>"
              . "<td>$mem%</td><td>$cpu%</td></tr>\n";
        }
        return $html . "</table></div>" . _section_close();
    }

    # Auth failures     show attacker IPs and usernames
    if ( $rule_name eq 'auth_failures' ) {
        my %ips;
        for my $e (@$events) {
            $ips{ $e->{src_ip} // 'unknown' }++ if $e->{src_ip};
        }
        my $html = _section_open('Top Attacker IPs');
        $html .= <<'HTML';
<div class="table-wrap"><table class="data-table">
<tr><th>IP Address</th><th>Attempts</th></tr>
HTML
        for my $ip ( sort { $ips{$b} <=> $ips{$a} } keys %ips ) {
            $html .=
                "<tr><td class=\"mono\">"
              . _esc($ip) . "</td>"
              . "<td><strong>$ips{$ip}</strong></td></tr>\n";
        }
        return $html . "</table></div>" . _section_close();
    }

    return '';
}

#
# PLAIN TEXT FALLBACKS
#

sub _render_digest_text {
    my ($stats) = @_;
    my $date    = $stats->{date} // strftime( "%Y-%m-%d", localtime );
    my $t       = '';

    $t .= "TNWatch Daily Digest - $date\n";
    $t .= "=" x 50 . "\n\n";

    # TNAudit
    my $ta = $stats->{tnaudit} // {};
    $t .= "FILE INTEGRITY (TNAudit)\n" . "-" x 30 . "\n";
    $t .= sprintf "Status:        %s\n",   $ta->{status} // 'UNKNOWN';
    $t .= sprintf "Total Files:   %s\n",   _num( $ta->{total}   // 0 );
    $t .= sprintf "Verified OK:   %s\n",   _num( $ta->{ok}      // 0 );
    $t .= sprintf "Issues:        %s\n",   _num( $ta->{changed} // 0 );
    $t .= sprintf "Last Check:    %s\n\n", $ta->{last_check} // '-';

    for my $f ( @{ $ta->{changed_files} // [] } ) {
        my $path = $f->{message} // '';
        $path =~ s/^TNAudit:\s+\S+\s+--\s+//;
        $t .= "  CHANGED: $path\n";
    }
    $t .= "\n" if @{ $ta->{changed_files} // [] };

    # Services
    my $sv = $stats->{services} // {};
    $t .= "SERVICES\n" . "-" x 30 . "\n";
    $t .= sprintf "Status:     %s\n", $sv->{status}  // 'UNKNOWN';
    $t .= sprintf "Total:      %d\n", $sv->{total}   // 0;
    $t .= sprintf "Running:    %d\n", $sv->{running} // 0;
    $t .= sprintf "Down:       %d\n", $sv->{down}    // 0;
    for my $svc ( @{ $sv->{down_list} // [] } ) { $t .= "  DOWN: $svc\n" }
    $t .= "\n";

    # PF
    my $pf = $stats->{pf} // {};
    $t .= "PACKET FILTER (PF)\n" . "-" x 30 . "\n";
    $t .= sprintf "Status:       %s\n", $pf->{pf_status} // 'unknown';
    $t .= sprintf "Since:        %s\n", $pf->{pf_since}  // '-'
      if $pf->{pf_since};
    $t .= sprintf "Active States: %s\n", _num( $pf->{states}       // 0 );
    $t .= sprintf "Inserts/s:    %s\n",  _num( $pf->{inserts_ps}   // 0 );
    $t .= sprintf "Removals/s:   %s\n",  _num( $pf->{removals_ps}  // 0 );
    $t .= sprintf "Spike Events: %s\n",  _num( $pf->{block_spikes} // 0 );
    $t .= "\n";

    # HTTPD
    my $hd = $stats->{httpd} // {};
    $t .= "HTTPD ERROR LOG\n" . "-" x 30 . "\n";
    $t .= sprintf "4xx Errors: %s\n",   _num( $hd->{errors_4xx} // 0 );
    $t .= sprintf "5xx Errors: %s\n\n", _num( $hd->{errors_5xx} // 0 );

    # TNWAF
    my $wf = $stats->{tnwaf} // {};
    $t .= "TNWAF\n" . "-" x 30 . "\n";
    $t .= sprintf "Rate Limits:    %s\n",   _num( $wf->{rate_limits}    // 0 );
    $t .= sprintf "Pattern Blocks: %s\n",   _num( $wf->{pattern_blocks} // 0 );
    $t .= sprintf "XSS Attempts:   %s\n",   _num( $wf->{xss}            // 0 );
    $t .= sprintf "SQLi Attempts:  %s\n\n", _num( $wf->{sqli}           // 0 );

    # Snort
    my $sn = $stats->{snort} // {};
    $t .= "SNORT IDS\n" . "-" x 30 . "\n";
    $t .= sprintf "Critical: %s\n",   _num( $sn->{critical} // 0 );
    $t .= sprintf "High:     %s\n",   _num( $sn->{high}     // 0 );
    $t .= sprintf "Low:      %s\n\n", _num( $sn->{low}      // 0 );

    # E2Guardian
    my $eg = $stats->{e2guardian} // {};
    $t .= "E2GUARDIAN\n" . "-" x 30 . "\n";
    $t .= sprintf "Blocked: %s\n\n", _num( $eg->{blocked} // 0 );

    # Unbound
    my $ub = $stats->{unbound} // {};
    $t .= "UNBOUND DNS\n" . "-" x 30 . "\n";
    $t .= sprintf "NXDOMAIN: %s\n",   _num( $ub->{nxdomain} // 0 );
    $t .= sprintf "Refused:  %s\n\n", _num( $ub->{refused}  // 0 );

    # Auth
    my $au = $stats->{auth} // {};
    $t .= "AUTHENTICATION\n" . "-" x 30 . "\n";
    $t .= sprintf "Failed Logins:       %s\n", _num( $au->{failures}  // 0 );
    $t .= sprintf "Successful Logins:   %s\n", _num( $au->{successes} // 0 );
    $t .= sprintf "doas Executions:     %s\n", _num( $au->{doas}      // 0 );
    $t .= sprintf "Root Login Attempts: %s\n",
      _num( $au->{root_attempts} // 0 );
    for my $ip ( @{ $au->{top_ips} // [] } ) {
        $t .= sprintf "  %-18s %s failures\n", $ip->{src_ip},
          _num( $ip->{count} );
    }
    $t .= "\n";

    $t .=
        "Generated: "
      . ( $stats->{generated} // strftime( "%Y-%m-%d %H:%M:%S", localtime ) )
      . "\n";
    $t .= "TNWatch - Tangent Networks\n";

    return $t;
}

sub _render_alert_text {
    my ( $rule_name, $detail ) = @_;
    my $rule    = $detail->{rule}   // {};
    my $count   = $detail->{count}  // 0;
    my $events  = $detail->{events} // [];
    my $now     = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    my $sev     = uc( $rule->{severity} // 'WARNING' );
    my $display = _rule_display_name($rule_name);

    my $t = "TNWatch Alert: $display\n";
    $t .= "=" x 50 . "\n\n";
    $t .= "Severity:   $sev\n";
    $t .= "Rule:       $rule_name\n";
    $t .= "Source:     " . ( $rule->{source}     // '?' ) . "\n";
    $t .= "Event:      " . ( $rule->{event_type} // '?' ) . "\n";
    $t .= "Count:      $count events\n";
    $t .= "Window:     " . _fmt_window( $rule->{window_seconds} // 300 ) . "\n";
    $t .= "Threshold:  " . ( $rule->{threshold} // 1 ) . " events\n";
    $t .= "Time:       $now\n\n";

    $t .= "Recent Events:\n" . "-" x 30 . "\n";
    my $show = @$events > 20 ? 20 : scalar @$events;
    for my $i ( 0 .. $show - 1 ) {
        my $e  = $events->[$i];
        my $ts = strftime( "%H:%M:%S", localtime( $e->{timestamp} // time() ) );
        my $ip = $e->{src_ip} // '-';
        $t .= sprintf "  [%s] %-16s %s\n", $ts, $ip,
          substr( $e->{message} // '', 0, 60 );
    }
    my $more = @$events - $show;
    $t .= "  ... and $more more events\n" if $more > 0;

    $t .= "\nTNWatch - Tangent Networks\n";
    return $t;
}

#
# HTML HELPERS
#

sub _section_open {
    my ($title) = @_;
    return <<HTML;
<div class="section">
<div class="section-head">$title</div>
<div class="section-body">
HTML
}

sub _section_close {
    return "</div></div>\n";
}

sub _kv {
    my ( $label, $val, $cls ) = @_;
    $cls //= '';
    my $val_class = "kv-val";
    $val_class .= " $cls" if $cls;
    return qq{<div class="kv-row"><span class="kv-label">$label</span>}
      . qq{<span class="$val_class">$val</span></div>\n};
}

sub _top_ip_table {
    my ( $ips, $title ) = @_;
    return '' unless @$ips;

    my $html = qq{<div style="margin-top:12px">\n};
    $html .=
qq{<div style="font-size:12px;font-weight:600;color:#6b7280;margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em">$title</div>\n};
    $html .= qq{<div class="table-wrap"><table class="data-table">\n};
    $html .= qq{<tr><th>#</th><th>IP Address</th><th>Count</th></tr>\n};

    my $rank = 1;
    for my $ip (@$ips) {
        $html .=
          sprintf
"<tr><td>%d</td><td class=\"mono\">%s</td><td><strong>%s</strong></td></tr>\n",
          $rank++, _esc( $ip->{src_ip} // '?' ), _num( $ip->{count} // 0 );
    }
    $html .= "</table></div></div>\n";
    return $html;
}

#
# UTILITY
#

sub _esc {
    my ($s) = @_;
    $s //= '';
    $s =~ s/&/&amp;/g;
    $s =~ s/</&lt;/g;
    $s =~ s/>/&gt;/g;
    $s =~ s/"/&quot;/g;
    return $s;
}

# Format number with thousands separator
sub _num {
    my ($n) = @_;
    $n //= 0;
    $n = int($n);
    1 while $n =~ s/^(-?\d+)(\d{3})/$1,$2/;
    return $n;
}

sub _fmt_window {
    my ($secs) = @_;
    return "${secs}s"              if $secs < 60;
    return int( $secs / 60 ) . "m" if $secs < 3600;
    return int( $secs / 3600 ) . "h";
}

sub _rule_display_name {
    my ($rule) = @_;
    my %names = (
        tnaudit_change   => 'File Integrity Change',
        pf_port_scan     => 'PF Port Scan Detected',
        tnwaf_rate_limit => 'TNWAF Rate Limit Triggered',
        snort_critical   => 'Snort Critical IDS Alert',
        snort_high       => 'Snort High IDS Alert',
        auth_failures    => 'SSH Auth Failure Burst',
        httpd_5xx_burst  => 'HTTPD 5xx Error Burst',
        service_down     => 'Service Down',
    );
    return $names{$rule} // do {
        ( my $n = $rule ) =~ s/_/ /g;
        ucfirst $n;
    };
}

sub _digest_has_issues {
    my ($stats) = @_;
    return 1 if ( $stats->{tnaudit}{changed}    // 0 ) > 0;
    return 1 if ( $stats->{services}{down}      // 0 ) > 0;
    return 1 if ( $stats->{snort}{critical}     // 0 ) > 0;
    return 1 if ( $stats->{auth}{root_attempts} // 0 ) > 0;
    return 0;
}

1;

__END__

=head1 NAME

TNWatchMail - Email delivery and HTML template engine for TNWatch

=head1 SYNOPSIS

    use TNWatchMail;

    # Daily digest
    TNWatchMail::send_digest(\%stats);

    # Immediate alert
    TNWatchMail::send_alert('auth_failures', {
        rule   => $rule_hashref,
        count  => 12,
        events => $events_arrayref,
    });

=head1 EMAIL FORMAT

Both functions send multipart/alternative MIME emails:
  - text/plain      terminal-friendly fallback
  - text/html       styled with inline CSS, dark/light mode

Delivered via /usr/sbin/sendmail to root@localhost.
Displayed in the Tangent Networks mail viewer UI.

=cut
