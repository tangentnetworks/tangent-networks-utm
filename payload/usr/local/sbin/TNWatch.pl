#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# TNWatch - OpenBSD Log Analysis & Email Alert System
# /usr/local/sbin/TNWatch.pl
#
# Usage:
#   TNWatch.pl --init-db
#   TNWatch.pl --parse <source>
#   TNWatch.pl --parse-all
#   TNWatch.pl --check-alerts
#   TNWatch.pl --send-digest
#   TNWatch.pl --query [--source S] [--severity S] [--since Xh] [--limit N] [--json]
#   TNWatch.pl --stats [--source S] [--since Xh]
#   TNWatch.pl --add-rule <name> --source S --event-type E --threshold N --window N --severity S
#   TNWatch.pl --test-email
#   TNWatch.pl --purge [--days N]
#   TNWatch.pl --status

use strict;
use warnings;
use lib '/etc/TNWatch';

use Getopt::Long qw(:config no_ignore_case bundling);
use POSIX        qw(strftime);
use JSON::PP;

use TNWatchDatabase;
use TNWatchParser;
use TNWatchMail;

#===================================================
# TAINT: Clean PATH
#===================================================
$ENV{PATH} = '/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

#===================================================
# GLOBALS
#===================================================

my $DB_PATH  = '/var/www/htdocs/tn/data/db/TNWatch.db';
my $LOG_FILE = '/var/log/TNWatch.log';
my $VERSION  = '1.0.0';

#===================================================
# OPTIONS PARSING
#===================================================

my %opt;
GetOptions(
    \%opt,
    'init-db',
    'parse=s',
    'parse-all',
    'check-alerts',
    'send-digest',
    'query',
    'stats',
    'add-rule=s',
    'test-email',
    'purge',
    'status',

    # Filters
    'source=s',
    'event-type=s',
    'severity=s',
    'since=s',
    'until=s',
    'src-ip=s',
    'limit=i',
    'json',
    'verbose',

    # Rule params
    'threshold=i',
    'window=i',

    # Maintenance
    'days=i',

    'help|h',
    'version|v',
) or usage(1);

usage(0)  if $opt{help};
version() if $opt{version};
usage(1)
  unless grep { $opt{$_} }
  qw(init-db parse parse-all check-alerts send-digest query stats add-rule test-email purge status);

#===================================================
# DISPATCH
#===================================================

if ( $opt{'init-db'} ) {
    cmd_init_db();
}
elsif ( defined $opt{parse} ) {
    cmd_parse( $opt{parse} );
}
elsif ( $opt{'parse-all'} ) {
    cmd_parse_all();
}
elsif ( $opt{'check-alerts'} ) {
    cmd_check_alerts();
}
elsif ( $opt{'send-digest'} ) {
    cmd_send_digest();
}
elsif ( $opt{query} ) {
    cmd_query();
}
elsif ( $opt{stats} ) {
    cmd_stats();
}
elsif ( $opt{'add-rule'} ) {
    cmd_add_rule( $opt{'add-rule'} );
}
elsif ( $opt{'test-email'} ) {
    cmd_test_email();
}
elsif ( $opt{purge} ) {
    cmd_purge();
}
elsif ( $opt{status} ) {
    cmd_status();
}

exit 0;

#===================================================
# COMMANDS
#===================================================

sub cmd_init_db {
    log_msg("Initializing TNWatch database at $DB_PATH");
    my $db = db_connect();
    $db->init_schema();
    $db->disconnect();
    print "TNWatch database initialized: $DB_PATH\n";
    log_msg("Database initialized successfully");
}

sub cmd_parse {
    my ($source) = @_;
    my $db       = db_connect();
    my $parser   = TNWatchParser->new( verbose => $opt{verbose} // 0 );

    my $state = $db->get_parse_state($source);
    log_msg(
"Parsing $source (last_pos=$state->{last_pos}, last_ts=$state->{last_ts})"
    );

    my ( $events, $new_state ) = eval { $parser->parse( $source, $state ) };
    if ($@) {
        log_msg("ERROR parsing $source: $@");
        die "Parse failed for $source: $@\n";
    }

    my $count = 0;
    if (@$events) {
        $count = $db->insert_events_bulk(@$events);
    }
    $db->update_parse_state( $source, %$new_state );
    $db->disconnect();

    printf "Parsed %s: %d new events\n", $source, $count;
    log_msg("Parsed $source: $count events stored");
}

sub cmd_parse_all {
    my $db     = db_connect();
    my $parser = TNWatchParser->new( verbose => $opt{verbose} // 0 );

    # Load all states at once
    my %states;
    for my $src (
        qw(tnaudit pf httpd tnwaf_access tnwaf_security
        snort e2guardian unbound syslog authlog services)
      )
    {
        $states{$src} = $db->get_parse_state($src);
    }

    my $results = $parser->parse_all( \%states );

    my $total = 0;
    for my $src ( sort keys %$results ) {
        my $r = $results->{$src};
        if ( $r->{error} ) {
            printf "  %-20s ERROR: %s\n", $src, $r->{error};
            log_msg("ERROR parsing $src: $r->{error}");
            next;
        }
        if ( $r->{count} > 0 ) {
            $db->insert_events_bulk( @{ $r->{events} } );
        }
        $db->update_parse_state( $src, %{ $r->{new_state} } )
          if $r->{new_state};
        printf "  %-20s %d events\n", $src, $r->{count};
        $total += $r->{count};
    }

    $db->disconnect();
    printf "\nTotal: %d new events stored\n", $total;
    log_msg("parse-all complete: $total total events");
}

sub cmd_check_alerts {
    my $db    = db_connect();
    my $rules = $db->get_alert_rules();
    my $now   = time();
    my @fired;

    for my $rule (@$rules) {
        my $window_start = $now - $rule->{window_seconds};

        # Count events matching this rule in the window
        my $count = $db->count_events(
            source     => $rule->{source},
            event_type => $rule->{event_type},
            since      => $window_start,
        );

        next unless $count >= $rule->{threshold};

        # Don't re-alert if we alerted recently (within window)
        if ( $rule->{last_alerted}
            && ( $now - $rule->{last_alerted} ) < $rule->{window_seconds} )
        {
            log_msg(
"Alert '$rule->{rule_name}' suppressed (already alerted recently)"
            );
            next;
        }

        # Fetch the triggering events
        my $events = $db->query_events(
            source     => $rule->{source},
            event_type => $rule->{event_type},
            since      => $window_start,
            limit      => 50,
        );

        log_msg(
"ALERT: rule='$rule->{rule_name}' count=$count threshold=$rule->{threshold}"
        );

        # Send immediate alert email
        my $sent = TNWatchMail::send_alert(
            $rule->{rule_name},
            {
                rule   => $rule,
                count  => $count,
                events => $events,
            }
        );

        if ($sent) {
            $db->update_last_alerted( $rule->{rule_name}, $now );
            my @ids = map { $_->{id} } @$events;
            $db->mark_events_alerted(@ids);
            push @fired, $rule->{rule_name};
            printf "ALERT SENT: %s (%d events in %ds window)\n",
              $rule->{rule_name}, $count, $rule->{window_seconds};
        }
        else {
            log_msg("ERROR: Failed to send alert for $rule->{rule_name}");
        }
    }

    if ( !@fired ) {
        print "No alerts triggered.\n" if $opt{verbose};
    }

    $db->disconnect();
}

sub cmd_send_digest {
    my $db       = db_connect();
    my $since    = time() - 86400;                      # Last 24 hours
    my $date_str = strftime( "%Y-%m-%d", localtime );

    log_msg("Generating daily digest for $date_str");

    # Gather all stats
    my %stats = (
        date      => $date_str,
        since_ts  => $since,
        generated => strftime( "%Y-%m-%d %H:%M:%S", localtime ),
    );

    # === TNAudit integrity summary ===
    $stats{tnaudit} = _gather_tnaudit_stats( $db, $since );

    # === PF stats ===
    # Read from the pf_summary event (pfctl counters) rather than
    # individual block events -- pfctl gives exact kernel totals.
    $stats{pf} = _gather_pf_stats( $db, $since );

    # === HTTP errors ===
    $stats{httpd} = {
        errors_4xx => $db->count_events(
            source     => 'httpd',
            event_type => '4xx_error',
            since      => $since
        ),
        errors_5xx => $db->count_events(
            source     => 'httpd',
            event_type => '5xx_error',
            since      => $since
        ),
        top_ips =>
          $db->get_top_ips( source => 'httpd', since => $since, limit => 5 ),
    };

    # === TNWAF ===
    $stats{tnwaf} = {
        rate_limits => $db->count_events(
            source     => 'tnwaf',
            event_type => 'rate_limit',
            since      => $since
        ),
        pattern_blocks => $db->count_events(
            source     => 'tnwaf',
            event_type => 'pattern_block',
            since      => $since
        ),
        xss => $db->count_events(
            source     => 'tnwaf',
            event_type => 'xss_attempt',
            since      => $since
        ),
        sqli => $db->count_events(
            source     => 'tnwaf',
            event_type => 'sqli_attempt',
            since      => $since
        ),
        suspicious => $db->count_events(
            source     => 'tnwaf',
            event_type => 'suspicious_request',
            since      => $since
        ),
    };

    # === Services ===
    $stats{services} = _gather_services_stats( $db, $since );

    # === Snort ===
    $stats{snort} = {
        critical => $db->count_events(
            source     => 'snort',
            event_type => 'alert_critical',
            since      => $since
        ),
        high => $db->count_events(
            source     => 'snort',
            event_type => 'alert_high',
            since      => $since
        ),
        low => $db->count_events(
            source     => 'snort',
            event_type => 'alert_low',
            since      => $since
        ),
    };

    # === E2Guardian ===
    $stats{e2guardian} = {
        blocked => $db->count_events(
            source     => 'e2guardian',
            event_type => 'blocked_domain',
            since      => $since
        ),
    };

    # === Unbound ===
    $stats{unbound} = {
        nxdomain => $db->count_events(
            source     => 'unbound',
            event_type => 'nxdomain',
            since      => $since
        ),
        refused => $db->count_events(
            source     => 'unbound',
            event_type => 'dns_refused',
            since      => $since
        ),
    };

    # === Auth ===
    $stats{auth} = {
        failures => $db->count_events(
            source     => 'authlog',
            event_type => 'auth_failure',
            since      => $since
        ),
        successes => $db->count_events(
            source     => 'authlog',
            event_type => 'auth_success',
            since      => $since
        ),
        doas => $db->count_events(
            source     => 'authlog',
            event_type => 'doas_exec',
            since      => $since
        ),
        root_attempts => $db->count_events(
            source     => 'authlog',
            event_type => 'root_login_attempt',
            since      => $since
        ),
        top_ips =>
          $db->get_top_ips( source => 'authlog', since => $since, limit => 5 ),
    };

    $db->disconnect();

    my $sent = TNWatchMail::send_digest( \%stats );
    if ($sent) {
        print "Daily digest sent for $date_str\n";
        log_msg("Daily digest sent successfully for $date_str");
    }
    else {
        print "ERROR: Failed to send digest\n";
        log_msg("ERROR: Failed to send daily digest");
        exit 1;
    }
}

sub cmd_query {
    my $db = db_connect();

    my %q;
    $q{source}     = $opt{source}       if $opt{source};
    $q{event_type} = $opt{'event-type'} if $opt{'event-type'};
    $q{severity}   = $opt{severity}     if $opt{severity};
    $q{src_ip}     = $opt{'src-ip'}     if $opt{'src-ip'};
    $q{since}      = $opt{since}        if $opt{since};
    $q{until}      = $opt{until}        if $opt{until};
    $q{limit}      = $opt{limit}        if $opt{limit};

    my $events = $db->query_events(%q);
    $db->disconnect();

    if ( $opt{json} ) {
        my $out = {
            success => JSON::PP::true,
            count   => scalar(@$events),
            events  => $events,
        };
        print JSON::PP->new->utf8->pretty->encode($out);
    }
    else {
        printf "%-20s %-12s %-8s %-16s %s\n",
          "TIMESTAMP", "SOURCE", "SEV", "SRC_IP", "MESSAGE";
        print "-" x 80, "\n";
        for my $e (@$events) {
            printf "%-20s %-12s %-8s %-16s %s\n",
              strftime( "%Y-%m-%d %H:%M:%S", localtime( $e->{timestamp} ) ),
              $e->{source},
              $e->{severity}, $e->{src_ip} // '-',
              substr( $e->{message} // '', 0, 60 );
        }
        printf "\n%d event(s)\n", scalar(@$events);
    }
}

sub cmd_stats {
    my $db = db_connect();
    my $since =
      $opt{since}
      ? TNWatchDatabase::_parse_since( $opt{since} )
      : time() - 86400;
    my $stats = $db->get_stats_by_source($since);
    $db->disconnect();

    if ( $opt{json} ) {
        print JSON::PP->new->utf8->pretty->encode($stats);
        return;
    }

    my $period = $opt{since} // '24h';
    print "TNWatch Stats (last $period)\n";
    print "=" x 50, "\n";

    for my $source ( sort keys %$stats ) {
        next if $opt{source} && $source ne $opt{source};
        printf "\n%s\n", uc($source);
        for my $etype ( sort keys %{ $stats->{$source} } ) {
            for my $sev ( sort keys %{ $stats->{$source}{$etype} } ) {
                printf "  %-30s [%-8s] %d\n", $etype, $sev,
                  $stats->{$source}{$etype}{$sev};
            }
        }
    }
}

sub cmd_add_rule {
    my ($rule_name) = @_;
    my $db = db_connect();

    die "Must specify --source\n"     unless $opt{source};
    die "Must specify --event-type\n" unless $opt{'event-type'};
    die "Must specify --threshold\n"  unless $opt{threshold};
    die "Must specify --window\n"     unless $opt{window};

    $db->add_alert_rule(
        rule_name      => $rule_name,
        source         => $opt{source},
        event_type     => $opt{'event-type'},
        threshold      => $opt{threshold},
        window_seconds => $opt{window},
        severity       => $opt{severity} // 'warning',
    );
    $db->disconnect();

    printf "Alert rule '%s' added.\n", $rule_name;
}

sub cmd_test_email {
    my %stats = (
        date      => strftime( "%Y-%m-%d", localtime ),
        since_ts  => time() - 86400,
        generated => strftime( "%Y-%m-%d %H:%M:%S", localtime ),
        _test     => 1,
        tnaudit   => {
            status        => 'VERIFIED',
            total         => 337,
            ok            => 337,
            changed       => 0,
            summary       => {},
            changed_files => []
        },
        pf => {
            pf_status    => 'Enabled',
            pf_since     => '2026-02-18',
            states       => 512,
            src_nodes    => 48,
            inserts_ps   => 12,
            removals_ps  => 8,
            churn        => 4,
            block_spikes => 0,
            table_counts => { blocklist => 130419, bogons => 46 }
        },
        httpd => { errors_4xx => 45, errors_5xx => 2, top_ips => [] },
        tnwaf => {
            rate_limits    => 3,
            pattern_blocks => 12,
            xss            => 0,
            sqli           => 0,
            suspicious     => 5
        },
        snort      => { critical => 0, high => 2, low => 8 },
        e2guardian => { blocked  => 15 },
        unbound    => { nxdomain => 234, refused => 0 },
        auth       => {
            failures      => 8,
            successes     => 3,
            doas          => 12,
            root_attempts => 0,
            top_ips       => []
        },
        services => {
            status        => 'ALL RUNNING',
            total         => 24,
            running       => 24,
            down          => 0,
            degraded      => 0,
            down_list     => [],
            degraded_list => [],
            down_events   => [],
            last_check    => strftime( "%Y-%m-%d %H:%M:%S", localtime ),
        },
    );

    print "Sending test email to root...\n";
    my $sent = TNWatchMail::send_digest( \%stats );
    if ($sent) {
        print
          "Test email sent. Check mail UI at /var/www/htdocs/tn/view/mail\n";
    }
    else {
        print "ERROR: Failed to send test email.\n";
        exit 1;
    }
}

sub cmd_purge {
    my $days = $opt{days} // 90;
    my $db   = db_connect();
    my $n    = $db->purge_old_events($days);
    $db->disconnect();
    printf "Purged %d events older than %d days.\n", $n, $days;
    log_msg("Purged $n events older than $days days");
}

sub cmd_status {
    my $db    = db_connect();
    my $dbs   = $db->get_db_stats();
    my $rules = $db->get_alert_rules();
    $db->disconnect();

    printf "TNWatch v%s -- Status\n", $VERSION;
    print "=" x 40, "\n";
    printf "Database:    %s\n", $dbs->{db_path};
    printf "DB Size:     %s\n", _format_bytes( $dbs->{db_size} );
    printf "Events:      %d\n", $dbs->{event_count};
    if ( $dbs->{oldest_ts} ) {
        printf "Oldest:      %s\n",
          strftime( "%Y-%m-%d %H:%M:%S", localtime( $dbs->{oldest_ts} ) );
        printf "Newest:      %s\n",
          strftime( "%Y-%m-%d %H:%M:%S", localtime( $dbs->{newest_ts} ) );
    }
    printf "Alert Rules: %d enabled\n", scalar(@$rules);
    print "\nAlert Rules:\n";
    for my $r (@$rules) {
        printf "  %-25s  %s/%s  threshold=%d  window=%ds\n",
          $r->{rule_name}, $r->{source}, $r->{event_type},
          $r->{threshold}, $r->{window_seconds};
    }
}

#===================================================
# INTERNAL HELPERS
#===================================================

sub db_connect {
    return TNWatchDatabase->connect($DB_PATH);
}

sub _gather_tnaudit_stats {
    my ( $db, $since ) = @_;

    # Get the most recent integrity_check event
    my $checks = $db->query_events(
        source     => 'tnaudit',
        event_type => 'integrity_check',
        limit      => 1,
    );

    my %result = (
        status  => 'UNKNOWN',
        total   => 0,
        ok      => 0,
        changed => 0,
        summary => {},
    );

    if ( $checks && @$checks ) {
        my $c = $checks->[0];
        my $d = $c->{details} // {};
        $result{total}   = $d->{total}   // 0;
        $result{changed} = $d->{changed} // 0;
        $result{ok}      = ( $result{total} - $result{changed} );
        $result{summary} = $d->{summary} // {};
        $result{status} =
          $result{changed} > 0 ? 'CHANGES DETECTED' : 'VERIFIED';
        $result{last_check} =
          strftime( "%Y-%m-%d %H:%M:%S", localtime( $c->{timestamp} ) );
    }

    # Also fetch changed file events for the digest detail
    $result{changed_files} = $db->query_events(
        source     => 'tnaudit',
        event_type => 'file_change',
        since      => $since,
        limit      => 50,
    );

    return \%result;
}

sub _gather_pf_stats {
    my ( $db, $since ) = @_;

    my $summaries = $db->query_events(
        source     => 'pf',
        event_type => 'pf_summary',
        limit      => 1,
    );

    my %result = (
        pf_status    => 'unknown',
        pf_since     => '',
        states       => 0,
        src_nodes    => 0,
        inserts_ps   => 0,
        removals_ps  => 0,
        churn        => 0,
        table_counts => {},
        block_spikes => 0,
    );

    if ( $summaries && @$summaries ) {
        my $d = $summaries->[0]{details} // {};
        $result{pf_status}    = $d->{pf_status}    // 'unknown';
        $result{pf_since}     = $d->{pf_since}     // '';
        $result{states}       = $d->{states}       // 0;
        $result{src_nodes}    = $d->{src_nodes}    // 0;
        $result{inserts_ps}   = $d->{inserts_ps}   // 0;
        $result{removals_ps}  = $d->{removals_ps}  // 0;
        $result{churn}        = $d->{churn}        // 0;
        $result{table_counts} = $d->{table_counts} // {};
    }

    $result{block_spikes} = $db->count_events(
        source     => 'pf',
        event_type => 'block_spike',
        since      => $since,
    );

    return \%result;
}

sub _gather_services_stats {
    my ( $db, $since ) = @_;

    # Get the most recent services_summary event
    my $summaries = $db->query_events(
        source     => 'services',
        event_type => 'services_summary',
        limit      => 1,
    );

    my %result = (
        status        => 'UNKNOWN',
        total         => 0,
        running       => 0,
        down          => 0,
        degraded      => 0,
        down_list     => [],
        degraded_list => [],
    );

    if ( $summaries && @$summaries ) {
        my $s = $summaries->[0];
        my $d = $s->{details} // {};
        $result{total}         = $d->{total}         // 0;
        $result{running}       = $d->{running}       // 0;
        $result{down}          = $d->{down}          // 0;
        $result{degraded}      = $d->{degraded}      // 0;
        $result{down_list}     = $d->{down_list}     // [];
        $result{degraded_list} = $d->{degraded_list} // [];
        $result{status} =
            $result{down}     ? 'SERVICES DOWN'
          : $result{degraded} ? 'DEGRADED'
          :                     'ALL RUNNING';
        $result{last_check} =
          strftime( "%Y-%m-%d %H:%M:%S", localtime( $s->{timestamp} ) );
    }

    # Also fetch individual service_down events for detail in digest
    $result{down_events} = $db->query_events(
        source     => 'services',
        event_type => 'service_down',
        since      => $since,
        limit      => 50,
    );

    return \%result;
}

sub log_msg {
    my ($msg) = @_;
    my $ts = strftime( "%Y-%m-%d %H:%M:%S", localtime );
    if ( open( my $fh, '>>', $LOG_FILE ) ) {
        print $fh "[$ts] $msg\n";
        close($fh);
    }
}

sub _format_bytes {
    my ($n) = @_;
    return sprintf "%.1f MB", $n / 1_048_576 if $n >= 1_048_576;
    return sprintf "%.1f KB", $n / 1_024     if $n >= 1_024;
    return "$n B";
}

sub usage {
    my ($exit) = @_;
    print <<'USAGE';
TNWatch v1.0 - OpenBSD Log Analysis & Alerting System
Tangent Networks | reads logs, watches services, emails digests.

USAGE:
  TNWatch.pl <command> [options]

  --help            Show this help text
  --version         Show version number

DATABASE
  --init-db
      Create or migrate the TNWatch SQLite database.
      Safe to run on an existing database -- no data is lost.
      Run after first install or after upgrading TNWatch.

        TNWatch.pl --init-db

PARSING
  --parse <source>
      Parse one log source and write new events to the database.
      TNWatch remembers the last position in each file so re-running
      is safe -- already-seen events are never duplicated.

      Sources:
        tnaudit       File integrity results (reads TNAudit DB)
        pf            Packet filter counters (pfctl -si)
        authlog       Authentication log (/var/log/authlog)
        httpd         HTTPD error log
        snort         Snort IDS alerts
        e2guardian    Web filter blocks
        unbound       DNS resolver log
        tnwaf         WAF access and security logs
        syslog        System log (/var/log/messages)
        services      Service health (services.json)

        TNWatch.pl --parse authlog
        TNWatch.pl --parse tnaudit

  --parse-all
      Parse every source in sequence. This is what cron runs every
      5 minutes.

        TNWatch.pl --parse-all

QUERYING EVENTS
  --query [options]
      Query the event database. Without filters returns the last 24h.

      --source <n>          Filter by log source (see sources above)
      --event-type <type>   Filter by event type
                            e.g. auth_failure, pf_summary, integrity_check
      --severity <level>    info | warning | critical
      --since <Xh|Xd>       Look back X hours or days e.g. 6h, 2d
      --src-ip <ip>         Filter by source IP address
      --limit <n>           Max results (default: 100)
      --json                Output as JSON

        TNWatch.pl --query --source authlog --severity critical
        TNWatch.pl --query --source pf --event-type block_spike
        TNWatch.pl --query --source tnaudit --since 7d --json
        TNWatch.pl --query --src-ip 203.0.113.42
        TNWatch.pl --query --severity critical --since 24h --limit 50

STATISTICS
  --stats [options]
      Print event counts grouped by source and severity.

      --source <n>      Limit to one source
      --since <Xh|Xd>   Time window (default: 24h)
      --json            Output as JSON

        TNWatch.pl --stats
        TNWatch.pl --stats --since 7d
        TNWatch.pl --stats --source tnwaf --since 48h --json

ALERTS
  --check-alerts
      Evaluate all alert rules against recent events. Sends an
      immediate email for any rule whose threshold has been crossed.
      Cron runs this after every --parse-all.

        TNWatch.pl --check-alerts

  --add-rule <name> --source <s> --event-type <e>
                    --threshold <n> --window <secs> [--severity <level>]
      Add a custom alert rule to the database.

      --source        Log source to watch
      --event-type    Event type to count
      --threshold     Number of events that triggers the alert
      --window        Time window in seconds to count events within
      --severity      Minimum severity to match (default: warning)

        TNWatch.pl --add-rule ssh_brute           --source authlog --event-type auth_failure           --threshold 20 --window 300 --severity critical

        TNWatch.pl --add-rule waf_flood           --source tnwaf --event-type rate_limit           --threshold 100 --window 60

EMAIL
  --send-digest
      Build and send the daily digest email using the last 24h of
      data. Cron runs this at 06:05 each morning.

        TNWatch.pl --send-digest

  --test-email
      Send a test digest to root using live database data.
      Use after installation or config changes to verify mail
      delivery is working.

        TNWatch.pl --test-email
        # Then check: http://192.168.122.25/tn/view/mail

MAINTENANCE
  --status
      Show operational status: database path, event counts, and
      the last parse timestamp for each log source.

        TNWatch.pl --status

  --purge [--days <n>]
      Delete events older than n days (default: 90).

        TNWatch.pl --purge
        TNWatch.pl --purge --days 30

TYPICAL WORKFLOWS

  First install:
    TNWatch.pl --init-db
    TNWatch.pl --parse-all
    TNWatch.pl --test-email

  Investigate recent auth failures:
    TNWatch.pl --query --source authlog --severity critical --since 6h

  Check what fired overnight:
    TNWatch.pl --stats --since 24h

  Force an immediate digest:
    TNWatch.pl --parse-all && TNWatch.pl --send-digest

  Add a brute-force SSH alert:
    TNWatch.pl --add-rule ssh_brute       --source authlog --event-type auth_failure       --threshold 20 --window 300 --severity critical

  Weekly maintenance (also runs via cron):
    TNWatch.pl --purge --days 90

CRON SCHEDULE
  Every 5 min : --parse-all && --check-alerts
  06:00 daily : --parse-all
  06:05 daily : --send-digest
  Weekly      : --init-db

FILES
  /usr/local/sbin/TNWatch.pl              This script
  /etc/TNWatch/TNWatchParser.pm           Log parsers
  /etc/TNWatch/TNWatchDatabase.pm         Database layer
  /etc/TNWatch/TNWatchMail.pm             Email renderer
  /var/www/htdocs/tn/data/db/TNWatch.db   Event database
  /var/log/tnwatch.log                    Cron output log

USAGE
    exit $exit;
}

sub version {
    print "TNWatch v$VERSION\n";
    exit 0;
}

__END__

=head1 NAME

TNWatch.pl - OpenBSD log analysis and email alerting CLI

=head1 SYNOPSIS

See --help for full usage.

=head1 CRONTAB SETUP

    # /etc/crontab
    # Check alerts every 5 minutes
    */5  *  *  *  *  root  /usr/local/sbin/TNWatch.pl --parse-all && \
                            /usr/local/sbin/TNWatch.pl --check-alerts

    # Daily digest at 6 AM
    0    6  *  *  *  root  /usr/local/sbin/TNWatch.pl --send-digest

    # Weekly purge of events > 90 days
    0    0  *  *  0  root  /usr/local/sbin/TNWatch.pl --purge --days 90

=cut
