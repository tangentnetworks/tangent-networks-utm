#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# TNWatch Test Suite
# /usr/local/sbin/TNWatch_test.pl
# Run as root: perl -T /usr/local/sbin/TNWatch_test.pl

use strict;
use warnings;
use lib '/etc/TNWatch';
use POSIX qw(strftime);

BEGIN {
    $ENV{PATH} = '/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
}

# ==========================================================
# HARNESS
# ==========================================================

my ( $pass, $fail, $skip ) = ( 0, 0, 0 );
my @failures;

sub ok {
    my ( $label, $result, $detail ) = @_;
    if ($result) {
        printf "  [OK]   %s\n", $label;
        $pass++;
    }
    else {
        printf "  [FAIL] %s%s\n", $label, ( $detail ? " -- $detail" : '' );
        $fail++;
        push @failures, $label . ( $detail ? ": $detail" : '' );
    }
}

sub skip_test {
    my ( $label, $reason ) = @_;
    printf "  [SKIP] %s (%s)\n", $label, $reason;
    $skip++;
}

sub section {
    my ($title) = @_;
    print "\n# == $title ==\n";
}

sub note {
    printf "         %s\n", $_[0];
}

print "\n";
print "# ==========================================\n";
print "#  TNWatch Test Suite\n";
printf "#  %s\n", strftime( "%Y-%m-%d %H:%M:%S", localtime );
print "# ==========================================\n";

# ==========================================================
# 1. PERL MODULE DEPENDENCIES
# ==========================================================
section("1. Perl Module Dependencies");

for my $mod (qw(DBI DBD::SQLite JSON::PP POSIX Getopt::Long)) {
    my $ok = eval "require $mod; 1";
    ok( "use $mod", $ok, $@ );
}
ok( "Perl version >= 5.14", $] >= 5.014, "got $]" );

# ==========================================================
# 2. TNWATCH MODULE LOADS
# ==========================================================
section("2. TNWatch Module Loads");

my $db_mod_ok = eval { require TNWatchDatabase; 1 };
ok( "use TNWatchDatabase", $db_mod_ok, $@ );

my $parser_mod_ok = eval { require TNWatchParser; 1 };
ok( "use TNWatchParser", $parser_mod_ok, $@ );

my $mail_mod_ok = eval { require TNWatchMail; 1 };
ok( "use TNWatchMail", $mail_mod_ok, $@ );

# ==========================================================
# 3. LOG FILE / DATA PATHS
# ==========================================================
section("3. Log File / Data Paths");

my %paths = (
    'TNAudit DB'       => '/var/www/htdocs/tn/data/db/TNAudit.db',
    'HTTPD error log'  => '/var/www/htdocs/tn/data/logs/httpd/httpd_error.log',
    'WAF access log'   => '/var/www/htdocs/tn/data/logs/waf/access.log',
    'WAF security log' => '/var/www/htdocs/tn/data/logs/waf/security.log',
    'WAF error log'    => '/var/www/htdocs/tn/data/logs/waf/error.log',
    'Snort alert log'  => '/var/www/htdocs/tn/data/logs/snort/alert.log',
    'E2Guardian log'   => '/var/www/htdocs/tn/data/logs/e2guardian/access.log',
    'Unbound log'      => '/var/www/htdocs/tn/data/logs/unbound/unbound.log',
    'Syslog messages'  => '/var/www/htdocs/tn/data/logs/system/messages',
    'Syslog daemon'    => '/var/www/htdocs/tn/data/logs/system/daemon',
    'authlog'          => '/var/log/authlog',
    'services.json'    => '/var/www/htdocs/tn/data/logs/bootlog/services.json',
    'TNWatch DB dir'   => '/var/www/htdocs/tn/data/db',
);

# Logs that may not exist yet (created on first use) are skipped rather
# than failed -- WAF error log only appears after TNWAF.pm is deployed.
my %optional_paths = map { $_ => 1 } ( 'WAF error log', );

for my $label ( sort keys %paths ) {
    my $path = $paths{$label};
    if    ( -d $path ) { ok( "$label (dir exists)", 1 ) }
    elsif ( -f $path ) {
        ok( "$label (readable, " . ( -s $path ) . "B)",
            -r $path, "not readable" );
    }
    elsif ( $optional_paths{$label} ) {
        skip_test( "$label", "not yet created" );
    }
    else { ok( "$label exists", 0, "missing: $path" ) }
}
ok( "TNWatch.pl executable", -x '/usr/local/sbin/TNWatch.pl' );

# ==========================================================
# 4. PFCTL COMMANDS
# ==========================================================
section("4. pfctl Commands");

# TNWatch reads pfctl -si directly (independent of pf_stats.json)
my %pf_si;
open( my $pfsi, '-|', '/sbin/pfctl', '-si' ) or do {
    ok( "pfctl -si runs", 0, "cannot open: $!" );
    goto PF_DONE;
};
while (<$pfsi>) {
    if (/current entries\s+(\d+)/) { $pf_si{current}  = int($1) }
    if (/searches\s+(\d+)/)        { $pf_si{searches} = int($1) }
    if (/inserts\s+(\d+)/)         { $pf_si{inserts}  = int($1) }
    if (/removals\s+(\d+)/)        { $pf_si{removals} = int($1) }
}
close $pfsi;
ok( "pfctl -si runs",            %pf_si > 0 );
ok( "pfctl -si has state count", defined $pf_si{current} );
ok( "pfctl -si has inserts",     defined $pf_si{inserts} );
note(
    sprintf "states: %d, inserts: %d, removals: %d",
    $pf_si{current}  // 0,
    $pf_si{inserts}  // 0,
    $pf_si{removals} // 0
);
PF_DONE:

my $pfctl_info = qx{/sbin/pfctl -s info 2>/dev/null};
ok( "pfctl -s info runs",      $pfctl_info =~ /\w/ );
ok( "pfctl has state entries", $pfctl_info =~ /current entries/ );

my $pfctl_tables = qx{/sbin/pfctl -s Tables 2>/dev/null};
ok( "pfctl -s Tables runs", defined $pfctl_tables );
my @tables = ( $pfctl_tables =~ /^(\S+)/mg );
note( "tables: " . ( @tables ? join( ', ', @tables ) : 'none' ) );

# ==========================================================
# 5. DATABASE
# ==========================================================
section("5. TNWatchDatabase");

my $test_db = "/tmp/tnwatch_test_$$.db";
my $db;

if ($db_mod_ok) {
    $db = eval { TNWatchDatabase->connect($test_db) };
    ok( "DB connect", $db, $@ );

    if ($db) {
        ok( "init_schema()", eval { $db->init_schema(); 1 }, $@ );

        my $id = eval {
            $db->insert_event(
                source     => 'test',
                event_type => 'unit_test',
                severity   => 'info',
                timestamp  => time(),
                src_ip     => '192.0.2.1',
                message    => 'TNWatch test event',
            );
        };
        ok( "insert_event()", $id && $id > 0, $@ );

        my $events = eval { $db->query_events( source => 'test', limit => 5 ) };
        ok( "query_events()", $events && @$events > 0, $@ );
        ok( "event data intact",
            $events && $events->[0]{message} eq 'TNWatch test event' );

        my $count = eval {
            $db->insert_events_bulk(
                map {
                    {
                        source     => 'test',
                        event_type => 'bulk',
                        severity   => 'info',
                        timestamp  => time(),
                        message    => "bulk $_"
                    }
                } 1 .. 5
            );
            $db->count_events( source => 'test' );
        };
        ok( "insert_events_bulk()", ( $count // 0 ) >= 6, "count=$count" );

        my $rules = eval { $db->get_alert_rules() };
        ok(
            "alert rules seeded",
            $rules && @$rules >= 7,
            "got " . scalar( @{ $rules // [] } ) . " rules"
        );
        note( "rules: "
              . join( ', ', map { $_->{rule_name} } @{ $rules // [] } ) );

        eval {
            $db->update_parse_state(
                'test',
                last_pos => 42,
                last_ts  => time()
            );
        };
        my $ps = eval { $db->get_parse_state('test') };
        ok( "parse_state roundtrip", $ps && $ps->{last_pos} == 42, $@ );

        $db->disconnect;
    }
}
else {
    skip_test( "Database tests", "TNWatchDatabase failed to load" );
}

# ==========================================================
# 6. PARSERS
# ==========================================================
section("6. TNWatchParser -- each source");

if ($parser_mod_ok) {
    my $parser = TNWatchParser->new( verbose => 0 );
    my $state  = { last_pos => 0, last_ts => 0 };

    # TNAudit
    if ( -f '/var/www/htdocs/tn/data/db/TNAudit.db' ) {
        my ( $ev, $ns ) = eval { $parser->parse( 'tnaudit', $state ) };
        ok( "parse_tnaudit runs", !$@, $@ );
        ok( "tnaudit returns arrayref", ref($ev) eq 'ARRAY' );
        my $sum =
          $ev
          ? ( grep { $_->{event_type} eq 'integrity_check' } @$ev )[0]
          : undef;
        ok( "tnaudit integrity_check event", $sum );
        if ($sum) {
            my $d = ref( $sum->{details} ) eq 'HASH' ? $sum->{details} : {};
            note(
                sprintf "TNAudit: %d total, %d issues",
                $d->{total}   // 0,
                $d->{changed} // 0
            );
        }
    }
    else {
        skip_test( "parse_tnaudit", "TNAudit.db not found" );
    }

    # PF counters
    {
        my ( $ev, $ns ) = eval { $parser->parse( 'pf', $state ) };
        ok( "parse_pf_counters runs", !$@, $@ );
        my $sum =
          $ev ? ( grep { $_->{event_type} eq 'pf_summary' } @$ev )[0] : undef;
        ok( "pf_summary event emitted", $sum );
        if ($sum) {
            my $d = ref( $sum->{details} ) eq 'HASH' ? $sum->{details} : {};
            note(
                sprintf "PF: %d blocks, %d passes, %d states",
                $d->{blocks} // 0,
                $d->{passes} // 0,
                $d->{states} // 0
            );
            if ( %{ $d->{table_counts} // {} } ) {
                note(
                    "tables: "
                      . join( ', ',
                        map { "$_=$d->{table_counts}{$_}" }
                        sort keys %{ $d->{table_counts} } )
                );
            }
        }
    }

    # Text log parsers
    my %text_sources = (
        authlog        => '/var/log/authlog',
        daemon         => '/var/www/htdocs/tn/data/logs/system/daemon',
        e2guardian     => '/var/www/htdocs/tn/data/logs/e2guardian/access.log',
        httpd          => '/var/www/htdocs/tn/data/logs/httpd/httpd_error.log',
        snort          => '/var/www/htdocs/tn/data/logs/snort/alert.log',
        syslog         => '/var/www/htdocs/tn/data/logs/system/messages',
        tnwaf_access   => '/var/www/htdocs/tn/data/logs/waf/access.log',
        tnwaf_error    => '/var/www/htdocs/tn/data/logs/waf/error.log',
        tnwaf_security => '/var/www/htdocs/tn/data/logs/waf/security.log',
        unbound        => '/var/www/htdocs/tn/data/logs/unbound/unbound.log',
    );

    for my $src ( sort keys %text_sources ) {
        my $path = $text_sources{$src};
        if ( !-f $path ) { skip_test( "parse_$src", "not found" ); next }
        my ( $ev, $ns ) = eval { $parser->parse( $src, $state ) };
        ok( "parse_$src (" . scalar( @{ $ev // [] } ) . " events)", !$@, $@ );
    }

    # Services
    if ( -f '/var/www/htdocs/tn/data/logs/bootlog/services.json' ) {
        my ( $ev, $ns ) =
          eval { $parser->parse( 'services', { last_pos => 0, last_ts => 0 } ) };
        ok( "parse_services runs", !$@, $@ );
        my $sum =
          $ev
          ? ( grep { $_->{event_type} eq 'services_summary' } @$ev )[0]
          : undef;
        ok( "services_summary event",  $sum );
        ok( "services mtime in state", $ns && ( $ns->{last_ts} // 0 ) > 0 );
        if ($sum) {
            my $d = eval {
                require JSON::PP;
                JSON::PP::decode_json( $sum->{details} );
            } // {};
            note(
                sprintf "Services: %d/%d running, %d down, %d degraded",
                $d->{running}  // 0,
                $d->{total}    // 0,
                $d->{down}     // 0,
                $d->{degraded} // 0
            );
            note( "down: " . join( ', ', @{ $d->{down_list} // [] } ) )
              if @{ $d->{down_list} // [] };
            note( "degraded: " . join( ', ', @{ $d->{degraded_list} // [] } ) )
              if @{ $d->{degraded_list} // [] };
            note(
                "high_mem: "
                  . join( ', ',
                    map { "$_->{name} ($_->{mem}%)" }
                      @{ $d->{high_mem} // [] } )
            ) if @{ $d->{high_mem} // [] };
        }

     # Verify mtime gate works -- second parse with same mtime returns no events
        if ($ns) {
            my ( $ev2, $ns2 ) = eval { $parser->parse( 'services', $ns ) };
            ok(
                "services mtime gate (no duplicate events)",
                !$@ && scalar( @{ $ev2 // [] } ) == 0,
                "got " . scalar( @{ $ev2 // [] } ) . " events on second parse"
            );
        }
    }
    else {
        skip_test( "parse_services", "services.json not found" );
    }

}
else {
    skip_test( "Parser tests", "TNWatchParser failed to load" );
}

# ==========================================================
# 7. PARSER UNIT TESTS (synthetic data, no live files needed)
# ==========================================================
section("7. Parser unit tests -- synthetic data");

if ($parser_mod_ok) {
    require File::Temp;
    require JSON::PP;
    my $parser = TNWatchParser->new( verbose => 0 );
    my $state0 = { last_pos => 0, last_ts => 0 };

    # -- parse_tnwaf_error ----------------------------------------
    {
        my $tmp = File::Temp->new( SUFFIX => '.log', UNLINK => 1 );
        print $tmp
"[Mon Feb 24 14:10:57 2026] HTTP 429 Too Many Requests - IP=1.2.3.4 URI=/cgi-bin/test.pl\n";
        print $tmp
"[Mon Feb 24 14:11:02 2026] HTTP 400 Bad Request - IP=5.6.7.8 URI=/view/home\n";
        print $tmp
"[Mon Feb 24 14:11:10 2026] HTTP 404 Not Found - IP=9.9.9.9 URI=/admin/config.php\n";
        print $tmp
"[Mon Feb 24 14:11:15 2026] HTTP 500 Internal Server Error - IP=1.1.1.1 URI=/cgi-bin/status.pl\n";
        $tmp->flush;

        my $p2 =
          TNWatchParser->new( paths => { tnwaf_error => $tmp->filename } );
        my ( $ev, $ns ) = eval { $p2->parse( 'tnwaf_error', $state0 ) };
        ok( "parse_tnwaf_error runs", !$@, $@ );
        ok( "tnwaf_error: 429 rate_limit",
            $ev && grep { $_->{event_type} eq 'rate_limit' } @$ev );
        ok( "tnwaf_error: 400 bad_request",
            $ev && grep { $_->{event_type} eq 'bad_request' } @$ev );
        ok(
            "tnwaf_error: 404 suspicious URI caught",
            $ev && grep {
                $_->{event_type} eq '4xx_error' && $_->{message} =~ /admin/
            } @$ev
        );
        ok(
            "tnwaf_error: 500 5xx_error critical",
            $ev && grep {
                $_->{event_type} eq '5xx_error' && $_->{severity} eq 'critical'
            } @$ev
        );
        ok( "tnwaf_error: src_ip captured",
            $ev && grep { ( $_->{src_ip} // '' ) eq '1.2.3.4' } @$ev );
        ok(
            "tnwaf_error: incremental state",
            $ns && ( $ns->{last_pos} // 0 ) > 0
        );
    }

    # -- parse_daemon ---------------------------------------------
    {
        my $tmp = File::Temp->new( SUFFIX => '.log', UNLINK => 1 );
        print $tmp
"Feb 24 14:00:01 fw smtpd[9696]: delivery failed for user\@example.com\n";
        print $tmp
          "Feb 24 14:00:02 fw ntpd[43035]: lost sync with 203.0.113.1\n";
        print $tmp
          "Feb 24 14:00:03 fw dhcpd[32057]: no free leases -- exhausted\n";
        print $tmp
          "Feb 24 14:00:04 fw unbound[14772]: SERVFAIL from upstream 8.8.8.8\n";
        print $tmp
"Feb 24 14:00:05 fw collectd[58010]: plugin load error: no such module\n";
        print $tmp
          "Feb 24 14:00:06 fw ntpd[43035]: peer 203.0.113.1 now invalid\n";
        print $tmp
          "Feb 24 14:00:07 fw smtpd[9696]: delivery ok for postmaster\n";
        print $tmp "Feb 24 14:00:08 fw dhcpd[32057]: DHCPACK 10.0.2.5\n";
        $tmp->flush;

        my $p2 = TNWatchParser->new( paths => { daemon => $tmp->filename } );
        my ( $ev, $ns ) = eval { $p2->parse( 'daemon', $state0 ) };
        ok( "parse_daemon runs", !$@, $@ );
        ok( "daemon: smtp_error captured",
            $ev && grep { $_->{event_type} eq 'smtp_error' } @$ev );
        ok( "daemon: ntp lost sync captured",
            $ev && grep { $_->{event_type} eq 'ntp_error' } @$ev );
        ok( "daemon: dhcp exhausted captured",
            $ev && grep { $_->{event_type} eq 'dhcp_error' } @$ev );
        ok( "daemon: dns SERVFAIL captured",
            $ev && grep { $_->{event_type} eq 'dns_error' } @$ev );
        ok( "daemon: collectd error captured",
            $ev && grep { $_->{event_type} eq 'collectd_error' } @$ev );
        my $noise =
          grep { $_->{message} =~ /now invalid|delivery ok|DHCPACK/ } @$ev;
        ok(
            "daemon: noise lines suppressed",
            $noise == 0,
            "got $noise noise events"
        );
        note(
            sprintf
              "daemon: %d signal events from 8 lines (3 noise suppressed)",
            scalar @$ev
        );
    }

    # -- parse_services aggregated + high_mem ---------------------
    {
        require JSON::PP;
        my $svc_data = {
            timestamp => "2026-02-25T10:00:00+0530",
            services  => {
                httpd => {
                    type         => 'standalone',
                    status       => 'running',
                    display_name => 'httpd',
                    pid          => '1234',
                    mem          => '0.1',
                    cpu          => '0.0',
                    rss          => '3096',
                    vsz          => '1664',
                    user         => 'www',
                    command      => 'httpd',
                    listeners    => [],
                    arguments    => 'httpd: logger',
                },
                clamd => {
                    type         => 'standalone',
                    status       => 'running',
                    display_name => 'clamd',
                    pid          => '23345',
                    mem          => '11.7',
                    cpu          => '0.0',
                    rss          => '976444',
                    vsz          => '998884',
                    user         => '_clamav',
                    command      => 'clamd',
                    listeners    => [],
                    arguments    => '/usr/local/sbin/clamd',
                },
                smtpd => {
                    type         => 'standalone',
                    status       => 'stopped',
                    display_name => 'smtpd',
                    pid          => undef,
                    mem          => '0.0',
                    cpu          => '0.0',
                    rss          => '0',
                    vsz          => '0',
                    user         => '_smtpd',
                    command      => 'smtpd',
                    listeners    => [],
                    arguments    => 'smtpd',
                },
                pmacct => {
                    type               => 'aggregated',
                    status             => 'running',
                    display_name       => 'pmacct',
                    aggregated_metrics => {
                        all_running   => JSON::PP::false(),
                        running_count => 2,
                        total_count   => 3,
                        total_mem     => '0.30',
                        total_rss     => 18948,
                        total_vsz     => 23892,
                        total_cpu     => '0.00',
                    },
                    subprocesses => [
                        {
                            key          => 'pmacct_egress_json_log',
                            display_name => 'pmacct egress log',
                            status       => 'running',
                            mem          => '0.1',
                            cpu          => '0.0',
                            pid          => '26548',
                            rss          => '5660',
                            vsz          => '5916',
                            user         => 'root',
                            command      => 'pmacctd',
                            arguments    => 'pmacctd: Core Process',
                            listeners    => []
                        },
                        {
                            key          => 'pmacct_egress_json_mfs',
                            display_name => 'pmacct egress pipe',
                            status       => 'running',
                            mem          => '0.1',
                            cpu          => '0.0',
                            pid          => '56137',
                            rss          => '6644',
                            vsz          => '8988',
                            user         => 'root',
                            command      => 'pmacctd',
                            arguments    => 'pmacctd: Core Process',
                            listeners    => []
                        },
                        {
                            key          => 'pmacct_ingress_json_mfs',
                            display_name => 'pmacct ingress pipe',
                            status       => 'stopped',
                            mem          => '0.0',
                            cpu          => '0.0',
                            pid          => undef,
                            rss          => '0',
                            vsz          => '0',
                            user         => 'root',
                            command      => 'pmacctd',
                            arguments    => 'pmacctd: Core Process',
                            listeners    => []
                        },
                    ],
                },
            },
        };

        my $tmp = File::Temp->new( SUFFIX => '.json', UNLINK => 1 );
        print $tmp JSON::PP->new->encode($svc_data);
        $tmp->flush;

        my $p2 = TNWatchParser->new( paths => { services => $tmp->filename } );
        my ( $ev, $ns ) = eval { $p2->parse( 'services', $state0 ) };
        ok( "parse_services synthetic runs", !$@, $@ );
        ok(
            "services: service_down for smtpd",
            $ev && grep {
                     $_->{event_type} eq 'service_down'
                  && $_->{message} =~ /smtpd/i
            } @$ev
        );
        ok(
            "services: service_degraded for pmacct",
            $ev && grep {
                     $_->{event_type} eq 'service_degraded'
                  && $_->{message} =~ /pmacct/i
            } @$ev
        );
        ok(
            "services: degraded msg shows failed subprocess",
            $ev && grep {
                     $_->{event_type} eq 'service_degraded'
                  && $_->{message} =~ /ingress/
            } @$ev
        );
        ok(
            "services: service_high_mem for clamd (11.7%)",
            $ev && grep {
                     $_->{event_type} eq 'service_high_mem'
                  && $_->{message} =~ /clamd/i
            } @$ev
        );
        ok(
            "services: no high_mem for httpd (0.1%)",
            !grep {
                     $_->{event_type} eq 'service_high_mem'
                  && $_->{message} =~ /httpd/i
            } @{ $ev // [] }
        );
        ok( "services: services_summary present",
            $ev && grep { $_->{event_type} eq 'services_summary' } @$ev );

        my ($sum) =
          grep { $_->{event_type} eq 'services_summary' } @{ $ev // [] };
        if ($sum) {
            my $d = eval { JSON::PP::decode_json( $sum->{details} ) } // {};
            ok( "services: summary total=4",    ( $d->{total}    // 0 ) == 4 );
            ok( "services: summary down=1",     ( $d->{down}     // 0 ) == 1 );
            ok( "services: summary degraded=1", ( $d->{degraded} // 0 ) == 1 );
            ok(
                "services: high_mem in summary",
                scalar( @{ $d->{high_mem} // [] } ) >= 1
            );
        }

        my ($ev2) = eval { $p2->parse( 'services', $ns ) };
        ok(
            "services: mtime gate prevents re-parse",
            !$@ && scalar( @{ $ev2 // [] } ) == 0,
            "got " . scalar( @{ $ev2 // [] } ) . " events on re-parse"
        );
    }

}
else {
    skip_test( "Parser unit tests", "TNWatchParser failed to load" );
}

# ==========================================================
# 8. MAIL RENDERING (no send)
# ==========================================================
section("8. TNWatchMail -- HTML rendering");

if ($mail_mod_ok) {
    my %s = (
        date      => strftime( "%Y-%m-%d",          localtime ),
        generated => strftime( "%Y-%m-%d %H:%M:%S", localtime ),
        _test     => 1,
        tnaudit   => {
            status        => 'VERIFIED',
            total         => 337,
            ok            => 337,
            changed       => 0,
            summary       => {},
            changed_files => [],
            last_check    => '2026-02-18 05:30:00'
        },
        pf => {
            blocks       => 78901,
            passes       => 377888,
            delta_blocks => 23,
            states       => 1234,
            block_spikes => 0,
            bad_offset   => 0,
            memory_err   => 0,
            table_counts => { blocklist => 130419, bogons => 46 }
        },
        httpd => {
            errors_4xx => 45,
            errors_5xx => 2,
            top_ips    => [ { src_ip => '203.0.113.45', count => 12 } ]
        },
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
            top_ips       => [ { src_ip => '198.51.100.7', count => 8 } ]
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
            last_check    => strftime( "%Y-%m-%d %H:%M:%S", localtime )
        },
    );

    my $dhtml = eval { TNWatchMail::_render_digest_html( \%s ) };
    ok( "digest HTML renders",        !$@, $@ );
    ok( "digest has TNAudit section", ( $dhtml // '' ) =~ /TNAudit/ );
    ok( "digest has PF section",      ( $dhtml // '' ) =~ /Packet Filter/ );
    ok( "digest has dark mode CSS",
        ( $dhtml // '' ) =~ /prefers-color-scheme/ );
    ok( "digest has responsive tables", ( $dhtml // '' ) =~ /table-wrap/ );
    note( sprintf "Digest HTML: %d bytes", length( $dhtml // '' ) );

    my $dtext = eval { TNWatchMail::_render_digest_text( \%s ) };
    ok( "digest text renders", !$@, $@ );
    ok( "digest text has sections", ( $dtext // '' ) =~ /FILE INTEGRITY/ );

    my $ahtml = eval {
        TNWatchMail::_render_alert_html(
            'auth_failures',
            {
                rule => {
                    source         => 'authlog',
                    event_type     => 'auth_failure',
                    severity       => 'warning',
                    threshold      => 5,
                    window_seconds => 600
                },
                count  => 12,
                events => [
                    {
                        id         => 1,
                        source     => 'authlog',
                        event_type => 'auth_failure',
                        severity   => 'warning',
                        timestamp  => time() - 60,
                        src_ip     => '198.51.100.7',
                        message    => "SSH auth failure from 198.51.100.7"
                    }
                ],
            }
        );
    };
    ok( "alert HTML renders", !$@, $@ );
    ok( "alert HTML has IP data", ( $ahtml // '' ) =~ /198\.51/ );
    note( sprintf "Alert HTML: %d bytes", length( $ahtml // '' ) );

    # Test with changes detected
    $s{tnaudit}{changed}       = 2;
    $s{tnaudit}{status}        = 'CHANGES DETECTED';
    $s{tnaudit}{changed_files} = [
        {
            message =>
              'TNAudit: MODIFIED -- /var/www/htdocs/tn/cgi-bin/control.pl',
            severity => 'critical',
            details  => { new_sha256 => 'def456abc789', status => 'modified' },
        }
    ];
    my $dhtml2 = eval { TNWatchMail::_render_digest_html( \%s ) };
    ok( "digest with changes renders", !$@, $@ );
    ok(
        "digest shows CHANGES DETECTED",
        ( $dhtml2 // '' ) =~ /CHANGES DETECTED/
    );

}
else {
    skip_test( "Mail rendering tests", "TNWatchMail failed to load" );
}

# ==========================================================
# 8. CLI SMOKE TESTS
# ==========================================================
section("8. TNWatch.pl CLI");

# Untaint fixed executable paths for taint mode.
# These are literal constants -- the regex is just Perl's
# mechanism for producing an untainted copy of a known-safe string.
my ($tw)      = ( '/usr/local/sbin/TNWatch.pl' =~ /^([\w\/.-]+)$/ );
my ($sqlite3) = ( '/usr/local/bin/sqlite3'     =~ /^([\w\/.-]+)$/ );
my ($tnwatch_db) =
  ( '/var/www/htdocs/tn/data/db/TNWatch.db' =~ /^([\w\/.-]+)$/ );

if ( -x $tw ) {
    ok( "--version", qx{$tw --version 2>&1} =~ /TNWatch/ );
    ok( "--help", qx{$tw --help    2>&1} =~ /usage|--parse|--query|options/i );

    # Remove stale DB if events table is missing, then re-init.
    # Safe to delete: TNWatch.db is rebuilt from live log sources each run.
    if ( -f $tnwatch_db ) {
        my $probe = qx{$sqlite3 $tnwatch_db "SELECT count(*) FROM events" 2>&1};
        if ( $? != 0 || $probe =~ /no such table/ ) {
            unlink $tnwatch_db;
            note("removed stale TNWatch.db (missing events table)");
        }
    }
    my $init_out = qx{$tw --init-db 2>&1};
    ok( "--init-db", $? == 0, "exit $?: $init_out" );

    ok( "--status", qx{$tw --status 2>&1} =~ /TNWatch/ );

    for my $src (qw(tnaudit pf services)) {
        next
          if $src eq 'tnaudit' && !-f '/var/www/htdocs/tn/data/db/TNAudit.db';
        next
          if $src eq 'services'
          && !-f '/var/www/htdocs/tn/data/logs/bootlog/services.json';

        # $src comes from a literal qw() list -- untaint for qx{}
        my ($safe_src) = ( $src =~ /^(\w+)$/ );
        my $out = qx{$tw --parse $safe_src 2>&1};
        ok( "--parse $src", $? == 0, "exit $?: $out" );
        note( $out =~ s/\n/ /gr ) if $out =~ /\S/;
    }

    ok( "--query --json",
        qx{$tw --query --source pf --json --limit 3 2>&1} =~ /success/ );
    ok( "--stats",        do { qx{$tw --stats --since 1h 2>&1}; $? == 0 } );
    ok( "--check-alerts", do { qx{$tw --check-alerts 2>&1};     $? == 0 } );

}
else {
    skip_test( "CLI tests", "TNWatch.pl not found" );
}

# ==========================================================
# 9. END-TO-END: --test-email
# ==========================================================
section("9. End-to-end: --test-email");

if ( defined $tw && -x $tw ) {
    print "\n  Sending test digest to root...\n";
    my $out = qx{$tw --test-email 2>&1};
    ok( "--test-email exits 0",   $? == 0,              "exit $?" );
    ok( "--test-email output OK", $out =~ /sent|mail/i, "got: $out" );
    note("Check: http://192.168.122.25/tn/view/mail");
}
else {
    skip_test( "--test-email", "TNWatch.pl not installed" );
}

# ==========================================================
# SUMMARY
# ==========================================================

print "\n# ==========================================\n";
printf "  Results: %d passed, %d failed, %d skipped\n", $pass, $fail, $skip;
print "# ==========================================\n";

if (@failures) {
    print "\nFailed:\n";
    print "  - $_\n" for @failures;
}

# glob returns tainted strings under -T; untaint each path before unlink
for my $f ( glob "/tmp/tnwatch_test_*.db" ) {
    my ($safe) = ( $f =~ m{^(/tmp/tnwatch_test_[\w.]+\.db)$} );
    unlink $safe if defined $safe;
}
exit( $fail > 0 ? 1 : 0 );
