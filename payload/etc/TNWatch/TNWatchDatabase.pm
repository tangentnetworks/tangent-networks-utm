package TNWatchDatabase;

# TNWatch - Database Operations Module
# /etc/TNWatch/TNWatchDatabase.pm
#
# Handles all SQLite interactions for TNWatch.
# Schema: events, alert_rules, digest_schedule

use strict;
use warnings;
use DBI;
use JSON::PP;
use POSIX qw(strftime);

my $DB_PATH = '/var/www/htdocs/tn/data/db/TNWatch.db';

# ==================================================
# CONNECTION
# ==================================================

sub connect {
    my ( $class, $path ) = @_;
    $path //= $DB_PATH;

    my $dbh = DBI->connect(
        "dbi:SQLite:dbname=$path",
        '', '',
        {
            RaiseError     => 1,
            AutoCommit     => 1,
            sqlite_unicode => 1,
        }
    ) or die "Cannot connect to TNWatch database: $DBI::errstr\n";

    # Performance tuning
    $dbh->do("PRAGMA journal_mode = WAL");
    $dbh->do("PRAGMA synchronous = NORMAL");
    $dbh->do("PRAGMA foreign_keys = ON");

    return bless { dbh => $dbh, path => $path }, $class;
}

sub dbh { return $_[0]->{dbh} }

sub disconnect {
    my ($self) = @_;
    $self->{dbh}->disconnect if $self->{dbh};
}

# ==================================================
# SCHEMA INITIALIZATION
# ==================================================

sub init_schema {
    my ($self) = @_;
    my $dbh = $self->{dbh};

    $dbh->begin_work;

    # Main events table
    $dbh->do(
        q{
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY,
            source      TEXT    NOT NULL,
            event_type  TEXT    NOT NULL,
            severity    TEXT    NOT NULL CHECK(severity IN ('info','warning','critical')),
            timestamp   INTEGER NOT NULL,
            src_ip      TEXT,
            dst_ip      TEXT,
            port        INTEGER,
            protocol    TEXT,
            message     TEXT,
            details     TEXT,
            alerted     INTEGER DEFAULT 0,
            created_at  INTEGER DEFAULT (strftime('%s','now'))
        )
    }
    );

    # Alert rules
    $dbh->do(
        q{
        CREATE TABLE IF NOT EXISTS alert_rules (
            id              INTEGER PRIMARY KEY,
            rule_name       TEXT    UNIQUE NOT NULL,
            source          TEXT    NOT NULL,
            event_type      TEXT    NOT NULL,
            threshold       INTEGER NOT NULL DEFAULT 1,
            window_seconds  INTEGER NOT NULL DEFAULT 300,
            severity        TEXT    NOT NULL DEFAULT 'warning',
            enabled         INTEGER DEFAULT 1,
            last_alerted    INTEGER DEFAULT 0
        )
    }
    );

    # Digest schedule
    $dbh->do(
        q{
        CREATE TABLE IF NOT EXISTS digest_schedule (
            id          INTEGER PRIMARY KEY,
            digest_name TEXT    UNIQUE NOT NULL,
            hour        INTEGER NOT NULL DEFAULT 6,
            minute      INTEGER NOT NULL DEFAULT 0,
            recipients  TEXT    NOT NULL DEFAULT 'root',
            enabled     INTEGER DEFAULT 1
        )
    }
    );

    # Parse state - tracks where we left off in each log file
    $dbh->do(
        q{
        CREATE TABLE IF NOT EXISTS parse_state (
            source      TEXT    PRIMARY KEY,
            last_pos    INTEGER DEFAULT 0,
            last_ts     INTEGER DEFAULT 0,
            last_run    INTEGER DEFAULT 0,
            notes       TEXT
        )
    }
    );

    # Indexes
    for my $idx (
        "CREATE INDEX IF NOT EXISTS idx_timestamp  ON events(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_source     ON events(source)",
        "CREATE INDEX IF NOT EXISTS idx_severity   ON events(severity)",
        "CREATE INDEX IF NOT EXISTS idx_src_ip     ON events(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_alerted    ON events(alerted)",
        "CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)",
      )
    {
        $dbh->do($idx);
    }

    # Seed default alert rules
    $self->_seed_alert_rules;

    # Seed default digest schedule
    $dbh->do(
        q{
        INSERT OR IGNORE INTO digest_schedule (digest_name, hour, minute, recipients)
        VALUES ('daily', 6, 0, 'root')
    }
    );

    $dbh->commit;

    return 1;
}

sub _seed_alert_rules {
    my ($self) = @_;
    my $dbh = $self->{dbh};

    my @rules = (

# rule_name             source      event_type          threshold  window  severity
        [ 'tnaudit_change',   'tnaudit', 'file_change',    1, 300, 'critical' ],
        [ 'pf_block_spike',   'pf',      'block_spike',    1, 300, 'warning' ],
        [ 'tnwaf_rate_limit', 'tnwaf',   'rate_limit',     1, 300, 'warning' ],
        [ 'snort_critical',   'snort',   'alert_critical', 1, 300, 'critical' ],
        [ 'snort_high',       'snort',   'alert_high',     1, 300, 'warning' ],
        [ 'auth_failures',    'authlog', 'auth_failure',   5, 600, 'warning' ],
        [ 'httpd_5xx_burst',  'httpd',    '5xx_error',    10, 300, 'warning' ],
        [ 'service_down',     'services', 'service_down', 1,  300, 'critical' ],
    );

    my $sth = $dbh->prepare(
        q{
        INSERT OR IGNORE INTO alert_rules
            (rule_name, source, event_type, threshold, window_seconds, severity)
        VALUES (?, ?, ?, ?, ?, ?)
    }
    );

    for my $r (@rules) {
        $sth->execute(@$r);
    }
}

# ==================================================
# EVENT CRUD
# ==================================================

sub insert_event {
    my ( $self, %e ) = @_;
    my $dbh = $self->{dbh};

    # Encode details hashref to JSON if needed
    if ( ref $e{details} eq 'HASH' || ref $e{details} eq 'ARRAY' ) {
        $e{details} = encode_json( $e{details} );
    }

    $e{timestamp} //= time();

    my $sth = $dbh->prepare(
        q{
        INSERT INTO events
            (source, event_type, severity, timestamp, src_ip, dst_ip,
             port, protocol, message, details, alerted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    }
    );

    $sth->execute(
        $e{source},  $e{event_type}, $e{severity}, $e{timestamp},
        $e{src_ip},  $e{dst_ip},     $e{port},     $e{protocol},
        $e{message}, $e{details},    $e{alerted} // 0
    );

    return $dbh->last_insert_id( '', '', 'events', 'id' );
}

sub insert_events_bulk {
    my ( $self, @events ) = @_;
    my $dbh   = $self->{dbh};
    my $count = 0;

    # Auto-migrate: if events table is missing (stale DB), re-run schema init.
    # Disable RaiseError temporarily so the probe fails gracefully.
    {
        local $dbh->{RaiseError} = 0;
        local $dbh->{PrintError} = 0;
        unless ( defined $dbh->do("SELECT 1 FROM events LIMIT 1") ) {
            $dbh->{RaiseError} = 1;
            $self->init_schema();
        }
    }

    my $sth = $dbh->prepare(
        q{
        INSERT INTO events
            (source, event_type, severity, timestamp, src_ip, dst_ip,
             port, protocol, message, details, alerted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    }
    );

    $dbh->begin_work;
    eval {
        for my $e (@events) {
            if ( ref $e->{details} eq 'HASH' || ref $e->{details} eq 'ARRAY' ) {
                $e->{details} = encode_json( $e->{details} );
            }
            $e->{timestamp} //= time();
            $sth->execute(
                $e->{source},    $e->{event_type}, $e->{severity},
                $e->{timestamp}, $e->{src_ip},     $e->{dst_ip},
                $e->{port},      $e->{protocol},   $e->{message},
                $e->{details},   $e->{alerted} // 0
            );
            $count++;
        }
        $dbh->commit;
    };
    if ($@) {
        $dbh->rollback;
        die "Bulk insert failed: $@\n";
    }

    return $count;
}

# ==================================================
# QUERYING
# ==================================================

sub query_events {
    my ( $self, %opts ) = @_;
    my $dbh = $self->{dbh};

    my @conditions;
    my @params;

    if ( $opts{source} ) {
        push @conditions, "source = ?";
        push @params,     $opts{source};
    }
    if ( $opts{event_type} ) {
        push @conditions, "event_type = ?";
        push @params,     $opts{event_type};
    }
    if ( $opts{severity} ) {

        # Support '>= warning' style or exact
        push @conditions, "severity = ?";
        push @params,     $opts{severity};
    }
    if ( $opts{src_ip} ) {
        push @conditions, "src_ip = ?";
        push @params,     $opts{src_ip};
    }
    if ( $opts{since} ) {
        my $since_ts = _parse_since( $opts{since} );
        push @conditions, "timestamp >= ?";
        push @params,     $since_ts;
    }
    if ( $opts{until} ) {
        push @conditions, "timestamp <= ?";
        push @params,     $opts{until};
    }
    if ( defined $opts{alerted} ) {
        push @conditions, "alerted = ?";
        push @params,     $opts{alerted};
    }

    my $where = @conditions  ? "WHERE " . join( " AND ", @conditions ) : "";
    my $limit = $opts{limit} ? "LIMIT $opts{limit}" : "LIMIT 1000";
    my $order = $opts{order} // "DESC";

    my $sql = "SELECT * FROM events $where ORDER BY timestamp $order $limit";
    my $sth = $dbh->prepare($sql);
    $sth->execute(@params);

    my @rows;
    while ( my $row = $sth->fetchrow_hashref ) {

        # Decode JSON details
        if ( $row->{details} ) {
            eval { $row->{details} = decode_json( $row->{details} ) };
        }
        push @rows, $row;
    }

    return \@rows;
}

sub count_events {
    my ( $self, %opts ) = @_;
    my $dbh = $self->{dbh};

    my @conditions;
    my @params;

    if ( $opts{source} ) {
        push @conditions, "source = ?";
        push @params,     $opts{source};
    }
    if ( $opts{event_type} ) {
        push @conditions, "event_type = ?";
        push @params,     $opts{event_type};
    }
    if ( $opts{severity} ) {
        push @conditions, "severity = ?";
        push @params,     $opts{severity};
    }
    if ( $opts{src_ip} ) {
        push @conditions, "src_ip = ?";
        push @params,     $opts{src_ip};
    }
    if ( $opts{since} ) {
        push @conditions, "timestamp >= ?";
        push @params,     _parse_since( $opts{since} );
    }

    my $where = @conditions ? "WHERE " . join( " AND ", @conditions ) : "";
    my ($count) = $dbh->selectrow_array( "SELECT COUNT(*) FROM events $where",
        undef, @params );
    return $count // 0;
}

sub get_top_ips {
    my ( $self, %opts ) = @_;
    my $dbh = $self->{dbh};

    my $since =
      $opts{since} ? _parse_since( $opts{since} ) : ( time() - 86400 );
    my $source = $opts{source} // '%';
    my $limit  = $opts{limit}  // 10;

    my $sth = $dbh->prepare(
        q{
        SELECT src_ip, COUNT(*) as count
        FROM events
        WHERE src_ip IS NOT NULL
          AND source LIKE ?
          AND timestamp >= ?
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT ?
    }
    );
    $sth->execute( $source, $since, $limit );
    return $sth->fetchall_arrayref( {} );
}

sub get_stats_by_source {
    my ( $self, $since_ts ) = @_;
    $since_ts //= time() - 86400;
    my $dbh = $self->{dbh};

    my $sth = $dbh->prepare(
        q{
        SELECT source, event_type, severity, COUNT(*) as count
        FROM events
        WHERE timestamp >= ?
        GROUP BY source, event_type, severity
        ORDER BY source, count DESC
    }
    );
    $sth->execute($since_ts);

    my %stats;
    while ( my $row = $sth->fetchrow_hashref ) {
        $stats{ $row->{source} }{ $row->{event_type} }{ $row->{severity} } =
          $row->{count};
    }
    return \%stats;
}

# ==================================================
# ALERT RULES
# ==================================================

sub get_alert_rules {
    my ($self) = @_;
    my $dbh = $self->{dbh};
    return $dbh->selectall_arrayref(
        "SELECT * FROM alert_rules WHERE enabled = 1",
        { Slice => {} } );
}

sub get_alert_rule {
    my ( $self, $rule_name ) = @_;
    my $dbh = $self->{dbh};
    return $dbh->selectrow_hashref(
        "SELECT * FROM alert_rules WHERE rule_name = ?",
        undef, $rule_name );
}

sub update_last_alerted {
    my ( $self, $rule_name, $ts ) = @_;
    $ts //= time();
    $self->{dbh}
      ->do( "UPDATE alert_rules SET last_alerted = ? WHERE rule_name = ?",
        undef, $ts, $rule_name );
}

sub mark_events_alerted {
    my ( $self, @ids ) = @_;
    return unless @ids;
    my $placeholders = join( ',', ('?') x @ids );
    $self->{dbh}
      ->do( "UPDATE events SET alerted = 1 WHERE id IN ($placeholders)",
        undef, @ids );
}

sub add_alert_rule {
    my ( $self, %r ) = @_;
    $self->{dbh}->do(
        q{
        INSERT OR REPLACE INTO alert_rules
            (rule_name, source, event_type, threshold, window_seconds, severity, enabled)
        VALUES (?, ?, ?, ?, ?, ?, 1)
    }, undef,
        $r{rule_name},      $r{source},                $r{event_type},
        $r{threshold} // 1, $r{window_seconds} // 300, $r{severity} // 'warning'
    );
}

# ==================================================
# PARSE STATE TRACKING
# ==================================================

sub get_parse_state {
    my ( $self, $source ) = @_;
    my $dbh = $self->{dbh};
    my $row = eval {
        $dbh->selectrow_hashref( "SELECT * FROM parse_state WHERE source = ?",
            undef, $source );
    };
    if ($@) {

        # Table missing (DB predates current schema) -- create it now
        $dbh->do(
            q{
            CREATE TABLE IF NOT EXISTS parse_state (
                source    TEXT PRIMARY KEY,
                last_pos  INTEGER DEFAULT 0,
                last_ts   INTEGER DEFAULT 0,
                last_run  INTEGER DEFAULT 0,
                notes     TEXT
            )
        }
        );
        $row = undef;
    }
    return $row
      // { source => $source, last_pos => 0, last_ts => 0, last_run => 0 };
}

sub update_parse_state {
    my ( $self, $source, %state ) = @_;
    $self->{dbh}->do(
        q{
        INSERT OR REPLACE INTO parse_state (source, last_pos, last_ts, last_run, notes)
        VALUES (?, ?, ?, ?, ?)
    }, undef,
        $source,
        $state{last_pos} // 0,
        $state{last_ts}  // 0,
        $state{last_run} // time(),
        $state{notes}
    );
}

# ==================================================
# DIGEST HELPERS
# ==================================================

sub get_digest_schedule {
    my ($self) = @_;
    return $self->{dbh}
      ->selectall_arrayref( "SELECT * FROM digest_schedule WHERE enabled = 1",
        { Slice => {} } );
}

sub get_event_summary {
    my ( $self, $since_ts ) = @_;
    $since_ts //= time() - 86400;
    my $dbh = $self->{dbh};

    my %summary;

    # Counts by source + severity
    my $sth = $dbh->prepare(
        q{
        SELECT source, severity, COUNT(*) as cnt
        FROM events
        WHERE timestamp >= ?
        GROUP BY source, severity
    }
    );
    $sth->execute($since_ts);
    while ( my $row = $sth->fetchrow_hashref ) {
        $summary{ $row->{source} }{ $row->{severity} } = $row->{cnt};
    }

    # Total
    my ($total) =
      $dbh->selectrow_array( "SELECT COUNT(*) FROM events WHERE timestamp >= ?",
        undef, $since_ts );
    $summary{_total} = $total // 0;

    return \%summary;
}

# ==================================================
# MAINTENANCE
# ==================================================

sub purge_old_events {
    my ( $self, $days ) = @_;
    $days //= 7;
    my $cutoff = time() - ( $days * 86400 );
    my $dbh    = $self->{dbh};

    my ($count) =
      $dbh->selectrow_array( "SELECT COUNT(*) FROM events WHERE timestamp < ?",
        undef, $cutoff );
    $dbh->do( "DELETE FROM events WHERE timestamp < ?", undef, $cutoff );
    return $count // 0;
}

sub get_db_stats {
    my ($self) = @_;
    my $dbh = $self->{dbh};

    my ($event_count) = $dbh->selectrow_array("SELECT COUNT(*) FROM events");
    my ($oldest) = $dbh->selectrow_array("SELECT MIN(timestamp) FROM events");
    my ($newest) = $dbh->selectrow_array("SELECT MAX(timestamp) FROM events");

    # File size
    my $size = -s $self->{path} // 0;

    return {
        event_count => $event_count // 0,
        oldest_ts   => $oldest,
        newest_ts   => $newest,
        db_size     => $size,
        db_path     => $self->{path},
    };
}

# ==================================================
# INTERNAL HELPERS
# ==================================================

sub _parse_since {
    my ($since) = @_;
    return $since if $since =~ /^\d+$/;    # Already a unix timestamp

    my $now = time();
    if ( $since =~ /^(\d+)h$/ ) { return $now - ( $1 * 3600 ) }
    if ( $since =~ /^(\d+)m$/ ) { return $now - ( $1 * 60 ) }
    if ( $since =~ /^(\d+)d$/ ) { return $now - ( $1 * 86400 ) }
    if ( $since =~ /^(\d+)w$/ ) { return $now - ( $1 * 604800 ) }

    warn "Unknown 'since' format: $since — defaulting to 24h\n";
    return $now - 86400;
}

1;

__END__

=head1 NAME

TNWatchDatabase - SQLite database operations for TNWatch

=head1 SYNOPSIS

    use TNWatchDatabase;

    my $db = TNWatchDatabase->connect();
    $db->init_schema();

    # Insert an event
    $db->insert_event(
        source     => 'pf',
        event_type => 'block',
        severity   => 'info',
        timestamp  => time(),
        src_ip     => '203.0.113.45',
        port       => 22,
        protocol   => 'tcp',
        message    => 'PF blocked SSH attempt',
    );

    # Query recent critical events
    my $events = $db->query_events(
        severity => 'critical',
        since    => '1h',
    );

    # Get stats for digest
    my $stats = $db->get_event_summary(time() - 86400);

=head1 METHODS

See inline POD. All methods die on DB error unless noted.

=cut
