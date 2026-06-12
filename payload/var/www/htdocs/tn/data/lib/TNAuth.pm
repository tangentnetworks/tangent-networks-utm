# ============================================================================
# MODULE: TNAuth.pm
# PURPOSE: User authentication, session management, registration, password
#          reset, recovery codes, and security questions.
# VERSION: 2.2.0
#
# ROLE IN THE STACK:
#   TNAuth is the identity layer. It owns the auth.db database and all
#   operations that read or write user identity data. It delegates all
#   cryptographic operations to TNSecurity and all path resolution to TNEnv.
#
# RESPONSIBILITIES:
#   1. User management     -- register_user(), delete_user(), get_user_by_*(),
#                             update_password(). First registered user becomes
#                             admin automatically.
#   2. Authentication      -- authenticate_user() verifies password via
#                             TNSecurity::verify_password(), auto-rehashes
#                             legacy SHA-256 to PBKDF2 on successful login,
#                             enforces failed-attempt lockout with auto-expiry.
#   3. Session management  -- create_session(), validate_session(),
#                             destroy_session(), cleanup_expired_sessions().
#                             Sessions stored in auth.db with INTEGER timestamps.
#   4. Registration tokens -- generate_registration_token(), validate_registration_token(),
#                             get_unused_tokens(). Admin receives 5 tokens on
#                             first registration; subsequent users need one token each.
#   5. Security questions  -- get_security_questions(), verify_security_answers().
#                             Answers are PBKDF2-hashed identically to passwords.
#   6. Recovery codes      -- verify_recovery_code(). 10 single-use codes
#                             generated per user at registration, stored as
#                             sha256_hex hashes.
#   7. Reset rate limiting -- check_reset_attempts(), clear_reset_attempts().
#                             Per-username counter in rate_limits table with
#                             configurable max attempts and lockout duration.
#
# DATABASE:
#   data/db/auth.db (SQLite, WAL mode)
#   Tables: users, sessions, security_questions, recovery_codes,
#           registration_tokens, rate_limits
#   Foreign keys enforced via PRAGMA foreign_keys = ON.
#   WAL journal mode required for concurrent slowcgi worker access.
#
# INTEGRATION:
#   Loaded by  : control.pl, TNSecurityCheck.pm
#   Depends on : TNEnv (db path), TNSecurity (all crypto), TNConfig (devel mode,
#                rate limit config, session lifetime config)
#   Does NOT load TNWAF -- auth is entirely separate from HTTP routing.
#
# AUTHOR: DAVID PETER, TANGENT NETWORKS
# ============================================================================

package TNAuth;
use strict;
use warnings;

use File::Basename;
use Cwd 'abs_path';

# Required for database interactions and path handling
use DBI;
use File::Spec;

BEGIN {
    my $lib_path = dirname(__FILE__);
    $lib_path = abs_path($lib_path) if -d $lib_path;
    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        unshift @INC, $1 unless grep { $_ eq $1 } @INC;
    }
}

use TNEnv;
use TNSecurity;
use TNConfig;

our $VERSION = '2.2.0';

# =============================================
# CHROOT-AWARE DATABASE PATH
# =============================================

sub get_auth_db_path {
    return File::Spec->catfile( TNEnv::get_db_path(), 'auth.db' );
}

# =============================================
# DATABASE CONNECTION
# =============================================

sub get_db_handle {
    my $db_path = get_auth_db_path();
    my $dsn     = "dbi:SQLite:dbname=$db_path";

    # RaiseError: die on DB failure -- prevents silent data corruption.
    # sqlite_use_immediate_transaction: avoids "database is locked" under
    # concurrent CGI writes from slowcgi worker processes.
    my $dbh = DBI->connect(
        $dsn, '', '',
        {
            RaiseError                       => 1,
            AutoCommit                       => 1,
            sqlite_use_immediate_transaction => 1,
            PrintError                       => 0
        }
    );

    die "FATAL: Database Connection Failed: $DBI::errstr\n" unless $dbh;

    # Enforce foreign key constraints -- without this pragma SQLite silently
    # ignores all ON DELETE CASCADE rules defined in schema.sql.
    $dbh->do('PRAGMA foreign_keys = ON');

    # WAL mode: one writer + concurrent readers, essential for slowcgi.
    $dbh->do('PRAGMA journal_mode = WAL');

    return $dbh;
}

# =============================================
# USER MANAGEMENT
# =============================================

# Removes user and all associated security data
sub delete_user {
    my ($user_id) = @_;
    my $dbh = get_db_handle();

    # Atomic operation: If one part fails, the whole deletion rolls back
    eval {
        $dbh->begin_work;

        # Purge security questions (Child Table)
        $dbh->do( 'DELETE FROM security_questions WHERE user_id = ?',
            undef, $user_id );

        # Purge recovery codes (Child Table)
        $dbh->do( 'DELETE FROM recovery_codes WHERE user_id = ?',
            undef, $user_id );

        # Purge active sessions (Force logout)
        $dbh->do( 'DELETE FROM sessions WHERE user_id = ?', undef, $user_id );

        # Remove the primary user record
        $dbh->do( 'DELETE FROM users WHERE id = ?', undef, $user_id );

        $dbh->commit;

        # Audit: Log the deletion to your custom system.log
        TNSecurity::log_security_event( 'info', 'USER_DELETED',
            "UID: $user_id removed by Admin" );
    };

    if ($@) {
        my $err = $@;
        $dbh->rollback;
        TNSecurity::log_security_event( 'error', 'USER_DELETE_FAILED',
            "UID: $user_id - $err" );
        return { success => 0, error => "Transaction failed: $err" };
    }

    return { success => 1 };
}

# Register new user
sub register_user {
    my ( $username, $password, $email, $security_questions, $token ) = @_;

    # Check if first user (admin) or requires token
    my $status = check_registration_status();

    unless ( $status->{is_first_user} ) {
        unless ($token) {
            return { success => 0, error => 'Registration token required' };
        }

        my $token_valid = validate_registration_token($token);
        unless ( $token_valid->{success} ) {
            return { success => 0, error => 'Invalid registration token' };
        }
    }

    my $dbh = get_db_handle();

  # Check if user exists.
  # Email uniqueness is only checked when an email was supplied -- passing undef
  # to 'OR email = ?' would match NULL = NULL (false in SQL), which is correct,
  # but passing '' would match any row with an empty email string. Guard both.
    my $existing;
    if ($email) {
        $existing = $dbh->selectrow_hashref(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            undef, $username, $email );
    }
    else {
        $existing =
          $dbh->selectrow_hashref( 'SELECT id FROM users WHERE username = ?',
            undef, $username );
    }

    if ($existing) {
        return { success => 0, error => 'Username or email already exists' };
    }

    # Hash password
    my ( $hash, $salt ) = TNSecurity::hash_password($password);

    # Determine role
    my $role = $status->{is_first_user} ? 'admin' : 'user';

    # Generate user ID
    my $user_id = TNSecurity::generate_token(16);

    # Insert user with INTEGER timestamp
    eval {
        $dbh->do(
'INSERT INTO users (id, username, email, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            undef, $user_id, $username, $email, $hash, $salt, $role, time()
        );
    };

    if ($@) {
        return { success => 0, error => "Registration failed: $@" };
    }

    # Store security questions if provided
    if ( $security_questions && ref($security_questions) eq 'ARRAY' ) {
        foreach my $qa (@$security_questions) {
            my $question = $qa->{question};
            my $answer   = $qa->{answer};

            my ( $answer_hash, $answer_salt ) =
              TNSecurity::hash_password($answer);

            $dbh->do(
'INSERT INTO security_questions (user_id, question, answer_hash, answer_salt, created_at) VALUES (?, ?, ?, ?, ?)',
                undef,
                $user_id,
                $question,
                $answer_hash,
                $answer_salt,
                time()
            );
        }
    }

    # Mark token as used if provided
    if ( $token && !$status->{is_first_user} ) {
        $dbh->do(
'UPDATE registration_tokens SET used = 1, used_at = ?, used_by = ? WHERE token = ?',
            undef, time(), $user_id, $token
        );
    }

    my @recovery_codes;
    for ( 1 .. 10 ) {
        my $code = TNSecurity::generate_token(16);    # 16 bytes = 32 hex chars
        my $code_hash = TNSecurity::hash_recovery_code($code);
        $dbh->do(
'INSERT INTO recovery_codes (user_id, code_hash, created_at, used) VALUES (?, ?, ?, 0)',
            undef, $user_id, $code_hash, time()
        );
        push @recovery_codes, $code;
    }

    # Generate registration tokens for first admin
    my @registration_tokens;
    if ( $role eq 'admin' ) {
        for ( 1 .. 5 ) {
            my $result = generate_registration_token();
            push @registration_tokens, $result->{token} if $result->{success};
        }
    }

    return {
        success             => 1,
        user_id             => $user_id,
        role                => $role,
        recovery_codes      => \@recovery_codes,
        registration_tokens => \@registration_tokens,
    };
}

sub authenticate_user {
    my ( $username, $password ) = @_;

    # DEVEL mode bypass
    if ( TNConfig::is_devel_mode() && $password eq 'DEVEL_BYPASS' ) {
        TNSecurity::log_security_event( 'warning', 'DEVEL: Auth bypassed',
            $username );
        return {
            success  => 1,
            user_id  => 'dev',
            username => $username,
            role     => 'admin'
        };
    }

    my $dbh = get_db_handle();

    my $user = $dbh->selectrow_hashref(
'SELECT id, username, password_hash, salt, role, locked, locked_until FROM users WHERE username = ?',
        undef, $username
    );

    unless ($user) {
        return { success => 0, error => 'Invalid credentials' };
    }

    # Check lockout -- auto-clear timed lockouts that have expired
    if ( $user->{locked} ) {
        my $locked_until = $user->{locked_until} // 0;
        if ( $locked_until > 0 && time() > $locked_until ) {

            # Timed lockout has expired -- clear it
            $dbh->do(
'UPDATE users SET locked = 0, locked_until = 0, failed_attempts = 0 WHERE id = ?',
                undef, $user->{id}
            );
            TNSecurity::log_security_event( 'info', 'ACCOUNT_UNLOCKED',
                "$user->{username} lockout expired, auto-cleared" );
        }
        else {
            return { success => 0, error => 'Account locked' };
        }
    }

    # Verify password
    unless (
        TNSecurity::verify_password(
            $password, $user->{password_hash},
            $user->{salt}
        )
      )
    {
        # Increment failed attempts
        $dbh->do(
'UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?',
            undef, $user->{id}
        );

  # Auto-lock if threshold reached -- floors prevent trivially bypassable config
        my $max_attempts =
          TNConfig::get_config( 'rate_limit', 'MAX_LOGIN_ATTEMPTS' ) // 5;
        my $lockout_duration =
          TNConfig::get_config( 'rate_limit', 'LOCKOUT_DURATION' ) // 1800;
        $max_attempts = 3 if $max_attempts < 3;    # floor: below 3 is unusable
        $max_attempts = 10
          if $max_attempts > 10;    # ceiling: above 10 is no protection
        $lockout_duration = 300
          if $lockout_duration < 300;    # floor: 5 min minimum
        my ($current_attempts) = $dbh->selectrow_array(
            'SELECT failed_attempts FROM users WHERE id = ?',
            undef, $user->{id} );
        if ( $current_attempts >= $max_attempts ) {
            $dbh->do(
                'UPDATE users SET locked = 1, locked_until = ? WHERE id = ?',
                undef, time() + $lockout_duration,
                $user->{id}
            );
            TNSecurity::log_security_event( 'warning', 'ACCOUNT_LOCKED',
                "$username locked after $current_attempts failed attempts" );
        }

        return { success => 0, error => 'Invalid credentials' };
    }

    # Reset failed attempts on success, update last_login
    # Transparent rehash: if the stored hash uses the legacy algorithm, upgrade
    # it to PBKDF2 now while we have the plaintext password in hand.
    if ( TNSecurity::needs_rehash( $user->{password_hash} ) ) {
        my ( $new_hash, $new_salt ) = TNSecurity::hash_password($password);
        $dbh->do( 'UPDATE users SET password_hash = ?, salt = ? WHERE id = ?',
            undef, $new_hash, $new_salt, $user->{id} );
    }

    $dbh->do(
'UPDATE users SET failed_attempts = 0, last_login = ?, login_count = login_count + 1 WHERE id = ?',
        undef, time(), $user->{id}
    );

    return {
        success  => 1,
        user_id  => $user->{id},
        username => $user->{username},
        role     => $user->{role}
    };
}

sub get_user_by_username {
    my ($username) = @_;

    my $dbh = get_db_handle();

    return $dbh->selectrow_hashref(
'SELECT id, username, email, role, created_at FROM users WHERE username = ?',
        undef, $username
    );
}

sub get_user_by_id {
    my ($user_id) = @_;

    my $dbh = get_db_handle();

    return $dbh->selectrow_hashref(
        'SELECT id, username, email, role, created_at FROM users WHERE id = ?',
        undef, $user_id
    );
}

sub update_password {
    my ( $user_id, $new_password ) = @_;

    my ( $hash, $salt ) = TNSecurity::hash_password($new_password);

    my $dbh = get_db_handle();

    eval {
        $dbh->do( 'UPDATE users SET password_hash = ?, salt = ? WHERE id = ?',
            undef, $hash, $salt, $user_id );
    };

    if ($@) {
        return { success => 0, error => "Password update failed: $@" };
    }

    return { success => 1 };
}

# =============================================
# SESSION MANAGEMENT
# =============================================

sub create_session {
    my ( $user_id, $ip, $user_agent ) = @_;

    my $session_id = TNSecurity::generate_token(32);
    my $now        = time();
    my $lifetime   = TNConfig::get_config( 'session', 'SESSION_LIFETIME' )
      // 7200;

    # Enforce floor (15 min) and ceiling (24 h) -- operator cannot misconfigure
    # the appliance into an insecure or unusable session duration
    $lifetime = 900   if $lifetime < 900;
    $lifetime = 86400 if $lifetime > 86400;
    my $expires = $now + $lifetime;

    my $dbh = get_db_handle();

    eval {
        $dbh->do(
'INSERT INTO sessions (session_id, user_id, ip_address, user_agent, created_at, last_activity, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            undef,
            $session_id,
            $user_id,
            $ip,
            $user_agent,
            $now,
            $now,
            $expires
        );
    };

    if ($@) {
        return { success => 0, error => "Session creation failed: $@" };
    }

    return { success => 1, session_id => $session_id };
}

sub validate_session {
    my ($session_id) = @_;

    return undef unless $session_id;

    my $dbh = get_db_handle();
    my $now = time();

    my $session = $dbh->selectrow_hashref(
        'SELECT s.session_id, s.user_id, s.created_at, u.username, u.role 
         FROM sessions s 
         JOIN users u ON s.user_id = u.id 
         WHERE s.session_id = ? AND s.expires_at > ?',
        undef, $session_id, $now
    );

    return undef unless $session;

    # Update last_activity
    $dbh->do( 'UPDATE sessions SET last_activity = ? WHERE session_id = ?',
        undef, $now, $session_id );

    # Calculate session age in seconds
    my $session_age = $now - $session->{created_at};

    return {
        session_id  => $session->{session_id},
        user_id     => $session->{user_id},
        username    => $session->{username},
        role        => $session->{role},
        session_age => $session_age
    };
}

sub destroy_session {
    my ($session_id) = @_;

    my $dbh = get_db_handle();

    $dbh->do( 'DELETE FROM sessions WHERE session_id = ?', undef, $session_id );

    return { success => 1 };
}

sub cleanup_expired_sessions {
    my $dbh = get_db_handle();
    my $now = time();

    my $deleted =
      $dbh->do( 'DELETE FROM sessions WHERE expires_at < ?', undef, $now );

    return { success => 1, deleted => $deleted || 0 };
}

# =============================================
# SECURITY QUESTIONS
# =============================================

sub get_security_questions {
    my ($username) = @_;

    my $dbh = get_db_handle();

    my $user =
      $dbh->selectrow_hashref( 'SELECT id FROM users WHERE username = ?',
        undef, $username );

    return [] unless $user;

    my $questions = $dbh->selectall_arrayref(
        'SELECT question FROM security_questions WHERE user_id = ?',
        { Slice => {} },
        $user->{id}
    );

    return [ map { $_->{question} } @$questions ];
}

sub verify_security_answers {
    my ( $username, $answers ) = @_;

    my $dbh = get_db_handle();

    my $user =
      $dbh->selectrow_hashref( 'SELECT id FROM users WHERE username = ?',
        undef, $username );

    return { success => 0 } unless $user;

    my $stored = $dbh->selectall_arrayref(
'SELECT question, answer_hash, answer_salt FROM security_questions WHERE user_id = ? ORDER BY id',
        { Slice => {} },
        $user->{id}
    );

    return { success => 0 } unless $stored && @$stored;

  # answers may arrive as an arrayref (positional) or hashref (by question text)
    my $answers_arr;
    if ( ref($answers) eq 'ARRAY' ) {
        $answers_arr = $answers;
    }
    else {
        # hashref keyed by question text -- convert to positional array
        $answers_arr = [ map { $answers->{ $_->{question} } } @$stored ];
    }

    return { success => 0 } unless scalar(@$answers_arr) == scalar(@$stored);

    for my $i ( 0 .. $#$stored ) {
        my $provided = $answers_arr->[$i];
        return { success => 0 } unless defined $provided && length($provided);
        unless (
            TNSecurity::verify_password(
                $provided, $stored->[$i]{answer_hash},
                $stored->[$i]{answer_salt}
            )
          )
        {
            return { success => 0 };
        }
    }

    return { success => 1 };
}

sub get_available_questions {
    return (
        'What was your first pet\'s name?',
        'What city were you born in?',
        'What is your mother\'s maiden name?',
        'What was the name of your first school?',
        'What is your favorite book?'
    );
}

# =============================================
# REGISTRATION TOKENS
# =============================================

sub check_registration_status {
    my $dbh = get_db_handle();

    my $count = $dbh->selectrow_array('SELECT COUNT(*) FROM users');

    return {
        is_first_user  => ( $count == 0 ) ? 1 : 0,
        requires_token => ( $count > 0 )  ? 1 : 0
    };
}

sub validate_registration_token {
    my ($token) = @_;

    my $dbh = get_db_handle();

    my $record = $dbh->selectrow_hashref(
        'SELECT token, used FROM registration_tokens WHERE token = ?',
        undef, $token );

    return { success => 0 } unless $record;
    return { success => 0 } if $record->{used};

    return { success => 1 };
}

sub generate_registration_token {
    my $token = TNSecurity::generate_token(16);

    my $dbh = get_db_handle();

    $dbh->do(
        'INSERT INTO registration_tokens (token, created_at) VALUES (?, ?)',
        undef, $token, time() );

    return { success => 1, token => $token };
}

sub get_unused_tokens {
    my $dbh = get_db_handle();

    my $tokens = $dbh->selectall_arrayref(
'SELECT token, created_at FROM registration_tokens WHERE used = 0 ORDER BY created_at DESC',
        { Slice => {} }
    );

    return $tokens || [];
}

# =============================================
# RECOVERY CODES
# =============================================

sub verify_recovery_code {
    my ( $username, $code ) = @_;

    my $dbh = get_db_handle();

    my $user =
      $dbh->selectrow_hashref( 'SELECT id FROM users WHERE username = ?',
        undef, $username );

    return { success => 0 } unless $user;

    my $codes = $dbh->selectall_arrayref(
'SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used = 0',
        { Slice => {} },
        $user->{id}
    );

    foreach my $record (@$codes) {

        # Recovery codes are stored as sha256_hex(code) -- hash the supplied
        # code and compare to the stored hash. TNSecurity::hash_code() keeps
        # the hashing contract in one place: sha256_hex($code).
        # timing_safe_compare is applied inside verify_recovery_hash().
        if ( TNSecurity::verify_recovery_hash( $code, $record->{code_hash} ) ) {

            # Mark as used
            $dbh->do(
                'UPDATE recovery_codes SET used = 1, used_at = ? WHERE id = ?',
                undef, time(), $record->{id}
            );
            return { success => 1 };
        }
    }

    return { success => 0 };
}

# =============================================
# PASSWORD RESET RATE LIMITING
# =============================================
# Per-username attempt counter stored in the rate_limits table.
# MAX_RESET_ATTEMPTS from security.conf (default 3).
# Blocked until blocked_until timestamp expires (LOCKOUT_DURATION seconds).

sub check_reset_attempts {
    my ($username) = @_;
    my $dbh = get_db_handle()
      or return { allowed => 0, error => 'DB unavailable' };

    my $max = TNConfig::get_config( 'rate_limit', 'MAX_RESET_ATTEMPTS' ) // 3;
    my $lockout = TNConfig::get_config( 'rate_limit', 'LOCKOUT_DURATION' )
      // 1800;
    my $now = time();

    my $row = $dbh->selectrow_hashref(
'SELECT count, blocked_until FROM rate_limits WHERE identifier = ? AND limit_type = ?',
        undef, $username, 'password_reset'
    );

    if ($row) {

        # Still blocked from a previous lockout
        if ( $row->{blocked_until} && $now < $row->{blocked_until} ) {
            return {
                allowed     => 0,
                retry_after => $row->{blocked_until} - $now
            };
        }

        # Window expired -- reset counter
        if ( $row->{count} >= $max ) {

            # If we're here blocked_until has passed; clear it
            $dbh->do(
'UPDATE rate_limits SET count = 1, blocked_until = 0, last_request = ?
                  WHERE identifier = ? AND limit_type = ?',
                undef, $now, $username, 'password_reset'
            );
            return { allowed => 1 };
        }
    }

    # Increment counter; create row if first attempt
    $dbh->do(
'INSERT INTO rate_limits (identifier, limit_type, count, window_start, violations, last_request, blocked_until)
              VALUES (?, ?, 1, ?, 0, ?, 0)
         ON CONFLICT(identifier, limit_type) DO UPDATE SET
              count        = count + 1,
              last_request = excluded.last_request',
        undef, $username, 'password_reset', $now, $now
    );

    # Re-read to get updated count
    my $updated = $dbh->selectrow_hashref(
        'SELECT count FROM rate_limits WHERE identifier = ? AND limit_type = ?',
        undef, $username, 'password_reset'
    );
    my $count = $updated ? $updated->{count} : 1;

    if ( $count > $max ) {
        my $blocked_until = $now + $lockout;
        $dbh->do(
'UPDATE rate_limits SET blocked_until = ? WHERE identifier = ? AND limit_type = ?',
            undef, $blocked_until, $username, 'password_reset'
        );
        return { allowed => 0, retry_after => $lockout };
    }

    return { allowed => 1, attempts => $count, max => $max };
}

sub clear_reset_attempts {
    my ($username) = @_;
    my $dbh = get_db_handle() or return;
    $dbh->do( 'DELETE FROM rate_limits WHERE identifier = ? AND limit_type = ?',
        undef, $username, 'password_reset' );
}

1;

__END__

=head1 NAME

TNAuth -- Chroot-aware authentication module for TNSecurity Suite

=head1 DESCRIPTION

This module handles user authentication, session management, and security
questions for the TNSecurity suite. It uses INTEGER Unix timestamps to match
the database schema.

=head1 CHANGES IN THIS VERSION

- Fixed all timestamp operations to use INTEGER Unix timestamps (time())
- Fixed column name: 'ip' -> 'ip_address' in sessions table
- Added answer_salt support in security_questions
- Added login_count increment on successful authentication
- Fixed session validation to update last_activity
- All datetime operations now compatible with INTEGER schema

=cut
