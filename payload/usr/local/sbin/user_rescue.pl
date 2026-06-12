#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ============================================================
# user_repair.pl - Taint-Safe Emergency Recovery Tool
# ============================================================
# Location: /usr/local/sbin/user_rescue.pl
#
# PURPOSE:
#   Emergency command-line tool for account recovery when the
#   web UI is inaccessible. Supports password reset and full
#   account purge with re-creation.
#
# USAGE:
#   perl -T /usr/local/sbin/user_rescue.pl
#
# REQUIREMENTS:
#   Must be run as root (database write access).
#   Must be run from the host system, not inside the chroot.
#   Services do not need to be stopped.
#
# VERSION: 2.1.0
# ============================================================

use strict;
use warnings;

# ============================================================
# TAINT-SAFE BOOTSTRAP
# Must run in BEGIN before any use statements that load TN modules.
# PATH is set here so system() calls later are safe under taint mode.
# ============================================================

BEGIN {
    # Clean environment first -- required before any external call
    $ENV{PATH} = '/bin:/usr/bin:/sbin:/usr/sbin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

    # Script lives in /usr/local/sbin -- lib path is fixed.
    my $lib_path = '/var/www/htdocs/tn/data/lib';

    unless ( -d $lib_path ) {
        die "FATAL: Library path not found: $lib_path\n";
    }

    # Untaint before adding to @INC
    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        $lib_path = $1;
        unshift @INC, $lib_path;
    }
    else {
        die "FATAL: Library path contains unsafe characters: $lib_path\n";
    }
}

use TNEnv;         # Path resolution and taint utilities
use TNSecurity;    # Password hashing, token generation
use TNAuth;        # User and session management
use TNConfig;      # DEVEL mode awareness

# ============================================================
# PREFLIGHT CHECKS
# ============================================================

# Refuse to run in DEVEL mode -- this tool resets production credentials
if ( TNConfig::is_devel_mode() ) {
    die "FATAL: DEVEL mode is active. Set DEVEL=0 in security.conf before "
      . "using this tool.\n";
}

# Verify database is writable by the current user
my $db_path = TNAuth::get_auth_db_path();
die "FATAL: Database not writable: $db_path\n"
  . "       Run as: doas -u www perl -T $0\n"
  unless -w $db_path;

# ============================================================
# MAIN MENU
# ============================================================

print "============================================================\n";
print " TN SECURITY - EMERGENCY ACCOUNT REPAIR\n";
print " Database: $db_path\n";
print "============================================================\n\n";

print "Select action:\n";
print "  [1] Reset password for existing user\n";
print "  [2] Purge and re-create user account\n";
print "  [3] Unlock locked account\n";
print "  [q] Quit\n";
print "\nChoice: ";

my $raw_choice = <STDIN>;
chomp $raw_choice;
my $choice = ( $raw_choice =~ /^([123q])$/ ) ? $1 : '';

if    ( $choice eq '1' ) { handle_reset(); }
elsif ( $choice eq '2' ) { handle_purge(); }
elsif ( $choice eq '3' ) { handle_unlock(); }
elsif ( $choice eq 'q' ) { print "Exiting.\n"; exit 0; }
else                     { die "Invalid selection. Exiting.\n"; }

# ============================================================
# ACTION: RESET PASSWORD
# ============================================================

sub handle_reset {
    my $user        = prompt_username("Username to reset password for");
    my $user_record = TNAuth::get_user_by_username($user)
      or die "ERROR: User '$user' not found in database.\n";

    print "Resetting password for: $user_record->{username} "
      . "(role: $user_record->{role})\n";

    my $new_pass = prompt_password("Enter new password");
    my $confirm  = prompt_password("Confirm new password");

    die "ERROR: Passwords do not match.\n" unless $new_pass eq $confirm;
    die "ERROR: Password must be at least 12 characters.\n"
      unless length($new_pass) >= 12;

  # Use TNAuth::update_password() -- correct hash/salt generation via TNSecurity
    my $result = TNAuth::update_password( $user_record->{id}, $new_pass );

    if ( $result->{success} ) {

        # Also clear any lockout state so the user can log in immediately
        my $dbh = TNAuth::get_db_handle();
        $dbh->do(
            'UPDATE users SET locked = 0, failed_attempts = 0 WHERE id = ?',
            undef, $user_record->{id} );
        print "\nSUCCESS: Password reset and account unlocked for '$user'.\n";
        TNSecurity::log_security_event( 'warning', 'EMERGENCY_RESET',
            "Password reset via emergency tool for user: $user" );
    }
    else {
        die "ERROR: Password reset failed: $result->{error}\n";
    }
}

# ============================================================
# ACTION: PURGE AND RE-CREATE
# ============================================================

sub handle_purge {
    my $user        = prompt_username("Username to purge and re-create");
    my $user_record = TNAuth::get_user_by_username($user)
      or die "ERROR: User '$user' not found in database.\n";

    my $role = $user_record->{role};

    print
      "\nWARNING: This will permanently delete '$user' and all associated\n";
    print "data (sessions, security questions, recovery codes) and create\n";
    print "a fresh account with the same username and role '$role'.\n\n";
    print "Type 'CONFIRM' to proceed: ";

    my $raw_conf = <STDIN>;
    chomp $raw_conf;
    die "Aborted.\n" unless $raw_conf eq 'CONFIRM';

    # Collect new password BEFORE deleting the old account.
    # If the operator miskeys the password twice we abort without touching
    # the database -- the existing account is still intact.
    my $new_pass = prompt_password("New password for '$user'");
    my $confirm  = prompt_password("Confirm new password");

    die "ERROR: Passwords do not match.\n" unless $new_pass eq $confirm;
    die "ERROR: Password must be at least 12 characters.\n"
      unless length($new_pass) >= 12;

    # Purge via TNAuth::delete_user() -- handles all child tables atomically
    my $delete_result = TNAuth::delete_user( $user_record->{id} );
    unless ( $delete_result->{success} ) {
        die "ERROR: Purge failed: $delete_result->{error}\n";
    }
    print "User '$user' purged.\n";

    # Register_user() requires a token for non-first users. Generate a
    # single-use internal token and consume it immediately. If re-creation
    # fails for any reason, mark the token as used so it cannot be
    # replayed --  and report the danger state clearly so the operator
    # knows the account no longer exists and must re-run this option.
    my $token_result = TNAuth::generate_registration_token();
    unless ( $token_result->{success} ) {

        # Account is deleted. Die loudly so the operator knows.
        die "FATAL: Account '$user' has been deleted but the internal\n"
          . "       registration token could not be generated.\n"
          . "       The account no longer exists. Re-run option [2] to\n"
          . "       recreate it.\n";
    }
    my $internal_token = $token_result->{token};

    my $reg_result = TNAuth::register_user(
        $user,           # username
        $new_pass,       # password
        '',              # email -- blank, set via UI after recovery
        [],              # security questions -- none, set via UI after recovery
        $internal_token  # consumed immediately on success
    );

    unless ( $reg_result->{success} ) {

        # Re-creation failed. Consume the token so it cannot be replayed,
        # then die with a clear operator message.
        eval {
            my $dbh = TNAuth::get_db_handle();
            $dbh->do(
'UPDATE registration_tokens SET used = 1, used_at = ?, used_by = ?
                  WHERE token = ?',
                undef, time(), 'PURGE_CLEANUP', $internal_token
            );
        };
        die "FATAL: Account '$user' was deleted but re-creation failed:\n"
          . "       $reg_result->{error}\n"
          . "       The account no longer exists. Re-run option [2] to\n"
          . "       recreate it. The internal token has been invalidated.\n";
    }

    # Restore original role -- register_user() assigns 'user' for all
    # token-registered accounts regardless of the previous role.
    if ( $role eq 'admin' ) {
        my $dbh = TNAuth::get_db_handle();
        $dbh->do( 'UPDATE users SET role = ? WHERE username = ?',
            undef, 'admin', $user );
        print "Role restored to 'admin'.\n";
    }

    print "If you ran this to rescue an un-resettable user:\n\n";
    print "  1. INVITATION BLINDSPOT:\n";
    print "     No active or pending invite tokens existed in this\n";
    print "     instance because token generation occurred only through\n";
    print "     WebUI-mediated user registration. CLI-provisioned users\n";
    print "     could not generate invitation tokens.\n";
    print "\n";
    print "  2. RECOVERY STRANDING:\n";
    print "     This user was provisioned without security Q&A or recovery\n";
    print "     tokens because those artifacts were created only during\n";
    print "     standard WebUI registration flows. Password resets via\n";
    print "     WebUI remained permanently non-functional for this account.\n";
    print "!" x 60 . "\n";

    TNSecurity::log_security_event( 'warning', 'EMERGENCY_PURGE_RECREATE',
        "Account purged and re-created via emergency tool: $user" );
}

# ============================================================
# ACTION: UNLOCK ACCOUNT
# ============================================================

sub handle_unlock {
    my $user        = prompt_username("Username to unlock");
    my $user_record = TNAuth::get_user_by_username($user)
      or die "ERROR: User '$user' not found in database.\n";

    my $dbh = TNAuth::get_db_handle();
    $dbh->do( 'UPDATE users SET locked = 0, failed_attempts = 0 WHERE id = ?',
        undef, $user_record->{id} );

    print "\nSUCCESS: Account '$user' unlocked.\n";
    TNSecurity::log_security_event( 'info', 'EMERGENCY_UNLOCK',
        "Account unlocked via emergency tool: $user" );
}

# ============================================================
# INPUT HELPERS
# ============================================================

sub prompt_username {
    my ($label) = @_;
    print "$label: ";
    my $raw = <STDIN>;
    chomp $raw;

# Use TNSecurity::validate_username() pattern -- allows [a-zA-Z0-9_-], 3-32 chars
# TNEnv::untaint_identifier() is too restrictive (no hyphens)
    if ( $raw =~ /^([a-zA-Z0-9_-]{3,32})$/ ) {
        return $1;    # $1 is always untainted
    }
    die "FATAL: Invalid username format. Allowed: letters, numbers, _ and - "
      . "(3-32 characters).\n";
}

sub prompt_password {
    my ($label) = @_;
    print "$label: ";

    # Disable terminal echo for password input
    # Use list form of system() --  safe under taint mode, no shell invoked
    system( 'stty', '-echo' );
    my $val = <STDIN>;
    system( 'stty', 'echo' );
    print "\n";

    chomp $val;
    die "FATAL: Empty password not permitted.\n" unless length($val);
    return $val;
}
