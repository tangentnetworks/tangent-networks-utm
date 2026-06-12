#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ============================================================
# create_session.pl - CLI Session Cookie Generator
# ============================================================
# Location: /usr/local/sbin/create_session.pl
#
# PURPOSE:
#   Authenticates a user via command line and outputs a signed
#   session cookie value for manual browser injection. Used for
#   testing and emergency access when web login is unavailable.
#
# USAGE: Run as root
#   perl -T /usr/local/sbin/create_session.pl
#
# SECURITY WARNING:
#   This bypasses the web login UI and creates a fully valid
#   session. Use only in development or emergency situations.
#   Sessions created here are logged with IP 127.0.0.1 and
#   User-Agent 'CLI' and expire normally after 8 hours.
#
# AUTHOR: David Peter, Tangent Networks
# VERSION: 1.1.0
# ============================================================

use strict;
use warnings;

# ============================================================
# TAINT-SAFE BOOTSTRAP
# ============================================================

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/sbin:/usr/sbin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

    # Script lives in /usr/local/sbin -- lib path is fixed.
    my $lib_path = '/var/www/htdocs/tn/data/lib';

    unless ( -d $lib_path ) {
        die "FATAL: Library path not found: $lib_path\n";
    }

    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        $lib_path = $1;
        unshift @INC, $lib_path;
    }
    else {
        die "FATAL: Library path contains unsafe characters: $lib_path\n";
    }
}

use TNEnv;    # Must load first
use TNAuth;
use TNSecurity;

print "=" x 60 . "\n";
print "TNSecurity - CLI Session Generator\n";
print "=" x 60 . "\n\n";

# ============================================================
# COLLECT CREDENTIALS
# ============================================================

print "Username: ";
my $raw_username = <STDIN>;
chomp $raw_username;

# Validate and untaint -- same pattern as TNSecurity::validate_username
my $username;
if ( $raw_username =~ /^([a-zA-Z0-9_-]{3,32})$/ ) {
    $username = $1;
}
else {
    die "ERROR: Invalid username format.\n";
}

print "Password: ";
system( 'stty', '-echo' );
my $password = <STDIN>;
system( 'stty', 'echo' );
chomp $password;
print "\n";

die "ERROR: Empty password.\n" unless length($password);

# ============================================================
# AUTHENTICATE
# ============================================================

print "\nAuthenticating...\n";

my $auth = TNAuth::authenticate_user( $username, $password );

unless ( $auth->{success} ) {
    print "ERROR: $auth->{error}\n";
    exit 1;
}

printf "  Authenticated : %s\n", $auth->{username};
printf "  Role          : %s\n", $auth->{role};

# ============================================================
# CREATE AND SIGN SESSION
# ============================================================

print "\nCreating session...\n";

# IP is 127.0.0.1 (CLI origin), User-Agent is 'CLI' so sessions
# created here are identifiable in the sessions table.
my $session = TNAuth::create_session( $auth->{user_id}, '127.0.0.1', 'CLI' );

unless ( $session->{success} ) {
    print "ERROR: Session creation failed.\n";
    exit 1;
}

# Sign the session ID -- produces "session_id.hmac_signature"
# This is the exact format TNSecurityCheck expects in the cookie.
my $signed = TNSecurity::sign_session_id( $session->{session_id} );

# ============================================================
# OUTPUT
# ============================================================

print "\n" . "=" x 60 . "\n";
print "SESSION COOKIE\n";
print "=" x 60 . "\n\n";
print "Add this cookie to your browser:\n\n";
printf "  Name  : tn_session\n";
printf "  Value : %s\n", $signed;
printf "  IP    : %%INT_IP4%%\n";
printf "  Path  : /\n\n";

print "HOW TO ADD:\n\n";
print "Firefox:\n";
print "  F12 --> Storage --> Cookies --> right-click --> Add cookie\n\n";
print "Chrome / Edge:\n";
print "  F12 --> Application --> Cookies --> click domain --> add row\n\n";
print "Then navigate to: https://%%INT_IP4%%/\n\n";
print "Session expires in 8 hours.\n\n";

exit 0;
