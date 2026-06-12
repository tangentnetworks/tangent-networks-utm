#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;
use File::Basename qw(dirname);
use File::Copy;
use File::Path qw(make_path);
use Fcntl      qw(:flock);

BEGIN {
    $ENV{PATH} = '/bin:/usr/bin:/sbin:/usr/sbin';
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

    my $lib_path =
      File::Spec->catdir( $RealBin, File::Spec->updir, 'data', 'lib' );
    unless ( File::Spec->file_name_is_absolute($lib_path) ) {
        $lib_path = File::Spec->rel2abs($lib_path);
    }
    if ( $lib_path =~ m{^([-/\w.]+)$} ) {
        unshift @INC, $1;
    }
    else {
        die "FATAL: Invalid lib path\n";
    }

# Pre-read JSON POST body before TNSecurityCheck drains STDIN (STDIN-PREREAD-001)
# Required because security level is determined from POST body (delete/purge = protected)
    if (   $ENV{CONTENT_TYPE}
        && $ENV{CONTENT_TYPE} =~ /application\/json/
        && $ENV{CONTENT_LENGTH} )
    {
        read( STDIN, my $json_body, $ENV{CONTENT_LENGTH} );
        $ENV{POSTDATA} = $json_body;
    }
}

use TNEnv;
use TNSecurityCheck;
use CGI;
use JSON::PP;

# ============================================================================
# PARSE REQUEST -- determine action before security_check level decision
# ============================================================================
my $request_method = $ENV{REQUEST_METHOD} || 'GET';
my $q              = CGI->new;

my $action_param;
my $json_data;

if ( $request_method eq 'POST' ) {
    my $json_text = $ENV{POSTDATA} || $q->param('POSTDATA') || '';
    $json_data = eval { decode_json($json_text) };

    if ($json_data) {
        $action_param = $json_data->{action} || 'list';
    }
    else {
        print "Status: 400 Bad Request\r\n";
        print "Content-Type: application/json\r\n\r\n";
        print encode_json(
            { status => 'error', message => 'Invalid JSON in POST body' } );
        exit 1;
    }
}
else {
    $action_param = $q->param('action') || 'list';
}

# Validate action before using it to determine security level
my $action = ( $action_param =~ /^(list|delete|purge)$/ ) ? $1 : 'list';

# Dynamic security level -- delete/purge require session + CSRF
my $security_level =
  ( $action eq 'delete' || $action eq 'purge' ) ? 'protected' : 'standard';
my $session = security_check($security_level);

# ============================================================================
# CONFIGURATION
# ============================================================================
my $SCRIPT_DIR = dirname(__FILE__);
if ( $SCRIPT_DIR =~ m{^([-/\w.]+)$} ) { $SCRIPT_DIR = $1 }
else                                  { die "FATAL: Invalid script_dir\n" }

# Pre-compute canonical paths before pledge (RELABS-001)
my $MAIL_DIR = File::Spec->rel2abs(
    File::Spec->catdir( $SCRIPT_DIR, '..', 'data', 'mail', 'root', 'new' ) );
my $OUTPUT_DIR = File::Spec->rel2abs(
    File::Spec->catdir( $SCRIPT_DIR, '..', 'data', 'inbox', 'mail' ) );

for my $ref ( \$MAIL_DIR, \$OUTPUT_DIR ) {
    if ( $$ref =~ m{^([-/\w.]+)$} ) { $$ref = $1 }
    else                            { die "FATAL: Invalid path: $$ref\n" }
}

my $DIR_MODE  = 0755;
my $FILE_MODE = 0644;

# ============================================================================
# RESPONSE HELPERS
# ============================================================================
sub send_json {
    my ($data) = @_;
    my $out = JSON::PP->new->utf8->encode($data);
    print "Status: 200 OK\r\n";
    print "Content-Type: application/json; charset=UTF-8\r\n";
    print "X-Frame-Options: DENY\r\n";
    print "X-Content-Type-Options: nosniff\r\n";
    print "Cache-Control: no-cache, no-store, must-revalidate, private\r\n";
    print "Connection: close\r\n";
    print "\r\n";
    print $out;
    exit 0;
}

sub send_error {
    my ( $code, $message ) = @_;
    my %st = (
        400 => 'Bad Request',
        403 => 'Forbidden',
        404 => 'Not Found',
        500 => 'Internal Server Error'
    );
    print "Status: $code " . ( $st{$code} || 'Error' ) . "\r\n";
    print "Content-Type: application/json\r\n";
    print "\r\n";
    print JSON::PP->new->utf8->encode(
        { status => 'error', message => $message } );
    exit 0;
}

sub die_json {
    my ($msg) = @_;
    $msg =~ s/ at .* line \d+\.?\n?$//;
    send_error( 500, $msg );
}

# ============================================================================
# ENSURE OUTPUT DIR EXISTS BEFORE PLEDGE
# ============================================================================
unless ( -d $OUTPUT_DIR ) {
    make_path( $OUTPUT_DIR, { mode => $DIR_MODE, error => \my $err } );
    if ( $err && @$err ) {
        die_json( "Cannot create output directory: "
              . join( ", ", map { values %$_ } @$err ) );
    }
}

# ============================================================================
# OPENBSD PLEDGE + UNVEIL
# ============================================================================
{
    my $app_root = $SCRIPT_DIR;
    $app_root =~ s{/cgi-bin$}{};
    $app_root =~ s{^/var/www}{};
    eval {
        if ( eval { require OpenBSD::Unveil; 1 } ) {
            OpenBSD::Unveil::unveil( "$app_root/data/lib", "r" )
              or die "unveil lib: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/config", "r" )
              or die "unveil config: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/keys", "r" )
              or die "unveil keys: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/db", "r" )
              or die "unveil db: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/mail/root/new", "r" )
              or die "unveil mail: $!";
            OpenBSD::Unveil::unveil( "$app_root/data/inbox/mail", "rwc" )
              or die "unveil inbox: $!";
            OpenBSD::Unveil::unveil() or die "unveil lock: $!";
        }
        if ( eval { require OpenBSD::Pledge; 1 } ) {
            OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock")
              or die "pledge: $!";
        }
    };
    if ($@) {
        send_error( 500, "Internal server error" );
    }
}

# ============================================================================
# DISPATCH
# ============================================================================
eval {
    if ( $action eq 'delete' ) {
        handle_delete($json_data);
    }
    elsif ( $action eq 'purge' ) {
        handle_purge();
    }
    else {
        handle_list();
    }
};

if ($@) {
    die_json($@);
}

exit 0;

# ============================================================================
# ACTION HANDLERS
# ============================================================================

sub handle_delete {
    my ($data) = @_;

    my $filename = get_safe_filename( $data->{file} );

    my $mail_path   = File::Spec->catfile( $MAIL_DIR,   $filename );
    my $output_path = File::Spec->catfile( $OUTPUT_DIR, $filename );

    # Untaint constructed paths
    if ( $mail_path =~ m{^([-/\w.]+)$} ) { $mail_path = $1 }
    else                                 { die_json("Invalid mail path") }
    if ( $output_path =~ m{^([-/\w.]+)$} ) { $output_path = $1 }
    else                                   { die_json("Invalid output path") }

    unlink $mail_path   if -f $mail_path;
    unlink $output_path if -f $output_path;

    send_json( { status => 'success', message => 'Email deleted' } );
}

sub handle_purge {
    my $max_age_days    = 7;
    my $max_age_seconds = $max_age_days * 24 * 60 * 60;
    my $cutoff_time     = time() - $max_age_seconds;
    my $deleted_count   = 0;

    for my $dir ( $MAIL_DIR, $OUTPUT_DIR ) {
        next unless -d $dir;
        opendir( my $dh, $dir ) or next;
        my @files =
          grep { /^(\d[\w\.\-]+)$/ && -f File::Spec->catfile( $dir, $_ ) }
          readdir($dh);
        closedir($dh);

        foreach my $file (@files) {
            $file =~ /^(\d[\w\.\-]+)$/;
            my $clean = $1;
            my $path  = File::Spec->catfile( $dir, $clean );
            if ( $path =~ m{^([-/\w.]+)$} ) { $path = $1 }
            else                            { next }
            my $mtime = ( stat($path) )[9];
            if ( defined $mtime && $mtime < $cutoff_time ) {
                $deleted_count++ if ( $dir eq $MAIL_DIR && unlink $path );
                unlink $path     if $dir eq $OUTPUT_DIR;
            }
        }
    }

    send_json(
        {
            status  => 'success',
            message =>
              "Purged $deleted_count emails older than $max_age_days days",
            deleted => $deleted_count,
        }
    );
}

sub handle_list {
    my $limit  = int( $q->param('limit')  || 0 );
    my $offset = int( $q->param('offset') || 0 );

    my @emails = process_mail_files( $limit, $offset );

    send_json(
        {
            status => 'success',
            count  => scalar(@emails),
            emails => \@emails,
        }
    );
}

# ============================================================================
# MAIL PROCESSING
# ============================================================================

sub process_mail_files {
    my ( $limit, $offset ) = @_;
    $limit  ||= 0;
    $offset ||= 0;

    my @emails;
    return @emails unless -d $MAIL_DIR;

    opendir( my $dh, $MAIL_DIR ) or die "Cannot open mail directory: $!";
    my @files =
      grep { /^(\d[\w\.\-]+)$/ && -f File::Spec->catfile( $MAIL_DIR, $_ ) }
      readdir($dh);
    closedir($dh);

    return @emails unless @files;

    # Sort by mtime descending -- stat only, no file reads yet
    my @sorted = map { $_->[0] }
      sort { $b->[1] <=> $a->[1] }
      map {
        my $path  = File::Spec->catfile( $MAIL_DIR, $_ );
        my $mtime = ( stat($path) )[9] || 0;
        [ $_, $mtime ]
      } @files;

    # Apply pagination before parsing
    if ( $limit > 0 ) {
        my $end = $offset + $limit;
        $end    = scalar(@sorted)                if $end > scalar(@sorted);
        @sorted = @sorted[ $offset .. $end - 1 ] if $offset < scalar(@sorted);
    }

    foreach my $file (@sorted) {
        $file =~ /^(\d[\w\.\-]+)$/;
        my $clean = $1;
        my $email = parse_mail_fast($clean);
        push @emails, $email if $email;
    }

    return @emails;
}

sub parse_mail_fast {
    my ($file) = @_;

    my $mail_path   = File::Spec->catfile( $MAIL_DIR,   $file );
    my $output_path = File::Spec->catfile( $OUTPUT_DIR, $file );

    # Untaint
    if ( $mail_path =~ m{^([-/\w.]+)$} ) { $mail_path = $1 }
    else                                 { return undef }
    if ( $output_path =~ m{^([-/\w.]+)$} ) { $output_path = $1 }
    else                                   { return undef }

    my @stat = stat($mail_path);
    return undef unless @stat;

    my ( $size, $mtime ) = ( $stat[7], $stat[9] );

    # Copy to output cache only if stale
    unless ( -f $output_path && ( stat(_) )[9] >= $mtime ) {
        copy( $mail_path, $output_path ) or return undef;
        chmod $FILE_MODE, $output_path;
    }

    my ( $subject, $from, $date ) = extract_headers($mail_path);

    return {
        id        => $file,
        file      => $file,
        subject   => $subject || 'No Subject',
        from      => $from    || 'Unknown',
        date      => $date    || scalar( localtime($mtime) ),
        timestamp => $mtime,
        size      => $size,
        priority  => detect_priority($subject),
        read      => 0,
    };
}

sub extract_headers {
    my ($path) = @_;

    open( my $fh, '<', $path ) or return ( undef, undef, undef );
    my $buffer = '';
    read( $fh, $buffer, 4096 );
    close($fh);

    return ( undef, undef, undef ) unless $buffer;

    my ($headers) = $buffer =~ /^(.*?)\n\n/s;
    return ( undef, undef, undef ) unless $headers;

    my $subject = ( $headers =~ /^Subject:\s*(.+?)$/im ) ? $1 : undef;
    my $from    = ( $headers =~ /^From:\s*(.+?)$/im )    ? $1 : undef;
    my $date    = ( $headers =~ /^Date:\s*(.+?)$/im )    ? $1 : undef;

    return ( $subject, $from, $date );
}

sub detect_priority {
    my ($subject) = @_;
    return 'normal' unless defined $subject;
    return ( $subject =~ /\b(?:error|fail|critical|urgent|alert)\b/i )
      ? 'high'
      : 'normal';
}

# ============================================================================
# UTILITY
# ============================================================================

sub get_safe_filename {
    my ($raw) = @_;
    die "Missing filename" unless defined $raw && length($raw);
    if ( $raw =~ /^([\w\.\-]+)$/ ) {
        my $clean = $1;
        die "Invalid filename" if $clean =~ /^\.\.?$/ || $clean =~ /\.\./;
        return $clean;
    }
    die "Invalid filename format";
}
