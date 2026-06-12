#!/usr/bin/perl -T

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

use strict;
use warnings;
use English qw(-no_match_vars);
use File::Basename;
use File::Path qw(make_path);
use JSON;
use POSIX qw(strftime);
use Getopt::Long;

# Untaint PATH
$ENV{PATH} = '/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

# Configuration file path
my $config_file = '/etc/tangent_services.pm';
my $status_dir  = '/var/www/htdocs/tn/data/services/status';
my $log_file    = '/var/www/htdocs/tn/data/logs/bootlog/services.log';
my $json_file   = '/var/www/htdocs/tn/data/logs/bootlog/services.json';

# Command line options
my $output_mode    = 'all';    # all, log, json, status
my $single_service = '';
GetOptions(
    'output=s'  => \$output_mode,
    'service=s' => \$single_service,
    'config=s'  => \$config_file,
  )
  or die
"Usage: $0 [--output all|log|json|status] [--service SERVICE_KEY] [--config PATH]\n";

# Untaint command-line arguments
if ( $output_mode =~ /^(all|log|json|status)$/ ) {
    $output_mode = $1;
}
else {
    die "Invalid output mode: $output_mode\n";
}

if ( $single_service && $single_service =~ /^([a-zA-Z0-9_-]+)$/ ) {
    $single_service = $1;
}
elsif ($single_service) {
    die "Invalid service key: $single_service\n";
}

if ( $config_file =~ /^([a-zA-Z0-9_\-\/\.]+)$/ ) {
    $config_file = $1;
}
else {
    die "Invalid config file path: $config_file\n";
}

# Untaint fixed paths
if ( $status_dir =~ /^([a-zA-Z0-9_\-\/\.]+)$/ ) {
    $status_dir = $1;
}
else {
    die "Invalid status_dir path: $status_dir\n";
}

if ( $log_file =~ /^([a-zA-Z0-9_\-\/\.]+)$/ ) {
    $log_file = $1;
}
else {
    die "Invalid log_file path: $log_file\n";
}

if ( $json_file =~ /^([a-zA-Z0-9_\-\/\.]+)$/ ) {
    $json_file = $1;
}
else {
    die "Invalid json_file path: $json_file\n";
}

# Load configuration
our ( %programs, %aggregation );
require $config_file or die "Cannot load config file $config_file: $!";

#####################################
# Core Monitoring Functions (Reusable)
#####################################

sub get_pid_from_file {
    my ($pid_file) = @_;

    # Untaint $pid_file: only allow alphanumeric, slashes, dots, and underscores
    if ( $pid_file =~ /^([a-zA-Z0-9_\-\/\.]+)$/ ) {
        $pid_file = $1;
    }
    else {
        die "Invalid PID file path: $pid_file";
    }
    if ( -f $pid_file ) {
        open( my $fh, '<', $pid_file ) or return undef;
        my $pid = <$fh>;
        chomp($pid) if defined $pid;
        close($fh);

        # Untaint $pid: only allow digits
        if ( defined $pid && $pid =~ /^(\d+)$/ ) {
            $pid = $1;
            return $pid;
        }
    }
    return undef;
}

sub get_pid_for_rcctl {
    my ($name) = @_;

    # Untaint $name: only allow alphanumeric, hyphens, and underscores
    if ( $name =~ /^([a-zA-Z0-9_-]+)$/ ) {
        $name = $1;
    }
    else {
        die "Invalid service name: $name";
    }
    my $pgrep_output = `pgrep -n $name 2>/dev/null`;
    chomp($pgrep_output);

    # Untaint pgrep output
    if ( $pgrep_output && $pgrep_output =~ /^(\d+)$/ ) {
        return $1;
    }
    return undef;
}

sub get_process_info {
    my ($pid) = @_;

    # Wash the PID (ensure it's just digits)
    return undef unless ( defined $pid && $pid =~ /^(\d+)$/ );
    my $safe_pid = $1;

    # Open with a list to bypass the shell (Taint requirement)
    # We use -ww to prevent OpenBSD from truncating the 'args' column
    open( my $ps_fh, "-|", "ps", "-ww", "-p", $safe_pid, "-o",
        "pid=,user=,pcpu=,pmem=,rss=,vsz=,comm=,args=" )
      or return undef;
    my $ps_output = <$ps_fh>;
    close($ps_fh);

    return undef unless $ps_output;
    $ps_output =~ s/^\s+//;

    # WASHING STATION: Capture and untaint every single field
    if ( $ps_output =~
        /^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/ )
    {
        return {
            pid  => $1,    # Untainted
            user => $2,    # Untainted
            cpu  => $3,    # Untainted
            mem  => $4,    # Untainted
            rss  => $5,    # Untainted
            vsz  => $6,    # Untainted
            comm => $7,    # Untainted
            args => $8     # Untainted
        };
    }
    return undef;
}

sub get_port_listeners {
    my ($pid) = @_;

    # Untaint $pid: only allow digits
    if ( defined $pid && $pid =~ /^(\d+)$/ ) {
        $pid = $1;
    }
    else {
        return ();
    }
    my @listeners;

    # Use list form to avoid shell
    open( my $netstat_fh, "-|", "netstat", "-an", "-p", "tcp" ) or return ();
    while ( my $line = <$netstat_fh> ) {
        chomp($line);

        # Look for lines containing our PID and extract port numbers
        if ( $line =~ /tcp.*\*\.(\d+)/ && $line =~ /$pid/ ) {
            my $port = $1;    # Already untainted by regex capture
            push @listeners, { pid => $pid, address => "0.0.0.0:$port" };
        }
    }
    close($netstat_fh);
    return @listeners;
}

sub monitor_service {
    my ( $prog_key, $info ) = @_;
    my ( $pid, $pid_file_path, $pid_file_contents );

    if ( $info->{type} eq "pid_file" ) {
        $pid_file_path     = $info->{pid_file};
        $pid_file_contents = get_pid_from_file($pid_file_path);
        $pid               = $pid_file_contents;
    }
    elsif ( $info->{type} eq "rcctl" ) {
        my $name = $info->{name} || $prog_key;
        $pid = get_pid_for_rcctl($name);
    }

    my $proc_info = get_process_info($pid);
    my @listeners = $proc_info ? get_port_listeners( $proc_info->{pid} ) : ();

    return {
        key               => $prog_key,
        display_name      => $info->{display_name},
        type              => $info->{type},
        status            => $proc_info ? 'running' : 'stopped',
        pid_file_path     => $pid_file_path,
        pid_file_contents => $pid_file_contents,
        process           => $proc_info,
        listeners         => \@listeners,
    };
}

sub monitor_all_services {
    my %results;
    foreach my $prog_key ( sort keys %programs ) {
        $results{$prog_key} =
          monitor_service( $prog_key, $programs{$prog_key} );
    }
    return \%results;
}

#####################################
# Output Functions
#####################################

sub write_text_log {
    my ($results) = @_;

    open( my $fh, '>', $log_file ) or die "Cannot open $log_file: $!";

    foreach my $prog_key ( sort keys %$results ) {
        my $data = $results->{$prog_key};
        print $fh "=== $data->{display_name} Status Report ===\n";

        if ( $data->{status} eq 'running' ) {
            my $p = $data->{process};
            print $fh "Status:               Running\n";
            print $fh "PID:                  $p->{pid}\n";
            print $fh "User:                 $p->{user}\n";
            print $fh "CPU Usage:            $p->{cpu}%\n";
            print $fh "Memory Usage:         $p->{mem}%\n";
            print $fh "RSS:                  $p->{rss} KB\n";
            print $fh "VSZ:                  $p->{vsz} KB\n";
            print $fh "Command:              $p->{comm}\n";
            print $fh "Arguments:            $p->{args}\n";
            print $fh "PID File Path:        $data->{pid_file_path}\n"
              if $data->{pid_file_path};
            print $fh "PID File Contents:    $data->{pid_file_contents}\n"
              if $data->{pid_file_contents};

            if ( @{ $data->{listeners} } ) {
                print $fh "Port Listeners:\n";
                foreach my $listener ( @{ $data->{listeners} } ) {
                    print $fh
"  PID: $listener->{pid}, Address: $listener->{address}\n";
                }
            }
        }
        else {
            print $fh "Status:               Not running\n";
        }
        print $fh "\n";
    }

    close($fh);
}

sub aggregate_services {
    my ($results) = @_;
    my %aggregated;

    foreach my $group_key ( keys %aggregation ) {
        my $group = $aggregation{$group_key};
        my @subprocs;
        my $all_running = 1;
        my $any_running = 0;
        my ( $total_cpu, $total_mem, $total_rss, $total_vsz ) = ( 0, 0, 0, 0 );

        foreach my $service_key ( @{ $group->{services} } ) {
            my $data = $results->{$service_key};
            next unless $data;

            if ( $data->{status} eq 'running' ) {
                $any_running = 1;
                my $p = $data->{process};
                $total_cpu += $p->{cpu};
                $total_mem += $p->{mem};
                $total_rss += $p->{rss};
                $total_vsz += $p->{vsz};

                push @subprocs,
                  {
                    key          => $service_key,
                    display_name => $data->{display_name},
                    status       => 'running',
                    pid          => $p->{pid},
                    user         => $p->{user},
                    cpu          => $p->{cpu},
                    mem          => $p->{mem},
                    rss          => $p->{rss},
                    vsz          => $p->{vsz},
                    command      => $p->{comm},
                    arguments    => $p->{args},
                    listeners    => $data->{listeners},
                  };
            }
            else {
                $all_running = 0;
                push @subprocs,
                  {
                    key          => $service_key,
                    display_name => $data->{display_name},
                    status       => 'stopped',
                  };
            }
        }

        my $group_status =
          $all_running ? 'running' : ( $any_running ? 'degraded' : 'stopped' );

        $aggregated{$group_key} = {
            display_name       => $group->{display_name},
            type               => 'aggregated',
            status             => $group_status,
            subprocesses       => \@subprocs,
            aggregated_metrics => {
                total_cpu     => sprintf( "%.2f", $total_cpu ),
                total_mem     => sprintf( "%.2f", $total_mem ),
                total_rss     => $total_rss,
                total_vsz     => $total_vsz,
                all_running   => $all_running ? JSON::true : JSON::false,
                running_count =>
                  scalar( grep { $_->{status} eq 'running' } @subprocs ),
                total_count => scalar(@subprocs),
            }
        };
    }

    return \%aggregated;
}

sub build_json_structure {
    my ($results) = @_;

    my %services_in_groups;
    foreach my $group_key ( keys %aggregation ) {
        foreach my $service_key ( @{ $aggregation{$group_key}->{services} } ) {
            $services_in_groups{$service_key} = 1;
        }
    }

    my %json_services;
    my $aggregated = aggregate_services($results);

    # Add aggregated groups
    foreach my $group_key ( keys %$aggregated ) {
        $json_services{$group_key} = $aggregated->{$group_key};
    }

    # Add standalone services
    foreach my $prog_key ( keys %$results ) {
        next if $services_in_groups{$prog_key};

        my $data         = $results->{$prog_key};
        my $service_data = {
            display_name => $data->{display_name},
            type         => 'standalone',
            status       => $data->{status},
        };

        if ( $data->{status} eq 'running' ) {
            my $p = $data->{process};
            $service_data->{pid}           = $p->{pid};
            $service_data->{user}          = $p->{user};
            $service_data->{cpu}           = $p->{cpu};
            $service_data->{mem}           = $p->{mem};
            $service_data->{rss}           = $p->{rss};
            $service_data->{vsz}           = $p->{vsz};
            $service_data->{command}       = $p->{comm};
            $service_data->{arguments}     = $p->{args};
            $service_data->{listeners}     = $data->{listeners};
            $service_data->{pid_file_path} = $data->{pid_file_path}
              if $data->{pid_file_path};
        }

        $json_services{$prog_key} = $service_data;
    }

    return {
        timestamp => strftime( "%Y-%m-%dT%H:%M:%S%z", localtime ),
        services  => \%json_services,
    };
}

sub write_json_file {
    my ($results) = @_;

    my $json_data = build_json_structure($results);

    open( my $fh, '>', $json_file ) or die "Cannot open $json_file: $!";
    print $fh JSON->new->pretty->encode($json_data);
    close($fh);
}

sub untaint_directory_path {
    my ($path) = @_;
    if ( $path =~ /^([a-zA-Z0-9_\-\/\.]+)$/ ) {
        return $1;
    }
    die "Invalid directory path: $path\n";
}

sub write_individual_status_files {
    my ($results) = @_;

    # Get aggregated data
    my $aggregated = aggregate_services($results);

    # Track which services are in groups
    my %services_in_groups;
    foreach my $group_key ( keys %aggregation ) {
        foreach my $service_key ( @{ $aggregation{$group_key}->{services} } ) {
            $services_in_groups{$service_key} = 1;
        }
    }

    # Write aggregated group status files
    foreach my $group_key ( keys %$aggregated ) {

        # Untaint the group_key for path construction
        my $safe_group_key;
        if ( $group_key =~ /^([a-zA-Z0-9_-]+)$/ ) {
            $safe_group_key = $1;
        }
        else {
            warn "Skipping invalid group key: $group_key\n";
            next;
        }

        my $status_path = "$status_dir/$safe_group_key";
        $status_path = untaint_directory_path($status_path);
        make_path($status_path) unless -d $status_path;

        my $status_file = "$status_path/status";
        $status_file = untaint_directory_path($status_file);
        open( my $fh, '>', $status_file )
          or die "Cannot write to $status_file: $!";
        print $fh JSON->new->pretty->encode( $aggregated->{$group_key} );
        close($fh);
    }

    # Write standalone service status files
    foreach my $prog_key ( keys %$results ) {
        next if $services_in_groups{$prog_key};

        # Untaint the prog_key for path construction
        my $safe_prog_key;
        if ( $prog_key =~ /^([a-zA-Z0-9_-]+)$/ ) {
            $safe_prog_key = $1;
        }
        else {
            warn "Skipping invalid service key: $prog_key\n";
            next;
        }

        my $data        = $results->{$prog_key};
        my $status_path = "$status_dir/$safe_prog_key";
        $status_path = untaint_directory_path($status_path);
        make_path($status_path) unless -d $status_path;

        my $service_data = {
            display_name => $data->{display_name},
            type         => 'standalone',
            status       => $data->{status},
        };

        if ( $data->{status} eq 'running' ) {
            my $p = $data->{process};
            $service_data->{pid}           = $p->{pid};
            $service_data->{user}          = $p->{user};
            $service_data->{cpu}           = $p->{cpu};
            $service_data->{mem}           = $p->{mem};
            $service_data->{rss}           = $p->{rss};
            $service_data->{vsz}           = $p->{vsz};
            $service_data->{command}       = $p->{comm};
            $service_data->{arguments}     = $p->{args};
            $service_data->{listeners}     = $data->{listeners};
            $service_data->{pid_file_path} = $data->{pid_file_path}
              if $data->{pid_file_path};
        }

        my $status_file = "$status_path/status";
        $status_file = untaint_directory_path($status_file);
        open( my $fh, '>', $status_file )
          or die "Cannot write to $status_file: $!";
        print $fh JSON->new->pretty->encode($service_data);
        close($fh);
    }
}

#####################################
# Main Execution
#####################################

# Untaint dirname results for path operations
sub safe_dirname {
    my ($path) = @_;
    my $dir = dirname($path);
    if ( $dir =~ /^([a-zA-Z0-9_\-\/\.]+)$/ ) {
        return $1;
    }
    die "Invalid directory from dirname: $dir\n";
}

# Create output directories if they don't exist
my $log_dir  = safe_dirname($log_file);
my $json_dir = safe_dirname($json_file);
make_path($log_dir)    unless -d $log_dir;
make_path($json_dir)   unless -d $json_dir;
make_path($status_dir) unless -d $status_dir;

# Monitor services
my $results;
if ( $single_service && exists $programs{$single_service} ) {
    $results = { $single_service =>
          monitor_service( $single_service, $programs{$single_service} ) };
}
else {
    $results = monitor_all_services();
}

# Write outputs based on mode
if ( $output_mode eq 'all' ) {
    write_text_log($results);
    write_json_file($results);
    write_individual_status_files($results);
    print "All outputs written successfully.\n";
}
elsif ( $output_mode eq 'log' ) {
    write_text_log($results);
    print "Text log written to $log_file\n";
}
elsif ( $output_mode eq 'json' ) {
    write_json_file($results);
    print "JSON written to $json_file\n";
}
elsif ( $output_mode eq 'status' ) {
    write_individual_status_files($results);
    print "Individual status files written to $status_dir\n";
}
else {
    die "Invalid output mode: $output_mode\n";
}

# Print to STDOUT if running interactively
if ( -t STDOUT && !$single_service ) {
    print "\n=== Service Status Summary ===\n";
    foreach my $prog_key ( sort keys %$results ) {
        my $data = $results->{$prog_key};
        printf "%-30s %s\n", $data->{display_name}, $data->{status};
    }
}
