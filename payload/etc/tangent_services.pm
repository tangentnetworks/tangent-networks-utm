#!/usr/bin/perl
# Service Monitoring Configuration
# Edit this file to add/remove services to monitor

our %programs = (

    # PID-based programs (with PID file)
    'clamd' => {
        pid_file     => "/var/www/htdocs/tn/data/run/clamav/clamd.pid",
        type         => "pid_file",
        display_name => "clamd"
    },
    'collectd' => {
        pid_file     => "/var/www/htdocs/tn/data/run/collectd/collectd.pid",
        type         => "pid_file",
        display_name => "collectd"
    },
    'e2guardian' => {
        pid_file     => "/var/www/htdocs/tn/data/run/e2guardian/e2guardian.pid",
        type         => "pid_file",
        display_name => "e2guardian"
    },
    'freshclam' => {
        pid_file     => "/var/www/htdocs/tn/data/run/clamav/freshclam.pid",
        type         => "pid_file",
        display_name => "freshclam"
    },
    'p3scan' => {
        pid_file     => "/var/www/htdocs/tn/data/run/p3scan/p3scan.pid",
        type         => "pid_file",
        display_name => "p3scan"
    },
    'pmacct_egress_json_log' => {
        pid_file =>
          "/var/www/htdocs/tn/data/run/pmacct/pmacct-ext_if_json_log.pid",
        type         => "pid_file",
        display_name => "pmacct egress json log"
    },
    'pmacct_egress_json_mfs' => {
        pid_file =>
          "/var/www/htdocs/tn/data/run/pmacct/pmacct-int_if_json_mfs.pid",
        type         => "pid_file",
        display_name => "pmacct egress json pipe"
    },
    'pmacct_ingress_json_mfs' => {
        pid_file =>
          "/var/www/htdocs/tn/data/run/pmacct/pmacct-int_if_json_mfs.pid",
        type         => "pid_file",
        display_name => "pmacct ingress json pipe"
    },
    'smtp-gated' => {
        pid_file     => "/var/www/htdocs/tn/data/run/smtp-gated/smtp-gated.pid",
        type         => "pid_file",
        display_name => "smtp gated"
    },
    'snortinline' => {
        pid_file     => "/var/www/htdocs/tn/data/run/snort/snort_.pid",
        type         => "pid_file",
        display_name => "snortinline"
    },
    'snort' => {
        pid_file     => "/var/www/htdocs/tn/data/run/snort/snort_%%INT_IF%%.pid",
        type         => "pid_file",
        display_name => "snort"
    },
    'snortsentry' => {
        pid_file => "/var/www/htdocs/tn/data/run/snortsentry/snortsentry.pid",
        type     => "pid_file",
        display_name => "snortsentry"
    },
    'sockd' => {
        pid_file     => "/var/www/htdocs/tn/data/run/sockd/sockd.pid",
        type         => "pid_file",
        display_name => "sockd"
    },
    'spamd' => {
        pid_file     => "/var/www/htdocs/tn/data/run/spamd/spamd.pid",
        type         => "pid_file",
        display_name => "spamd"
    },
    'sslproxy' => {
        pid_file     => "/var/www/htdocs/tn/data/run/sslproxy/sslproxy.pid",
        type         => "pid_file",
        display_name => "sslproxy"
    },

    # rcctl-managed daemons
    'cron'     => { type => "rcctl", name => "cron",  display_name => "cron" },
    'dhcpd'    => { type => "rcctl", name => "dhcpd", display_name => "dhcpd" },
    'ftpproxy' =>
      { type => "rcctl", name => "ftp-proxy", display_name => "ftp proxy" },
    'httpd'  => { type => "rcctl", name => "httpd",  display_name => "httpd" },
    'ntpd'   => { type => "rcctl", name => "ntpd",   display_name => "ntpd" },
    'pflogd' => { type => "rcctl", name => "pflogd", display_name => "pflogd" },
    'rad'    => { type => "rcctl", name => "rad",    display_name => "rad" },
    'slaacd' => { type => "rcctl", name => "slaacd", display_name => "slaacd" },
    'smtpd'  => { type => "rcctl", name => "smtpd",  display_name => "smtpd" },
    'syslogd' =>
      { type => "rcctl", name => "syslogd", display_name => "syslogd" },
    'unbound' =>
      { type => "rcctl", name => "unbound", display_name => "unbound" },
);

# Aggregation groups - services listed here will be aggregated in JSON output only
# Text log output will still show all services individually
our %aggregation = (
    'pmacct' => {
        display_name => 'pmacct',
        services     => [
            'pmacct_egress_json_log', 'pmacct_egress_json_mfs',
            'pmacct_ingress_json_mfs'
        ]
    }
);

1;
