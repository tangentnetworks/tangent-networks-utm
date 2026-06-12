<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# CGI Architecture Reference

**Tangent Networks -- CGI Patterns, Security Levels, and Sandbox Model**

---

## Overview

Every CGI script on the appliance follows one of three operation patterns
depending on what it does and what privileges it needs. All three patterns
share a common bootstrap sequence and a common security gate, but differ in
their sandbox constraints, security level, and whether they use the queue
system or operate directly on files.

The three patterns are:

The read-only stats pattern, used by scripts that read system state (pfctl
counters, JSON stat files, live data) and return it to the UI. These scripts
may need to call system binaries via `open(my $fh, '-|', ...)`, which
requires the `exec` pledge promise and is incompatible with the locked-down
sandbox. They run without pledge/unveil constraints and use `security_check('standard')`.

The queue-based async pattern, used by scripts that need to trigger
privileged operations (network queries, daemon management, PF table updates)
that the `www` user cannot perform directly inside the chroot. The CGI
script writes a request file to a queue directory, optionally polls for an
outcome file, and returns the result to the browser. The actual privileged
operation is performed by a root-side shell daemon outside the chroot. These
scripts use `security_check('protected')` with full pledge/unveil.

The direct file mutation pattern, used by scripts that need to modify
application-owned data files (PF rule queues, configuration files) where
the `www` user has write access and no privilege escalation is needed. The
operation is atomic: write to a `.tmp` file, `rename()` over the original.
These scripts use `security_check('restricted')` with full pledge/unveil
and a complete audit trail.

---

## Security Levels

`TNSecurityCheck::security_check($level)` is called at the top of every CGI
script, before any request processing. It enforces a layered sequence of
checks and either returns a session hashref on success or emits a JSON error
response and calls `exit` on failure. There are three levels.

### standard

No authentication required. Checks two things only: origin validation
(rejects cross-origin requests with a mismatched `HTTP_ORIGIN` or
`HTTP_REFERER`) and download protection (rejects requests with
`HTTP_ACCEPT` headers indicating automated download tools). Returns an
anonymous session hashref with `role => 'public'`.

Use standard for endpoints that serve read-only data the UI legitimately
needs without a login — system statistics, live counters, public status
information. Do not use standard for any endpoint that modifies state or
accesses user-specific data.

```perl
my $session = security_check('standard');
# $session->{role} eq 'public'
# $session->{username} eq 'anonymous'
# No session cookie checked. No CSRF checked.
```

### protected

Full authentication required. Enforces six layers in sequence: session
cookie validation (HMAC signature check then database lookup), origin
validation, download protection, POST method enforcement, CSRF token
validation (HMAC time-window check). Returns the validated session hashref
with the authenticated user's username, role, and session age.

Use protected for endpoints that read user-specific data or trigger
operations that any authenticated user may perform. The CSRF check means
every POST body must include a `csrf_token` field obtained from
`/cgi-bin/control.pl/api/csrf`.

```perl
my $session = security_check('protected');
# $session->{username}  — authenticated username
# $session->{role}      — 'admin' or 'user'
# $session->{user_id}   — user ID from database
# $session->{session_age} — seconds since session created
# POST enforced. CSRF validated. Session verified against database.
```

Note: scripts that handle both GET (polling) and POST (submit) use
`security_check('protected')` once at the top. The method enforcement inside
the check fires only for the POST submission path — GET polling calls that
arrive without a POST body reach the check, pass origin and download
validation, and then encounter the method check. If you need a GET polling
endpoint on a protected script, structure it so the GET handler returns
before the CSRF check is reached, or use a separate polling endpoint at
standard level. The ASN lookup script handles this by checking
`$ENV{REQUEST_METHOD}` after the security check and routing GET requests
to the polling handler directly.

### restricted

Admin-only. All six layers from protected plus a seventh: role check
requiring `$session->{role} eq 'admin'`. Non-admin authenticated users
receive a 403. Returns the validated admin session hashref.

Use restricted for endpoints that modify security-sensitive data, delete
records, change PF rules, or perform operations with irreversible
consequences. All restricted-level scripts must include a `write_log()`
audit trail recording the authenticated admin's username, the action taken,
and the result.

```perl
my $session = security_check('restricted');
# Guaranteed: $session->{role} eq 'admin'
# $session->{username} is always a real admin username — use it in audit logs.
# POST enforced. CSRF validated. Session verified. Admin role confirmed.
```

### DEVEL mode bypass

When `DEVEL=1` is set in `security.conf`, all three levels return a
synthetic admin session immediately without checking any credentials. Every
security check logs a debug event. DEVEL mode is only permitted on loopback
addresses — `router.pl` returns 503 for all requests if DEVEL is active on
a non-loopback address. Never deploy with DEVEL=1.

---

## Bootstrap Sequence

Every CGI script follows the same bootstrap sequence regardless of security
level or operation pattern. The order is mandatory — deviating from it
causes pledge failures, taint errors, or corrupted output.

### Step 1 — Shebang and pragmas

```perl
#!/usr/bin/perl -T
use strict;
use warnings;
```

`-T` enables taint mode. Every value from outside the process is tainted
until explicitly untainted with a pattern match. This is non-negotiable —
taint mode is the primary defence against injection attacks in the CGI layer.

### Step 2 — Library path setup (BEGIN block)

```perl
use FindBin qw($RealBin);
use File::Spec;

BEGIN {
    my $lib_path = File::Spec->catdir($RealBin, File::Spec->updir, 'data', 'lib');
    unless (File::Spec->file_name_is_absolute($lib_path)) {
        $lib_path = File::Spec->rel2abs($lib_path);
    }
    if ($lib_path =~ m{^([-/\w.]+)$}) {
        unshift @INC, $1;
    } else {
        die "FATAL: Invalid lib path\n";
    }
}
```

This runs at compile time and makes the TN module library available. The
regex pattern match is the untaint step — Perl taint mode requires this
before a tainted string can be used in a sensitive operation. The pattern
`[-/\w.]+` allows only the characters that legitimately appear in an
absolute filesystem path.

### Step 3 -- TNEnv and TNSecurityCheck

```perl
use TNEnv;
use TNSecurityCheck;
```

`TNEnv` must be the first TN module loaded. It cleans the process
environment (`PATH`, `IFS`, `CDPATH`, `ENV`, `BASH_ENV`), sets up
`LD_LIBRARY_PATH` for chroot library resolution, and configures STDIN/STDERR
with UTF-8 encoding layers while leaving STDOUT as raw bytes. STDOUT must be
raw — the JSON serialiser produces raw UTF-8 octets and adding an encoding
layer would double-encode non-ASCII output.

### Step 4 -- Pre-pledge dependencies

For protected and restricted scripts, load everything that requires dynamic
library loading before pledge locks down `dlopen()`:

```perl
use DBD::SQLite;   # XS module — must load before pledge
use JSON::XS;      # XS module — load here if used
```

`DBD::SQLite` uses an XS shared library. DBI loads the DBD driver lazily on
the first `connect()` call. If that call happens after `pledge("stdio rpath
wpath cpath flock")` is active, `dlopen()` needs the `prot_exec` promise
which is not granted. Pre-loading here ensures the `.so` is mapped into the
process before the sandbox is locked down.

### Step 5 -- Security check

```perl
my $session = security_check('standard');   # or 'protected' or 'restricted'
```

This must come before any request processing, any file operations, and
before pledge/unveil. If the check fails the script exits here — no request
data is processed, no files are touched.

### Step 6 -- Load remaining modules and set environment

```perl
use CGI qw(:standard);
use JSON::PP ();
use POSIX qw(strftime);

$ENV{PATH} = '/bin:/usr/bin';
delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};
```

Non-XS modules can be loaded after the security check. The `PATH` narrowing
here is belt-and-suspenders — `TNEnv` already cleans the environment at
compile time, but making it explicit in the script body clarifies intent
and protects against future refactoring that might move the TNEnv load.

### Step 7 -- Pre-pledge computation

Compute everything that requires unrestricted filesystem access before
unveil is applied:

```perl
my $_app_root = get_db_path();
$_app_root =~ s{/data/db/?.*$}{};

my $QUEUE_DIR    = File::Spec->catdir($_app_root, 'data', 'services', 'queue', 'my-queue');
my $CANONICAL_Q  = File::Spec->rel2abs($QUEUE_DIR);
```

`File::Spec->rel2abs()` calls `getcwd()` internally. Once any `unveil()`
call has been issued the kernel begins restricting filesystem visibility —
`getcwd()` on an un-unveiled path returns undef or fails. All canonical path
computation must happen before the first unveil call.

The pre-computed canonical base is used later for path traversal checks via
`index()`:

```perl
unless (index($full_path, $CANONICAL_Q) == 0) {
    # path traversal detected — reject
}
```

This pattern is correct and safe after unveil because it uses string
comparison, not a filesystem call.

### Step 8 -- Emit Content-Type header

```perl
my $cgi = CGI->new;
print $cgi->header(
    -type    => 'application/json',
    -charset => 'utf-8',
    -status  => '200 OK'
);
```

The Content-Type header must be emitted before pledge is applied. If pledge
initialisation fails and the script emits an error response, the Content-Type
header has already been sent and the browser receives valid JSON. Without
this, a pledge failure produces raw output before any HTTP header, which the
browser cannot parse.

### Step 9 -- pledge and unveil

See the Sandbox section below.

### Step 10 -- Request processing

Only after the sandbox is locked down does the script read and process
request data.

---

## Sandbox -- pledge(2) and unveil(2)

Protected and restricted scripts apply pledge and unveil after the
Content-Type header is emitted. Standard scripts that call system binaries
(pfctl, pfinfo, etc.) via `open(my $fh, '-|', ...)` do not apply
pledge/unveil — the `exec` promise required for subprocess execution is
incompatible with the locked-down set used by database-accessing scripts.

### pledge promise set

All protected and restricted scripts use the same promise string:

```perl
OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock") or die "pledge: $!";
```

`stdio` - standard I/O, memory allocation, time. Required for all output
and for `JSON::XS` memory operations.

`rpath` - read-only filesystem access. Required for reading config,
library, and key files, and for reading queue outcome files.

`wpath` - write filesystem access. Required for writing queue request files,
log files, and temporary files.

`cpath` - create and delete filesystem entries. Required for creating queue
directories, writing new files, and the `rename()` in atomic rewrites.

`flock` - file locking. Required for `flock(LOCK_EX)` in log writes and
config reads.

`exec`, `proc`, `inet`, `unix` are not included. CGI scripts never exec
subprocesses, never fork, never open network connections, and never use Unix
domain sockets. The database connection uses SQLite's file interface covered
by rpath/wpath/cpath, not a network socket.

### unveil path structure

All existence checks (`-d`, `-f`) must happen before the first `unveil()`
call. Once any unveil is issued the kernel restricts filesystem visibility
and un-unveiled paths appear not to exist. The correct pattern is: probe
all candidate paths while the filesystem is fully visible, collect the ones
that exist, then issue all unveil calls in one pass, then lock.

```perl
if (eval { require OpenBSD::Unveil; 1 }) {

    # Mandatory paths — always unveiled
    my @to_unveil = (
        [ "$app_root/data/lib",    "r"   ],  # TN module library
        [ "$app_root/data/config", "r"   ],  # security.conf
        [ "$app_root/data/db",     "rwc" ],  # auth.db (session validation)
        [ "/tmp",                  "rwc" ],  # CGI error log (chroot /tmp)
        [ "/dev/urandom",          "r"   ],  # token and salt generation
    );

    # Optional paths — probe existence before any unveil() call
    for my $entry (
        [ "$app_root/data/keys",          "r" ],  # HMAC and session key files
        [ "/usr/lib/perl5",               "r" ],  # base Perl (if present)
        [ "/usr/libdata/perl5",           "r" ],  # base Perl (alternate layout)
        [ "/usr/local/lib/perl5",         "r" ],  # CPAN/ports modules
        [ "/usr/local/libdata/perl5",     "r" ],  # CPAN/ports (alternate)
        [ "/usr/local/lib",               "r" ],  # shared libs (DBD::SQLite, etc.)
        [ "/usr/lib",                     "r" ],  # base shared libs
    ) {
        push @to_unveil, $entry if -d $entry->[0];
    }

    # Script-specific paths added before this loop
    # (queue directories, data directories, etc.)

    # Issue all unveil calls
    for my $entry (@to_unveil) {
        OpenBSD::Unveil::unveil($entry->[0], $entry->[1])
            or die "unveil $entry->[0]: $!";
    }

    # Lock unveil — no further paths can be added
    OpenBSD::Unveil::unveil() or die "unveil lock: $!";
}
```

The Perl module trees use `if -d $entry->[0]` because their layout varies
between OpenBSD versions and chroot configurations. Hard-failing on a missing
optional path would break the entire sandbox initialisation — which is worse
than not unveiling a non-existent directory. Mandatory paths (lib, config,
db, /tmp, /dev/urandom) do not use the existence probe because the script
cannot function without them.

### Script-specific unveil additions

Each script unveils only what it legitimately needs beyond the mandatory set.
Adding paths to unveil beyond what the script uses widens the attack surface
unnecessarily.

A queue-based script adds its queue directory:

```perl
[ "$app_root/data/services/queue/pf-rules/asn-lookup", "rwc" ],
```

A file mutation script adds its target directory:

```perl
[ "$app_root/data/services/queue/pf-rules/user-input", "rwc" ],
```

A script that reads GeoIP data adds:

```perl
[ "$app_root/data/db/GeoIP", "r" ],
```

A script that writes to the stats directory adds:

```perl
[ "$app_root/data/stats", "rwc" ],
```

### Sandbox failure handling

The entire pledge/unveil block runs inside an `eval`. On failure the error
is logged to the CGI error log in `/tmp` and the script emits a JSON error
response and exits. Because the Content-Type header was already emitted in
step 8, the browser receives a valid JSON error rather than a raw crash dump.

```perl
if ($@) {
    my $err = $@; chomp $err;
    my $d = strftime('%Y-%m-%d', localtime);
    if (open(my $lf, '>>', "/tmp/scriptname-${d}.log")) {
        print $lf "[FATAL] sandbox_init_failed: $err\n";
        close $lf;
    }
    print encode_json({ success => 0, error => 'Internal server error' });
    exit 1;
}
```

---

## Operation Patterns

### Pattern 1 -- Read-Only Stats (standard, no sandbox)

Used by scripts that read system state via system binaries or pre-written
JSON files and return it to the UI. These scripts call `pfctl`, `ps`, or
similar tools via `open(my $fh, '-|', 'binary', 'args')` — the list form
bypasses the shell. The `exec` promise required for this is not compatible
with the locked-down pledge set, so these scripts run without sandbox
constraints.

```perl
#!/usr/bin/perl -T
use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;

BEGIN {
    # ... lib path setup ...
}

use TNEnv;
use TNSecurityCheck;

my $session = security_check('standard');

use JSON::XS;
use POSIX qw(strftime);

$ENV{PATH} = '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin';
delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};

# Read system state
open(my $fh, '-|', 'pfctl', '-si') or die "Cannot run pfctl: $!";
# ... parse output ...
close($fh);

# Output
my $json_out = JSON::XS->new->pretty->canonical->encode($stats);

# Dual-mode: CGI header only when running as CGI
if (exists $ENV{GATEWAY_INTERFACE}) {
    print "Content-Type: application/json\n\n";
}
print $json_out;
```

Key points for this pattern: no CGI module needed if the script outputs
`Content-Type` manually. The `GATEWAY_INTERFACE` check allows the same
script to be run from cron or the command line for testing. The script
may also write its output to a JSON file for the dashboard to read later,
which avoids running pfctl on every page load.

### Pattern 2 -- Queue-Based Async (protected, full sandbox)

Used by scripts that need privileged operations performed by a root-side
daemon. The CGI script writes a request file, the daemon processes it and
writes an outcome file, and the CGI script either polls synchronously
(Perl does the waiting) or provides a separate GET endpoint for the browser
to poll.

The key design principle is that Perl does the waiting, not JavaScript.
The browser sends a single POST request and waits for the HTTP response.
Perl writes the request file, polls the outcome directory, and returns
the result in the same HTTP response. This eliminates race conditions and
keeps the JavaScript simple.

For long-running operations where polling from Perl would exceed CGI
timeouts, a separate GET endpoint is provided. The POST creates the request
and returns immediately, and the browser polls the GET endpoint until the
result is ready.

```perl
#!/usr/bin/perl -T
use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;

BEGIN { # ... lib path setup ... }

use TNEnv;
use TNSecurityCheck;
use DBD::SQLite;      # pre-load XS before pledge
use JSON::XS;

my $session = security_check('protected');

use CGI qw(:standard);
use JSON::PP ();
use File::Path qw(make_path);
use POSIX qw(strftime);

$ENV{PATH} = '/bin:/usr/bin';
delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};

# Derive app root from TNEnv
my $_app_root = get_db_path();
$_app_root =~ s{/data/db/?.*$}{};

# Queue paths
my $REQUEST_DIR = File::Spec->catdir($_app_root, 'data', 'services',
                                     'queue', 'my-queue', 'request');
my $RESULT_DIR  = File::Spec->catdir($_app_root, 'data', 'services',
                                     'queue', 'my-queue', 'result');

# Pre-compute canonical bases BEFORE pledge
my $CANONICAL_REQUEST = File::Spec->rel2abs($REQUEST_DIR);
my $CANONICAL_RESULT  = File::Spec->rel2abs($RESULT_DIR);

# Ensure queue directory exists before pledge locks filesystem
make_path($REQUEST_DIR, $RESULT_DIR, { mode => 0755 })
    unless -d $REQUEST_DIR;

# Emit Content-Type before pledge
my $cgi = CGI->new;
print $cgi->header(-type => 'application/json', -charset => 'utf-8');

# pledge + unveil
{
    my $app_root = $_app_root;
    eval {
        if (eval { require OpenBSD::Unveil; 1 }) {
            my @to_unveil = (
                [ "$app_root/data/lib",    "r"   ],
                [ "$app_root/data/config", "r"   ],
                [ "$app_root/data/db",     "rwc" ],
                [ "/tmp",                  "rwc" ],
                [ "/dev/urandom",          "r"   ],
                [ "$app_root/data/services/queue/my-queue", "rwc" ],
            );
            for my $entry (
                [ "$app_root/data/keys",          "r" ],
                [ "/usr/lib/perl5",               "r" ],
                [ "/usr/libdata/perl5",           "r" ],
                [ "/usr/local/lib/perl5",         "r" ],
                [ "/usr/local/libdata/perl5",     "r" ],
                [ "/usr/local/lib",               "r" ],
                [ "/usr/lib",                     "r" ],
            ) { push @to_unveil, $entry if -d $entry->[0] }
            for my $entry (@to_unveil) {
                OpenBSD::Unveil::unveil($entry->[0], $entry->[1])
                    or die "unveil $entry->[0]: $!";
            }
            OpenBSD::Unveil::unveil() or die "unveil lock: $!";
        }
        if (eval { require OpenBSD::Pledge; 1 }) {
            OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock")
                or die "pledge: $!";
        }
    };
    if ($@) {
        my $err = $@; chomp $err;
        print encode_json({ success => 0, error => 'Internal server error' });
        exit 1;
    }
}

# Ensure queue directories exist (cpath covers creation after pledge)
make_path($REQUEST_DIR, $RESULT_DIR, { mode => 0755 });

# Route by method
my $method = $ENV{REQUEST_METHOD} || 'GET';

if ($method eq 'GET') {
    # Polling endpoint — check for result file
    my $id = untaint_id($cgi->param('id') // '');
    my $result_file = File::Spec->catfile($RESULT_DIR, "${id}.json");
    unless (index($result_file, $CANONICAL_RESULT) == 0) {
        print encode_json({ ready => 0, error => 'Path error' });
        exit 0;
    }
    unless (-f $result_file) {
        print encode_json({ ready => 0 });
        exit 0;
    }
    open(my $fh, '<', $result_file) or do {
        print encode_json({ ready => 0, error => 'Result unreadable' });
        exit 0;
    };
    local $/; my $json = <$fh>; close($fh);
    print $json;
    exit 0;
}

# POST — submit request
my $data = eval { decode_json($cgi->param('POSTDATA') || '{}') };
if ($@) {
    print encode_json({ success => 0, error => 'Invalid JSON' });
    exit 0;
}

# Untaint and validate input
my $id = untaint_id($data->{id} // '');
unless ($id) {
    print encode_json({ success => 0, error => 'Invalid input' });
    exit 0;
}

# Remove stale result
my $result_file = File::Spec->catfile($RESULT_DIR, "${id}.json");
unlink $result_file if -f $result_file;

# Write request file
my $request_file = File::Spec->catfile($REQUEST_DIR, $id);
unless (index($request_file, $CANONICAL_REQUEST) == 0) {
    print encode_json({ success => 0, error => 'Path error' });
    exit 0;
}
open(my $fh, '>', $request_file) or do {
    print encode_json({ success => 0, error => 'Failed to create request' });
    exit 0;
};
print $fh time() . "\n";
close($fh);

print encode_json({ success => 1, id => $id });
exit 0;
```

### Pattern 3 -- Direct File Mutation (restricted, full sandbox)

Used by scripts that modify application-owned data files directly, where
no privilege escalation is needed but the operation is destructive or
irreversible and requires an admin. Examples: deleting entries from PF
rule queue files, updating configuration data.

Atomic rewrite is mandatory for all file mutations. Write to a `.tmp` file
alongside the target, then `rename()` over it. This is atomic at the
filesystem level — readers never see a partial write. Never truncate and
rewrite in place.

```perl
#!/usr/bin/perl -T
use strict;
use warnings;
use FindBin qw($RealBin);
use File::Spec;

BEGIN { # ... lib path setup ... }

use TNEnv;
use TNSecurityCheck;
use DBD::SQLite;
use JSON::XS;

my $session = security_check('restricted');
# $session->{username} is guaranteed to be an authenticated admin

use CGI qw(:standard);
use JSON::PP ();
use POSIX qw(strftime);

$ENV{PATH} = '/bin:/usr/bin';
delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};

my $_app_root = get_db_path();
$_app_root =~ s{/data/db/?.*$}{};

my $DATA_DIR       = File::Spec->catdir($_app_root, 'data', 'services',
                                        'queue', 'pf-rules', 'user-input');
my $CANONICAL_DATA = File::Spec->rel2abs($DATA_DIR);

my $LOG = "/tmp/scriptname-" . strftime("%Y-%m-%d", localtime) . ".log";

my $cgi = CGI->new;
print $cgi->header(-type => 'application/json', -charset => 'utf-8');

# pledge + unveil (POST only — no queue, narrower unveil)
{
    my $app_root = $_app_root;
    eval {
        if (eval { require OpenBSD::Unveil; 1 }) {
            my @to_unveil = (
                [ "$app_root/data/lib",    "r"   ],
                [ "$app_root/data/config", "r"   ],
                [ "$app_root/data/db",     "rwc" ],
                [ "/tmp",                  "rwc" ],
                [ "/dev/urandom",          "r"   ],
                [ "$app_root/data/services/queue/pf-rules/user-input", "rwc" ],
            );
            for my $entry (
                [ "$app_root/data/keys",          "r" ],
                [ "/usr/lib/perl5",               "r" ],
                [ "/usr/libdata/perl5",           "r" ],
                [ "/usr/local/lib/perl5",         "r" ],
                [ "/usr/local/libdata/perl5",     "r" ],
                [ "/usr/local/lib",               "r" ],
                [ "/usr/lib",                     "r" ],
            ) { push @to_unveil, $entry if -d $entry->[0] }
            for my $entry (@to_unveil) {
                OpenBSD::Unveil::unveil($entry->[0], $entry->[1])
                    or die "unveil $entry->[0]: $!";
            }
            OpenBSD::Unveil::unveil() or die "unveil lock: $!";
        }
        if (eval { require OpenBSD::Pledge; 1 }) {
            OpenBSD::Pledge::pledge("stdio rpath wpath cpath flock")
                or die "pledge: $!";
        }
    };
    if ($@) {
        my $err = $@; chomp $err;
        write_log('FATAL', "sandbox_init_failed: $err");
        print encode_json({ success => 0, error => 'Internal server error' });
        exit 1;
    }
}

# Audit logging — always includes admin username
sub write_log {
    my ($level, $msg) = @_;
    my $ts       = strftime("%Y-%m-%d %H:%M:%S", localtime);
    my $username = $session->{username} || 'unknown';
    open(my $fh, '>>', $LOG) or return;
    print $fh "[$ts] USER:$username [$level] $msg\n";
    close($fh);
}

# POST only
my $method = $ENV{REQUEST_METHOD} || '';
unless ($method eq 'POST') {
    write_log('ERROR', "Invalid method: $method");
    print encode_json({ success => 0, error => 'POST only' });
    exit 1;
}

# Parse and validate input
my $data = eval { decode_json($cgi->param('POSTDATA') || '') };
if ($@ || !$data) {
    write_log('ERROR', "Invalid JSON");
    print encode_json({ success => 0, error => 'Invalid JSON' });
    exit 1;
}

# ... validate and untaint fields ...

# Atomic file mutation
sub safe_delete_line {
    my ($filename, $target_line) = @_;

    # Validate filename — alphanumeric, hyphen, underscore, dot only
    unless ($filename =~ /^([a-z0-9_-]+\.(?:txt|json))$/i) {
        return (0, 'Invalid filename');
    }
    my $safe_filename = $1;
    my $full_path     = File::Spec->catfile($DATA_DIR, $safe_filename);

    # Path traversal check using pre-computed canonical base
    unless (index($full_path, $CANONICAL_DATA) == 0) {
        return (0, 'Path traversal detected');
    }

    # Untaint after path confirmation
    if ($full_path =~ m{^([-/\w.]+)$}) {
        $full_path = $1;
    } else {
        return (0, 'Invalid path characters');
    }

    unless (-f $full_path) {
        return (0, 'File not found');
    }

    # Read all lines
    my @lines;
    open(my $fh, '<', $full_path) or return (0, "Cannot read: $!");
    while (my $line = <$fh>) {
        chomp $line;
        push @lines, $line if $line =~ /\S/;
    }
    close($fh);

    my $original = scalar @lines;
    @lines = grep { $_ ne $target_line } @lines;
    return (0, 'Entry not found') if scalar(@lines) == $original;

    # Atomic rewrite
    my $tmp = $full_path . '.tmp';
    open(my $out, '>', $tmp) or return (0, "Cannot write temp: $!");
    print $out "$_\n" for @lines;
    close($out);

    unless (rename($tmp, $full_path)) {
        unlink $tmp;
        return (0, "Cannot rename: $!");
    }

    return (1, $original - scalar(@lines));
}

# ... call safe_delete_line and log result ...

exit 0;
```

---

## Taint Untainting Patterns

Every value from outside the process is tainted in `-T` mode: CGI
parameters, environment variables, database values, file contents. Before
any tainted value can be used in a file operation, system call, or regex
that could affect program flow, it must be untainted with a pattern match
that captures only the expected characters.

The pattern match is the untaint step — the captured group `$1` is clean.
The match must be strict enough to reject anything that does not belong.
Never use `(.*)` or `(.+)` as an untaint pattern — these accept everything
including traversal sequences and injection characters.

Common untaint helpers used across CGI scripts:

```perl
# IP address: IPv4, IPv4 CIDR, IPv6, IPv6 CIDR
sub untaint_ip {
    my ($ip) = @_;
    # IPv4
    return $1 if $ip =~ /^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}
                           (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/x;
    # IPv4 CIDR
    return $1 if $ip =~ /^((?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[12][0-9]|3[0-2]))$/;
    # IPv6 (simplified — full validation in production)
    return $1 if $ip =~ /^((?:[0-9a-fA-F]{0,4}:){2,7}:?[0-9a-fA-F]{0,4})$/;
    return undef;
}

# ASN: AS followed by up to 10 digits, case-insensitive, normalised to uppercase
sub untaint_asn {
    my ($raw) = @_;
    $raw = uc($raw // '');
    $raw = "AS$raw" if $raw =~ /^\d{1,10}$/;
    return $1 if $raw =~ /^(AS\d{1,10})$/;
    return undef;
}

# PF action: block or pass only
sub untaint_action {
    my ($action) = @_;
    return $1 if $action =~ /^(block|pass)$/;
    return undef;
}

# Feed URL: http/https only, explicit scheme rejection
sub untaint_url {
    my ($url) = @_;
    return undef unless $url =~ /^(https?:\/\/[a-zA-Z0-9\-._~:\/?#\[\]@!$&'()*+,;=%]+)$/;
    my $clean = $1;
    return undef if $clean =~ /^(file|ftp|data|javascript):/i;
    return $clean;
}

# General identifier: alphanumeric and underscore only
sub untaint_id {
    my ($id) = @_;
    return $1 if $id =~ /^([a-zA-Z0-9_-]{1,64})$/;
    return undef;
}
```

---

## Queue Consumers

Four root-side daemons consume queues written by CGI scripts. All run
outside the chroot as root and write outcome files that the `www` user
can read.

`queue_processor.sh` — processes `data/services/queue/request/` for
`manage_services.pl`. Handles service start/stop/restart operations. Outcome
files written to `data/services/queue/outcome/`. Request format: one line,
`ACTION SERVICE`.

`unbound_queue_runner.sh` → `manage_unbound.sh` — processes
`data/services/queue/unbound/request/` for `unbound_control.pl`. Handles
DNS blocklist management, zone reloads, and cache operations. Request files
are JSON with timestamp and random component in the name. Outcome files
written to `data/services/queue/unbound/outcome/`.

`integrity_check_runner.sh` → `integrity_check.sh` — processes
`data/services/queue/request/` for the TNAudit web interface. Handles
`verify <check>` and `update-baseline <check>` operations. Outcome files
contain raw JSON output from `TNAudit.pl --json`. See
`TNAUDIT_DEVELOPER_GUIDE.md` for the full request format and queue-and-poll
pattern.

`pf_asn_runner.sh` — processes
`data/services/queue/pf-rules/asn-lookup/request/` for `pf_asn_lookup.pl`.
Performs PeeringDB, RIPE STAT, and PTR lookups for ASN impact analysis — the
`www` user inside the chroot cannot reach the internet. Result files written
to `data/services/queue/pf-rules/asn-lookup/result/` as `AS{number}.json`.

New queue consumers follow the same pattern: a root-side shell script polls
a request directory, processes each file, and writes a JSON outcome file.
The CGI script's only responsibility is writing a valid request file and
reading the outcome — it never executes privileged operations directly.

---

## Queue and Data Directory Permissions

Queue and data directories that CGI scripts write to must be owned by `www`
and writable by `www`. Directories that root-side daemons also write to
(outcome/result directories) should be `www:wheel 755` so that root can
write outcomes that `www` can read.

```sh
# Queue directories writable by www CGI scripts
chown -R www:www /var/www/htdocs/tn/data/services/queue/
chmod 755 /var/www/htdocs/tn/data/services/queue/
find /var/www/htdocs/tn/data/services/queue/ -type d -exec chmod 755 {} +

# CGI scripts: owned by www, executable
chown www:www /var/www/htdocs/tn/cgi-bin/*.pl
chmod 755 /var/www/htdocs/tn/cgi-bin/*.pl

# Key files: root-owned, read-only
chown root:wheel /var/www/htdocs/tn/data/keys/
chmod 700 /var/www/htdocs/tn/data/keys/
chmod 600 /var/www/htdocs/tn/data/keys/*.key
```

---

## JavaScript Integration

The browser side is simple — send a POST request with a JSON body
containing the CSRF token, handle the JSON response. For operations that
return results immediately, one request is sufficient. For operations that
use the GET polling pattern, send the POST first, then poll the GET
endpoint until `ready` is true.

```javascript
// Get CSRF token (required for protected and restricted endpoints)
const csrfResp = await fetch('/cgi-bin/control.pl/api/csrf');
const { token } = await csrfResp.json();

// Submit request (protected or restricted endpoint)
const response = await fetch('/cgi-bin/my_script.pl', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        csrf_token: token,
        action: 'my_action',
        value: 'my_value'
    })
});
const result = await response.json();

// For queue-based operations with separate polling endpoint
async function pollForResult(id, maxAttempts = 30) {
    for (let i = 0; i < maxAttempts; i++) {
        const resp = await fetch(`/cgi-bin/my_script.pl?id=${encodeURIComponent(id)}`);
        const data = await resp.json();
        if (data.ready !== false) return data;
        await new Promise(r => setTimeout(r, 1000));
    }
    throw new Error('Timeout waiting for result');
}
```

Note that GET polling endpoints at `protected` level do not require a CSRF
token — the CSRF check in `TNSecurityCheck` only applies to POST requests.
The session cookie provides authentication for the GET poll, and the
`SameSite=Strict` cookie attribute prevents cross-origin polling.

---

## Troubleshooting

### 500 error from a CGI script

Check the CGI error log in the chroot `/tmp` directory. Scripts redirect
STDERR to date-stamped files:

```sh
# Inside the chroot (as root)
ls /var/www/tmp/
tail -50 /var/www/tmp/scriptname-$(date +%Y-%m-%d).log
```

Common causes: the CGI module is not loaded before `$cgi->header()` is
called; `DBD::SQLite` was not loaded before pledge; an unveil path that
the script needs was not added to the unveil list; `POSTDATA` is empty
because the request body was not read with `$cgi->param('POSTDATA')`.

### Timeout waiting for queue outcome

```sh
# Is the queue daemon running?
pgrep -f queue_runner

# Check queue directories for stale request files
ls -la /var/www/htdocs/tn/data/services/queue/request/
ls -la /var/www/htdocs/tn/data/services/queue/outcome/

# Check daemon log
tail -50 /var/www/tmp/queue_processor-$(date +%Y-%m-%d).log
```

### pledge failure: operation not permitted

The script is attempting a filesystem or system operation not covered by
the promise set. Common causes: attempting to exec a subprocess after pledge
(requires `exec` promise which is incompatible with the standard set); trying
to call `getcwd()` or `rel2abs()` after unveil has been applied (these
internally stat directories that may not be unveiled); accessing a path
that was not added to the unveil list.

### Path traversal check failing on legitimate input

Verify that the canonical base was computed before pledge with `rel2abs()`.
If the base was computed inside the pledge/unveil block, `rel2abs()` will
have returned a wrong or undefined value because `getcwd()` cannot see
un-unveiled directories. The canonical computation must happen before the
first `unveil()` call.

### JSON parse error in outcome file

Simple command output (flush, reload, enable/disable): use sed/awk for JSON
encoding — `jq` is not always available in all execution contexts.

Complex output with multiline strings, special characters, or nested data:
use `jq -n --arg key "$value" '{key: $key}'`. Never manually concatenate
JSON strings — unescaped newlines, quotes, or backslashes in command output
will produce malformed JSON.

Inspect the raw outcome file to see what was actually written:

```sh
cat /var/www/htdocs/tn/data/services/queue/outcome/*.json
```

---

## Summary Reference

| Level       | Auth required | CSRF | POST enforced | Admin only | pledge/unveil |
|-------------|---------------|------|---------------|------------|---------------|
| standard    | No            | No   | No            | No         | Only if no exec needed |
| protected   | Yes           | Yes  | Yes           | No         | Yes |
| restricted  | Yes           | Yes  | Yes           | Yes        | Yes |

| Pattern             | Level      | File operation       | Audit log |
|---------------------|------------|----------------------|-----------|
| Read-only stats     | standard   | Read or exec         | No        |
| Queue-based async   | protected  | Write request file   | Optional  |
| Direct file mutation| restricted | Atomic read-modify-write | Mandatory |

---

## Author and Attribution

Primary Author: David Peter
Organization:   Tangent Networks
Web:            https://tangentnet.top
Email:          tangent.net@zohomail.in

---

## License

BSD 3-Clause License

Copyright (c) 2025-2026 David Peter, Tangent Networks
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions, and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions, and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF
OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

*End of CGI_ARCHITECTURE.md*
