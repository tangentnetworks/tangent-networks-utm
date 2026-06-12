<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# SECURITY_ARCHITECTURE.md

**Tangent Networks UTM Appliance -- Security Architecture Reference**

---

## Overview

The Tangent appliance implements a layered security model where each layer
is independent and assumes all outer layers may have been bypassed. The
layers from the network perimeter inward are: the PF firewall, the OpenBSD
httpd TLS termination and path restriction, the TNWAF routing and request
validation layer, the pledge/unveil process sandbox, the TNSecurityCheck
authentication and authorisation gate, and the TNSecurity cryptographic
primitives that underpin sessions, CSRF tokens, and password storage.

All server-side code runs under Perl taint mode (`-T`). Every string
arriving from outside the process -- environment variables, CGI parameters,
file paths, database values -- is tainted and must pass an explicit pattern
match before use. There are no exceptions to this rule in production code.

The central configuration file is `/var/www/htdocs/tn/data/config/security.conf`.
It controls the DEVEL mode flag, all feature toggles, rate limit parameters,
session lifetime, CSRF token lifetime, and database path. Every security
feature reads from this file at startup via `TNConfig.pm`. If the file is
absent, unreadable, or missing its `[mode]` section, `TNConfig` fails closed:
`DEVEL=0`, all security features enabled, no credentials set.

---

## Network Perimeter -- PF Firewall

The outermost layer. Default-deny on all interfaces. The ruleset is
documented in full in `FIREWALL.md`. Key points relevant to the security
architecture:

All inbound traffic arrives on `vio0` (WAN). The LAN interface `vio1`
serves clients. Services are not directly accessible from the WAN -- only
the ports explicitly passed reach the appliance. Bogon blocks and
anti-spoofing rules are applied before any pass rule is evaluated.

The proxy services (SSLproxy, p3scan, smtp-gated, e2guardian, spamd,
Dante) are inserted into the traffic path by PF divert rules. Client
traffic is redirected to the proxy before it can reach the internet.
The proxies themselves are confined to their task by the architecture --
they cannot initiate arbitrary outbound connections because PF only passes
traffic originating from the correct daemon users and ports.

SSH is LAN-only. There is no WAN SSH entry. Root login via SSH is refused
by sshd configuration.

---

## TLS and HTTP Entry Point -- httpd

OpenBSD `httpd(8)` terminates TLS 1.2 and 1.3. TLS 1.0 and 1.1 are not
offered. The certificate and private key are stored outside the web root.

All HTTP requests are rewritten to `router.pl` via the httpd configuration.
httpd does not serve files directly from the document root -- every request,
including static assets, passes through the CGI layer. This is the
architectural decision that makes TNWAF the single entry point: there is no
path that can reach a file without going through `router.pl` first.

httpd enforces path-based hard blocks before any CGI code runs. The
following paths return 403 directly from httpd without the request ever
reaching Perl:

`data/keys/` -- HMAC key files and session keys. These must never be served
under any circumstance.

`data/config/` -- security.conf and other configuration files containing
credentials and feature flags.

`data/lib/` -- the Perl module library. Serving source code would expose
every security implementation detail.

`data/scripts/` -- operational scripts.

`data/session/` and `data/run/` -- runtime state including PID files and
session infrastructure.

`data/queue/` -- the privilege escalation queue used by service_manager.sh.
Serving queue files would expose pending privileged operations.

The httpd `location` blocks for `data/db/` are partially open: GeoIP lookup
data and PF table data under `data/db/GeoIP/` and `data/db/pf/` are
accessible because the UI reads them for display. SQLite database files
(`.db`, `.db-wal`, `.db-shm`) are blocked by a catch-all pattern -- the
database files containing credentials and session data are never served.

---

## TNWAF -- Web Application Firewall

`TNWAF.pm` is loaded by `router.pl` and is the first Perl code that
executes for every request. It performs request validation, rate limiting,
routing, server-side SRI verification, and response header injection.

### Deployment Gate

Before any routing logic runs, `router.pl` checks whether DEVEL mode is
active and whether the server address is a loopback address. If DEVEL mode
is on and the server is bound to a non-loopback address, the request is
refused with a 503 and nothing is served. This prevents an accidental
production deployment with security bypasses active. The check uses
`$ENV{SERVER_ADDR}` set by httpd/slowcgi -- it cannot be spoofed by the
client.

### Request Validation

`validate_request()` runs before any routing decision. It enforces a 2048-
byte URI length limit and blocks URIs matching six patterns:

`..` -- path traversal. Blocked unconditionally regardless of context.

`[<>'"]` -- HTML and SQL injection characters in the URI.

`union.*select` (case-insensitive) -- SQL injection pattern.

`script.*src` (case-insensitive) -- script injection pattern.

`javascript:` (case-insensitive) -- JavaScript URI scheme.

`data:text/html` (case-insensitive) -- data URI HTML injection.

Any match causes an immediate 400 response. The blocked URI is logged to
`data/logs/waf/security.log` and emitted to syslog via `logger -t tnwaf
-p security.warning`. The TNWatch `parse_tnwaf_security` parser reads the
security log and emits a `blocked_uri` event, which triggers the
`tnwaf_rate_limit` alert rule if it fires repeatedly.

Only `GET`, `POST`, `HEAD`, and `OPTIONS` methods are permitted. Any other
method is blocked with a 400 before routing.

### Rate Limiting

`check_rate_limit()` runs after request validation. The rate limiter
maintains two in-process hash tables: `%RATE_LIMITS` tracks request counts
per IP within 60-second sliding windows, and `%IP_BLOCKS` tracks IPs that
have exceeded the limit and their block expiry timestamps.

The default limit is 60 requests per minute, configurable via
`MAX_REQUESTS_PER_MINUTE` in `security.conf`. A floor of 10 req/min and
a lockout floor of 60 seconds are enforced in code -- the operator cannot
misconfigure the appliance into having no rate protection. Exceeding the
limit blocks the IP for `LOCKOUT_DURATION` seconds (default 1800, floor 60).

The rate limiter state is in-process memory, not the database. This means
it resets on every slowcgi worker restart. For a UTM appliance where httpd
and slowcgi typically run as a small fixed worker pool, this is acceptable --
it limits burst attacks from a single connection but does not provide
cross-session persistence. Network-level rate limiting at the PF layer is
the persistent mechanism.

A blocked IP receives a 429 response. The block is logged to both the
security log and syslog.

### Routing

After validation and rate limiting, `route_request()` dispatches to one of
several handler functions. The URI is matched against explicit patterns in
order. There is no wildcard catch-all that serves arbitrary files -- every
path is explicitly permitted or falls through to a 404.

CGI scripts under `/cgi-bin/` are dispatched via `proxy_to_cgi()`, which
validates that the target script exists and is executable before calling
`exec()`. A script that does not exist returns 404. `exec()` replaces the
current process, which means TNWAF's memory state (including the rate limit
tables) is not accessible from the CGI script -- each CGI invocation is a
fresh process.

Static HTML files are served via `serve_static_html()`, which applies a
strict `[\w.-]+\.html` filename pattern before constructing the filesystem
path. View fragments under `/view/` and documentation fragments under
`/docs/` use equivalent pattern validation.

Asset files (JS, CSS, fonts, images) are served via `serve_asset()`. The
asset type (`js`, `css`, `fonts`, `img`, `images`) is validated against the
URI structure. Path traversal (`..`) is explicitly checked in addition to
the character class validation -- two independent checks for the same attack.

`serve_data()` handles requests under `/data/`. It applies a denylist of
top-level subdirectory names: `keys`, `config`, `lib`, `lib-bak`, `scripts`,
`session`, `run`, `queue` all return 403. For `db/`, SQLite files
(`.db`, `.db-wal`, `.db-shm`) are blocked by pattern. Everything else in
`data/` is accessible -- this covers log files, GeoIP data, PF table exports,
and service status JSON that the UI legitimately reads.

### Server-Side SRI Verification

Every JavaScript file served by `serve_file()` undergoes server-side
integrity verification before delivery. `TNWAF.pm` contains a compile-time
hash table (`%CONFIG{sri_hashes}`) mapping each JS asset path to its known-
good SHA-384 hash. When a JS file is requested, the file content is read,
hashed with SHA-384, and compared against the table entry using string
equality.

If the hashes do not match -- indicating the file has been modified on disk
since the hash was computed -- the file is refused with a 500 and the mismatch
is logged to the security log as `SRI_TAMPER`. The browser never receives
the compromised file regardless of what the HTML `integrity=` attribute says.
This is a defence-in-depth measure: the browser's SRI check is the standard
mechanism, but the server-side check catches tampering before the file
leaves the server.

The `X-Content-Digest` response header carries the expected SRI hash for
JS files, allowing external monitoring tools to verify the served hash
matches expectations.

### Security Response Headers

All responses served through `print_headers()` in TNWAF carry:

`X-Frame-Options: DENY` -- prevents the UI from being embedded in an iframe.
Belt-and-suspenders alongside `frame-ancestors 'none'` in the CSP.

`X-Content-Type-Options: nosniff` -- prevents MIME type sniffing. Critical
for preventing a log file or JSON response from being interpreted as
executable content.

`X-XSS-Protection: 1; mode=block` -- legacy XSS filter for older browsers.

`Referrer-Policy: strict-origin-when-cross-origin` -- limits referrer
leakage on cross-origin navigations.

`Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()`
-- denies all hardware and payment APIs. The appliance UI has no use for any
of these.

`Strict-Transport-Security: max-age=31536000; includeSubDomains` -- instructs
browsers to enforce HTTPS for one year. Effective only over HTTPS; ignored
and harmless over HTTP.

`Cache-Control: no-cache, no-store, must-revalidate, private` with
`Pragma: no-cache` and `Expires: 0` -- all responses are uncacheable. This
prevents sensitive UI state from being stored in the browser cache.

HTML responses additionally receive the full Content Security Policy.

### Content Security Policy

The CSP is built dynamically from the `%CONFIG{csp}` hash in `TNWAF.pm`.
Key directives:

`default-src 'self'` -- all resource types default to same-origin only.

`script-src 'self'` -- no inline scripts, no `unsafe-eval`. All JavaScript
is in external files that pass SRI verification on both the server and the
browser.

`style-src 'self' 'unsafe-inline'` -- `'unsafe-inline'` is required because
Tailwind CSS and Flowbite generate some inline style attributes for custom
form elements. This is a known trade-off.

`img-src 'self' data:` -- `data:` is required for inline SVG data URIs
generated by Tailwind/Flowbite for custom selects and checkboxes.

`object-src 'none'` -- blocks all Flash, Java, and plugin content entirely.

`frame-ancestors 'none'` -- prevents all framing, complementing
`X-Frame-Options: DENY`.

`form-action 'self'` -- form submissions can only target the same origin.

`upgrade-insecure-requests` -- instructs the browser to upgrade HTTP
sub-resource requests to HTTPS.

JSON API responses from `TNSecurity::print_secure_headers()` use a tighter
CSP: `default-src 'none'; connect-src 'self'`. API endpoints have no
legitimate need to load any resources -- only fetch calls back to the same
origin are permitted.

### Triple Logging

TNWAF writes to three separate log files. `data/logs/waf/access.log`
receives one entry per request with timestamp, IP, method, URI, and user
agent. `data/logs/waf/security.log` receives entries for blocked requests,
rate limit events, and SRI tamper detections. `data/logs/waf/error.log`
receives HTTP error responses (4xx and 5xx) with the format
`[timestamp] HTTP CODE STATUS - IP=x.x.x.x URI=/path` -- this is the format
parsed by TNWatch's `parse_tnwaf_error` parser.

Error events are also written to `data/logs/httpd/httpd_error.log` for the
UI log viewer. Security events are additionally submitted to syslog via
`logger -t tnwaf -p security.warning`, making them visible in
`data/logs/system/messages` for the TNWatch syslog parser.

---

## Process Sandbox -- pledge(2) and unveil(2)

OpenBSD's `pledge(2)` and `unveil(2)` restrict what a process can do after
the sandbox is initialised. Every CGI script applies both before processing
any request data.

`unveil(2)` is applied in `control.pl` before the first request is processed.
All existence checks (`-d`, `-f`) are performed before the first `unveil()`
call -- once any unveil is issued the kernel restricts filesystem visibility
and subsequent existence checks on un-unveiled paths return false. The
correct pattern is: collect all paths to unveil, check their existence while
the filesystem is fully visible, then issue all unveil calls in one pass,
then lock with `unveil()`.

`control.pl` unveils:

`data/lib` (read) -- the Perl module library.
`data/config` (read) -- security.conf.
`data/db` (read-write-create) -- auth.db for session and user operations.
`data/keys` (read) -- HMAC and session key files.
`data/logs` (read-write-create) -- security event logging.
`/tmp` (read-write-create) -- slowcgi stderr log redirect.
`/dev/urandom` (read) -- random number generation for tokens and salts.
Perl module trees and shared libraries (read) -- probed for existence before
unveiling, covers both chroot and non-chroot layouts.

After all unveil calls, `unveil()` with no arguments locks the unveil list --
no further paths can be added and any access to an un-unveiled path fails.

`pledge(2)` is then applied with `"stdio rpath wpath cpath flock"`. The
`exec` promise is not included -- `control.pl` does not need to exec
subprocesses. `proc` is not included -- no forking. `inet` and `unix` are
not included -- no network access from the CGI process. The database
connection uses SQLite's file interface (covered by rpath/wpath/cpath), not
a network socket.

`router.pl` is the exception to the pledge/unveil pattern. It loads over
100 distinct paths dynamically via the lib loader and the TNWAF dispatcher,
making a meaningful unveil whitelist impossible -- a whitelist covering every
possible path would be equivalent to no whitelist. This is documented and
accepted. The TNWAF input validation, rate limiting, and routing logic
compensate at the application layer.

All other CGI scripts that use `TNSecurityCheck.pm` apply pledge and unveil
appropriate to their specific function. The unveil scope for each script
covers only what that script legitimately needs.

---

## TNEnv -- Environment Bootstrap

`TNEnv.pm` must be the first TN module loaded in every script and module.
It runs at compile time (`BEGIN`) and performs four tasks: it cleans the
process environment for taint mode (sets a minimal `PATH`, deletes `IFS`,
`CDPATH`, `ENV`, `BASH_ENV`); sets `LD_LIBRARY_PATH` for chroot library
resolution; configures STDIN and STDERR with UTF-8 encoding layers while
leaving STDOUT as raw bytes (critical -- the JSON serialiser produces raw
UTF-8 octets, and adding an encoding layer on top would double-encode
non-ASCII output); and resolves and validates the library path from its
own `__FILE__` location, adding it to `@INC`.

All path utilities in TNEnv reject `..` segments before pattern matching --
the traversal check is a separate explicit rejection, not relying on the
regex to catch it. `_resolve_path()` handles chroot environments where
`abs_path()` may return undef for paths that exist within the chroot but
whose parent directories are not visible from the current context.

---

## TNConfig -- Configuration Management

`TNConfig.pm` is the single point of access for `security.conf`. It parses
the file once and caches the result in `%CONFIG`. Subsequent calls to
`get_config()` and `is_devel_mode()` read from the in-process cache.

The fail-closed design is the critical security property: if `security.conf`
is missing, unreadable, or parsed without a `[mode]` section, `_fail_closed()`
is called. This sets `DEVEL=0`, enables all security features, and leaves
the DEVEL password hash empty. The failure is logged loudly to STDERR where
it appears in the web server error log. The system continues to function
with full security enforced rather than falling back to any insecure default.

`write_config()` is the only function that modifies `security.conf`. It uses
targeted in-place replacement of the `DEVEL = N` line, preserving all
comments and operator edits. It acquires `flock(LOCK_EX)` on both the read
and write passes to prevent concurrent modification from multiple slowcgi
worker processes.

The DEVEL mode password is stored as a PBKDF2 hash in `security.conf` under
`[mode]`, not as plaintext. `check_devel_password()` calls
`TNSecurity::verify_password()` for the comparison. The plaintext
`DEVEL_PASSWORD` field visible in `security.conf` is the legacy format and
should be replaced with `DEVEL_PASSWORD_HASH` and `DEVEL_PASSWORD_SALT`
generated by `init_db.pl` at install time.

---

## TNSecurity -- Cryptographic Primitives

`TNSecurity.pm` provides the cryptographic operations used throughout the
stack. All operations that touch security-sensitive values go through this
module -- nowhere else in the codebase are hashes computed, tokens generated,
or signatures verified.

### Password Hashing

Two algorithms are in use, identified by a prefix on the stored hash:

The current algorithm uses PBKDF2-HMAC-SHA256 with 100,000 iterations and
a 32-byte derived key, via `Crypt::PBKDF2`. Hashes are stored with the
prefix `pbkdf2:` followed by the hex-encoded derived key. The salt is stored
separately in the `salt` column.

The legacy algorithm uses iterated SHA-256 with 10,000 rounds. Stored
hashes have no prefix. They are accepted for login but transparently rehashed
to PBKDF2 on the next successful authentication via `needs_rehash()` and the
rehash block in `TNAuth::authenticate_user()`. Once all users have logged in
at least once after the upgrade, no legacy hashes remain in the database.

`PBKDF2_ITERATIONS` is a named constant in `TNSecurity.pm`. Changing it
invalidates all existing hashes and requires a migration step. It must not
be changed without a deliberate database migration plan.

Recovery codes use `sha256_hex($code)` without a salt. This is intentional
and documented: recovery codes are long, random, and single-use. They are
not subject to dictionary attacks. Adding a salt would make the comparison
more complex without meaningful security benefit. `verify_recovery_hash()`
applies `timing_safe_compare()` to prevent timing attacks even against the
simpler scheme.

### Session ID Signing

Session IDs generated by `TNAuth::create_session()` are random 64-character
hex strings. Before being placed in the session cookie, they are signed with
HMAC-SHA256 using the key from `data/keys/session.key`. The signed form is
`session_id.hex_signature`. The cookie value is always the signed form.

On every request, `TNSecurityCheck::_check_session()` extracts the cookie
value, calls `TNSecurity::verify_session_id()` to strip and verify the
signature, and only then queries the database with the bare session ID. A
forged or tampered cookie fails signature verification and is rejected
without any database query.

The session key file is read by `TNSecurity::read_key()`. A missing key
file is always a fatal error -- the system dies immediately rather than
auto-generating a new key, which would silently invalidate all existing
sessions. Key files are created by `init_db.pl` at install time and must
not be deleted or rotated without a planned session invalidation.

### CSRF Tokens

CSRF tokens are deterministic time-window MACs: `HMAC-SHA256("csrf:W",
hmac_key)` where `W = floor(time() / TOKEN_LIFETIME)`. The default lifetime
is 3600 seconds (one hour). Being deterministic means validation re-derives
the expected value rather than performing a database lookup -- no CSRF token
storage is needed.

Validation accepts tokens from the current window and the previous window.
This handles the boundary case where a token is fetched just before a window
boundary and submitted just after it. It does not create a meaningful
extension of token validity -- the maximum accepted age is just under two
window lengths (just under two hours by default).

The format check `$token =~ /^[a-f0-9]{64}$/` runs before the HMAC
comparison. A token that does not match this pattern is rejected without
calling the HMAC function, preventing format-confusion attacks.

`timing_safe_compare()` is used for all credential comparisons: password
hashes, session signatures, CSRF tokens, and recovery code hashes. The
implementation is a character-by-character XOR accumulator -- it takes
constant time proportional to the string length regardless of where the
first differing byte occurs, preventing timing oracle attacks.

### Key Management

Two key files are used. `data/keys/session.key` signs session IDs. It is
also used for password reset tokens via `TNSecurity::hmac_hex()` with
`key_name='session'` -- using the same key is intentional and safe because
the HMAC input for reset tokens includes a `:reset` purpose tag, making
the output domain-separated from session signatures.

`data/keys/hmac.key` is used for CSRF tokens and general HMAC operations.

Both key files are mode 0600. The `data/keys/` directory is mode 0700. The
httpd `location` block blocks HTTP access entirely. The unveil in `control.pl`
grants read-only access. The files are read once per process invocation and
the key value is used directly from the string -- no in-memory caching across
requests.

---

## TNAuth -- Authentication and Session Management

`TNAuth.pm` manages users, sessions, registration tokens, security questions,
and recovery codes. It operates exclusively via SQLite (`auth.db`) using DBI
with `RaiseError => 1` (all database failures die), `AutoCommit => 1`, and
`sqlite_use_immediate_transaction => 1`. The immediate transaction mode
prevents "database is locked" errors under concurrent slowcgi writes -- all
writers immediately acquire a write lock rather than attempting an optimistic
read-then-upgrade.

### Authentication Flow

`authenticate_user()` performs the following steps in order:

DEVEL mode bypass: if `TNConfig::is_devel_mode()` is true and the password
is `DEVEL_BYPASS`, authentication succeeds immediately with admin role and
user ID `'dev'`. This bypass is logged at warning severity.

User lookup: the user record is fetched by username. If no record exists,
`'Invalid credentials'` is returned -- the same message as a wrong password,
preventing username enumeration.

Lockout check: if the user is locked and `locked_until` is in the future,
access is denied. If `locked_until` has passed, the lockout is automatically
cleared and authentication proceeds. This auto-clear means a timed lockout
expires without requiring admin intervention.

Password verification: `TNSecurity::verify_password()` is called with the
submitted password, the stored hash, and the stored salt. On failure, the
`failed_attempts` counter is incremented. When `failed_attempts` reaches the
`MAX_LOGIN_ATTEMPTS` threshold (default 5, floor 3, ceiling 10), the account
is locked until `now + LOCKOUT_DURATION`.

Transparent rehash: on successful authentication, `needs_rehash()` checks
whether the stored hash uses the legacy algorithm. If so, a new PBKDF2 hash
is computed and stored immediately, while the plaintext password is still in
scope.

Last login update: `last_login` and `login_count` are updated atomically
with the `failed_attempts` reset.

### Session Creation and Lifetime

`create_session()` generates a 64-character random hex session ID using
`TNSecurity::generate_token()`, stores it in the `sessions` table with the
client IP, user agent, creation timestamp, and expiry timestamp, and returns
the bare session ID. The caller (`handle_login()` in `control.pl`) then
signs it with `TNSecurity::sign_session_id()` before placing it in the
cookie.

Session lifetime is read from `security.conf [session] SESSION_LIFETIME`
(default 7200 seconds). A floor of 900 seconds (15 minutes) and ceiling of
86400 seconds (24 hours) are enforced in code. These bounds prevent the
operator from misconfiguring the appliance into insecure (never-expiring) or
unusable (30-second) sessions.

`validate_session()` performs a JOIN between `sessions` and `users`,
filtering on `session_id` and `expires_at > now`. On success it updates
`last_activity`. It returns the username and role from the users table -- not
from the session row -- ensuring that role changes take effect on the next
request without requiring re-login.

Session cookies are set with the attributes from `security.conf`:
`HttpOnly=1`, `SameSite=Strict`, `Secure=0` (HTTP-only LAN appliance -- the
`Secure` flag is intentionally off). `SameSite=Strict` provides CSRF
protection at the browser level in addition to the HMAC-based CSRF tokens.

`cleanup_expired_sessions()` deletes all rows where `expires_at < now`. It
is called by the `TNAuth::cleanup_expired_sessions()` cron entry running as
`www` every Monday at 15:01. This is a maintenance operation -- expired
sessions are already rejected by `validate_session()` due to the
`expires_at > now` filter. The cleanup prevents the sessions table from
growing indefinitely.

### Registration Control

New user registration requires either being the first user (zero rows in
the `users` table, granted admin role automatically) or presenting a valid
single-use registration token. Tokens are generated by an admin via the
`api/registration/tokens` endpoint and stored in the `registration_tokens`
table. Each token is 64 hex characters and can be used exactly once -- on
use, the token row is updated with `used=1`, `used_at`, and `used_by`.

This design means the administrator controls who can register. There is no
open registration. An attacker who discovers the registration endpoint cannot
create an account without a valid token.

### Password Reset

The reset flow uses a short-lived HMAC-signed reset token rather than a
database-stored token. The flow is:

The user submits their username. Rate limiting is checked via
`check_reset_attempts()` -- default 3 attempts, after which the user is
locked out for `LOCKOUT_DURATION` seconds.

The user answers their security questions (set at registration time,
stored as PBKDF2 hashes) or submits a single-use recovery code (stored as
`sha256_hex(code)`).

On successful verification, `_issue_reset_token()` in `control.pl` generates
a token: `base64("username:expiry").hmac_hex("payload:reset", session_key)`.
The token is returned to the client in the API response.

The user submits the new password along with the reset token. `_verify_reset_token()`
checks the HMAC signature, decodes the payload, verifies the username matches,
and checks that `time() <= expiry`. The reset token TTL is 600 seconds (10
minutes). A used reset token cannot be detected as used (no database storage)
but it expires after 10 minutes, limiting the replay window.

---

## TNSecurityCheck -- CGI Security Gate

`TNSecurityCheck.pm` provides `security_check($level)` -- a single function
call placed at the top of every CGI script that requires authentication or
authorisation. It enforces a six-layer check sequence and either returns a
session hashref on success or calls `_error_response()` and exits on failure.

Three security levels are defined.

`standard` -- public endpoints. Checks origin and download protection only.
Returns an anonymous session with role `public`. Used by endpoints that
serve public data but should not be accessible from cross-origin contexts.

`protected` -- authenticated endpoints. Runs all six layers: session
validation, origin check, download protection, POST method enforcement, CSRF
validation. Returns the validated session hashref. Used by most management
API endpoints.

`restricted` -- admin-only endpoints. Same as `protected` plus a role check
requiring `role eq 'admin'`. Returns the validated session hashref only for
admin-role sessions.

The six layers in order:

Layer 1 -- Session validation: reads `HTTP_COOKIE`, extracts the
`tn_session=` value, calls `TNSecurity::verify_session_id()` to check the
HMAC signature, then calls `TNAuth::validate_session()` to check the
database. A forged signature never reaches the database.

Layer 2 -- Origin validation: checks `HTTP_ORIGIN` and `HTTP_REFERER`
against `HTTP_HOST`. Same-origin requests that omit both headers pass.
Cross-origin requests with a mismatched origin or referer are rejected.

Layer 3 -- Download protection: checks `HTTP_ACCEPT` for MIME types that
indicate automated download tools (`application/octet-stream`,
`text/x-perl`, `application/x-perl`). These headers appear in wget/curl
invocations targeting source files.

Layer 4 -- Method enforcement: POST is required for `protected` and
`restricted` endpoints.

Layer 5 -- CSRF validation: the JSON request body is decoded and the
`csrf_token` field is passed to `TNSecurity::validate_csrf_token()`. The
HMAC is verified against the current and previous time windows.

Layer 6 -- Role check (restricted only): `$session->{role} eq 'admin'`.

DEVEL mode bypasses all six layers and returns a synthetic admin session.
DEVEL bypass events are logged at debug severity so they appear in the
security log during development.

---

## DEVEL Mode

DEVEL mode is a development-only configuration controlled by `DEVEL=1` in
`security.conf [mode]`. When active it bypasses all security checks: TNWAF
rate limiting is not disabled but all TNSecurityCheck layers are bypassed,
CSRF validation returns true, session validation returns a synthetic admin
session, and `TNAuth::authenticate_user()` accepts `DEVEL_BYPASS` as a
valid password for any username.

Three safeguards prevent DEVEL mode from being active in production:

The deployment gate in `router.pl` checks `SERVER_ADDR` against loopback
addresses before routing any request. A DEVEL-mode server bound to a non-
loopback address returns 503 for all requests.

`TNConfig::load_config()` fails closed on any configuration problem --
missing file, parse error, or missing `[mode]` section all result in
`DEVEL=0`.

The DEVEL mode indicator is visible in the web UI: a yellow warning banner
appears on all pages when DEVEL mode is active, and `devel.js` loads the
developer tools panel only when the server confirms `devel_mode=true` via
the `api/session` endpoint. `devel.js` is not in the SRI hash table and is
not served in production -- it is served only when DEVEL mode is active.

DEVEL mode is enabled and disabled via `control.pl` endpoints
(`devel/enable`, `devel/disable`) which require the DEVEL password
(PBKDF2-hashed in `security.conf`). Disabling DEVEL mode writes `DEVEL=0`
to `security.conf` and requires a web server restart to take effect. The
developer tools panel in `devel.js` provides a `Disable DEVEL Mode` button
that calls `devel/disable` and prompts the operator to restart httpd and
slowcgi.

---

## auth.db Schema

The authentication database at `data/db/auth.db` contains six tables.

`users` -- primary user records. Columns: `id` (64-char hex), `username`,
`email`, `password_hash` (prefixed PBKDF2 or legacy SHA-256), `salt`,
`role` (`admin` or `user`), `created_at`, `last_login`, `login_count`,
`failed_attempts`, `locked` (boolean), `locked_until` (unix timestamp).

`sessions` -- active sessions. Columns: `session_id` (64-char hex),
`user_id` (FK → users), `ip_address`, `user_agent`, `created_at`,
`last_activity`, `expires_at`. All timestamps are unix integers.

`security_questions` -- per-user challenge questions for password reset.
Columns: `user_id` (FK → users), `question`, `answer_hash`, `answer_salt`.
Answers are stored as PBKDF2 hashes -- the same algorithm and the same
`needs_rehash()` path applies to them.

`recovery_codes` -- one-time recovery codes. Columns: `user_id` (FK →
users), `code_hash` (sha256_hex), `used` (boolean), `used_at`.

`registration_tokens` -- admin-issued invitation tokens for new user
registration. Columns: `token` (64-char hex), `created_at`, `used`
(boolean), `used_at`, `used_by` (user_id).

`rate_limits` -- per-identifier rate limiting for password reset attempts.
Columns: `identifier` (username), `limit_type` (`password_reset`), `count`,
`window_start`, `violations`, `last_request`, `blocked_until`.

Foreign key constraints with `ON DELETE CASCADE` are enforced via
`PRAGMA foreign_keys = ON`. Deleting a user record cascades to sessions,
security questions, and recovery codes -- all in a single transaction in
`TNAuth::delete_user()`.

---

## Security Event Logging

Security events flow through two parallel channels.

`TNSecurity::log_security_event()` writes to `data/logs/security.log` (via
`log_to_file()` with `flock(LOCK_EX)`) and optionally to syslog. The log
format is `[timestamp] [level] [ip] event - details`. This file is in the
`data/logs/` tree and is rotated by `tangent_logrotate.sh` with a dated
archive.

`TNWAF::log_security()` writes to `data/logs/waf/security.log` and submits
to syslog via `logger -t tnwaf -p security.warning`. This file is also
rotated by `tangent_logrotate.sh`.

`control.pl` redirects STDERR to `/tmp/control-YYYY-MM-DD.log` (inside the
chroot, mapping to `/var/www/tmp/`) at startup. All `warn()` and `die()`
calls from Perl go here with timestamps. The `$SIG{__WARN__}` and
`$SIG{__DIE__}` handlers ensure all warnings and fatal errors are timestamped
and flushed. This log is the primary diagnostic source for CGI failures.

TNWatch's `tnaudit` parser reads `TNAudit.db` directly every 5 minutes and
emits `file_change` events for any file in a non-clean state. The
`tnaudit_change` alert rule triggers an immediate email on the first
detected change. This closes the loop between file integrity monitoring and
the alerting system.

---

## Session Cleanup Cron Entry

```
1   15  *  *  1  www   perl -e 'use lib "/var/www/htdocs/tn/data/lib"; use TNAuth; TNAuth::cleanup_expired_sessions();' >/dev/null
```

Runs as `www` (the web server user) on Mondays at 15:01. Deletes all rows
from the `sessions` table where `expires_at < now`. Running as `www` rather
than root is correct -- `www` has read-write access to `auth.db` (required
for web session management) and nothing more. The job runs weekly because
expired sessions are already non-functional -- the cleanup is a maintenance
task, not a security requirement.

---

## Crontab Summary (Security-Relevant Entries)

```
# /etc/crontab
# TNAudit and TNWatch
*    *  *  *  *  root  /usr/local/sbin/TNWatch_runner.sh >/dev/null 2>&1
0    9  *  *  *  root  /usr/local/sbin/TNWatch.pl --send-digest
0    8  *  *  1  root  /usr/local/sbin/TNWatch.pl --purge --days 7
5    8  *  *  1  root  /usr/local/sbin/TNWatch.pl --init-db
0    8  *  *  *  root  /usr/local/sbin/TNAudit.pl --create-baseline >> /var/log/integrity_baseline.log 2>&1
1   15  *  *  1  www   perl -e 'use lib "/var/www/htdocs/tn/data/lib"; use TNAuth; TNAuth::cleanup_expired_sessions();' >/dev/null
```

---

## Author and Attribution

Primary Author: David Peter
Organization:   Tangent Networks
Web:            https://tangentnet.top
Email:          tangent.net@zohomail.in

---

## License

BSD 3-Clause License (Simplified)

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

*End of SECURITY_ARCHITECTURE.md*
