<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# WebUI.md -- SPA Shell
Tangent Networks Dashboard
Covers: view.html, session.js, view.js, token.js (shell context),
        powermgmt.js

---

## Overview

view.html is the persistent application shell. It loads once after a
successful login and remains loaded for the entire dashboard session.
It is never reloaded between view navigations. The main content area
(#main-content) is the only part of the page that changes -- view
fragments are fetched from TNWAF and injected into it by view.js.

Every view CGI document in this project assumes the shell is running.
The concepts documented here -- the session gate, window.currentUser,
window.TNToken, the viewLoaded event, the viewCleanup event -- are the
shared foundation that all view-specific scripts build on.

---

## TNWAF Serving Path

    / or /view.html -> serve_html() -> serve_file(view.html, text/html, CSP=1)

view.html is the only route in TNWAF that maps to serve_html() directly.
Both / and /view.html reach it. The full CSP header is applied.

View fragment requests made by view.js:

    /view/<name> -> serve_view($name) -> serve_file(view/<name>, text/html, CSP=1)

TNWAF validates the view name against /^(\w+)$/ and reads from
$BASE_DIR/view/. Each fragment is served with CSP. The fragment files
are plain HTML -- no CGI execution. The CGI scripts for a given view are
called by the view's own JavaScript after the fragment is injected into
the shell.

---

## Page Structure

view.html is a full-height flex column. The outer structure that never
changes across view navigations:

    Fixed top navbar (z-40)
        Logo / mobile sidebar toggle (#sidebar-toggle-btn)
        Theme toggle (#theme-toggle)
        User dropdown (#user-menu-button -> #dropdown-user)
            Links: Reset Password, Documentation, Privacy, Legal, License

    Fixed left sidebar (#top-bar-sidebar, z-50)
        Logo button
        Navigation (#nav-system -> #view-opts)
            System section:
                Overview      -> /view/dashboard
                Logs          -> /view/logs
                Firewall      -> /view/firewall
                Services      -> /view/services
                System Mail   -> /view/mail
            Network section:
                External Traffic -> /view/external
                Internal Traffic -> /view/internal
            Manage System section:
                System Setup     -> /view/manage
                Integrity Check  -> /view/integrity
        Power state buttons (sidebar bottom, mt-auto):
            #logout-btn   (green)
            #restart-btn  (blue)
            #poweroff-btn (red)

    #main-content (ml-64 on sm+, full width on mobile)
        View fragments load here. This element is destroyed and
        recreated on every view transition by ContentLoader.

    #backToTop button

    Footer (ml-64 on sm+)

Sidebar backdrop (#sidebar-backdrop): visible on mobile when sidebar
is open. Tap to close.

Session loading overlay (#session-loading): a full-screen spinner shown
while session.js runs the initial authentication check. Hidden by CSS
once session validation completes (the 'session-valid' class is added
to documentElement by session.js on success).

---

## Script Load Order

All scripts in view.html body carry defer and SRI integrity attributes.

    HEAD (defer -- runs after DOM parsed, before DOMContentLoaded):
        session.js   -- MUST RUN FIRST per HTML comment

    BODY (defer -- same execution queue, in order):
        token.js     -- exposes window.TNToken
        ts.js        -- theme toggle, sidebar, dropdown, back-to-top
        view.js      -- SPA view loader
        powermgmt.js -- sidebar power buttons

Because all are defer, execution order matches declaration order and all
run after the full DOM is parsed. session.js is in the head specifically
to convey its primacy -- it executes first in the defer queue.

The actual execution sequence after DOM parse completes:

    1. session.js IIFE fires immediately (async IIFE, not DOMContentLoaded)
       -- fetches /api/session
       -- if not authenticated: redirect to /index.html immediately
       -- if authenticated: sets window.currentUser, adds session-valid
          class, starts periodic check, optionally loads devel.js
    2. token.js DOMContentLoaded: fetchCSRFToken(), startAutoRefresh()
    3. ts.js DOMContentLoaded: theme, sidebar, dropdown, back-to-top
    4. view.js auto-invokes initializeViewSystem():
       -- if DOM loading: addEventListener DOMContentLoaded
       -- if DOM ready: init() immediately
    5. powermgmt.js DOMContentLoaded: setupLogoutButton(),
       setupRestartButton(), setupPoweroffButton()

---

## session.js -- Session Gate and Heartbeat

Version: (no version declared)
Filename in repo: assets/js/session-auth.js (note: served as session.js)

session.js is an async IIFE that executes immediately on script load.
It does not wait for DOMContentLoaded. This is deliberate -- the session
check is the highest priority action on page load. If the user has no
valid session they should be redirected to the login page before any
other script has a chance to render the dashboard UI.

### Initial Session Check

    1. GET /cgi-bin/control.pl/api/session
       credentials: 'same-origin', Accept: 'application/json'

    2. If response.ok is false:
           throw Error -> catch -> redirect to /index.html

    3. If data.authenticated is false:
           console.warn + redirect to /index.html

    4. On authenticated success:
           Set window.currentUser = {
               username:        data.username,
               userId:          data.user_id,
               role:            data.role,
               sessionAge:      data.session_age,
               develMode:       data.devel_mode || false,
               authenticatedAt: Date.now()
           }
           document.documentElement.classList.add('session-valid')
           setInterval(checkSessionPeriodic, 5 * 60 * 1000)
           updateUserInfo(data)
           if data.devel_mode: showDevelWarning() + loadDevelScript()

### window.currentUser

This is the global object that all view scripts read to know who is
logged in. It is set once by session.js on the initial check and is not
updated by the periodic check. Fields:

    username        -- string, the authenticated username
    userId          -- string, 64-char hex user ID
    role            -- 'admin' | 'user'
    sessionAge      -- seconds since session was created at login
    develMode       -- boolean, true if DEVEL mode active on server
    authenticatedAt -- Date.now() at time of session validation

View scripts and devel.js read this object directly. No authentication
state is duplicated elsewhere in the shell.

### Periodic Session Check

Runs every 5 minutes via setInterval. Checks /api/session again:

    If response.ok is false:
        redirect to /index.html (no alert -- network-level failure)

    If data.authenticated is false:
        alert('Your session has expired. Please log in again.')
        redirect to /index.html

    On network error or JSON parse failure:
        console.error but do NOT redirect -- a transient blip should not
        kick the user out. The next cycle will catch a genuine expiry.

The server SESSION_LIFETIME is 7200 seconds (2 hours) from security.conf.
With a 5-minute polling interval, a session expiry will be detected
within 5 minutes of it occurring on the server. The alert informs the
user before the redirect on periodic expiry (not on initial load failure,
where a silent redirect is more appropriate).

### window.logout

session.js exposes window.logout as a global function. It is a named
function on the window object rather than a method, so any script can
call it.

    window.logout = async function () {
        get csrf from window.TNToken.get()
        POST /cgi-bin/control.pl/auth/logout
            body: { csrf_token: csrf }
        finally: window.location.href = '/index.html'
    }

The finally block means the redirect always happens regardless of whether
the server call succeeded. The CSRF token is obtained from TNToken -- if
token.js has not yet initialized (unlikely given the defer order, but
possible on very slow connections) TNToken.get() returns null, the POST
body contains csrf_token: null, control.pl returns 403, and the finally
block still redirects. The server-side session will persist until it
expires naturally in that edge case.

Note: powermgmt.js handles logout via its own getCsrfToken() helper
(which polls window.TNToken.has()) and its own fetch call, not via
window.logout. The two paths produce the same result but powermgmt.js
adds a confirmation modal first.

### DEVEL Mode in the Shell

When data.devel_mode is true:

showDevelWarning() creates and appends a #devel-warning div to body. It
contains the text "WARNING: DEVELOPMENT MODE ACTIVE -- Security Disabled"
and a dismiss button (#devel-warning-close). Clicking the dismiss button
adds the 'devel-dismissed' class to the banner and removes 'devel-active'
from body.

loadDevelScript() creates a <script> element with src='/assets/js/devel.js'
and defer=true, appends it to document.head. No SRI integrity attribute
is set on this dynamically injected script tag. This is intentional and
documented in devel-mode.md: in DEVEL mode server-side SRI enforcement
is disabled, and requiring a client-side integrity attribute on a script
that only loads in DEVEL mode would add no security value while creating
a maintenance burden every time devel.js is modified.

devel.js reads window.currentUser to populate the DEV TOOLS panel's
user/role/session-age display. It must load after session.js sets
window.currentUser, which is guaranteed by the dynamic injection
happening inside the session.js success path.

---

## token.js -- CSRF Token Manager (Shell Context)

token.js is identical to the version loaded on the static auth pages.
See static-auth-pages.md for the full specification. The shell context
adds one important behaviour:

powermgmt.js does not call TNToken.get() directly on click. Instead it
uses getCsrfToken(), a local helper that polls window.TNToken.has() every
100ms with a 5-second timeout. This handles the race condition where a
user clicks a power button in the very first seconds after page load,
before token.js's DOMContentLoaded handler has completed the fetch:

    function getCsrfToken(timeout = 5000) {
        return new Promise((resolve, reject) => {
            if (window.TNToken && window.TNToken.has()) {
                return resolve(window.TNToken.get());
            }
            const interval = setInterval(() => {
                if (window.TNToken && window.TNToken.has()) {
                    clearInterval(interval);
                    resolve(window.TNToken.get());
                }
            }, 100);
            setTimeout(() => {
                clearInterval(interval);
                reject(new Error('CSRF token not available'));
            }, timeout);
        });
    }

On logout, powermgmt.js calls TNToken.clear() after the power action
is queued and the silent logout is sent. This stops the auto-refresh
timer and nulls the in-memory token, preventing any further authenticated
requests from the browser tab before the redirect to maintenance.html.

---

## view.js -- SPA View Loader

Version: Phase 2 Complete (last modified 2025-12-25)
Exposes: window.ViewSystem

view.js manages the SPA lifecycle: which sidebar link is active, which
view is loaded in #main-content, and the full cleanup/load cycle on
navigation.

### Configuration

VIEW_SYSTEM_CONFIG is a module-level const (not frozen -- window-level
scope, but not intentionally mutable):

    ENABLE_AJAX_LOADING: true
    AJAX_TIMEOUT_MS: 10000  (defined but not currently enforced with AbortController)
    ACTIVE_LINK_CLASSES:   ['border-l-4', 'border-blue-400', 'bg-blue-50', 'dark:bg-blue-900/20']
    INACTIVE_LINK_CLASSES: ['border-l-0', 'bg-transparent']
    DEFAULT_VIEW_SELECTOR: 'a[href*="/view/dashboard"]'

    VIEWS: {
        'dashboard': { title: 'Dashboard',        template: '/view/dashboard' },
        'logs':      { title: 'Logs',             template: '/view/logs'      },
        'firewall':  { title: 'Firewall',         template: '/view/firewall'  },
        'services':  { title: 'Services',         template: '/view/services'  },
        'mail':      { title: 'System Mail',      template: '/view/mail'      },
        'external':  { title: 'External Traffic', template: '/view/external'  },
        'internal':  { title: 'Internal Traffic', template: '/view/internal'  },
        'manage':    { title: 'System Setup',     template: '/view/manage'    },
        'integrity': { title: 'System Setup',     template: '/view/integrity' },
    }

Note: both 'manage' and 'integrity' carry the title 'System Setup'.
This appears to be a copy-paste omission -- integrity should likely read
'Integrity Check' to match the sidebar label. The title value is not
currently used in the DOM so it has no visible effect.

Note: AJAX_TIMEOUT_MS is defined as 10000 but fetch() in loadViewContent
has no AbortController or AbortSignal. The timeout is not enforced. A
hanging view load will wait indefinitely until the browser's own fetch
timeout fires.

### Internal Modules

view.js uses three revealing-module IIFEs plus one plain function.

ViewState: module-level state holder.

    getCurrentView()    -- returns current view string or null
    setCurrentView(id)  -- sets currentView, logs to console
    getActiveLink()     -- returns the currently active anchor element
    setActiveLink(el)   -- stores the active anchor element
    reset()             -- nulls both, logs reset

ActiveLinkManager: manages sidebar link highlighting.

    initializeDefaultView()
        Finds DEFAULT_VIEW_SELECTOR ('a[href*="/view/dashboard"]')
        Activates it visually, extracts the view id, sets ViewState

    handleLinkClick(linkElement, event)
        event.preventDefault() -- suppresses browser navigation
        Extracts viewId from href via extractViewFromHref()
        If already on this view: return (no-op)
        Activates the new link, deactivates the old one
        Calls ContentLoader.loadViewContent(viewId) if AJAX enabled

    extractViewFromHref(href)
        Parses href as URL, splits pathname, finds the segment after 'view'
        Returns that segment as the viewId string

ContentLoader: manages the content area lifecycle.

    initialize()
        Stores reference to #main-content
        Must succeed before any loadViewContent call

    _cleanupPreviousView()   -- "NUCLEAR CLEANUP"
        Dispatches 'viewCleanup' CustomEvent on mainContentArea
        Completely destroys mainContentArea (parent.replaceChild with a
        new <main> element that has all the same attributes)
        Reassigns mainContentArea to the new element
        This is the most aggressive possible cleanup -- no DOM references
        to any previous view's elements can survive it

    _showLoadingState()
        Injects a centered spinner with "Loading <viewname>..." text
        Uses innerHTML on the freshly recreated mainContentArea

    _showErrorState(message)
        Injects a centered error panel with SVG icon and error text
        Uses innerHTML -- message is inserted via template literal
        which means it is not escaped. Error messages come from
        fetch failures (HTTP status strings, JS Error.message values)
        not from server-controlled content, so XSS risk is low but
        worth noting.

    _executeViewScripts(viewId)
        Finds all <script> elements within mainContentArea
        For each: creates a new <script> element, copies attributes,
        replaces the old element. This is required because innerHTML
        insertion does not execute scripts.
        Inline scripts are wrapped in an IIFE with a try-catch.
        External scripts get data-view attribute and onerror/onload
        handlers.

    loadViewContent(viewId) -- the main cycle:
        1. _cleanupPreviousView()
        2. _showLoadingState()
        3. Validate viewId against VIEWS config
        4. fetch(viewConfig.template, GET, Accept: text/html,
                 X-Requested-With: XMLHttpRequest, cache: no-cache)
        5. mainContentArea.innerHTML = htmlContent
        6. _executeViewScripts(viewId)
        7. Dispatch 'viewLoaded' CustomEvent with { viewId, timestamp }

EventHandler: wires sidebar links.

    setupSidebarListeners()
        Queries all 'a[href^="/view/"]' inside #nav-system
        Adds click listener (removeEventListener first to avoid duplicates)
        Each click calls ActiveLinkManager.handleLinkClick()

### viewLoaded and viewCleanup Events

These two CustomEvents are the contract between view.js and view-specific
scripts.

viewCleanup fires on mainContentArea before the element is destroyed:

    event.detail.previousView -- the viewId that is being torn down

View scripts can listen for this to stop timers, cancel pending fetches,
or flush state. Since mainContentArea itself is replaced, any listeners
attached to it are automatically removed. Listeners on window or document
must be explicitly removed in the viewCleanup handler.

viewLoaded fires on the new mainContentArea after content is injected
and scripts are executed:

    event.detail.viewId   -- the new view's id string
    event.detail.timestamp -- Date.now() at load completion

View scripts that need to know when they have been fully loaded into the
shell can listen for this event on their containing mainContentArea.

### window.ViewSystem Public API

    ViewSystem.getCurrentView()         -- current viewId string or null
    ViewSystem.initialize()             -- re-run initializeViewSystem()
    ViewSystem.loadView(viewId)         -- programmatically load a view
    ViewSystem.debug.getState()         -- { currentView, config }
    ViewSystem.debug.reset()            -- reset ViewState

### Initialization Sequence

initializeViewSystem() is called immediately at the bottom of view.js
(auto-initialize pattern). If DOM is still loading it waits for
DOMContentLoaded, otherwise calls init() immediately.

init():
    EventHandler.setupSidebarListeners()
    ActiveLinkManager.initializeDefaultView()  -> sets dashboard as active
    if ENABLE_AJAX_LOADING:
        ContentLoader.initialize()             -> gets #main-content ref
        ContentLoader.loadViewContent('dashboard')  -> loads default view

The dashboard view loads automatically on every visit to view.html.

---

## powermgmt.js -- Power Management

Version: (no version declared)
CGI endpoints: /cgi-bin/control.pl/auth/logout, /cgi-bin/power_mgmt.pl

powermgmt.js manages the three sidebar power buttons. All actions use
custom modal dialogs -- no browser confirm(), alert(), or prompt() is used.

### Button Wiring

DOMContentLoaded calls init() which wires three buttons:

    #logout-btn   -> handleLogout
    #restart-btn  -> handleRestart
    #poweroff-btn -> handlePoweroff

### Logout Flow

    1. showConfirmModal({ title: 'Logout', message: '...', confirmVariant: 'safe' })
       -> user must confirm or cancel
    2. getCsrfToken(5000) -- polls TNToken.has() for up to 5 seconds
    3. POST /cgi-bin/control.pl/auth/logout
       body: { csrf_token: token }
       headers: Content-Type: application/json, X-Requested-With: XMLHttpRequest
    4. if response.ok: window.location.href = '/index.html'
    5. on error: showAlertModal('Error', 'Logout failed: ' + error.message)

This is the standard logout path from the sidebar button. window.logout
(defined in session.js) is a separate path for programmatic logout.
Both call the same control.pl endpoint.

### Restart Flow -- Double Confirmation

Power actions that affect the system require two separate confirmations
to prevent accidental execution.

    1. showConfirmModal -- "WARNING: Restart System", Continue / Cancel
    2. showConfirmModal -- "WARNING: Final Confirmation", Restart / Cancel
    3. executePowerAction('restart')

### Shutdown Flow -- Confirmation + Typed Challenge

Shutdown is more destructive than restart (requires physical access to
recover) so it uses a typed challenge as the second step.

    1. showConfirmModal -- "WARNING: Shutdown System", Continue / Cancel
       confirmVariant: 'danger'
    2. showPromptModal -- "WARNING: Type to Confirm"
       message: 'Type POWEROFF in capital letters to confirm shutdown:'
       expected: 'POWEROFF'
       The confirm button is disabled until input === 'POWEROFF' exactly
       (no trim, no case folding -- must be exact uppercase)
    3. executePowerAction('shutdown')

### executePowerAction(action)

Shared by restart and shutdown. The action string is 'restart' or
'shutdown'.

    1. showSpinnerModal('Processing', 'Sending command to system...')
       returns the overlay element

    2. getCsrfToken(5000)

    3. POST /cgi-bin/power_mgmt.pl
       body: { action: action, csrf_token: token }
       headers: Content-Type: application/json, X-Requested-With: XMLHttpRequest

    4. Parse JSON response. If data.success is false:
       throw Error(data.error || data.message || 'Action failed')

    5. Silent logout -- POST /cgi-bin/control.pl/auth/logout
       body: { csrf_token: token, silent: true }
       Failure is caught and silently ignored -- the system is going
       down anyway and the session will expire naturally.

    6. TNToken.clear() -- stops the 30-minute auto-refresh timer and
       nulls the in-memory token.

    7. Disable all buttons on the page:
       document.querySelectorAll('button').forEach(btn => btn.disabled = true)
       Prevents any further user interaction while the redirect happens.

    8. window.location.href = '/maintenance.html?action=' + action
       -> action is either 'restart' or 'shutdown'

    On any error: remove spinner, showAlertModal with error message.

### Modal System

All four modal types are built programmatically using DOM APIs. No
innerHTML is used for content insertion -- all text is set via
element.textContent which is inherently XSS-safe. The overlay element
carries class 'modal-overlay' which is styled in the dashboard CSS.

showSpinnerModal(title, message):
    Non-interactive. Shows a spinner, title, and subtitle.
    Returns the overlay element so the caller can remove it on error.
    Not automatically removed on success -- the page navigates away.

showConfirmModal({ title, message, confirmText, confirmVariant, cancelText }):
    Returns Promise<boolean>.
    Resolves true on confirm button click.
    Resolves false on cancel, backdrop click, or Escape key.
    confirmVariant sets data-variant on the confirm button for CSS styling:
        'safe'    -- green (logout)
        'primary' -- blue (restart steps)
        'danger'  -- red (shutdown steps)
        'neutral' -- grey (alert OK button)
    confirmBtn.focus() is called on creation for keyboard accessibility.

showAlertModal(title, message):
    Thin wrapper around showConfirmModal with cancelText: null and
    confirmVariant: 'neutral'. Returns Promise<void>.

showPromptModal({ title, message, expected, confirmText, confirmVariant }):
    Returns Promise<boolean>.
    input === expected is checked on confirm click and on Enter keypress.
    On mismatch: shows error message, clears input, refocuses.
    On match: resolves true.
    Resolves false on cancel, backdrop click, or Escape key.

---

## Shell Startup Sequence -- Complete Timeline

This is the full sequence from browser navigation to first view content:

    Browser requests /view.html or /
    TNWAF validates request, checks rate limit, serves view.html with CSP

    Browser parses HTML, encounters defer scripts in order:
        session.js, token.js, ts.js, view.js, powermgmt.js

    DOM parse completes. Defer queue executes in order:

    [1] session.js IIFE fires (async):
            GET /api/session
            if not authenticated: redirect to /index.html  <-- STOPS HERE
            if authenticated:
                window.currentUser = { ... }
                document.documentElement.classList.add('session-valid')
                setInterval(checkSessionPeriodic, 300000)
                if devel_mode: showDevelWarning() + loadDevelScript()

    [2] token.js DOMContentLoaded:
            GET /api/csrf (with retry)
            window.TNToken available
            startAutoRefresh (30-minute interval)

    [3] ts.js DOMContentLoaded:
            initializeThemeToggle()
            initializeSidebarToggle()
            initializeUserDropdown()
            initializeBackToTopButton()

    [4] view.js auto-invokes initializeViewSystem():
            EventHandler.setupSidebarListeners()
            ActiveLinkManager.initializeDefaultView()
                -> dashboard link activated
            ContentLoader.initialize() -> stores #main-content ref
            ContentLoader.loadViewContent('dashboard'):
                _cleanupPreviousView() (no-op on first load)
                _showLoadingState() (spinner in #main-content)
                GET /view/dashboard (TNWAF -> serve_view('dashboard'))
                mainContentArea.innerHTML = fragment HTML
                _executeViewScripts('dashboard')
                dispatch 'viewLoaded' event

    [5] powermgmt.js DOMContentLoaded:
            setupLogoutButton()
            setupRestartButton()
            setupPoweroffButton()

    Steps [1] through [5] happen in parallel due to async nature of [1].
    In practice: session.js's GET /api/session typically completes after
    the synchronous init code in [2]-[5] has run but before the dashboard
    view fetch in [4] completes. The session-valid class on documentElement
    is what CSS uses to hide the #session-loading spinner and show the UI.

---

## Known Notes

view.js AJAX_TIMEOUT_MS not enforced:
    AJAX_TIMEOUT_MS = 10000 is declared but fetch() has no AbortController.
    A hanging view fetch waits for the browser's built-in fetch timeout
    (typically 300 seconds). If a view CGI hangs, the dashboard will show
    the loading spinner indefinitely rather than failing after 10 seconds.
    An AbortController with setTimeout would fix this.

_showErrorState innerHTML:
    The error message string is inserted via a template literal into
    innerHTML. Error messages come from HTTP status text (e.g. 'Not Found')
    or JavaScript Error.message values, not from server-controlled content,
    so the XSS surface is minimal. However, a server that returned a
    crafted status text could inject content here. Using textContent
    insertion for the error message would be safer.

integrity view title:
    VIEW_SYSTEM_CONFIG.VIEWS.integrity.title is 'System Setup' which
    matches 'manage' rather than 'Integrity Check'. The title value
    is not currently rendered anywhere in the UI so this has no visible
    effect, but it should be corrected for consistency.

session.js filename:
    The file header comment says "Filename: assets/js/session-auth.js"
    but it is served and referenced as session.js. The comment is stale
    from an earlier naming iteration.

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
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions, and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM,
DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

*End of WebUI.md*
