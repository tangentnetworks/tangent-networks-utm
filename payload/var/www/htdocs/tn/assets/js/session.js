// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

// =============================================
// SESSION PROTECTION
// Filename: assets/js/session-auth.js
// =============================================

(async function checkSession() {
    try {
        console.log('[Auth] Validating session with server...');

        const response = await fetch('/cgi-bin/control.pl/api/session', {
            method: 'GET',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        });

        if (!response.ok) {
            throw new Error('Session check failed');
        }

        const data = await response.json();

        if (!data.authenticated) {
            console.warn('[Auth] Session not authenticated, redirecting to login');
            window.location.href = '/index.html';
            return;
        }

        // Store user info globally for use by view scripts
        window.currentUser = {
            username:        data.username,
            userId:          data.user_id,
            role:            data.role,
            sessionAge:      data.session_age,
            develMode:       data.devel_mode || false,
            authenticatedAt: Date.now()
        };

        console.log('[Auth] Session validated for user: ' + data.username);

        // Show DEVEL mode warning banner if enabled
        if (data.devel_mode) {
            showDevelWarning();
            loadDevelScript();
        }

        // Mark document as session-valid so dependent styles/scripts can proceed
        document.documentElement.classList.add('session-valid');

        // Start periodic session check -- interval is 5 minutes.
        // With a 30-minute server TTL this catches expiry within one polling cycle.
        setInterval(checkSessionPeriodic, 5 * 60 * 1000);

        updateUserInfo(data);

    } catch (error) {
        console.error('[Auth] Session validation error:', error);
        window.location.href = '/index.html';
    }
})();

// =============================================
// PERIODIC SESSION CHECK
// =============================================
// Runs every 5 minutes while the dashboard is open.
// Redirects to login if the server-side session has expired.
// Response body and ok status are checked separately to avoid
// a malformed JSON response masking an expired session.

async function checkSessionPeriodic() {
    try {
        const response = await fetch('/cgi-bin/control.pl/api/session', {
            method: 'GET',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        });

        if (!response.ok) {
            console.warn('[Auth] Periodic check: server returned ' + response.status);
            window.location.href = '/index.html';
            return;
        }

        const data = await response.json();

        if (!data.authenticated) {
            alert('Your session has expired. Please log in again.');
            window.location.href = '/index.html';
        }

    } catch (error) {
        // Network error or JSON parse failure -- log but do not redirect.
        // A transient network blip should not kick the user out.
        // The next polling cycle will catch a genuine expiry.
        console.error('[Auth] Periodic session check failed:', error);
    }
}

// =============================================
// LOGOUT
// =============================================
// Sends CSRF token with the POST so the server accepts the request
// and destroys the session row in the database. The finally block
// redirects regardless of outcome so the user always lands on the
// login page, but a missing CSRF token would leave the session alive
// server-side until it expires naturally.

window.logout = async function () {
    try {
        const csrf = window.TNToken.get();

        await fetch('/cgi-bin/control.pl/auth/logout', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ csrf_token: csrf })
        });

    } catch (error) {
        console.error('[Auth] Logout error:', error);
    } finally {
        // Always redirect -- even if the server call failed the browser
        // should return to the login page.
        window.location.href = '/index.html';
    }
};

// =============================================
// DEVEL MODE
// =============================================

function showDevelWarning() {
    const banner = document.createElement('div');
    banner.id = 'devel-warning';
    banner.innerHTML = `
        <span class="devel-warning-text">WARNING: DEVELOPMENT MODE ACTIVE &mdash; Security Disabled</span>
        <button class="devel-close" id="devel-warning-close" aria-label="Dismiss">&times;</button>
    `;

    function insertBanner() {
        document.body.appendChild(banner);
        document.body.classList.add('devel-active');
        document.getElementById('devel-warning-close').addEventListener('click', () => {
            banner.classList.add('devel-dismissed');
            document.body.classList.remove('devel-active');
        });
    }

    if (document.body) {
        insertBanner();
    } else {
        document.addEventListener('DOMContentLoaded', insertBanner);
    }
}

// devel.js is loaded dynamically only when the server confirms DEVEL mode.
// It is intentionally loaded without an SRI integrity attribute here because
// in DEVEL mode SRI enforcement is disabled server-side anyway. In production
// data.devel_mode is always false so this function never runs.
function loadDevelScript() {
    const script = document.createElement('script');
    script.src   = '/assets/js/devel.js';
    script.defer = true;
    document.head.appendChild(script);
    console.log('[Auth] DEVEL mode script loaded');
}

// =============================================
// USER INFO
// =============================================

function updateUserInfo(data) {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => updateUserDisplay(data));
    } else {
        updateUserDisplay(data);
    }
}

function updateUserDisplay(data) {
    console.log('[UI] User info updated: ' + data.username);
    // Extend here to populate any user display elements in the navbar,
    // e.g.: document.getElementById('user-display').textContent = data.username;
}
