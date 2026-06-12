// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

// =============================================
// devel.js - Development Tools Panel
// =============================================
// Only loads when DEVEL mode is enabled.
// Provides tools for developers during UI work.
// All styles live in devel.css -- injected below.
//
// AUTHOR: David Peter, Tangent Networks
// VERSION: 3.0.0
// =============================================

(function () {
    'use strict';

    console.log('[Devel] Development tools loaded');

    // =============================================
    // INJECT devel.css AT RUNTIME
    // =============================================
    // devel.css never loads in production -- only
    // this script injects it, and this script only
    // loads when the server confirms devel_mode.

    (function injectDevelCSS() {
        const link = document.createElement('link');
        link.rel  = 'stylesheet';
        link.href = '/assets/css/devel.css';
        document.head.appendChild(link);
    })();

    // =============================================
    // DEVEL TOOLS PANEL
    // =============================================

    function createDevelPanel() {

        const panel = document.createElement('div');
        panel.id = 'devel-tools-panel';

        panel.innerHTML = `
            <div class="devel-expanded">
                <div class="devel-panel-header">
                    <span class="devel-panel-title">DEV TOOLS</span>
                    <button class="devel-panel-close" id="devel-panel-close" aria-label="Close">&times;</button>
                </div>
                <div class="devel-info-block">
                    <div><strong>User:</strong> <span id="devel-username">...</span></div>
                    <div><strong>Role:</strong> <span id="devel-role">...</span></div>
                    <div><strong>Session Age:</strong> <span id="devel-session-age">...</span>s</div>
                </div>
                <div class="devel-actions">
                    <button id="devel-disable-btn" class="devel-btn devel-btn--danger">SECURITY: Disable DEVEL Mode</button>
                    <button id="devel-refresh-sri-btn" class="devel-btn devel-btn--primary">INFO: Regenerate SRI Hashes</button>
                    <button id="devel-session-info-btn" class="devel-btn devel-btn--success">INFO: Show Session Info</button>
                    <button id="devel-clear-console-btn" class="devel-btn devel-btn--muted">Clear Console</button>
                </div>
                <div id="devel-status" class="devel-status"></div>
            </div>
            <div class="devel-pill" id="devel-pill" role="button" aria-label="Toggle dev tools">
                <span class="devel-pill-dot"></span>
                DEV TOOLS
            </div>
        `;

        document.body.appendChild(panel);

        // Populate user info
        if (window.currentUser) {
            const u = window.currentUser;
            document.getElementById('devel-username').textContent    = u.username   || 'unknown';
            document.getElementById('devel-role').textContent        = u.role       || 'unknown';
            document.getElementById('devel-session-age').textContent = u.sessionAge || 0;
        }

        // Pill toggle
        document.getElementById('devel-pill').addEventListener('click', togglePanel);

        // Close button collapses back to pill
        document.getElementById('devel-panel-close').addEventListener('click', (e) => {
            e.stopPropagation();
            panel.classList.remove('devel-open');
        });

        // Action buttons
        document.getElementById('devel-disable-btn').addEventListener('click', handleDisableDevel);
        document.getElementById('devel-refresh-sri-btn').addEventListener('click', handleRefreshSRI);
        document.getElementById('devel-session-info-btn').addEventListener('click', handleShowSessionInfo);
        document.getElementById('devel-clear-console-btn').addEventListener('click', () => {
            console.clear();
            showStatus('Console cleared', 'success');
        });
    }

    function togglePanel() {
        const panel = document.getElementById('devel-tools-panel');
        if (panel) panel.classList.toggle('devel-open');
    }

    // =============================================
    // DEVEL TOOL FUNCTIONS
    // =============================================

    async function handleDisableDevel() {
        if (!confirm('Disable DEVEL mode? This will enable full security and require you to re-authenticate. The web server must be restarted to apply the change.')) {
            return;
        }
        try {
            const response = await fetch('/cgi-bin/control.pl/devel/disable', {
                method: 'POST',
                credentials: 'same-origin'
            });
            const data = await response.json();
            if (data.success) {
                showStatus(data.message || 'DEVEL mode disabled. Restart web server to apply.', 'success');
                setTimeout(() => {
                    alert('DEVEL mode disabled. Please restart httpd/slowcgi:\n\nrcctl restart httpd slowcgi');
                }, 1000);
            } else {
                showStatus('Failed: ' + (data.error || 'Unknown error'), 'error');
            }
        } catch (err) {
            console.error('[Devel] Disable error:', err);
            showStatus('Network error: ' + err.message, 'error');
        }
    }

    async function handleRefreshSRI() {
        showStatus('Regenerating SRI hashes...', 'info');
        try {
            const response = await fetch('/cgi-bin/control.pl/devel/regenerate_sri', {
                method: 'POST',
                credentials: 'same-origin'
            });
            const data = await response.json();
            if (data.success) {
                showStatus(data.message || 'SRI hashes regenerated', 'success');
            } else {
                showStatus('Failed: ' + (data.error || 'Unknown error'), 'error');
            }
        } catch (err) {
            console.error('[Devel] SRI regeneration error:', err);
            showStatus('Network error: ' + err.message, 'error');
        }
    }

    async function handleShowSessionInfo() {
        try {
            const response = await fetch('/cgi-bin/control.pl/api/session', {
                method: 'GET',
                credentials: 'same-origin'
            });
            const data = await response.json();
            console.group('INFO: Session Info');
            console.log('Authenticated:', data.authenticated);
            console.log('Username:',      data.username);
            console.log('User ID:',       data.user_id);
            console.log('Role:',          data.role);
            console.log('Session Age:',   data.session_age, 'seconds');
            console.log('DEVEL Mode:',    data.devel_mode);
            console.groupEnd();
            showStatus('Session info logged to console', 'success');
        } catch (err) {
            console.error('[Devel] Session info error:', err);
            showStatus('Failed to get session info', 'error');
        }
    }

    function showStatus(message, type) {
        const el = document.getElementById('devel-status');
        if (!el) return;
        el.textContent = message;
        el.dataset.statusType = type;
        el.classList.add('devel-visible');
        setTimeout(() => {
            el.classList.remove('devel-visible');
        }, 5000);
    }

    // =============================================
    // LOCAL LOG HELPER
    // =============================================
    // Does NOT overwrite global console.log.
    // Use develLog() inside this module only.

    function develLog(...args) {
        console.log('[DEVEL]', ...args);
    }

    // =============================================
    // KEYBOARD SHORTCUTS
    // =============================================

    document.addEventListener('keydown', (e) => {
        // Ctrl+Shift+D: Toggle dev panel
        if (e.ctrlKey && e.shiftKey && e.key === 'D') {
            e.preventDefault();
            togglePanel();
        }
        // Ctrl+Shift+C: Clear console
        if (e.ctrlKey && e.shiftKey && e.key === 'C') {
            e.preventDefault();
            console.clear();
        }
        // Ctrl+Shift+I: Show session info
        if (e.ctrlKey && e.shiftKey && e.key === 'I') {
            e.preventDefault();
            handleShowSessionInfo();
        }
    });

    // =============================================
    // INITIALIZATION
    // =============================================

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', createDevelPanel);
    } else {
        createDevelPanel();
    }

    develLog('Keyboard shortcuts:');
    develLog('  Ctrl+Shift+D: Toggle dev panel');
    develLog('  Ctrl+Shift+C: Clear console');
    develLog('  Ctrl+Shift+I: Show session info');

})();
