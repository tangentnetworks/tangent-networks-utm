// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * unbound.js
 * Unbound DNS management -- stats, cache operations, DNS lookup, service reload.
 *
 * Boots exclusively via the manageNavReady event dispatched by managenav.js.
 * Registers onActivate / onDeactivate with ManageNav; does nothing until the
 * unbound tab is opened by the user.
 *
 * No globals exported. No timers start at load time. No confirm() or alert().
 * Requires: unbound.css (overlay + spinner + output block)
 */
(function () {
    'use strict';

    // =========================================================================
    // CONSTANTS
    // =========================================================================
    const ENDPOINT   = '/cgi-bin/unbound_control.pl';
    const STATS_FILE = '/data/db/unbound/stats.json';
    const POLL_MS    = 30000;

    // =========================================================================
    // MODULE STATE
    // =========================================================================
    let statsTimer    = null;
    let isInitialized = false;

    // =========================================================================
    // UTILITIES
    // =========================================================================
    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = String(str ?? '');
        return d.innerHTML;
    }

    function isValidDomain(domain) {
        return /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i.test(domain);
    }

    // =========================================================================
    // CSRF TOKEN
    // Fetches a fresh token from control.pl before each mutating request.
    // Tokens are single-use and short-lived -- always fetch immediately before use.
    // =========================================================================
    async function getCsrfToken() {
        const res = await fetch('/cgi-bin/control.pl/api/csrf', {
            method:      'GET',
            credentials: 'same-origin'
        });
        if (!res.ok) throw new Error('Failed to fetch CSRF token: HTTP ' + res.status);
        const data = await res.json();
        if (!data.token) throw new Error('CSRF token missing from response');
        return data.token;
    }

    // =========================================================================
    // STATS
    // =========================================================================
    async function loadStats() {
        try {
            const res = await fetch(STATS_FILE);
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const data = await res.json();
            renderStats(data);
        } catch (err) {
            console.error('[Unbound] Stats load error:', err);
            renderStatsError();
        }
    }

    function renderStats(data) {
        const map = {
            'queries-total':  data.queries_total,
            'queries-cached': data.queries_cached,
            'cache-hit-rate': data.cache_hit_rate,
            'cache-size':     data.cache_size,
            'uptime':         data.uptime,
            'ratelimited':    data.num_queries_ip_ratelimited,
            'recursion':      data.total_recursion,
            'avg-response':   data.avg_response_time
        };
        Object.entries(map).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value ?? '--';
        });
    }

    function renderStatsError() {
        ['queries-total', 'queries-cached'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = 'Error';
        });
        ['cache-hit-rate', 'cache-size', 'uptime', 'ratelimited', 'recursion', 'avg-response'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = '--';
        });
    }

    // =========================================================================
    // STATS POLLING
    // =========================================================================
    function startPolling() {
        stopPolling();
        statsTimer = setInterval(() => {
            if (document.querySelector('#unbound-content.active')) {
                loadStats();
            }
        }, POLL_MS);
    }

    function stopPolling() {
        if (statsTimer) {
            clearInterval(statsTimer);
            statsTimer = null;
        }
    }

    // =========================================================================
    // MODAL -- CONFIRMATION
    // Shown before any destructive or mutating operation.
    // Returns a Promise<boolean> -- true if user confirmed, false if cancelled.
    // =========================================================================
    function showConfirmModal({ title, message, detail = null, confirmLabel = 'Confirm', danger = false }) {
        return new Promise(resolve => {
            removeModal('unbound-confirm-modal');

            const overlay = document.createElement('div');
            overlay.id = 'unbound-confirm-modal';
            overlay.className = 'unbound-overlay';

            const confirmBtnClass = danger
                ? 'rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-700'
                : 'rounded-lg bg-blue-700 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-800';

            overlay.innerHTML = `
                <div class="unbound-modal rounded-xl bg-gray-50 dark:bg-gray-800 shadow-xl">
                    <div class="border-b border-gray-200 dark:border-gray-700 px-5 py-4">
                        <h3 class="text-sm font-bold tracking-wide text-gray-700 dark:text-white uppercase">
                            ${escapeHtml(title)}
                        </h3>
                    </div>
                    <div class="px-5 py-4 space-y-2">
                        <p class="text-sm text-gray-700 dark:text-white">${escapeHtml(message)}</p>
                        ${detail ? `
                        <div class="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2">
                            <p class="text-xs font-mono text-gray-700 dark:text-white break-all">${escapeHtml(detail)}</p>
                        </div>` : ''}
                    </div>
                    <div class="border-t border-gray-200 dark:border-gray-700 px-5 py-3 flex items-center justify-end space-x-2">
                        <button id="unbound-cancel-btn"
                                class="rounded-lg border border-gray-300 dark:border-gray-600 px-4 py-2 text-xs font-semibold text-gray-700 dark:text-white hover:bg-gray-100 dark:hover:bg-gray-700">
                            Cancel
                        </button>
                        <button id="unbound-confirm-btn" class="${confirmBtnClass}">
                            ${escapeHtml(confirmLabel)}
                        </button>
                    </div>
                </div>`;

            document.body.appendChild(overlay);

            overlay.querySelector('#unbound-confirm-btn').addEventListener('click', () => {
                overlay.remove();
                resolve(true);
            });

            overlay.querySelector('#unbound-cancel-btn').addEventListener('click', () => {
                overlay.remove();
                resolve(false);
            });

            // Click outside cancels
            overlay.addEventListener('click', e => {
                if (e.target === overlay) {
                    overlay.remove();
                    resolve(false);
                }
            });
        });
    }

    // =========================================================================
    // MODAL -- VALIDATION ERROR
    // Replaces alert() for input validation failures.
    // =========================================================================
    function showValidationModal(message) {
        return new Promise(resolve => {
            removeModal('unbound-validation-modal');

            const overlay = document.createElement('div');
            overlay.id = 'unbound-validation-modal';
            overlay.className = 'unbound-overlay';

            overlay.innerHTML = `
                <div class="unbound-modal rounded-xl bg-gray-50 dark:bg-gray-800 shadow-xl">
                    <div class="border-b border-gray-200 dark:border-gray-700 px-5 py-4">
                        <h3 class="text-sm font-bold tracking-wide text-gray-700 dark:text-white uppercase">
                            Validation Error
                        </h3>
                    </div>
                    <div class="px-5 py-4">
                        <p class="text-sm text-gray-700 dark:text-white">${escapeHtml(message)}</p>
                    </div>
                    <div class="border-t border-gray-200 dark:border-gray-700 px-5 py-3 flex justify-end">
                        <button id="unbound-validation-ok"
                                class="rounded-lg bg-blue-700 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-800">
                            OK
                        </button>
                    </div>
                </div>`;

            document.body.appendChild(overlay);

            overlay.querySelector('#unbound-validation-ok').addEventListener('click', () => {
                overlay.remove();
                resolve();
            });
        });
    }

    // =========================================================================
    // MODAL -- OPERATION FEEDBACK
    // Shows processing spinner, then success or error result with optional output.
    // =========================================================================
    function showOperationModal(title) {
        removeModal('unbound-operation-modal');

        const overlay = document.createElement('div');
        overlay.id = 'unbound-operation-modal';
        overlay.className = 'unbound-overlay';

        overlay.innerHTML = `
            <div class="unbound-modal rounded-xl bg-gray-50 dark:bg-gray-800 shadow-xl">
                <div class="border-b border-gray-200 dark:border-gray-700 px-5 py-4 flex items-center justify-between">
                    <h3 class="text-sm font-bold tracking-wide text-gray-700 dark:text-white uppercase">
                        ${escapeHtml(title)}
                    </h3>
                    <button id="unbound-op-close"
                            class="rounded-lg border border-gray-300 dark:border-gray-600 px-2 py-1 text-xs text-gray-700 dark:text-white hover:bg-gray-100 dark:hover:bg-gray-700">
                        X
                    </button>
                </div>
                <div id="unbound-op-body" class="px-5 py-6 space-y-2 text-center">
                    <div class="unbound-spinner"></div>
                    <p class="text-sm text-gray-700 dark:text-white" class="mt-3">Processing...</p>
                </div>
            </div>`;

        document.body.appendChild(overlay);

        overlay.querySelector('#unbound-op-close').addEventListener('click', () => overlay.remove());

        return overlay;
    }

    function resolveOperationModal(overlay, status, message, output = null) {
        const body = overlay.querySelector('#unbound-op-body');
        if (!body) return;

        const isSuccess = status === 'success';
        const statusColor = isSuccess ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400';
        const label       = isSuccess ? 'OK' : 'Error';

        body.innerHTML = `
            <p class="text-xs font-bold uppercase tracking-wide ${statusColor}">${escapeHtml(label)}</p>
            <p class="text-sm text-gray-700 dark:text-white">${escapeHtml(message)}</p>
            ${output ? `
            <div class="rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 px-3 py-2 mt-2 text-left">
                <p class="text-xs font-bold uppercase tracking-wide text-gray-700 dark:text-white mb-1">
                    ${isSuccess ? 'Output' : 'Error Details'}
                </p>
                <pre class="unbound-output bg-gray-50 dark:bg-gray-800 text-gray-700 dark:text-white">${escapeHtml(output)}</pre>
            </div>` : ''}`;

        // Auto-close successes after 4 seconds; errors stay until dismissed
        if (isSuccess) {
            setTimeout(() => overlay.remove(), 4000);
        }
    }

    // =========================================================================
    // MODAL HELPER
    // =========================================================================
    function removeModal(id) {
        document.getElementById(id)?.remove();
    }

    // =========================================================================
    // BUTTON STATE HELPERS
    // =========================================================================
    function disableBtn(btn) {
        btn.disabled = true;
        btn.dataset.originalText = btn.textContent;
        btn.textContent = 'Working...';
    }

    function restoreBtn(btn) {
        btn.disabled = false;
        if (btn.dataset.originalText) {
            btn.textContent = btn.dataset.originalText;
        }
    }

    // =========================================================================
    // OPERATIONS
    // =========================================================================
    async function purgeCache() {
        const confirmed = await showConfirmModal({
            title:        'Full Cache Purge',
            message:      'This will clear all cached DNS records and may temporarily increase query latency.',
            confirmLabel: 'Purge Cache',
            danger:       true
        });
        if (!confirmed) return;

        const btn     = document.querySelector('[data-action="purge-cache"]');
        const overlay = showOperationModal('Full Cache Purge');
        disableBtn(btn);

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'flush_all', csrf_token: csrfToken })
            });
            if (!res.ok) throw new Error('Server error: HTTP ' + res.status);

            const result = await res.json();
            if (!result.success) throw new Error(result.error || 'Unknown error');

            resolveOperationModal(overlay, 'success', 'Cache purged successfully', result.output);
            setTimeout(loadStats, 2000);

        } catch (err) {
            console.error('[Unbound] Purge error:', err);
            resolveOperationModal(overlay, 'error', 'Failed to purge cache', err.message);
        } finally {
            restoreBtn(btn);
        }
    }

    async function flushDomain() {
        const input  = document.getElementById('flush-domain-input');
        const domain = input?.value.trim();

        if (!domain) {
            await showValidationModal('Please enter a domain name.');
            return;
        }
        if (!isValidDomain(domain)) {
            await showValidationModal('Please enter a valid domain name (e.g. example.com).');
            return;
        }

        const confirmed = await showConfirmModal({
            title:        'Flush Domain Cache',
            message:      'This will remove all cached DNS records for the following domain:',
            detail:       domain,
            confirmLabel: 'Flush Domain',
            danger:       false
        });
        if (!confirmed) return;

        const btn     = document.querySelector('[data-action="flush-domain"]');
        const overlay = showOperationModal('Flush Domain');
        disableBtn(btn);

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'flush_domain', domain, csrf_token: csrfToken })
            });
            if (!res.ok) throw new Error('Server error: HTTP ' + res.status);

            const result = await res.json();
            if (!result.success) throw new Error(result.error || 'Unknown error');

            resolveOperationModal(overlay, 'success', `Domain ${domain} flushed successfully`, result.output);
            input.value = '';

        } catch (err) {
            console.error('[Unbound] Flush error:', err);
            resolveOperationModal(overlay, 'error', 'Failed to flush domain', err.message);
        } finally {
            restoreBtn(btn);
        }
    }

    async function dumpCache() {
        const btn     = document.querySelector('[data-action="dump-cache"]');
        const overlay = showOperationModal('Export Cache');
        disableBtn(btn);

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'dump_cache', csrf_token: csrfToken })
            });
            if (!res.ok) throw new Error('Server error: HTTP ' + res.status);

            const result = await res.json();
            if (!result.success) throw new Error(result.error || 'Unknown error');

            resolveOperationModal(overlay, 'success', 'Cache exported successfully', result.output);

        } catch (err) {
            console.error('[Unbound] Dump error:', err);
            resolveOperationModal(overlay, 'error', 'Failed to export cache', err.message);
        } finally {
            restoreBtn(btn);
        }
    }

    async function reloadService() {
        const confirmed = await showConfirmModal({
            title:        'Reload Unbound Configuration',
            message:      'This will reload /var/unbound/etc/unbound.conf without restarting the service.',
            confirmLabel: 'Reload Service',
            danger:       false
        });
        if (!confirmed) return;

        const btn     = document.querySelector('[data-action="reload-unbound"]');
        const overlay = showOperationModal('Reload Configuration');
        disableBtn(btn);

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'reload', csrf_token: csrfToken })
            });
            if (!res.ok) throw new Error('Server error: HTTP ' + res.status);

            const result = await res.json();
            if (!result.success) throw new Error(result.error || 'Unknown error');

            resolveOperationModal(overlay, 'success', 'Configuration reloaded successfully', result.output);
            setTimeout(loadStats, 2000);

        } catch (err) {
            console.error('[Unbound] Reload error:', err);
            resolveOperationModal(overlay, 'error', 'Failed to reload configuration', err.message);
        } finally {
            restoreBtn(btn);
        }
    }

    async function dnsLookup() {
        const input  = document.getElementById('test-domain-input');
        const domain = input?.value.trim();

        if (!domain) {
            await showValidationModal('Please enter a domain name.');
            return;
        }
        if (!isValidDomain(domain)) {
            await showValidationModal('Please enter a valid domain name (e.g. example.com).');
            return;
        }

        const btn     = document.querySelector('[data-action="test-lookup"]');
        const overlay = showOperationModal('DNS Lookup');
        disableBtn(btn);

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'lookup', domain, csrf_token: csrfToken })
            });
            if (!res.ok) throw new Error('Server error: HTTP ' + res.status);

            const result = await res.json();
            if (!result.success) throw new Error(result.error || 'Unknown error');

            resolveOperationModal(overlay, 'success', `Lookup completed for ${domain}`, result.output);

        } catch (err) {
            console.error('[Unbound] Lookup error:', err);
            resolveOperationModal(overlay, 'error', 'Lookup failed', err.message);
        } finally {
            restoreBtn(btn);
        }
    }

    // =========================================================================
    // EVENT BINDING
    // Single delegated listener -- no per-button addEventListener accumulation
    // =========================================================================
    function bindDelegatedActions() {
        document.addEventListener('click', handleClick);
    }

    function handleClick(e) {
        if (!document.querySelector('#unbound-content.active')) return;

        const target = e.target.closest('[data-action]');
        if (!target) return;

        switch (target.getAttribute('data-action')) {
            case 'refresh-stats':  e.preventDefault(); loadStats();      break;
            case 'purge-cache':    e.preventDefault(); purgeCache();      break;
            case 'flush-domain':   e.preventDefault(); flushDomain();     break;
            case 'dump-cache':     e.preventDefault(); dumpCache();       break;
            case 'reload-unbound': e.preventDefault(); reloadService();   break;
            case 'test-lookup':    e.preventDefault(); dnsLookup();       break;
        }
    }

    // Allow Enter key in domain inputs to trigger their respective actions
    function bindInputEnterKeys() {
        const flushInput  = document.getElementById('flush-domain-input');
        const lookupInput = document.getElementById('test-domain-input');

        if (flushInput) {
            flushInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') { e.preventDefault(); flushDomain(); }
            });
        }
        if (lookupInput) {
            lookupInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') { e.preventDefault(); dnsLookup(); }
            });
        }
    }

    // =========================================================================
    // INIT / TEARDOWN
    // =========================================================================
    async function init() {
        if (isInitialized) return;
        isInitialized = true;

        console.log('[Unbound] Initializing');

        await loadStats();
        bindInputEnterKeys();
        startPolling();
    }

    function teardown() {
        stopPolling();
        isInitialized = false;
        // Close any open modals left from this tab
        ['unbound-operation-modal', 'unbound-confirm-modal', 'unbound-validation-modal']
            .forEach(removeModal);
        console.log('[Unbound] Torn down');
    }

    // =========================================================================
    // BOOT -- waits for ManageNav, never self-starts
    // =========================================================================
    function register() {
        window.ManageNav.register('unbound', {
            onActivate:   init,
            onDeactivate: teardown
        });
        console.log('[Unbound] Registered with ManageNav');
    }

    if (window.ManageNav) {
        register();
    } else {
        document.addEventListener('manageNavReady', register, { once: true });
    }

    // Delegated click handler registered once at load -- guard inside handles tab check
    bindDelegatedActions();

})();
