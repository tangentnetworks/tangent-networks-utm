// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * e2g.js
 * E2Guardian filter management -- feeds, mode switching, log viewer.
 *
 * Boots exclusively via the manageNavReady event dispatched by managenav.js.
 * Registers onActivate / onDeactivate with ManageNav; does nothing until the
 * e2guardian tab is actually opened by the user.
 *
 * No globals are exported. No timers start at load time.
 */
(function () {
    'use strict';

    // =========================================================================
    // CONSTANTS
    // =========================================================================
    const ENDPOINT_FEEDS      = '/cgi-bin/e2g_feeds.pl';
    const ENDPOINT_MODE       = '/cgi-bin/e2g_mode_switch.pl';
    const ENDPOINT_WRITE      = '/cgi-bin/e2g_write_input.pl';
    const ENDPOINT_LOG        = '/cgi-bin/e2g_get_log.pl';
    const ENDPOINT_LOG_INFO   = '/cgi-bin/e2g_get_log_info.pl';
    const ENDPOINT_READ_LOG   = '/cgi-bin/e2g_read_log.pl';
    const ENDPOINT_SVC_STATUS = '/data/services/queue/e2gfilters/status/e2guardian-status.json';
    const STATUS_FILE         = '/data/services/queue/e2gfilters/status/active_mode.json';

    const MODE_NAMES = {
        general:   'General (Adult Mode)',
        childsafe: 'ChildSafe (Family Mode)',
        custom:    'Custom (User-Managed)'
    };

    const LOG_PATTERNS = {
        general:   'e2guardian-adult-',
        childsafe: 'e2guardian-childsafe-',
        custom:    'e2g_user_filter-'
    };

    // =========================================================================
    // MODULE STATE  (private -- never touches window.*)
    // =========================================================================
    let allFeeds        = [];
    let activeMode      = 'unknown';
    let activeModeData  = null;
    let isInitialized   = false;
    let pendingSwitch   = null;
    let heartbeatTimer  = null;

    // Log viewer state kept private
    let currentLogContent  = '';
    let currentLogFilename = '';

    // =========================================================================
    // UTILITIES
    // =========================================================================
    // Fetches a fresh single-use CSRF token from control.pl before each mutating request.
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

    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = String(str ?? '');
        return d.innerHTML;
    }

    function formatBytes(bytes) {
        if (!bytes) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
    }

    function formatDateTime(date) {
        if (!(date instanceof Date) || isNaN(date)) return '--';
        const pad = n => String(n).padStart(2, '0');
        return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} `
             + `${pad(date.getHours())}:${pad(date.getMinutes())}`;
    }

    function showNotification(msg, type = 'info') {
        const el = document.createElement('div');
        el.className      = 'notification';
        el.dataset.type   = (['success', 'error', 'info', 'warning'].includes(type)) ? type : 'info';
        el.textContent    = msg;
        document.body.appendChild(el);
        setTimeout(() => el.remove(), 5000);
    }

    // =========================================================================
    // MODE DETECTION
    // =========================================================================
    async function detectActiveMode() {
        try {
            const res = await fetch(STATUS_FILE + '?nocache=' + Date.now());
            if (!res.ok) return;

            const text = await res.text();
            if (!text || !text.trim()) {
                // Silent during mode switch processing window --
                // shell script temporarily clears active_mode.json while updating
                return;
            }

            activeModeData = JSON.parse(text);
            activeMode     = activeModeData.mode;

            console.log('[E2G] Active mode from disk:', activeMode);
            updateUIForActiveMode();

        } catch (err) {
            console.warn('[E2G] Could not read status file:', err.message);
        }
    }

    // =========================================================================
    // HEARTBEAT
    // =========================================================================
    function startHeartbeat() {
        stopHeartbeat();
        console.log('[E2G] Heartbeat started');

        heartbeatTimer = setInterval(async () => {
            if (document.visibilityState !== 'visible') return;

            const previousMode    = activeMode;
            const previousUpdated = activeModeData ? activeModeData.updated : 0;
            await detectActiveMode();

            // Mode changed or updated timestamp changed -- switch completed
            if (activeModeData && (previousMode !== activeMode ||
                    (activeModeData.updated && activeModeData.updated !== previousUpdated))) {
                if (pendingSwitch && pendingSwitch === activeMode) {
                    console.log(`[E2G] Mode switch to ${activeMode} confirmed complete`);
                    pendingSwitch = null;   // unlock tab switcher
                }
                console.log(`[E2G] Mode changed ${previousMode} -> ${activeMode}, reloading feeds`);
                await loadFeeds(activeMode);
            }
        }, 2000);
    }

    function stopHeartbeat() {
        if (heartbeatTimer) {
            clearInterval(heartbeatTimer);
            heartbeatTimer = null;
            console.log('[E2G] Heartbeat stopped');
        }
    }

    // =========================================================================
    // UI -- MODE DISPLAY
    // =========================================================================
    function updateUIForActiveMode() {
        // Highlight the correct mode tab button
        document.querySelectorAll('span[data-tab]').forEach(btn => {
            const isActive = btn.dataset.tab === activeMode;
            btn.dataset.active = isActive ? 'true' : 'false';
        });

        updateStatusDisplay();
    }

    function updateStatusDisplay() {
        const el = document.getElementById('e2g-active-status');
        if (!el || !activeModeData) return;

        el.innerHTML = '';

        // Mode info card
        const statusCard = document.createElement('div');
        statusCard.className = 'e2g-status-card';

        const header = document.createElement('div');
        header.className = 'e2g-status-header';

        const modeName = document.createElement('span');
        modeName.className   = 'e2g-status-mode-name';
        modeName.textContent = activeModeData.mode_name;

        const updated = document.createElement('span');
        updated.className   = 'e2g-status-updated';
        updated.textContent = 'Updated: ' + (activeModeData.updated_human || 'Unknown');

        header.appendChild(modeName);
        header.appendChild(updated);

        const desc = document.createElement('p');
        desc.className   = 'e2g-status-description';
        desc.textContent = activeModeData.description;

        const scriptLine = document.createElement('div');
        scriptLine.className = 'e2g-status-script-line';

        const code = document.createElement('code');
        code.className   = 'e2g-status-code';
        code.textContent = activeModeData.script || ('e2g_' + activeMode + '_filter.sh');

        scriptLine.appendChild(code);
        scriptLine.appendChild(document.createTextNode(' is currently scheduled in crontab'));

        statusCard.appendChild(header);
        statusCard.appendChild(desc);
        statusCard.appendChild(scriptLine);
        el.appendChild(statusCard);

        // Select filter mode card
        const selectCard = document.createElement('div');
        selectCard.className = 'e2g-select-card';

        const selectTitle = document.createElement('p');
        selectTitle.className = 'e2g-select-title';
        const strong = document.createElement('strong');
        strong.textContent = 'Select Filter Mode:';
        selectTitle.appendChild(strong);

        const ul = document.createElement('ul');
        ul.className = 'e2g-select-list';
        [
            ['General:', 'Adult mode - malware and ads (no porn filtering)'],
            ['ChildSafe:', 'Family mode - malware, ads and porn blocking'],
            ['Custom:', 'User-managed threat intelligence'],
        ].forEach(([label, text]) => {
            const li = document.createElement('li');
            const b  = document.createElement('strong');
            b.textContent = label + ' ';
            li.appendChild(b);
            li.appendChild(document.createTextNode(text));
            ul.appendChild(li);
        });

        const hint = document.createElement('p');
        hint.className   = 'e2g-select-hint';
        hint.textContent = 'Click a tab above to switch modes (recommended: ChildSafe)';

        selectCard.appendChild(selectTitle);
        selectCard.appendChild(ul);
        selectCard.appendChild(hint);
        el.appendChild(selectCard);

        updateProcessingStatus();
    }

    // =========================================================================
    // FEEDS -- LOAD & RENDER
    // =========================================================================
    async function loadFeeds(mode) {
        const targetMode = mode || activeMode;

        try {
            console.log('[E2G] Loading feeds for mode:', targetMode);

            const res = await fetch(
                `${ENDPOINT_FEEDS}?mode=${targetMode}&v=${Date.now()}`,
                { credentials: 'same-origin' }
            );

            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const data = await res.json();
            allFeeds = data.feeds || [];

            console.log(`[E2G] ${allFeeds.length} feeds loaded for ${targetMode}`);
            renderFeeds();

        } catch (err) {
            console.error('[E2G] Feed load error:', err);
            showNotification('Failed to load feeds', 'error');
        }
    }

    function renderFeeds() {
        const container = document.getElementById('active-feeds-container');
        if (!container) return;

        const countEl = document.getElementById('feed-count');
        if (countEl) countEl.textContent = allFeeds.length;

        container.innerHTML = '';

        if (allFeeds.length === 0) {
            const empty = document.createElement('div');
            empty.className   = 'e2g-no-feeds';
            empty.textContent = 'No feeds configured for this mode.';
            container.appendChild(empty);
            return;
        }

        // Group by category
        const grouped = {};
        allFeeds.forEach((feed, idx) => {
            feed._realIdx = idx;
            (grouped[feed.category] = grouped[feed.category] || []).push(feed);
        });

        const frag = document.createDocumentFragment();
        Object.keys(grouped).sort().forEach(category => {
            const feeds = grouped[category];

            const catCard = document.createElement('div');
            catCard.className = 'e2g-category-card';

            const catHeader = document.createElement('div');
            catHeader.className = 'e2g-category-header';

            const catName = document.createElement('h4');
            catName.className   = 'e2g-category-name';
            catName.textContent = category;

            const catCount = document.createElement('span');
            catCount.className   = 'e2g-category-count';
            catCount.textContent = feeds.length;

            catHeader.appendChild(catName);
            catHeader.appendChild(catCount);
            catCard.appendChild(catHeader);

            const feedsList = document.createElement('div');
            feedsList.className = 'e2g-feeds-list';

            feeds.forEach(feed => {
                const isUser = feed.source === 'user';

                const row = document.createElement('div');
                row.className = 'e2g-feed-row';

                const body = document.createElement('div');
                body.className = 'e2g-feed-body';

                const tags = document.createElement('div');
                tags.className = 'e2g-feed-tags';

                const filterTag = document.createElement('span');
                filterTag.className   = 'e2g-feed-tag';
                filterTag.textContent = feed.filter;
                tags.appendChild(filterTag);

                if (isUser) {
                    const userTag = document.createElement('span');
                    userTag.className   = 'e2g-feed-tag e2g-feed-tag--user';
                    userTag.textContent = 'USER';
                    tags.appendChild(userTag);
                }

                const urlLink = document.createElement('a');
                urlLink.href      = feed.url;
                urlLink.target    = '_blank';
                urlLink.rel       = 'noopener noreferrer';
                urlLink.className = 'e2g-feed-url';
                urlLink.textContent = feed.url;

                body.appendChild(tags);
                body.appendChild(urlLink);
                row.appendChild(body);

                if (isUser) {
                    const delBtn = document.createElement('button');
                    delBtn.className            = 'e2g-feed-delete';
                    delBtn.dataset.action       = 'delete-user-feed';
                    delBtn.dataset.index        = feed._realIdx;
                    delBtn.textContent          = 'Remove';
                    row.appendChild(delBtn);
                }

                feedsList.appendChild(row);
            });

            catCard.appendChild(feedsList);
            frag.appendChild(catCard);
        });

        container.appendChild(frag);
    }

    // =========================================================================
    // FEEDS -- CUSTOM FEED MANAGEMENT  (merged from e2g_custom_feeds.js)
    // =========================================================================
    async function addFeed() {
        const catEl = document.getElementById('feed-category');
        const urlEl = document.getElementById('feed-url');
        const btn   = document.querySelector('[data-action="add-feed"]');
        if (!catEl || !urlEl) return;

        const category = catEl.value.trim();
        const url      = urlEl.value.trim();
        if (!category || !url) return;

        btn.disabled = true;
        try {
            const csrfToken = await getCsrfToken();
            const res  = await fetch(ENDPOINT_WRITE, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'add', category, url, csrf_token: csrfToken })
            });

            const text      = await res.text();
            const jsonStart = text.indexOf('{');
            if (jsonStart === -1) throw new Error('Invalid server response');

            const result = JSON.parse(text.substring(jsonStart));
            if (result.success) {
                showNotification(result.message, 'success');
                urlEl.value = '';
                await loadFeeds('custom');
            } else {
                throw new Error(result.error);
            }
        } catch (err) {
            console.error('[E2G] Add feed error:', err);
            showNotification(err.message, 'error');
        } finally {
            btn.disabled = false;
        }
    }

    async function testFeedUrl() {
        const urlEl = document.getElementById('feed-url');
        const btn   = document.querySelector('[data-action="test-feed"]');
        if (!urlEl || !urlEl.value.trim()) return;

        const original    = btn.textContent;
        btn.textContent   = 'Testing...';
        btn.disabled      = true;

        try {
            await fetch(urlEl.value.trim(), {
                method:         'GET',
                mode:           'no-cors',
                cache:          'no-cache',
                referrerPolicy: 'no-referrer'
            });
            showNotification('URL request sent', 'success');
        } catch {
            showNotification('URL request failed', 'error');
        } finally {
            btn.textContent = original;
            btn.disabled    = false;
        }
    }

    async function deleteFeed(url) {
        if (!url || !confirm('Remove this feed?')) return;
        try {
            const csrfToken = await getCsrfToken();
            await fetch(ENDPOINT_WRITE, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'remove', url, csrf_token: csrfToken })
            });
            await loadFeeds('custom');
        } catch (err) {
            console.error('[E2G] Delete feed error:', err);
        }
    }

    async function downloadFeedList() {
        try {
            const statusRes = await fetch(STATUS_FILE);
            if (!statusRes.ok) throw new Error('Could not determine active mode');

            const status = await statusRes.json();
            const mode   = status.mode;

            const filePaths = {
                childsafe: '/data/db/e2g/childsafe.txt',
                custom:    '/data/services/queue/e2gfilters/userlist/userfeeds.txt',
                general:   '/data/db/e2g/general.txt'
            };

            const filePath = filePaths[mode] || filePaths.general;
            console.log(`[E2G] Downloading ${mode} list from ${filePath}`);

            const fileRes = await fetch(filePath);
            if (!fileRes.ok) throw new Error(`File not found: ${filePath}`);

            const blob = await fileRes.blob();
            const blobUrl = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href     = blobUrl;
            a.download = `e2g_${mode}_list.txt`;
            document.body.appendChild(a);
            a.click();
            URL.revokeObjectURL(blobUrl);
            document.body.removeChild(a);

            showNotification(`Downloaded active (${mode}) list`, 'success');

        } catch (err) {
            console.error('[E2G] Download error:', err);
            showNotification('Download failed: ' + err.message, 'error');
        }
    }

    // =========================================================================
    // CHECK CUSTOM FEEDS EXIST
    // =========================================================================
    async function checkHasCustomFeeds() {
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT_WRITE, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'list', csrf_token: csrfToken })
            });
            const result = await res.json();
            return { hasFeeds: result.success && result.count > 0, count: result.count || 0 };
        } catch (err) {
            console.error('[E2G] Custom feed check error:', err);
            return { hasFeeds: false, count: 0 };
        }
    }

    // =========================================================================
    // MODE SWITCHING
    // =========================================================================
    async function handleModeTabClick(e) {
        const btn        = e.currentTarget;
        const targetMode = btn.dataset.tab;

        if (targetMode === activeMode || pendingSwitch) return;

        if (targetMode === 'custom') {
            const check = await checkHasCustomFeeds();
            if (!check.hasFeeds) {
                showNotification('Cannot activate Custom mode. Add at least one feed first.', 'error');
                return;
            }
        }

        pendingSwitch = targetMode;
        showModeSwitchModal(targetMode);

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT_MODE, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'switch_mode', mode: targetMode, csrf_token: csrfToken })
            });

            const result = await res.json();

            if (result.success) {
                console.log('[E2G] Mode switch initiated:', result.message);
                updateModalSuccess(result.data || {});
                // pendingSwitch stays set -- prevents double-click during processing
                // Heartbeat detects completion when active_mode.json updated timestamp changes
                setTimeout(() => {
                    closeModeSwitchModal();
                    showNotification('Filter update running in background -- UI updates automatically', 'info');
                }, 5000);
            } else {
                throw new Error(result.message || 'Switch failed');
            }

        } catch (err) {
            console.error('[E2G] Mode switch error:', err);
            updateModalError(
                err.name === 'AbortError'
                    ? 'Process taking too long -- check back in a minute.'
                    : err.message
            );
            pendingSwitch = null;
        }
    }

    // =========================================================================
    // MODE SWITCH MODAL
    // =========================================================================
    function showModeSwitchModal(targetMode) {
        closeModeSwitchModal();

        const modal = document.createElement('div');
        modal.className = 'modal-overlay mode-switch-modal-overlay';

        const content = document.createElement('div');
        content.className = 'modal-content';

        // Header
        const header = document.createElement('div');
        header.className = 'modal-header';

        const h3 = document.createElement('h3');

        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
        svg.setAttribute('fill', 'none');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.classList.add('e2g-modal-title-icon');
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('stroke', 'currentColor');
        path.setAttribute('stroke-linecap', 'round');
        path.setAttribute('stroke-linejoin', 'round');
        path.setAttribute('stroke-width', '2');
        path.setAttribute('d', 'M17.651 7.65a7.131 7.131 0 0 0-12.68 3.15M18.001 4v4h-4m-7.652 8.35a7.13 7.13 0 0 0 12.68-3.15M6 20v-4h4');
        svg.appendChild(path);

        h3.appendChild(svg);
        h3.appendChild(document.createTextNode('Switching to ' + (MODE_NAMES[targetMode] || targetMode)));
        header.appendChild(h3);

        // Body
        const body = document.createElement('div');
        body.className = 'modal-body';

        const progress = document.createElement('div');
        progress.className = 'progress-section';
        progress.id        = 'mode-switch-progress';

        const spinner = document.createElement('div');
        spinner.className = 'spinner';

        const pt1 = document.createElement('p');
        pt1.className   = 'progress-text';
        pt1.textContent = 'Activating ' + (MODE_NAMES[targetMode] || targetMode) + '...';

        const pd1 = document.createElement('p');
        pd1.className   = 'progress-detail';
        pd1.textContent = 'This process takes 15-20 minutes to download and process all filter feeds.';

        const pd2 = document.createElement('p');
        pd2.className   = 'progress-detail';
        pd2.textContent = 'Please keep this tab open. You can minimize the browser.';

        progress.appendChild(spinner);
        progress.appendChild(pt1);
        progress.appendChild(pd1);
        progress.appendChild(pd2);
        body.appendChild(progress);

        // Footer
        const footer = document.createElement('div');
        footer.className = 'modal-footer';

        const closeBtn = document.createElement('button');
        closeBtn.className   = 'e2g-btn e2g-btn-secondary';
        closeBtn.id          = 'close-mode-switch-modal';
        closeBtn.textContent = 'Close';
        closeBtn.addEventListener('click', () => {
            closeModeSwitchModal();
            pendingSwitch = null;
        });
        footer.appendChild(closeBtn);

        content.appendChild(header);
        content.appendChild(body);
        content.appendChild(footer);
        modal.appendChild(content);
        document.body.appendChild(modal);
    }

    function closeModeSwitchModal() {
        document.querySelector('.mode-switch-modal-overlay')?.remove();
    }

    function updateModalError(message) {
        const el = document.getElementById('mode-switch-progress');
        if (!el) return;
        el.innerHTML = '';

        const icon = document.createElement('div');
        icon.className   = 'e2g-progress-error-icon';
        icon.textContent = 'Error';

        const msgP = document.createElement('p');
        msgP.className   = 'e2g-progress-text--error';
        msgP.textContent = message;

        const hint = document.createElement('p');
        hint.className   = 'e2g-progress-text--muted';
        hint.textContent = 'Please try again or check the system logs.';

        el.appendChild(icon);
        el.appendChild(msgP);
        el.appendChild(hint);
    }

    async function updateModalSuccess(data) {
        const el = document.getElementById('mode-switch-progress');
        if (!el) return;

        let message = 'Mode switch task initiated.';
        if (data.duration) {
            const m = Math.floor(data.duration / 60);
            const s = data.duration % 60;
            message += ` (Request took ${m}m ${s}s)`;
        }

        el.innerHTML = '';

        const msgP = document.createElement('p');
        msgP.className   = 'e2g-progress-text--success';
        msgP.textContent = message;

        const warnBox = document.createElement('div');
        warnBox.className = 'e2g-progress-warning-box';

        const warnText = document.createElement('p');
        warnText.className = 'e2g-progress-warning-text';
        const b = document.createElement('strong');
        b.textContent = 'Background Job Active: ';
        warnText.appendChild(b);
        warnText.appendChild(document.createTextNode('The server is processing your filter changes.'));

        const warnNote = document.createElement('p');
        warnNote.className   = 'e2g-progress-warning-note';
        warnNote.textContent = 'The dashboard updates automatically when the shell script finishes (approx 15-20 mins). Do not trigger another switch.';

        warnBox.appendChild(warnText);
        warnBox.appendChild(warnNote);
        el.appendChild(msgP);
        el.appendChild(warnBox);

        await detectActiveMode();
        await loadFeeds(activeMode);
        await updateProcessingStatus();
    }

    // =========================================================================
    // PROCESSING STATUS PANEL
    // =========================================================================
    async function updateProcessingStatus() {
        if (!activeModeData || activeMode === 'none' || activeMode === 'unknown') return;

        const lastProcessed = await getLastProcessedTime();
        const nextCron      = getNextCronTime();
        const configAge     = lastProcessed ? getConfigAge(lastProcessed) : '--';

        const lastEl   = document.getElementById('last-processed');
        const nextEl   = document.getElementById('next-cron');
        const ageEl    = document.getElementById('config-age');

        if (lastEl) lastEl.textContent = lastProcessed ? formatDateTime(lastProcessed) : 'Never';
        if (nextEl) nextEl.textContent = nextCron ? formatDateTime(nextCron) : 'Not scheduled';
        if (ageEl)  ageEl.textContent  = configAge;
    }

    async function getLastProcessedTime() {
        const pattern = LOG_PATTERNS[activeMode];
        if (!pattern) return null;

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT_LOG_INFO, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'get_log_info', pattern, csrf_token: csrfToken })
            });

            if (!res.ok) return null;
            if (!res.headers.get('content-type')?.includes('application/json')) return null;

            const text = await res.text();
            if (!text.trim()) return null;

            const result = JSON.parse(text);
            return result.success && result.last_modified
                ? new Date(result.last_modified * 1000)
                : null;

        } catch (err) {
            console.warn('[E2G] Log info error:', err.message);
            return null;
        }
    }

    function getNextCronTime() {
        if (!activeModeData) return null;
        const now  = new Date();
        const next = new Date(now);
        next.setHours(
            parseInt(activeModeData.cron_hour, 10),
            parseInt(activeModeData.cron_minute || 0, 10),
            0, 0
        );
        if (now >= next) next.setDate(next.getDate() + 1);
        return next;
    }

    function getConfigAge(lastProcessed) {
        const diff    = Date.now() - lastProcessed;
        const hours   = Math.floor(diff / 3600000);
        const minutes = Math.floor((diff % 3600000) / 60000);
        if (hours > 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`;
        if (hours > 0)  return `${hours}h ${minutes}m`;
        return `${minutes}m`;
    }

    // =========================================================================
    // LOG VIEWER  (inline modal from e2g_code.html)
    // =========================================================================
    async function openLogViewer() {
        const modal   = document.getElementById('log-viewer-modal');
        const content = document.getElementById('log-content');
        const loading = document.getElementById('log-loading');
        const logInfo = document.getElementById('log-info');

        if (!modal) {
            showNotification('Log viewer modal not found in HTML', 'error');
            return;
        }

        modal.classList.remove('hidden');
        loading?.classList.remove('hidden');
        content?.classList.add('hidden');
        if (logInfo) logInfo.innerHTML = '';

        const pattern = LOG_PATTERNS[activeMode];
        if (!pattern) {
            showNotification('No active mode selected', 'error');
            loading?.classList.add('hidden');
            return;
        }

        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT_LOG, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'get_latest_log', pattern, csrf_token: csrfToken })
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const result = await res.json();

            if (!result.success || !result.log_content) {
                throw new Error(result.message || 'Failed to load log');
            }

            currentLogContent  = result.log_content;
            currentLogFilename = result.log_file;

            if (content) {
                content.textContent = result.log_content;
                content.classList.remove('hidden');
            }

            if (logInfo) {
                logInfo.innerHTML = '';
                const bar = document.createElement('div');
                bar.className = 'e2g-log-info-bar';

                const fname = document.createElement('span');
                fname.className   = 'e2g-log-info-filename';
                fname.textContent = 'File: ' + result.log_file;

                const meta = document.createElement('span');
                meta.className   = 'e2g-log-info-meta';
                meta.textContent = result.line_count + ' lines • ' + (result.size / 1024).toFixed(1) + ' KB';

                bar.appendChild(fname);
                bar.appendChild(meta);
                logInfo.appendChild(bar);
            }

        } catch (err) {
            console.error('[E2G] Log viewer error:', err);
            if (content) {
                content.textContent = `Error loading log: ${err.message}`;
                content.classList.remove('hidden');
            }
        } finally {
            loading?.classList.add('hidden');
        }
    }

    function closeLogViewer() {
        document.getElementById('log-viewer-modal')?.classList.add('hidden');
    }

    function copyLogToClipboard() {
        if (!currentLogContent) {
            showNotification('No log content to copy', 'error');
            return;
        }
        navigator.clipboard.writeText(currentLogContent)
            .then(() => {
                showNotification('Log copied to clipboard', 'success');
                const btn = document.getElementById('copy-log-btn');
                if (btn) {
                    const orig    = btn.textContent;
                    btn.textContent = 'Copied';
                    btn.disabled    = true;
                    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 2000);
                }
            })
            .catch(err => {
                console.error('[E2G] Clipboard error:', err);
                showNotification('Failed to copy log', 'error');
            });
    }

    function downloadLogFile() {
        if (!currentLogContent) {
            showNotification('No log content to download', 'error');
            return;
        }
        const blob = new Blob([currentLogContent], { type: 'text/plain' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = currentLogFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showNotification('Downloaded: ' + currentLogFilename, 'success');
    }

    // =========================================================================
    // LOG LIST + SPECIFIC LOG  (merged from e2glog.js)
    // =========================================================================
    async function listFilterLogs(filterType) {
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT_READ_LOG, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'list', filter_type: filterType, csrf_token: csrfToken })
            });
            const result = await res.json();
            if (result.success) {
                showLogListModal(result.logs, filterType);
            } else {
                showNotification(result.error || 'Failed to list logs', 'error');
            }
        } catch (err) {
            console.error('[E2G] List logs error:', err);
            showNotification('Error listing logs: ' + err.message, 'error');
        }
    }

    async function viewSpecificLog(filterType, filename) {
        try {
            const csrfToken = await getCsrfToken();
            const res = await fetch(ENDPOINT_READ_LOG, {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/json' },
                body:        JSON.stringify({ action: 'get_specific', filter_type: filterType, filename, csrf_token: csrfToken })
            });
            const result = await res.json();
            if (result.success) {
                showLogModal(result, filterType);
            } else {
                showNotification(result.error || 'Failed to load log', 'error');
            }
        } catch (err) {
            console.error('[E2G] View specific log error:', err);
            showNotification('Error loading log: ' + err.message, 'error');
        }
    }

    function showLogModal(logData, filterType) {
        const filterNames = { user: 'User Filter', childsafe: 'Child Safe Filter', adult: 'Adult Filter' };
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';

        const content = document.createElement('div');
        content.className = 'modal-content log-modal';

        // Header
        const header = document.createElement('div');
        header.className = 'modal-header';
        const h3 = document.createElement('h3');
        h3.textContent = (filterNames[filterType] || filterType) + ' - Processing Log';
        const closeX = document.createElement('button');
        closeX.className       = 'modal-close';
        closeX.dataset.action  = 'close-log-modal';
        closeX.textContent     = 'X';
        header.appendChild(h3);
        header.appendChild(closeX);

        // Body
        const body = document.createElement('div');
        body.className = 'modal-body';

        const meta = document.createElement('div');
        meta.className = 'log-metadata';
        [
            ['File', logData.filename],
            ['Modified', logData.mtime_human],
            ['Lines', logData.line_count],
            ['Size', formatBytes(logData.size)],
        ].forEach(([label, value]) => {
            const item = document.createElement('div');
            item.className = 'log-meta-item';
            const b = document.createElement('strong');
            b.textContent = label + ': ';
            item.appendChild(b);
            item.appendChild(document.createTextNode(String(value ?? '')));
            meta.appendChild(item);
        });

        const wrapper = document.createElement('div');
        wrapper.className = 'log-content-wrapper';
        const pre = document.createElement('pre');
        pre.className   = 'log-content';
        pre.id          = 'logContent';
        pre.textContent = logData.content;
        wrapper.appendChild(pre);

        body.appendChild(meta);
        body.appendChild(wrapper);

        // Footer
        const footer = document.createElement('div');
        footer.className = 'modal-footer';

        function makeBtn(label, action, extra) {
            const btn = document.createElement('button');
            btn.className      = 'e2g-btn e2g-btn-secondary';
            btn.dataset.action = action;
            btn.textContent    = label;
            if (extra) Object.entries(extra).forEach(([k, v]) => btn.dataset[k] = v);
            return btn;
        }

        footer.appendChild(makeBtn('Copy',     'copy-log'));
        footer.appendChild(makeBtn('Download', 'download-log', { filename: logData.filename, filter: filterType }));
        footer.appendChild(makeBtn('All Logs', 'view-all-logs', { filterType: filterType }));
        const closeBtn = makeBtn('Close', 'close-log-modal');
        closeBtn.className = 'e2g-btn e2g-btn-primary';
        footer.appendChild(closeBtn);

        content.appendChild(header);
        content.appendChild(body);
        content.appendChild(footer);
        modal.appendChild(content);
        document.body.appendChild(modal);

        // Auto-scroll if log is recent
        if (Date.now() / 1000 - logData.mtime < 300) {
            pre.scrollTop = pre.scrollHeight;
        }
    }

    function showLogListModal(logs, filterType) {
        const filterNames = { user: 'User Filter', childsafe: 'Child Safe Filter', adult: 'Adult Filter' };

        const modal = document.createElement('div');
        modal.className = 'modal-overlay';

        const content = document.createElement('div');
        content.className = 'modal-content log-list-modal';

        const header = document.createElement('div');
        header.className = 'modal-header';
        const h3 = document.createElement('h3');
        h3.textContent = (filterNames[filterType] || filterType) + ' - All Logs (' + logs.length + ')';
        const closeX = document.createElement('button');
        closeX.className      = 'modal-close';
        closeX.dataset.action = 'close-log-modal';
        closeX.textContent    = 'X';
        header.appendChild(h3);
        header.appendChild(closeX);

        const body = document.createElement('div');
        body.className = 'modal-body';

        if (logs.length === 0) {
            const noLogs = document.createElement('p');
            noLogs.className   = 'no-logs';
            noLogs.textContent = 'No logs found for this filter type.';
            body.appendChild(noLogs);
        } else {
            const list = document.createElement('div');
            list.className = 'log-list';
            logs.forEach(log => {
                const item = document.createElement('div');
                item.className           = 'log-list-item';
                item.dataset.action      = 'view-specific-log';
                item.dataset.filterType  = filterType;
                item.dataset.filename    = log.filename;

                const nameDiv = document.createElement('div');
                nameDiv.className   = 'log-item-name';
                nameDiv.textContent = log.filename;

                const metaDiv = document.createElement('div');
                metaDiv.className = 'log-item-meta';

                const timeSpan = document.createElement('span');
                timeSpan.textContent = log.mtime_human;

                const sizeSpan = document.createElement('span');
                sizeSpan.textContent = formatBytes(log.size);

                metaDiv.appendChild(timeSpan);
                metaDiv.appendChild(sizeSpan);
                item.appendChild(nameDiv);
                item.appendChild(metaDiv);
                list.appendChild(item);
            });
            body.appendChild(list);
        }

        const footer = document.createElement('div');
        footer.className = 'modal-footer';
        const closeBtn = document.createElement('button');
        closeBtn.className      = 'e2g-btn e2g-btn-primary';
        closeBtn.dataset.action = 'close-log-modal';
        closeBtn.textContent    = 'Close';
        footer.appendChild(closeBtn);

        content.appendChild(header);
        content.appendChild(body);
        content.appendChild(footer);
        modal.appendChild(content);
        document.body.appendChild(modal);
    }

    // =========================================================================
    // SERVICE STATUS MODAL  (merged from e2glog.js)
    // =========================================================================
    async function viewServiceStatus() {
        try {
            const res    = await fetch(ENDPOINT_SVC_STATUS);
            const status = await res.json();

            const modal = document.createElement('div');
            modal.className = 'modal-overlay';

            const content = document.createElement('div');
            content.className = 'modal-content status-modal';

            const header = document.createElement('div');
            header.className = 'modal-header';
            const h3 = document.createElement('h3');
            h3.textContent = 'E2Guardian Service Status';
            const closeX = document.createElement('button');
            closeX.className      = 'modal-close';
            closeX.dataset.action = 'close-log-modal';
            closeX.textContent    = 'X';
            header.appendChild(h3);
            header.appendChild(closeX);

            const body = document.createElement('div');
            body.className = 'modal-body';

            const grid = document.createElement('div');
            grid.className = 'status-grid';
            [
                ['PID',    status.pid    ?? 'N/A'],
                ['CPU',    (status.cpu   ?? 'N/A') + '%'],
                ['Memory', (status.mem   ?? 'N/A') + '%'],
                ['Status', status.status ?? 'unknown'],
            ].forEach(([label, value]) => {
                const item = document.createElement('div');
                item.className = 'status-item';
                const b = document.createElement('strong');
                b.textContent = label + ': ';
                item.appendChild(b);
                item.appendChild(document.createTextNode(String(value)));
                grid.appendChild(item);
            });
            body.appendChild(grid);

            const footer = document.createElement('div');
            footer.className = 'modal-footer';
            const closeBtn = document.createElement('button');
            closeBtn.className      = 'e2g-btn e2g-btn-primary';
            closeBtn.dataset.action = 'close-log-modal';
            closeBtn.textContent    = 'Close';
            footer.appendChild(closeBtn);

            content.appendChild(header);
            content.appendChild(body);
            content.appendChild(footer);
            modal.appendChild(content);
            document.body.appendChild(modal);
        } catch {
            showNotification('Failed to load service status', 'error');
        }
    }

    // =========================================================================
    // EVENT BINDING
    // =========================================================================
    function bindModeTabSwitchers() {
        // Clone to clear any old listeners before rebinding
        document.querySelectorAll('span[data-tab]').forEach(btn => {
            const fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', handleModeTabClick);
        });
    }

    function bindRefreshButton() {
        const old = document.querySelector('button[data-action="refresh"]');
        if (!old) return;
        const btn = old.cloneNode(true);
        old.parentNode.replaceChild(btn, old);

        btn.addEventListener('click', async () => {
            const svg = btn.querySelector('svg');
            svg?.classList.add('e2g-refresh-spin');
            try {
                await detectActiveMode();
                await loadFeeds(activeMode);
            } catch (err) {
                console.error('[E2G] Manual refresh failed:', err);
            } finally {
                setTimeout(() => svg?.classList.remove('e2g-refresh-spin'), 600);
            }
        });
    }

    // Single delegated listener for all dynamic actions across feeds + modals
    function bindDelegatedActions() {
        document.addEventListener('click', handleDelegatedClick);
    }

    function handleDelegatedClick(e) {
        // Only respond when e2guardian tab is active
        if (!document.querySelector('#e2guardian-content.active')) return;

        const target = e.target.closest('[data-action]');
        if (!target) return;

        const action = target.getAttribute('data-action');

        switch (action) {
            case 'add-feed':
                e.preventDefault();
                addFeed();
                break;
            case 'test-feed':
                e.preventDefault();
                testFeedUrl();
                break;
            case 'download':
                e.preventDefault();
                downloadFeedList();
                break;
            case 'delete-user-feed':
                e.preventDefault();
                deleteFeed(target.getAttribute('data-url'));
                break;
            case 'view-log':
                e.preventDefault();
                openLogViewer();
                break;
            case 'close-log-modal':
                e.preventDefault();
                // Works for both the fixed #log-viewer-modal and dynamic modals
                target.closest('.modal-overlay, #log-viewer-modal')?.remove();
                closeLogViewer();
                break;
            case 'copy-log':
                e.preventDefault();
                copyLogToClipboard();
                break;
            case 'download-log':
                e.preventDefault();
                downloadLogFile();
                break;
            case 'view-all-logs':
                e.preventDefault();
                listFilterLogs(target.getAttribute('data-filter-type'));
                break;
            case 'view-specific-log':
                e.preventDefault();
                viewSpecificLog(
                    target.getAttribute('data-filter-type'),
                    target.getAttribute('data-filename')
                );
                break;
            case 'view-service-status':
                e.preventDefault();
                viewServiceStatus();
                break;
        }
    }

    function bindLogModalButtons() {
        document.getElementById('close-log-modal-btn')
            ?.addEventListener('click', closeLogViewer);
        document.getElementById('copy-log-btn')
            ?.addEventListener('click', copyLogToClipboard);
        document.getElementById('download-log-btn')
            ?.addEventListener('click', downloadLogFile);
    }

    // =========================================================================
    // INIT / TEARDOWN
    // =========================================================================
    async function init() {
        if (isInitialized) return;
        isInitialized = true;

        console.log('[E2G] Initializing');

        await detectActiveMode();
        await loadFeeds();

        startHeartbeat();
        bindModeTabSwitchers();
        bindRefreshButton();
        bindLogModalButtons();
    }

    function teardown() {
        stopHeartbeat();
        isInitialized = false;
        console.log('[E2G] Torn down');
    }

    // =========================================================================
    // BOOT -- waits for ManageNav, never self-starts
    // =========================================================================
    function register() {
        window.ManageNav.register('e2guardian', {
            onActivate:   init,
            onDeactivate: teardown
        });
        console.log('[E2G] Registered with ManageNav');
    }

    if (window.ManageNav) {
        register();
    } else {
        document.addEventListener('manageNavReady', register, { once: true });
    }

    // Bind the single delegated click handler at load time (safe -- guarded by tab check inside)
    bindDelegatedActions();

})();
