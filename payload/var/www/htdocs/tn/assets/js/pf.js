// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

// managepf.js
// Single consolidated module for the PF tab in the management SPA.
// Replaces: manageip.js, manageasn.js, managepfgeoip.js, managelistpfsrc.js,
//           managerulebuilder.js, managevalidation.js, pfdefrules.js
//
// Requires: ui.js (UI.confirm, UI.toast) loaded before this file.
// Load order in HTML: ui.js -> managepf.js

(function () {
    'use strict';

    // ================================================================
    // CONFIG
    // ================================================================
    var CFG = {
        csrfApi:          '/cgi-bin/control.pl/api/csrf',
        writeInput:       '/cgi-bin/pf_write_input.pl',
        readInput:        '/cgi-bin/pf_read_input.pl',
        deleteInput:      '/cgi-bin/pf_delete_input.pl',
        triggerApi:       '/cgi-bin/pf_trigger.pl',
        validateApi:      '/cgi-bin/pf_validate_rule.pl',
        activeRulesApi:   '/cgi-bin/pf_active_rules.pl',
        verdictPath:      '/data/services/queue/pf-rules/validation-output/verdict.json',
        fullOutputPath:   '/data/services/queue/pf-rules/validation-output/full-context.txt',
        rulesPath:        '/data/services/queue/pf-rules/current',
        geoipHtml:        '/data/db/GeoIP/isocountrycodes.html',
        intelTxt:         '/data/db/pf/intel.txt',
        rulesRefresh:       30000,
        verdictTimeout:     120,
        writeRulesApi:      '/cgi-bin/pf_write_rules.pl',
        applyDeletionApi:   '/cgi-bin/pf_apply_deletion.pl',
        parsedRulesJson:    '/cgi-bin/pf_active_rules.pl',   // action:parse
        deletionTestResult: '/cgi-bin/pf_active_rules.pl',   // action:get_test_result
        deletionOutcome:    '/cgi-bin/pf_active_rules.pl'    // action:get_outcome
    };

    // ================================================================
    // STATE
    // ================================================================
    var csrfToken        = null;
    var stagedRules      = [];
    var verdictPoll      = null;
    var autoRefreshTimer = null;
    var _initInProgress  = false;   // guard against double-init on first load

    // ================================================================
    // UTILS
    // ================================================================
    function escapeHtml(text) {
        var d = document.createElement('div');
        d.textContent = String(text);
        return d.innerHTML;
    }

    function flashButton(btn, message, durationMs) {
        durationMs = durationMs || 1500;
        var orig = btn.textContent;
        btn.textContent = message;
        btn.classList.add('btn--copied');
        setTimeout(function () {
            btn.textContent = orig;
            btn.classList.remove('btn--copied');
        }, durationMs);
    }

    var fetchCSRFToken = async function() {
        try {
            var r = await fetch(CFG.csrfApi);
            if (!r.ok) {
                console.error('[PF] CSRF fetch failed:', r.status);
                // Trigger immediate session check -- 401/403 likely means expired session
                if (r.status === 401 || r.status === 403) {
                    if (window.ViewSystem && window.ViewSystem.checkSession) {
                        window.ViewSystem.checkSession();
                    }
                }
                return null;
            }
            var d = await r.json();
            if (d.token) { csrfToken = d.token; return csrfToken; }
        } catch (e) {
            console.error('[PF] CSRF fetch error:', e);
        }
        return null;
    }

    var ensureCSRF = async function() {
        if (!csrfToken) csrfToken = await fetchCSRFToken();
        return csrfToken;
    }

    // ================================================================
    // SECTION: IP / CIDR
    // ================================================================
    function initIP() {
        var input  = document.getElementById('ip-input');
        var addBtn = document.querySelector('[data-action="add-ip"]');
        var list   = document.getElementById('ip-recent-entries');
        if (!input || !addBtn || !list) return;

        addBtn.addEventListener('click', async function () {
            var val = input.value.trim();
            if (!val) return;

            var action = (document.querySelector('input[name="ip_action"]:checked') || {}).value || 'block';

            if (!await ensureCSRF()) {
                UI.toast('Security token unavailable - please refresh', 'error');
                return;
            }

            try {
                var r = await fetch(CFG.writeInput, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({ type: 'ip', action: action, value: val, csrf_token: csrfToken })
                });
                if (r.ok) {
                    var result = await r.json();
                    if (result.success) {
                        addEntryCard(list, val, action, 'ip');
                        input.value = '';
                        flashButton(addBtn, 'Added!');
                    } else {
                        UI.toast('Error: ' + (result.error || 'Failed'), 'error');
                    }
                } else {
                    UI.toast('Server error: ' + r.status, 'error');
                }
            } catch (e) {
                UI.toast('Network error: ' + e.message, 'error');
            }
        });

        input.addEventListener('keypress', function (e) { if (e.key === 'Enter') addBtn.click(); });
    }

    // ================================================================
    // SECTION: ASN
    // ================================================================
    function initASN() {
        var input  = document.getElementById('asn-input');
        var addBtn = document.querySelector('[data-action="add-asn"]');
        var list   = document.getElementById('asn-recent-entries');
        if (!input || !addBtn || !list) return;

        addBtn.addEventListener('click', async function () {
            var val = input.value.trim();
            if (!val) return;

            // Normalise: strip leading AS/as, pad back
            var num = val.replace(/^as/i, '');
            if (!/^\d{1,10}$/.test(num)) {
                UI.toast('Invalid ASN format - use AS15169 or 15169', 'error');
                return;
            }
            var asn = 'AS' + num;

            var action = (document.querySelector('input[name="asn_action"]:checked') || {}).value || 'block';

            if (!await ensureCSRF()) {
                UI.toast('Security token unavailable - please refresh', 'error');
                return;
            }

            try {
                var r = await fetch(CFG.writeInput, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({ type: 'asn', action: action, value: asn, csrf_token: csrfToken })
                });
                if (r.ok) {
                    var result = await r.json();
                    if (result.success) {
                        addEntryCard(list, asn, action, 'asn');
                        input.value = '';
                        flashButton(addBtn, 'Added!');
                    } else {
                        UI.toast('Error: ' + (result.error || 'Failed'), 'error');
                    }
                } else {
                    UI.toast('Server error: ' + r.status, 'error');
                }
            } catch (e) {
                UI.toast('Network error: ' + e.message, 'error');
            }
        });

        input.addEventListener('keypress', function (e) { if (e.key === 'Enter') addBtn.click(); });
    }

    // ================================================================
    // QUEUE LOADING - populate all lists from persisted queue files
    // Called once on tab activation via pf_read_input.pl (GET)
    // ================================================================
    var loadQueueEntries = async function() {
        try {
            if (!await ensureCSRF()) {
                console.error('[PF] loadQueueEntries: no CSRF token');
                return;
            }
            var r = await fetch(CFG.readInput, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                body: JSON.stringify({ action: 'read', csrf_token: csrfToken })
            });
            if (!r.ok) {
                console.error('[PF] loadQueueEntries failed: ' + r.status);
                return;
            }
            var data = await r.json();
            if (!data.success) return;

            // IP lists
            var ipList = document.getElementById('ip-recent-entries');
            if (ipList) {
                clearEntries(ipList);
                data.ip.block.forEach(function (v) { addEntryCard(ipList, v, 'block', 'ip'); });
                data.ip.pass.forEach(function  (v) { addEntryCard(ipList, v, 'pass',  'ip'); });
                restoreBannerIfEmpty(ipList, BANNERS.ip);
            }

            // ASN lists
            var asnList = document.getElementById('asn-recent-entries');
            if (asnList) {
                clearEntries(asnList);
                data.asn.block.forEach(function (v) { addEntryCard(asnList, v, 'block', 'asn'); });
                data.asn.pass.forEach(function  (v) { addEntryCard(asnList, v, 'pass',  'asn'); });
                restoreBannerIfEmpty(asnList, BANNERS.asn);
            }

            // User feeds (separate container from the protected intel.txt feeds)
            var feedList = document.getElementById('user-feed-entries');
            if (feedList && data.feeds) {
                feedList.innerHTML = '';
                data.feeds.forEach(function (f) { addEntryCard(feedList, f.url, f.action, 'feed'); });
            }

        } catch (e) {
            console.error('[PF] loadQueueEntries error:', e);
        }
    }

    // ================================================================
    // HELPERS - preserve informational banners when clearing entries
    // ================================================================
    function clearEntries(list) {
        // Remove entry cards
        var cards = list.querySelectorAll('.pf-entry');
        cards.forEach(function (c) { c.remove(); });
        // Remove any existing banners (both static HTML banners and JS-added ones)
        // so restoreBannerIfEmpty always has a clean slate and never doubles up
        var banners = list.querySelectorAll('.pf-info-banner, .rounded-lg.border.border-blue-200');
        banners.forEach(function (b) { b.remove(); });
    }

    function restoreBannerIfEmpty(list, bannerHtml) {
        // If no entry cards remain and no banner exists, re-insert the banner
        if (list.querySelectorAll('.pf-entry').length === 0 &&
            !list.querySelector('.pf-info-banner')) {
            var div = document.createElement('div');
            div.className = 'rounded-lg border border-blue-200 bg-blue-50 p-3 pf-info-banner dark:border-blue-800/50 dark:bg-blue-900/20';
            div.innerHTML = bannerHtml;
            list.insertBefore(div, list.firstChild);
        }
    }

    var BANNERS = {
        ip:  '<p class="text-sm text-gray-700 dark:text-gray-300"><span class="font-bold">User Input Only:</span> Enter IPs or CIDRs to block/pass. Each entry will be validated by Perl backend.</p>',
        asn: '<p class="text-sm text-gray-700 dark:text-gray-300"><span class="font-bold">User Input Only:</span> Enter AS numbers to block/pass. Format will be validated by Perl backend.</p>',
    };

    // ================================================================
    // ENTRY CARD - renders one queued item with a delete button
    // type: 'ip' | 'asn' | 'feed'
    // ================================================================
    function addEntryCard(list, value, action, type) {
        var entry = document.createElement('div');
        entry.className = 'pf-entry';
        entry.dataset.action = action;
        entry.dataset.value  = value;
        entry.dataset.type   = type;

        entry.innerHTML =
            '<div class="pf-entry-row">' +
                '<span class="pf-entry-value">' + escapeHtml(value) + '</span>' +
                '<div class="pf-entry-actions">' +
                    '<span class="pf-entry-badge">' + escapeHtml(action) + '</span>' +
                    '<button type="button" class="pf-entry-delete-btn" title="Remove from queue" ' +
                        'aria-label="Remove ' + escapeHtml(value) + ' from queue">' +
                        '<svg xmlns="http://www.w3.org/2000/svg" class="pf-entry-delete-icon" ' +
                            'fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">' +
                            '<path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>' +
                        '</svg>' +
                    '</button>' +
                '</div>' +
            '</div>' +
            '<div class="pf-entry-hint">Pending validation</div>';

        var deleteBtn = entry.querySelector('.pf-entry-delete-btn');
        deleteBtn.addEventListener('click', function () {
            deleteEntry(entry, type, action, value);
        });

        list.appendChild(entry);
    }

    // ================================================================
    // DELETE ENTRY - calls pf_delete_input.pl, removes card on success
    // ================================================================
    var deleteEntry = async function(card, type, action, value) {
        card.classList.add('pf-entry--pending');

        try {
            if (!await ensureCSRF()) {
                card.classList.remove('pf-entry--pending');
                UI.toast('Security token unavailable - please refresh', 'error');
                return;
            }
            var r = await fetch(CFG.deleteInput, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                body: JSON.stringify({ type: type, action: action, value: value, csrf_token: csrfToken })
            });

            var result = r.ok ? await r.json() : { success: false, error: 'Server error: ' + r.status };

            if (result.success) {
                card.classList.remove('pf-entry--pending');
                card.classList.add('pf-entry--deleting');
                requestAnimationFrame(function () {
                    card.classList.add('pf-entry--gone');
                });
                setTimeout(function () {
                    // Capture parent before removal -- closest() fails on detached nodes
                    var ipList  = card.closest('#ip-recent-entries');
                    var asnList = card.closest('#asn-recent-entries');
                    card.remove();
                    if (ipList)  restoreBannerIfEmpty(ipList,  BANNERS.ip);
                    if (asnList) restoreBannerIfEmpty(asnList, BANNERS.asn);
                }, 220);
            } else {
                card.classList.remove('pf-entry--pending');
                UI.toast('Delete failed: ' + (result.error || 'Unknown error'), 'error');
            }
        } catch (e) {
            card.classList.remove('pf-entry--pending');
            UI.toast('Network error during delete', 'error');
        }
    }

    // ================================================================
    // SECTION: GEOIP
    // ================================================================
    var initGeoIP = async function() {
        var container = document.getElementById('geoip-list-container');
        if (!container) return;

        try {
            var r = await fetch(CFG.geoipHtml);
            if (!r.ok) throw new Error('Failed to load countries');

            var html   = await r.text();
            var parser = new DOMParser();
            var doc    = parser.parseFromString(html, 'text/html');
            var labels = doc.querySelectorAll('label');

            container.innerHTML = '';
            var wrapper = document.createElement('div');

            labels.forEach(function (lbl) {
                var clone = lbl.cloneNode(true);
                clone.classList.add('geoip-label');
                wrapper.appendChild(clone);
            });

            container.appendChild(wrapper);

            bindGeoIPSearch();
            bindGeoIPButtons();
            bindGeoIPCheckboxes();
            bindGeoIPSubmit();
            updateGeoIPCount();

        } catch (e) {
            console.error('[PF] GeoIP load error:', e);
            container.innerHTML = '<div class="card--error-state"><p class="card--error-title">Error loading countries</p></div>';
        }
    }

    function bindGeoIPSearch() {
        var input = document.getElementById('geoip-search');
        if (!input) return;
        input.addEventListener('input', function () {
            var term = this.value.toLowerCase().trim();
            document.querySelectorAll('#geoip-list-container label').forEach(function (lbl) {
                if (lbl.textContent.toLowerCase().includes(term)) {
                    lbl.classList.remove('tn-hidden');
                } else {
                    lbl.classList.add('tn-hidden');
                }
            });
        });
    }

    function bindGeoIPButtons() {
        var selectAll = document.querySelector('[data-action="select-all-geoip"]');
        if (selectAll) {
            selectAll.addEventListener('click', function () {
                var boxes = document.querySelectorAll('#geoip-list-container input[type="checkbox"]');
                var allChecked = Array.from(boxes).every(function (cb) { return cb.checked; });
                boxes.forEach(function (cb) { cb.checked = !allChecked; });
                updateGeoIPCount();
            });
        }

        var clear = document.querySelector('[data-action="clear-geoip"]');
        if (clear) {
            clear.addEventListener('click', function () {
                document.querySelectorAll('#geoip-list-container input[type="checkbox"]:checked')
                    .forEach(function (cb) { cb.checked = false; });
                updateGeoIPCount();
            });
        }
    }

    function bindGeoIPCheckboxes() {
        document.querySelectorAll('#geoip-list-container input[type="checkbox"]')
            .forEach(function (cb) { cb.addEventListener('change', updateGeoIPCount); });
    }

    function bindGeoIPSubmit() {
        var btn = document.querySelector('[data-action="apply-geoip"]');
        if (!btn) return;

        btn.addEventListener('click', async function () {
            var selected = Array.from(
                document.querySelectorAll('#geoip-list-container input[type="checkbox"]:checked')
            ).map(function (cb) { return cb.value; });

            if (selected.length === 0) {
                UI.toast('Select at least one country', 'warning');
                return;
            }

            var action = (document.querySelector('input[name="geo_action"]:checked') || {}).value || 'block';

            if (!await ensureCSRF()) {
                UI.toast('Security token unavailable - please refresh', 'error');
                return;
            }

            try {
                var r = await fetch(CFG.writeInput, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({ type: 'geoip', action: action, countries: selected, csrf_token: csrfToken })
                });

                if (r.ok) {
                    var result = await r.json();
                    if (result.success) {
                        UI.toast(action + ' policy saved for ' + selected.length + ' countries - click Validate to apply', 'success', 4000);
                        document.querySelectorAll('#geoip-list-container input[type="checkbox"]:checked')
                            .forEach(function (cb) { cb.checked = false; });
                        updateGeoIPCount();
                    } else {
                        throw new Error(result.error || 'Server error');
                    }
                } else {
                    throw new Error('Server error: ' + r.status);
                }
            } catch (e) {
                UI.toast('Failed to save GeoIP policy: ' + e.message, 'error');
            }
        });
    }

    function updateGeoIPCount() {
        var count = document.querySelectorAll('#geoip-list-container input[type="checkbox"]:checked').length;
        var el = document.getElementById('selected-count');
        if (el) el.textContent = count + ' selected';
    }

    // ================================================================
    // SECTION: IP LIST FEEDS
    // ================================================================
    var initFeeds = async function() {
        var container = document.getElementById('feed-list');
        if (!container) return;

        try {
            if (!await ensureCSRF()) return;

            var r = await fetch(CFG.activeRulesApi, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                body: JSON.stringify({ action: 'get_intel', csrf_token: csrfToken })
            });
            if (!r.ok) throw new Error('HTTP ' + r.status);

            var data  = await r.json();
            var lines = (data.success && data.lines) ? data.lines : [];

            if (lines.length === 0) {
                container.innerHTML = '<div class="card--empty-state"><p class="log-status-label">No feeds configured</p></div>';
                return;
            }

            var wrapper = document.createElement('div');

            var infoBox = document.createElement('div');
            infoBox.className = 'feed-info-box';
            infoBox.innerHTML =
                '<p class="feed-info-box-text">' +
                '<span class="feed-info-box-label">Protected Sources:</span> ' +
                'These are curated threat intel feeds managed by the system. ' +
                'User-added feeds will be validated against this list to prevent duplicates.' +
                '</p>';
            wrapper.appendChild(infoBox);

            lines.forEach(function (line, idx) {
                var url  = line.replace(/^[^:]+:\s*/, '').trim();
                var type = (line.split(':')[0] || 'IP').trim();
                wrapper.appendChild(createFeedItem(url, type));
            });

            container.innerHTML = '';
            container.appendChild(wrapper);

        } catch (e) {
            console.error('[PF] Feed load error:', e);
            container.innerHTML = '<div class="card--error-state"><p class="card--error-title">Failed to load feeds</p></div>';
        }

        bindFeedInput();
    }

    function createFeedItem(url, type) {
        var item = document.createElement('div');
        item.className = 'feed-item';

        var icon = document.createElement('div');
        icon.className = 'feed-item-icon';
        icon.innerHTML =
            '<svg class="h-5 w-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">' +
            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" ' +
            'd="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04' +
            'A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 ' +
            '0-1.042-.133-2.052-.382-3.016z"></path></svg>';

        var content = document.createElement('div');
        content.className = 'feed-item-content';

        var badges = document.createElement('div');
        badges.className = 'feed-item-badges';

        var typeBadge = document.createElement('span');
        typeBadge.className = 'feed-type-badge';
        typeBadge.textContent = type;

        var protBadge = document.createElement('span');
        protBadge.className = 'feed-protected-badge';
        protBadge.textContent = 'Protected';

        badges.appendChild(typeBadge);
        badges.appendChild(protBadge);

        var label = document.createElement('div');
        label.className = 'feed-url-label';
        label.textContent = url;

        content.appendChild(badges);
        content.appendChild(label);
        item.appendChild(icon);
        item.appendChild(content);
        return item;
    }

    function bindFeedInput() {
        var addBtn = document.querySelector('[data-action="add-feed"]');
        var input  = document.getElementById('feed-input');
        if (!addBtn || !input) return;

        // Prevent double-binding
        if (addBtn.dataset.feedBound) return;
        addBtn.dataset.feedBound = '1';

        addBtn.addEventListener('click', async function () {
            var url = input.value.trim();

            if (!url) {
                UI.toast('Please enter a feed URL', 'warning');
                return;
            }
            if (!/^https?:\/\/.+/.test(url)) {
                UI.toast('URL must start with http:// or https://', 'warning');
                return;
            }

            var action = (document.querySelector('input[name="feed_action"]:checked') || {}).value || 'block';

            try {
                var r = await fetch(CFG.writeInput, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: 'feed', action: action, value: url, csrf_token: csrfToken })
                });

                if (r.ok) {
                    UI.toast('Feed queued - click Validate Rules to fetch and test', 'success', 4000);
                    input.value = '';
                    flashButton(addBtn, 'Added!');
                    // Add to user feed entries list if it exists
                    var userFeedList = document.getElementById('user-feed-entries');
                    if (userFeedList) addEntryCard(userFeedList, url, action, 'feed');
                } else {
                    UI.toast('Failed to add feed: ' + r.status, 'error');
                }
            } catch (e) {
                UI.toast('Network error - failed to add feed', 'error');
            }
        });
    }

    // ================================================================
    // SECTION: RULE BUILDER
    // ================================================================
    function initRuleBuilder() {
        var form = document.getElementById('rule-builder-form');
        if (!form) return;

        // Prevent double-binding
        if (form.dataset.rbBound) return;
        form.dataset.rbBound = '1';

        form.addEventListener('input', updateRulePreview);
        form.addEventListener('change', updateRulePreview);
        form.addEventListener('reset', function () { setTimeout(updateRulePreview, 50); });

        // quick and log toggles live outside the <form> element -- bind explicitly
        var quickCb = document.querySelector('[name="quick"]');
        var logCb   = document.querySelector('[name="log"]');
        if (quickCb) quickCb.addEventListener('change', updateRulePreview);
        if (logCb)   logCb.addEventListener('change', updateRulePreview);

        // Add rule button
        var addBtn = document.querySelector('[data-action="add-current-rule"]');
        if (addBtn) {
            addBtn.addEventListener('click', function () {
                var syntax = buildRuleSyntax().join(' ');
                if (!syntax || syntax === 'pass from any to any') {
                    UI.toast('Configure the rule before adding', 'warning');
                    return;
                }
                // Duplicate detection -- same syntax string already in staging list
                var isDuplicate = stagedRules.some(function (r) {
                    return r.syntax === syntax;
                });
                if (isDuplicate) {
                    UI.toast('This rule is already in your staging list', 'warning');
                    return;
                }
                // DAG cross-check -- warn if identical rule already exists in live anchor
                if (parsedRulesData) {
                    var liveRules = [];
                    (parsedRulesData.sections || []).forEach(function (sec) {
                        (sec.rules || []).forEach(function (r) {
                            if (r.raw) liveRules.push(r.raw.trim());
                        });
                    });
                    if (liveRules.indexOf(syntax.trim()) !== -1) {
                        UI.toast('This rule already exists in the live anchor', 'warning');
                        return;
                    }
                }
                stagedRules.push({ syntax: syntax, tokens: buildRuleSyntax(), ts: Date.now() });
                updateRulesDisplay();
                form.reset();
                setTimeout(updateRulePreview, 50);
                flashButton(addBtn, 'Added!');
            });
        }

        // Clear all button
        var clearBtn = document.querySelector('[data-action="clear-all-rules"]');
        if (clearBtn) {
            clearBtn.addEventListener('click', function () {
                if (stagedRules.length === 0) return;
                UI.confirm({
                    title:        'Clear all ' + stagedRules.length + ' staged rule' + (stagedRules.length !== 1 ? 's' : '') + '?',
                    body:         'The staging list will be emptied. No firewall rules are affected - these have not been applied yet.',
                    confirmLabel: 'Clear All',
                    variant:      'warning',
                    onConfirm:    function () { stagedRules = []; updateRulesDisplay(); }
                });
            });
        }

        // Validate staged rules
        var validateBtn = form.querySelector('[data-action="validate"]');
        if (validateBtn) {
            validateBtn.addEventListener('click', async function () {

                if (!await ensureCSRF()) {
                    UI.toast('Security token unavailable - please refresh', 'error');
                    return;
                }

                // No staged rules -- rules have already been queued to the backend.
                // Trigger the full backend validation workflow (pf_trigger -> pf_monitor ->
                // pf_validator) and poll for the verdict modal so the user can then Apply.
                if (stagedRules.length === 0) {
                    validateBtn.textContent = 'Validating...';
                    validateBtn.disabled = true;
                    try {
                        var r = await fetch(CFG.triggerApi, {
                            method: 'POST',
                            credentials: 'same-origin',
                            headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                            body: JSON.stringify({ action: 'validate', csrf_token: csrfToken })
                        });
                        if (r.ok) {
                            startVerdictPoll();
                        } else {
                            throw new Error('Server error: ' + r.status);
                        }
                    } catch (e) {
                        UI.toast('Failed to start validation: ' + e.message, 'error');
                        validateBtn.textContent = 'Validate';
                        validateBtn.disabled = false;
                    }
                    // Button is re-enabled by resetValidateBtn() after the verdict arrives.
                    return;
                }

                // Staged rules present -- local syntax check via pf_validate_rule.pl
                // before the user decides to queue them.
                validateBtn.textContent = 'Validating...';
                validateBtn.disabled = true;

                try {
                    var r = await fetch(CFG.validateApi, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                        body: JSON.stringify({ rule: stagedRules.map(function (r) { return r.syntax; }).join('\n'), csrf_token: csrfToken })
                    });
                    var result = await r.json();
                    if (result.valid) {
                        UI.toast(stagedRules.length + ' rule' + (stagedRules.length !== 1 ? 's' : '') + ' validated - you can now Apply', 'success');
                    } else {
                        UI.toast('Syntax error: ' + (result.error || 'Invalid syntax'), 'error', 6000);
                    }
                } catch (e) {
                    UI.toast('Validation failed - check network connection', 'error');
                } finally {
                    validateBtn.textContent = 'Validate';
                    validateBtn.disabled = false;
                }
            });
        }

        // Submit / queue rules
        form.addEventListener('submit', async function (e) {
            e.preventDefault();

            if (stagedRules.length === 0) {
                UI.toast('No rules to apply - add some rules first', 'warning');
                return;
            }

            UI.confirm({
                title:        'Queue ' + stagedRules.length + ' custom rule' + (stagedRules.length !== 1 ? 's' : '') + '?',
                body:         'These rules will be queued for the firewall. Click Validate Rules after to test.',
                consequences: stagedRules.map(function (r, i) { return (i + 1) + '. ' + r.syntax; }),
                confirmLabel: 'Queue Rules',
                variant:      'warning',
                onConfirm:    async function () {
                    var allRules = stagedRules.map(function (r) { return r.syntax; }).join('\n');

                    if (!await ensureCSRF()) {
                        UI.toast('Security token unavailable - please refresh', 'error');
                        return;
                    }

                    try {
                        var r = await fetch(CFG.writeInput, {
                            method: 'POST',
                            credentials: 'same-origin',
                            headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                            body: JSON.stringify({ type: 'custom_rule', value: allRules, csrf_token: csrfToken })
                        });

                        if (r.ok) {
                            var result = await r.json();
                            if (result.success) {
                                UI.toast(stagedRules.length + ' rule' + (stagedRules.length !== 1 ? 's' : '') + ' queued - click Validate Rules to test', 'success', 4000);
                                stagedRules = [];
                                updateRulesDisplay();
                                form.reset();
                                updateRulePreview();
                            } else {
                                throw new Error(result.error || 'Server error');
                            }
                        } else {
                            throw new Error('Server error: ' + r.status);
                        }
                    } catch (e) {
                        UI.toast('Failed to queue rules: ' + e.message, 'error');
                    }
                }
            });
        });

        updateRulePreview();
        updateRulesDisplay();
    }

    function buildRuleSyntax() {
        var rule = [];
        var get  = function (sel) { return document.querySelector(sel); };
        var val  = function (sel) {
            var el = get(sel);
            return (el && el.value) ? el.value.trim() : '';
        };
        var chk  = function (sel) {
            var el = get(sel);
            return el ? el.checked : false;
        };

        // ── Action (required) ──
        var action = get('[name="action"]:checked');
        if (!action) return [];
        rule.push(action.value);

        // ── Direction ──
        var dir = get('[name="direction"]:checked');
        if (dir && dir.value) rule.push(dir.value);

        // ── Log ──
        if (chk('[name="log"]')) rule.push('log');

        // ── Quick ──
        if (chk('[name="quick"]')) rule.push('quick');

        // ── Interface ──
        var iface = val('[name="interface"]');
        if (iface) rule.push('on', iface);

        // ── Address family ──
        var af = val('[name="af"]');
        if (af) rule.push(af);

        // ── Protocol ──
        var proto = val('[name="proto"]');
        if (proto) rule.push('proto', proto);

        // ── Source ──
        rule.push('from');
        var fromAddr = val('[name="from_addr"]');
        rule.push(fromAddr || 'any');
        var fromPort = val('[name="from_port"]');
        if (fromPort) rule.push('port', fromPort);

        // ── Destination ──
        rule.push('to');
        var toAddr = val('[name="to_addr"]');
        rule.push(toAddr || 'any');
        var toPort = val('[name="to_port"]');
        if (toPort) rule.push('port', toPort);

        // ── TCP Flags ──
        var flags = val('[name="flags"]');
        if (flags) rule.push('flags', flags);

        // ── State tracking + connection limit options ──
        var state   = val('[name="state"]');
        var maxConn = val('[name="max_src_conn"]');
        var rateN   = val('[name="max_src_conn_rate"]');
        var rateT   = val('[name="max_src_conn_rate_sec"]');

        if (state === 'no state') {
            rule.push('no state');
        } else if (maxConn || (rateN && rateT)) {
            var stateWord = (state && state !== '') ? state : 'keep state';
            var stateOpts = [];
            if (maxConn)        stateOpts.push('max-src-conn ' + maxConn);
            if (rateN && rateT) stateOpts.push('max-src-conn-rate ' + rateN + '/' + rateT);
            rule.push(stateWord + ' (' + stateOpts.join(', ') + ')');
        } else if (state && state !== '') {
            rule.push(state);
        }

        // ── Queue (ALTQ/FQ-CoDel) ──
        var queue    = val('[name="queue"]');
        var queuePri = val('[name="queue_priority"]');
        if (queue && queuePri) {
            rule.push('queue (' + queue + ', ' + queuePri + ')');
        } else if (queue) {
            rule.push('queue', queue);
        }

        // ── Tag ──
        var tag = val('[name="tag"]');
        if (tag) rule.push('tag', tag);

        // ── Set Priority ──
        var prio1 = val('[name="prio1"]');
        var prio2 = val('[name="prio2"]');
        if (prio1 !== '' && prio2 !== '') {
            rule.push('set prio (' + prio1 + ', ' + prio2 + ')');
        } else if (prio1 !== '') {
            rule.push('set prio', prio1);
        }

        // ── Routing (route-to / reply-to / dup-to) ──
        var routeType    = val('[name="route_type"]');
        var routeGateway = val('[name="route_gateway"]');
        if (routeType && routeGateway) {
            rule.push(routeType, routeGateway);
        }

        // ── NAT translation (nat-to / rdr-to / binat-to) ──
        var natType = val('[name="nat_type"]');
        var natAddr = val('[name="nat_addr"]');
        if (natType && natAddr) {
            rule.push(natType, natAddr);
        }

        // ── Scrub ──
        var scrub  = val('[name="scrub"]');
        var maxMss = val('[name="max_mss"]');
        if (scrub || maxMss) {
            var scrubOpts = [];
            if (scrub)  scrubOpts.push(scrub);
            if (maxMss) scrubOpts.push('max-mss ' + maxMss);
            rule.push('scrub (' + scrubOpts.join(' ') + ')');
        }

        // ── Label ──
        var label = val('[name="label"]');
        if (label) rule.push('label "' + label + '"');

        // ── RTable ──
        var rtable = val('[name="rtable"]');
        if (rtable !== '') rule.push('rtable', rtable);

        return rule;
    }

    function ruleTokenClass(token) {
        if (['pass', 'block', 'match'].includes(token))
            return 'pf-token--action';
        if (['in', 'out', 'quick', 'log'].includes(token))
            return 'pf-token--direction';
        if (['from', 'to', 'on', 'proto', 'port', 'flags', 'queue', 'tag',
             'route-to', 'reply-to', 'dup-to', 'nat-to', 'rdr-to', 'binat-to',
             'set', 'rtable', 'label'].includes(token))
            return 'pf-token--directive';
        if (/^\d/.test(token) || token === 'any')
            return 'pf-token--value';
        if (['inet', 'inet6', 'tcp', 'udp', 'icmp', 'icmp6', 'esp', 'ah', 'gre'].includes(token))
            return 'pf-token--direction';
        if (/^(keep|modulate|synproxy|no)\s+state/.test(token) ||
            /^scrub\s*\(/.test(token) ||
            /^queue\s*\(/.test(token) ||
            /^set\s+prio/.test(token) ||
            /^keep\s+state\s*\(/.test(token) ||
            /^modulate\s+state\s*\(/.test(token))
            return 'pf-token--directive';
        return 'pf-token--default';
    }

    function updateRulePreview() {
        var tokens = buildRuleSyntax();
        var syntax = tokens.join(' ');

        // Write live syntax to the preview element if it exists
        var previewEl = document.getElementById('rule-preview');
        if (previewEl) {
            if (tokens.length === 0) {
                previewEl.textContent = 'Configure a rule above to see live PF syntax here.';
                previewEl.classList.add('pf-preview--empty');
            } else {
                previewEl.textContent = syntax;
                previewEl.classList.remove('pf-preview--empty');
            }
        }

        // Enable/disable the Add button
        // Trivial = no action, or the absolute minimum with quick (default) and no real config
        var addBtn = document.querySelector('[data-action="add-current-rule"]');
        if (addBtn) {
            var trivial = (tokens.length === 0 ||
                syntax === 'pass from any to any'        ||
                syntax === 'pass quick from any to any'  ||
                syntax === 'block from any to any'       ||
                syntax === 'block quick from any to any' ||
                syntax === 'match from any to any'       ||
                syntax === 'match quick from any to any');
            addBtn.disabled = trivial;
            if (trivial) {
                addBtn.classList.add('btn--disabled');
            } else {
                addBtn.classList.remove('btn--disabled');
            }
        }
    }

    function updateRulesDisplay() {
        var container   = document.getElementById('rules-list');
        var placeholder = document.getElementById('rules-placeholder');
        var countEl     = document.getElementById('rule-count');
        if (!container) return;

        if (countEl) countEl.textContent = stagedRules.length + ' rule' + (stagedRules.length !== 1 ? 's' : '');
        if (placeholder) {
            if (stagedRules.length === 0) {
                placeholder.classList.remove('tn-hidden');
            } else {
                placeholder.classList.add('tn-hidden');
            }
        }

        container.querySelectorAll('.rule-item').forEach(function (el) { el.remove(); });

        stagedRules.forEach(function (rule, idx) {
            var div = document.createElement('div');
            div.className = 'rule-item';

            var badge = '<div class="pf-rule-badge">' + (idx + 1) + '</div>';

            var tokenHtml = rule.tokens.map(function (t) {
                return '<span class="' + ruleTokenClass(t) + '">' + escapeHtml(t) + '</span>';
            }).join(' ');

            div.innerHTML =
                '<div class="pf-rule-row">' +
                    badge +
                    '<div class="pf-rule-tokens">' + tokenHtml + '</div>' +
                    '<button type="button" data-remove-index="' + idx + '" ' +
                        'class="pf-rule-remove-btn" ' +
                        'title="Remove rule">' +
                        '<svg class="pf-rule-remove-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">' +
                        '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>' +
                    '</button>' +
                '</div>';

            div.querySelector('[data-remove-index]').addEventListener('click', function () {
                stagedRules.splice(idx, 1);
                updateRulesDisplay();
            });

            container.appendChild(div);
        });
    }

    // ================================================================
    // SECTION: VALIDATION WORKFLOW
    // ================================================================
    function initValidation() {
        var validateBtn = document.querySelector('[data-action="validate-rules"]');
        if (validateBtn && !validateBtn.dataset.vBound) {
            validateBtn.dataset.vBound = '1';
            validateBtn.addEventListener('click', async function () {
                validateBtn.disabled = true;
                validateBtn.textContent = 'Validating...';

                try {
                    var r = await fetch(CFG.triggerApi, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'validate', csrf_token: csrfToken })
                    });
                    if (r.ok) {
                        startVerdictPoll();
                    } else {
                        throw new Error('Trigger failed');
                    }
                } catch (e) {
                    UI.toast('Failed to start validation - check network connection', 'error');
                    resetValidateBtn();
                }
            });
        }

        var resetBtn = document.querySelector('[data-action="reset-rules"]');
        if (resetBtn && !resetBtn.dataset.rBound) {
            resetBtn.dataset.rBound = '1';
            resetBtn.addEventListener('click', triggerReset);
        }
    }

    function resetValidateBtn() {
        // Reset the standalone validate-rules button (initValidation pathway)
        var btn = document.querySelector('[data-action="validate-rules"]');
        if (btn) { btn.disabled = false; btn.textContent = 'Validate Rules'; }
        // Reset the rule builder validate button (initRuleBuilder pathway)
        var rbBtn = document.querySelector('#rule-builder-form [data-action="validate"]');
        if (rbBtn) { rbBtn.disabled = false; rbBtn.textContent = 'Validate'; }
    }

    function startVerdictPoll() {
        if (verdictPoll) clearInterval(verdictPoll);
        var attempts = 0;

        verdictPoll = setInterval(async function () {
            attempts++;
            if (attempts > CFG.verdictTimeout) {
                clearInterval(verdictPoll);
                UI.toast('Validation timed out after 2 minutes - check /var/www/tmp/ for details', 'error', 6000);
                resetValidateBtn();
                return;
            }
            try {
                var r = await fetch(CFG.verdictPath + '?_=' + Date.now());
                if (r.ok) {
                    var verdict = await r.json();
                    clearInterval(verdictPoll);
                    showVerdictModal(verdict);
                    resetValidateBtn();
                }
            } catch (e) { /* not ready yet */ }
        }, 1000);
    }

    function showVerdictModal(verdict) {
        var existing = document.getElementById('verdict-modal');
        if (existing) existing.remove();

        var overlay = document.createElement('div');
        overlay.id = 'verdict-modal';
        overlay.className = 'modal-overlay';

        var content = document.createElement('div');
        content.className = 'modal-content pf-verdict-modal';

        // ── Header ──
        var header = document.createElement('div');
        header.className = 'modal-header ' + (verdict.success ? 'modal-header--pass' : 'modal-header--fail');

        var titleWrap = document.createElement('div');
        titleWrap.className = 'pf-verdict-title-wrap';

        var icon = document.createElement('span');
        icon.className = 'pf-verdict-icon pf-verdict-icon--' + (verdict.success ? 'pass' : 'fail');
        icon.setAttribute('aria-hidden', 'true');

        var title = document.createElement('h2');
        title.textContent = verdict.success ? 'Validation Passed' : 'Validation Failed';

        titleWrap.appendChild(icon);
        titleWrap.appendChild(title);

        var closeBtn = document.createElement('button');
        closeBtn.className = 'modal-close';
        closeBtn.setAttribute('aria-label', 'Close');
        closeBtn.textContent = '\u00d7';
        closeBtn.addEventListener('click', closeVerdictModal);

        header.appendChild(titleWrap);
        header.appendChild(closeBtn);

        // ── Body ──
        var body = document.createElement('div');
        body.className = 'modal-body';
        body.innerHTML = verdict.success ? renderVerdictSuccess(verdict) : renderVerdictError(verdict);

        // ── Footer ──
        var footer = document.createElement('div');
        footer.className = 'modal-footer';

        if (verdict.success) {
            var fullOutputBtn = document.createElement('button');
            fullOutputBtn.className = 'pf-verdict-btn pf-verdict-btn--neutral';
            fullOutputBtn.textContent = 'View Full Output';
            fullOutputBtn.addEventListener('click', function () { PF.showFullOutput(); });

            var applyBtn = document.createElement('button');
            applyBtn.className = 'pf-verdict-btn pf-verdict-btn--success';
            applyBtn.textContent = 'Apply Changes';
            applyBtn.addEventListener('click', function () { PF.applyRules(); });

            footer.appendChild(fullOutputBtn);
            footer.appendChild(applyBtn);
        } else {
            var errBtn = document.createElement('button');
            errBtn.className = 'pf-verdict-btn pf-verdict-btn--danger';
            errBtn.textContent = 'View Errors';
            errBtn.addEventListener('click', function () { PF.showFullOutput(); });
            footer.appendChild(errBtn);
        }

        var closeFooterBtn = document.createElement('button');
        closeFooterBtn.className = 'pf-verdict-btn pf-verdict-btn--neutral';
        closeFooterBtn.textContent = 'Close';
        closeFooterBtn.addEventListener('click', closeVerdictModal);
        footer.appendChild(closeFooterBtn);

        content.appendChild(header);
        content.appendChild(body);
        content.appendChild(footer);
        overlay.appendChild(content);
        document.body.appendChild(overlay);
    }

    function renderVerdictSuccess(verdict) {
        var s = verdict.stats || {};
        var statBox = function (label, val, color) {
            return '<div class="verdict-stat-' + color + ' verdict-stat-wrap">' +
                '<div class="verdict-stat-label">' + label + '</div>' +
                '<div class="verdict-stat-value verdict-num-' + color + '">' + (val || 0) + '</div>' +
                '</div>';
        };

        var html =
            '<div class="verdict-stack">' +
                '<div class="verdict-grid-4">' +
                    statBox('IPs Added', s.ip_added, 'green') +
                    statBox('ASNs Added', s.asn_added, 'blue') +
                    statBox('Countries', s.geoip_countries, 'purple') +
                    statBox('Feeds', s.feeds_added, 'cyan') +
                '</div>' +
                '<div class="verdict-grid-3">' +
                    statBox('Custom Rules', s.custom_rules, 'blue') +
                    statBox('Rejected', s.rejected, 'orange') +
                    statBox('Duplicates', s.duplicates, 'gray') +
                '</div>';

        if (verdict.warnings && verdict.warnings.length > 0) {
            html += '<div class="verdict-stat-yellow verdict-stat-wrap">' +
                '<div class="verdict-stat-label verdict-num-yellow">Warnings</div>' +
                '<ul class="verdict-warn-list verdict-num-yellow">' +
                verdict.warnings.map(function (w) { return '<li>' + escapeHtml(w) + '</li>'; }).join('') +
                '</ul></div>';
        }

        if (s.rejected > 0) {
            html += '<div class="verdict-stat-gray verdict-stat-wrap">' +
                '<p class="verdict-num-gray"><strong>Note:</strong> ' + s.rejected +
                ' entries rejected. View full output for details.</p></div>';
        }

        html += '</div>';
        return html;
    }

    function renderVerdictError(verdict) {
        var errors = verdict.errors || ['Unknown error occurred during validation'];
        return '<div class="verdict-stack">' +
            '<div class="verdict-stat-red verdict-stat-wrap">' +
                '<div class="verdict-stat-label verdict-num-red">Validation Errors</div>' +
                '<ul class="verdict-error-list verdict-num-red">' +
                errors.map(function (e) { return '<li>' + escapeHtml(e) + '</li>'; }).join('') +
                '</ul>' +
            '</div>' +
            '<div class="verdict-stat-blue verdict-stat-wrap">' +
                '<div class="verdict-stat-label verdict-num-blue">Troubleshooting</div>' +
                '<ul class="verdict-help-list verdict-num-blue">' +
                '<li>Check full output for detailed error messages</li>' +
                '<li>Verify PF syntax in custom rules</li>' +
                '<li>Check logs in /var/www/tmp/</li>' +
                '<li>Ensure pfctl is accessible</li>' +
                '</ul>' +
            '</div>' +
        '</div>';
    }

    // ================================================================
    // SECTION: APPLY / RESET ACTIONS (exposed as PF.* for modal buttons)
    // ================================================================
    function applyRules() {
        closeVerdictModal();   // Close verdict modal first -- confirm must not stack behind it
        UI.confirm({
            title:        'Apply rules to firewall?',
            body:         'The following changes will take effect immediately on the live firewall.',
            consequences: [
                'Rules loaded into anchor "addons"',
                'Changes become active immediately',
                'Configuration persists across reboots',
            ],
            warning:      'Ensure you have console access in case of connectivity issues.',
            confirmLabel: 'Apply Now',
            variant:      'danger',
            onConfirm:    async function () {
                try {
                    var r = await fetch(CFG.triggerApi, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'apply', csrf_token: csrfToken })
                    });
                    if (r.ok) {
                        UI.toast('Rules applied - firewall anchor updated', 'success', 4000);
                        if (RulesLoader.load) setTimeout(function () { RulesLoader.load(); }, 1000);
                    } else {
                        throw new Error('Server returned error');
                    }
                } catch (e) {
                    UI.toast('Failed to apply rules: ' + e.message, 'error');
                }
            }
        });
    }

    function triggerReset() {
        UI.confirm({
            title:        'Reset to base configuration?',
            body:         'This will immediately remove all user-added firewall rules.',
            consequences: [
                'Anchor "addons" flushed immediately',
                'All user-added rules removed',
                'Base firewall configuration restored',
            ],
            warning:      'This cannot be undone. Base pf.conf rules remain active.',
            confirmLabel: 'Reset Firewall',
            variant:      'danger',
            onConfirm:    async function () {
                try {
                    var r = await fetch(CFG.triggerApi, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'reset', csrf_token: csrfToken })
                    });
                    if (r.ok) {
                        UI.toast('Firewall reset - all user rules removed', 'success', 4000);
                        if (RulesLoader.load) setTimeout(function () { RulesLoader.load(); }, 1000);
                    } else {
                        throw new Error('Server returned error');
                    }
                } catch (e) {
                    UI.toast('Failed to reset: ' + e.message, 'error');
                }
            }
        });
    }

    function closeVerdictModal() {
        var m = document.getElementById('verdict-modal');
        if (m) m.remove();
    }

    var showFullOutput = async function() {
        try {
            var r = await fetch(CFG.fullOutputPath);
            var output = await r.text();

            var om = document.createElement('div');
            om.className = 'modal-overlay';

            var content = document.createElement('div');
            content.className = 'modal-content pf-modal-inner--wide';

            var header = document.createElement('div');
            header.className = 'modal-header';

            var titleEl = document.createElement('h2');
            titleEl.textContent = 'Full Validation Output';

            var closeBtn = document.createElement('button');
            closeBtn.className = 'modal-close';
            closeBtn.setAttribute('aria-label', 'Close');
            closeBtn.textContent = '\u00d7';
            closeBtn.addEventListener('click', function () { om.remove(); });

            header.appendChild(titleEl);
            header.appendChild(closeBtn);

            var body = document.createElement('div');
            body.className = 'modal-body pf-rules-container';
            var pre = document.createElement('pre');
            pre.className = 'pf-rules-pre';
            pre.textContent = output;
            body.appendChild(pre);

            var footer = document.createElement('div');
            footer.className = 'modal-footer';

            var copyBtn = document.createElement('button');
            copyBtn.className = 'pf-verdict-btn pf-verdict-btn--primary';
            copyBtn.textContent = 'Copy Output';
            copyBtn.addEventListener('click', function () { PF.copyOutput(copyBtn); });

            var closeFooterBtn = document.createElement('button');
            closeFooterBtn.className = 'pf-verdict-btn pf-verdict-btn--neutral';
            closeFooterBtn.textContent = 'Close';
            closeFooterBtn.addEventListener('click', function () { om.remove(); });

            footer.appendChild(copyBtn);
            footer.appendChild(closeFooterBtn);

            content.appendChild(header);
            content.appendChild(body);
            content.appendChild(footer);
            om.appendChild(content);
            document.body.appendChild(om);
        } catch (e) {
            UI.toast('Failed to load full output - file may not exist yet', 'error');
        }
    }

    var copyOutput = async function(btn) {
        var pre = btn.closest('.modal-overlay').querySelector('pre');
        try {
            await navigator.clipboard.writeText(pre.textContent);
            var origText = btn.textContent;
            var origClass = btn.className;
            btn.textContent = 'Copied!';
            btn.className = 'pf-verdict-btn pf-verdict-btn--success';
            setTimeout(function () {
                btn.textContent = origText;
                btn.className = origClass;
            }, 2000);
        } catch (e) {
            UI.toast('Failed to copy to clipboard', 'error');
        }
    }

    // Panel-level Apply buttons (one per card: IP, ASN, GeoIP, Feeds)
    function initPanelActions() {
        // pf-apply - triggers validate+apply workflow
        document.querySelectorAll('[data-action="pf-apply"]').forEach(function (btn) {
            if (btn.dataset.paBound) return;
            btn.dataset.paBound = '1';
            btn.addEventListener('click', async function () {
                btn.disabled = true;
                btn.textContent = 'Applying...';
                try {
                    var r = await fetch(CFG.triggerApi, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'apply', csrf_token: csrfToken })
                    });
                    if (r.ok) {
                        UI.toast('Apply triggered - rules loading into firewall', 'success', 4000);
                    } else {
                        throw new Error('Server error: ' + r.status);
                    }
                } catch (e) {
                    UI.toast('Apply failed: ' + e.message, 'error');
                } finally {
                    btn.disabled = false;
                    btn.textContent = 'Apply';
                }
            });
        });

        // pf-reset - the bottom Reset button
        document.querySelectorAll('[data-action="pf-reset"]').forEach(function (btn) {
            if (btn.dataset.prBound) return;
            btn.dataset.prBound = '1';
            btn.addEventListener('click', triggerReset);
        });
    }

    // ================================================================
    // SECTION: DEFAULT RULES VIEWER
    // ================================================================
    var RulesLoader = {
        container: null,
        isLoading: false,

        init: function () {
            this.container = document.getElementById('default-pf-rules');
        },

        load: async function () {
            if (this.isLoading) return;
            this.isLoading = true;
            this.showLoading();
            try {
                var r = await fetch(CFG.rulesPath + '?_=' + Date.now(), { cache: 'no-store' });
                if (!r.ok) throw new Error('HTTP ' + r.status);
                var text = await r.text();
                if (!text || !text.trim()) { this.showEmpty(); }
                else { this.display(text); }
            } catch (e) {
                this.showError(e.message);
            } finally {
                this.isLoading = false;
            }
        },

        display: function (text) {
            if (!this.container) return;
            var lines = text.split('\n');
            var stats = { pass: 0, block: 0, match: 0 };
            var html  = lines.map(function (line) {
                var t = line.trim();
                if (!t) return '';
                if (t.startsWith('#'))      return '<span class="pf-rule--comment">' + escapeHtml(line) + '</span>';
                if (t.startsWith('pass '))  { stats.pass++;  return highlightRule(line, 'pass'); }
                if (t.startsWith('block ')) { stats.block++; return highlightRule(line, 'block'); }
                if (t.startsWith('match ')) { stats.match++; return highlightRule(line, 'match'); }
                if (t.startsWith('table ') || t.startsWith('anchor '))
                    return '<span class="pf-rule--table">' + escapeHtml(line) + '</span>';
                if (/^\w+\s*=/.test(t))
                    return '<span class="pf-rule--macro">' + escapeHtml(line) + '</span>';
                if (t.startsWith('set '))
                    return '<span class="pf-rule--set">' + escapeHtml(line) + '</span>';
                return '<span class="pf-rule--default">' + escapeHtml(line) + '</span>';
            }).join('\n');

            this.container.innerHTML = html;
            this.updateStats(stats);
        },

        showLoading: function () {
            if (this.container)
                this.container.innerHTML = '<span class="pf-rule--default">Loading rules from ' + CFG.rulesPath + '...</span>';
        },

        showEmpty: function () {
            if (this.container)
                this.container.innerHTML = '<span class="pf-rule--comment">No rules loaded. Ensure pf_rules_sync.sh is running.</span>';
        },

        showError: function (msg) {
            if (this.container)
                this.container.innerHTML = '<span class="pf-rule--block">Error loading rules: ' + escapeHtml(msg) + '</span>';
        },

        updateStats: function (stats) {
            var p = document.getElementById('rule-count-pass');
            var b = document.getElementById('rule-count-block');
            var m = document.getElementById('rule-count-match');
            if (p) p.textContent = stats.pass  + ' pass';
            if (b) b.textContent = stats.block + ' block';
            if (m) m.textContent = stats.match + ' match';
        }
    };

    function highlightRule(line, action) {
        var colors = { pass: 'pf-rule--pass', block: 'pf-rule--block', match: 'pf-rule--match' };
        var tokens = escapeHtml(line).split(/(\s+)/);
        var first  = true;
        return tokens.map(function (tok) {
            var t = tok.trim();
            if (!t) return tok;
            if (first && (t === 'pass' || t === 'block' || t === 'match')) {
                first = false;
                return '<span class="' + colors[t] + '">' + tok + '</span>';
            }
            if (/^(tcp|udp|icmp|icmp6|esp|ah|gre)$/i.test(t))
                return '<span class="pf-rule--proto">' + tok + '</span>';
            if (/^\d+$/.test(t) || /^\d+:\d+$/.test(t))
                return '<span class="pf-rule--number">' + tok + '</span>';
            if (/^(in|out|on|from|to|proto|port|quick|log|flags|state|nat-to|rdr-to|route-to|keep|modulate|synproxy|return|all|any)$/i.test(t))
                return '<span class="pf-rule--keyword">' + tok + '</span>';
            return tok;
        }).join('');
    }

    function initDefaultRules() {
        var toggleBtn = document.getElementById('pf-default-rules-toggle');
        var content   = document.getElementById('pf-default-rules-content');
        var icon      = toggleBtn ? toggleBtn.querySelector('.pf-accordion-icon') : null;

        if (!toggleBtn || !content) return;

        // Start collapsed
        content.classList.add('hidden');
        toggleBtn.setAttribute('aria-expanded', 'false');
        if (icon) { icon.classList.add('tn-rotate-0'); icon.classList.remove('tn-rotate-180'); }

        toggleBtn.addEventListener('click', function () {
            var expanded = toggleBtn.getAttribute('aria-expanded') === 'true';
            if (expanded) {
                content.classList.add('hidden');
                toggleBtn.setAttribute('aria-expanded', 'false');
                if (icon) { icon.classList.add('tn-rotate-0'); icon.classList.remove('tn-rotate-180'); }
            } else {
                content.classList.remove('hidden');
                toggleBtn.setAttribute('aria-expanded', 'true');
                if (icon) { icon.classList.add('tn-rotate-180'); icon.classList.remove('tn-rotate-0'); }
                RulesLoader.load();
            }
        });

        // Refresh button
        var refreshBtn = document.getElementById('pf-refresh-rules-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', async function (e) {
                e.preventDefault();
                var ic = refreshBtn.querySelector('.pf-refresh-icon');
                if (ic) ic.classList.add('icon--spinning');
                refreshBtn.disabled = true;
                await RulesLoader.load();
                setTimeout(function () {
                    if (ic) ic.classList.remove('icon--spinning');
                    refreshBtn.disabled = false;
                }, 500);
            });
        }

        // Copy button
        var copyBtn = document.getElementById('pf-copy-rules-btn');
        if (copyBtn) {
            copyBtn.addEventListener('click', async function () {
                if (!RulesLoader.container) return;
                var copyText = copyBtn.querySelector('.pf-copy-text');
                var orig = copyText ? copyText.textContent : 'Copy';
                try {
                    await navigator.clipboard.writeText(RulesLoader.container.innerText || RulesLoader.container.textContent);
                    if (copyText) copyText.textContent = 'Copied!';
                    copyBtn.classList.add('btn--copied');
                    setTimeout(function () {
                        if (copyText) copyText.textContent = orig;
                        copyBtn.classList.remove('btn--copied');
                    }, 2000);
                } catch (e) {
                    if (copyText) copyText.textContent = 'Failed';
                    setTimeout(function () { if (copyText) copyText.textContent = orig; }, 2000);
                }
            });
        }

        // Auto-refresh when accordion is open
        if (autoRefreshTimer) clearInterval(autoRefreshTimer);
        autoRefreshTimer = setInterval(function () {
            var c = document.getElementById('pf-default-rules-content');
            if (c && !c.classList.contains('hidden')) RulesLoader.load();
        }, CFG.rulesRefresh);
    }

    // ================================================================
    // SECTION: ACTIVE ADDON RULES
    // Displays currently loaded anchor blocks with per-block deletion.
    // Source: GET /cgi-bin/pf_active_rules.pl -> active-addons.json
    // Deletion: POST to pf_active_rules.pl -> queue -> pf_monitor.sh
    // ================================================================

    var addonOutcomePoll = null;

    // ── Parsed rules deletion state ──
    var parsedRulesData     = null;   // parsed-rules.json payload
    var selectedRuleIds     = {};     // { id: true } user-checked
    var cascadeRuleIds      = {};     // { id: true } auto-selected by cascade
    var deletionTestPoll    = null;
    var deletionOutcomePoll = null;

    // Max entries shown in card body before truncation note
    var ADDON_CARD_MAX_ENTRIES = 10;

    function initActiveAddons() {
        var refreshBtn = document.getElementById('addon-rules-refresh');
        if (refreshBtn && !refreshBtn.dataset.aaBound) {
            refreshBtn.dataset.aaBound = '1';
            refreshBtn.addEventListener('click', function () {
                loadActiveAddons();
            });
        }
        loadActiveAddons();
    }

    var loadActiveAddons = async function () {
        var grid    = document.getElementById('addon-rules-grid');
        var loading = document.getElementById('addon-rules-loading');
        var status  = document.getElementById('addon-anchor-status');
        var errBanner = document.getElementById('addon-load-error');
        if (!grid) return;

        // Show loading, hide everything else
        grid.innerHTML = '';
        if (loading)   loading.classList.remove('tn-hidden');
        if (status)    status.classList.add('tn-hidden');
        if (errBanner) errBanner.classList.add('tn-hidden');

        // Spin refresh icon
        var icon = document.getElementById('addon-refresh-icon');
        if (icon) icon.classList.add('spinning');

        try {
            if (!await ensureCSRF()) {
                if (loading) loading.classList.add('tn-hidden');
                if (icon)    icon.classList.remove('spinning');
                UI.toast('Security token unavailable - please refresh', 'error');
                return;
            }

            var r = await fetch(CFG.activeRulesApi, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ action: 'read', csrf_token: csrfToken })
            });

            if (!r.ok) {
                throw new Error('Server error: ' + r.status);
            }

            var rawText = await r.text();
            if (!rawText || rawText.trim().length === 0) {
                throw new Error('Empty response body from pf_active_rules.pl');
            }

            var data;
            try {
                data = JSON.parse(rawText);
            } catch (parseErr) {
                console.error('[PF] loadActiveAddons raw body:', rawText.substring(0, 300));
                throw parseErr;
            }

            if (loading) loading.classList.add('tn-hidden');
            if (icon)    icon.classList.remove('spinning');

            if (!data) {
                UI.toast('Empty response from server', 'error');
                return;
            }

            if (!data.anchor_loaded) {
                if (data.load_error && data.load_error.length > 0) {
                    // Real pfctl error -- show error banner
                    var errText = document.getElementById('addon-load-error-text');
                    if (errText) errText.textContent = data.load_error;
                    if (errBanner) errBanner.classList.remove('tn-hidden');
                } else {
                    // Normal empty state -- no conf file, post-reset, or first run
                    var statusText = document.getElementById('addon-anchor-status-text');
                    if (statusText) statusText.textContent = 'No addon rules are currently configured. Use the panels above to add IP, ASN, GeoIP, or custom rules, then Apply.';
                    if (status) status.classList.remove('tn-hidden');
                }
                return;
            }

            if (!data.blocks || data.blocks.length === 0) {
                // Anchor loaded but empty -- same friendly message
                var statusText = document.getElementById('addon-anchor-status-text');
                if (statusText) statusText.textContent = 'No addon rules are currently configured. Use the panels above to add IP, ASN, GeoIP, or custom rules, then Apply.';
                if (status) status.classList.remove('tn-hidden');
                return;
            }

            // Render one card per block
            data.blocks.forEach(function (block) {
                var card = buildAddonCard(block);
                if (card) grid.appendChild(card);
            });

        } catch (e) {
            if (loading) loading.classList.add('tn-hidden');
            if (icon)    icon.classList.remove('spinning');
            console.error('[PF] loadActiveAddons error:', e);
            UI.toast('Failed to load active addon rules', 'error');
        }
    };

    function buildAddonCard(block) {
        var card = document.createElement('div');
        card.className = 'addon-block-card';
        card.dataset.type    = block.type;
        card.dataset.table   = block.table   || '';
        card.dataset.country = block.country || '';
        card.dataset.feed    = block.feed_index || '';

        // ── Header ──
        var header = document.createElement('div');
        header.className = 'addon-card-header';

        var titleRow = document.createElement('div');
        titleRow.className = 'addon-card-title-row';

        var title = document.createElement('span');
        title.className = 'addon-card-title';
        title.textContent = block.label || block.type;

        var badge = document.createElement('span');
        badge.className = 'addon-card-badge addon-card-badge--' + (block.action || 'block');
        badge.textContent = (block.action || 'block').toUpperCase();

        titleRow.appendChild(title);
        titleRow.appendChild(badge);

        var count = document.createElement('div');
        count.className = 'addon-card-count';
        if (block.type === 'custom') {
            count.textContent = (block.entry_count || 0) + ' rule' + (block.entry_count !== 1 ? 's' : '');
        } else {
            count.textContent = (block.entry_count || 0) + ' entr' + (block.entry_count !== 1 ? 'ies' : 'y') + ' in kernel';
        }

        header.appendChild(titleRow);
        header.appendChild(count);

        // ── Body ──
        var body = document.createElement('div');
        body.className = 'addon-card-body';

        if (block.type === 'custom') {
            // Custom rules -- checkbox per line
            var rules = block.rules || [];
            if (rules.length === 0) {
                var empty = document.createElement('p');
                empty.className = 'addon-truncation-note';
                empty.textContent = 'No rules in this section.';
                body.appendChild(empty);
            } else {
                rules.forEach(function (ruleText, idx) {
                    var item = document.createElement('div');
                    item.className = 'addon-custom-item';

                    var cb = document.createElement('input');
                    cb.type = 'checkbox';
                    cb.className = 'addon-custom-checkbox';
                    cb.id = 'addon-custom-cb-' + idx;
                    cb.dataset.rule = ruleText;

                    var lbl = document.createElement('label');
                    lbl.htmlFor = 'addon-custom-cb-' + idx;
                    lbl.className = 'addon-custom-rule-text';
                    lbl.textContent = ruleText;

                    item.appendChild(cb);
                    item.appendChild(lbl);
                    body.appendChild(item);
                });
            }
        } else {
            // Table entries -- numbered <ol>
            var entries = block.table_entries || [];
            var ol = document.createElement('ol');
            ol.className = 'addon-entry-list';

            var visible = entries.slice(0, ADDON_CARD_MAX_ENTRIES);
            visible.forEach(function (entry) {
                var li = document.createElement('li');
                li.textContent = entry;
                ol.appendChild(li);
            });

            body.appendChild(ol);

            if (entries.length > ADDON_CARD_MAX_ENTRIES) {
                var more = document.createElement('p');
                more.className = 'addon-truncation-note';
                more.textContent = 'and ' + (entries.length - ADDON_CARD_MAX_ENTRIES) +
                    ' more -- click Inspect to see all';
                body.appendChild(more);
            }

            if (entries.length === 0) {
                var empty = document.createElement('p');
                empty.className = 'addon-truncation-note';
                empty.textContent = 'Table is empty (entries may still be loading).';
                body.appendChild(empty);
            }
        }

        // ── Footer ──
        var footer = document.createElement('div');
        footer.className = 'addon-card-footer';

        // Inspect button (not for custom -- no table to inspect)
        if (block.type !== 'custom') {
            var inspectBtn = document.createElement('button');
            inspectBtn.type = 'button';
            inspectBtn.className = 'addon-btn-inspect';
            inspectBtn.innerHTML =
                '<svg xmlns="http://www.w3.org/2000/svg" class="addon-btn-icon" fill="none" ' +
                'viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">' +
                '<path stroke-linecap="round" stroke-linejoin="round" ' +
                'd="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>' +
                '<path stroke-linecap="round" stroke-linejoin="round" ' +
                'd="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>' +
                '</svg>Inspect';
            inspectBtn.addEventListener('click', function () {
                showAddonInspectModal(block);
            });
            footer.appendChild(inspectBtn);
        }

        // Remove button / Manage button
        if (block.type === 'custom') {
            // Custom rules are managed via the DAG deletion panel below.
            // This button scrolls to it rather than offering a parallel path.
            var manageBtn = document.createElement('button');
            manageBtn.type = 'button';
            manageBtn.className = 'addon-btn-inspect';
            manageBtn.innerHTML =
                '<svg xmlns="http://www.w3.org/2000/svg" class="addon-btn-icon" fill="none" ' +
                'viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">' +
                '<path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/>' +
                '</svg>Manage Rules';
            manageBtn.addEventListener('click', function () {
                var section = document.getElementById('parsed-rules-section');
                if (section) {
                    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    section.classList.add('parsed-rules-section--highlight');
                    setTimeout(function () {
                        section.classList.remove('parsed-rules-section--highlight');
                    }, 1800);
                }
            });
            footer.appendChild(manageBtn);
        } else {
            var removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'addon-btn-remove';
            removeBtn.innerHTML =
                '<svg xmlns="http://www.w3.org/2000/svg" class="addon-btn-icon" fill="none" ' +
                'viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">' +
                '<path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>' +
                '</svg>Remove Block';
            removeBtn.addEventListener('click', function () {
                confirmAddonDelete(block, card, null);
            });
            footer.appendChild(removeBtn);
        }

        card.appendChild(header);
        card.appendChild(body);
        card.appendChild(footer);
        return card;
    }

    // ── Entry Manager / Inspect modal ──
    // For table-backed blocks (ip_block, ip_pass, asn_block, geoip, feed):
    //   shows checkboxed entry list, max 10 visible + overflow scroll,
    //   search filter, select-all, Remove Selected button.
    // For custom blocks: read-only list (custom rules managed by DAG panel).
    function showAddonInspectModal(block) {
        var entries  = block.table_entries || [];
        var label    = block.label || block.type;
        var table    = block.table || '';
        var type     = block.type  || '';
        var isCustom = (type === 'custom');

        var overlay = document.createElement('div');
        overlay.className = 'modal-overlay';

        var content = document.createElement('div');
        content.className = 'modal-content addon-inspect-modal';

        // Header
        var header = document.createElement('div');
        header.className = 'modal-header';

        var titleEl = document.createElement('h2');
        titleEl.textContent = label + (isCustom ? ' -- Rules' : ' -- Kernel Table');

        var closeBtn = document.createElement('button');
        closeBtn.className = 'modal-close';
        closeBtn.setAttribute('aria-label', 'Close');
        closeBtn.textContent = '\u00d7';
        closeBtn.addEventListener('click', function () { overlay.remove(); });

        header.appendChild(titleEl);
        header.appendChild(closeBtn);

        // Body
        var body = document.createElement('div');
        body.className = 'modal-body';

        // Command line hint
        var cmdHint = document.createElement('div');
        cmdHint.className = 'addon-inspect-table-name';
        cmdHint.textContent = isCustom
            ? 'Custom rules -- manage via the DAG panel below'
            : 'pfctl -a addons -t ' + table + ' -T show';
        body.appendChild(cmdHint);

        if (entries.length === 0) {
            var emptyEl = document.createElement('p');
            emptyEl.className = 'addon-inspect-empty';
            emptyEl.textContent = isCustom
                ? 'No custom rules loaded.'
                : 'Table is empty -- no entries currently in kernel memory.';
            body.appendChild(emptyEl);
        } else if (isCustom) {
            // Custom: read-only list, no checkboxes
            var ol = document.createElement('ol');
            ol.className = 'addon-inspect-entry-list';
            entries.forEach(function (entry) {
                var li = document.createElement('li');
                li.textContent = entry;
                ol.appendChild(li);
            });
            body.appendChild(ol);
        } else {
            // Table-backed: search + checkboxes + remove action

            // Search filter
            var searchWrap = document.createElement('div');
            searchWrap.className = 'addon-inspect-search-wrap';

            var searchInput = document.createElement('input');
            searchInput.type = 'text';
            searchInput.placeholder = 'Filter entries\u2026';
            searchInput.className = 'addon-inspect-search';
            searchInput.setAttribute('autocomplete', 'off');
            searchWrap.appendChild(searchInput);

            // Select-all row
            var selectAllRow = document.createElement('div');
            selectAllRow.className = 'addon-inspect-select-all-row';

            var selectAllCb = document.createElement('input');
            selectAllCb.type = 'checkbox';
            selectAllCb.id  = 'inspect-select-all';
            selectAllCb.className = 'addon-inspect-cb';

            var selectAllLbl = document.createElement('label');
            selectAllLbl.htmlFor = 'inspect-select-all';
            selectAllLbl.className = 'addon-inspect-select-all-lbl';
            selectAllLbl.textContent = 'Select all visible';

            var selCountEl = document.createElement('span');
            selCountEl.className = 'addon-inspect-sel-count';
            selCountEl.textContent = '0 selected';

            selectAllRow.appendChild(selectAllCb);
            selectAllRow.appendChild(selectAllLbl);
            selectAllRow.appendChild(selCountEl);

            // Entry list -- max-height 10 rows, overflow scroll
            var listWrap = document.createElement('div');
            listWrap.className = 'addon-inspect-list-wrap';

            var ul = document.createElement('ul');
            ul.className = 'addon-inspect-entry-list addon-inspect-entry-list--checkable';

            var selectedEntries = {};

            function updateSelCount() {
                var n = Object.keys(selectedEntries).length;
                selCountEl.textContent = n + ' selected';
                removeBtn.disabled = (n === 0);
            }

            function renderList(filter) {
                ul.innerHTML = '';
                var shown = 0;
                entries.forEach(function (entry) {
                    if (filter && entry.toLowerCase().indexOf(filter.toLowerCase()) === -1) return;
                    shown++;
                    var li = document.createElement('li');
                    li.className = 'addon-inspect-entry-row';

                    var cb = document.createElement('input');
                    cb.type      = 'checkbox';
                    cb.className = 'addon-inspect-cb';
                    cb.checked   = !!selectedEntries[entry];
                    cb.addEventListener('change', function () {
                        if (cb.checked) selectedEntries[entry] = true;
                        else            delete selectedEntries[entry];
                        updateSelCount();
                        // Sync select-all state
                        var visibleCbs = ul.querySelectorAll('.addon-inspect-cb');
                        var allChecked = Array.from(visibleCbs).every(function (c) { return c.checked; });
                        selectAllCb.checked = allChecked;
                    });

                    var lbl = document.createElement('label');
                    lbl.className = 'addon-inspect-entry-lbl';
                    lbl.textContent = entry;
                    lbl.addEventListener('click', function () { cb.click(); });

                    li.appendChild(cb);
                    li.appendChild(lbl);
                    ul.appendChild(li);
                });

                if (shown === 0) {
                    var noMatch = document.createElement('li');
                    noMatch.className = 'addon-inspect-no-match';
                    noMatch.textContent = 'No entries match your filter.';
                    ul.appendChild(noMatch);
                }
            }

            // Select-all handler
            selectAllCb.addEventListener('change', function () {
                var visibleCbs = ul.querySelectorAll('.addon-inspect-cb');
                visibleCbs.forEach(function (cb) {
                    cb.checked = selectAllCb.checked;
                    // Find the label to get the entry value
                    var lbl = cb.nextSibling;
                    if (lbl && lbl.textContent) {
                        if (selectAllCb.checked) selectedEntries[lbl.textContent] = true;
                        else                     delete selectedEntries[lbl.textContent];
                    }
                });
                updateSelCount();
            });

            // Search handler
            searchInput.addEventListener('input', function () {
                renderList(searchInput.value);
                updateSelCount();
            });

            renderList('');
            listWrap.appendChild(ul);

            // Status bar (shown during deletion)
            var statusBar = document.createElement('div');
            statusBar.className = 'addon-inspect-status tn-hidden';

            body.appendChild(searchWrap);
            body.appendChild(selectAllRow);
            body.appendChild(listWrap);
            body.appendChild(statusBar);
        }

        // Footer
        var footer = document.createElement('div');
        footer.className = 'modal-footer';

        var closeFooterBtn = document.createElement('button');
        closeFooterBtn.className = 'pf-verdict-btn pf-verdict-btn--neutral';
        closeFooterBtn.textContent = 'Close';
        closeFooterBtn.addEventListener('click', function () { overlay.remove(); });
        footer.appendChild(closeFooterBtn);

        var removeBtn;
        if (!isCustom && entries.length > 0) {
            removeBtn = document.createElement('button');
            removeBtn.className = 'pf-verdict-btn pf-verdict-btn--danger';
            removeBtn.textContent = 'Remove Selected';
            removeBtn.disabled = true;

            removeBtn.addEventListener('click', async function () {
                var toRemove = Object.keys(selectedEntries);
                if (toRemove.length === 0) return;

                var statusBar = body.querySelector('.addon-inspect-status');

                UI.confirm({
                    title:        'Remove ' + toRemove.length + ' entr' +
                                  (toRemove.length !== 1 ? 'ies' : 'y') + ' from <' + table + '>?',
                    body:         'Selected entries will be removed from the live kernel table and from pf-addons.conf.',
                    consequences: toRemove.length <= 8
                        ? toRemove
                        : toRemove.slice(0, 8).concat(['… and ' + (toRemove.length - 8) + ' more']),
                    warning:      'pfctl -nf validates the change before applying. Takes effect immediately.',
                    confirmLabel: 'Remove Now',
                    variant:      'danger',
                    onConfirm:    async function () {
                        removeBtn.disabled = true;
                        closeFooterBtn.disabled = true;
                        if (statusBar) {
                            statusBar.className = 'addon-inspect-status addon-inspect-status--working';
                            statusBar.textContent = 'Queueing deletion\u2026';
                            statusBar.classList.remove('tn-hidden');
                        }

                        try {
                            if (!await ensureCSRF()) {
                                if (statusBar) statusBar.textContent = 'Security token unavailable';
                                closeFooterBtn.disabled = false;
                                return;
                            }

                            var r = await fetch(CFG.activeRulesApi, {
                                method: 'POST',
                                credentials: 'same-origin',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'X-Requested-With': 'XMLHttpRequest'
                                },
                                body: JSON.stringify({
                                    action:     'delete_entry',
                                    table:      table,
                                    type:       type,
                                    entries:    toRemove,
                                    csrf_token: csrfToken
                                })
                            });

                            var result = r.ok ? await r.json()
                                              : { success: false, error: 'Server error: ' + r.status };

                            if (!result.success) {
                                if (statusBar) {
                                    statusBar.className = 'addon-inspect-status addon-inspect-status--error';
                                    statusBar.textContent = 'Error: ' + (result.error || 'Unknown error');
                                }
                                closeFooterBtn.disabled = false;
                                return;
                            }

                            if (statusBar) statusBar.textContent = 'Waiting for firewall\u2026';

                            // Poll for outcome via CGI (WAF-safe)
                            var requestId = result.request_id;
                            var attempts  = 0;
                            var maxAttempts = 30;

                            var entryPoll = setInterval(async function () {
                                attempts++;
                                if (attempts > maxAttempts) {
                                    clearInterval(entryPoll);
                                    if (statusBar) {
                                        statusBar.className = 'addon-inspect-status addon-inspect-status--error';
                                        statusBar.textContent = 'Timed out -- check /var/www/tmp/ for details';
                                    }
                                    closeFooterBtn.disabled = false;
                                    return;
                                }
                                try {
                                    var pr = await fetch(CFG.activeRulesApi, {
                                        method: 'POST',
                                        credentials: 'same-origin',
                                        headers: {
                                            'Content-Type': 'application/json',
                                            'X-Requested-With': 'XMLHttpRequest'
                                        },
                                        body: JSON.stringify({
                                            action:     'get_delete_outcome',
                                            request_id: String(requestId),
                                            csrf_token: csrfToken
                                        })
                                    });
                                    if (!pr.ok) return;
                                    var outcome = await pr.json();
                                    if (outcome.not_ready) return;
                                    clearInterval(entryPoll);

                                    if (outcome.success) {
                                        if (statusBar) {
                                            statusBar.className = 'addon-inspect-status addon-inspect-status--pass';
                                            statusBar.textContent = outcome.message || 'Done \u2014 entries removed';
                                        }
                                        UI.toast(
                                            toRemove.length + ' entr' +
                                            (toRemove.length !== 1 ? 'ies' : 'y') +
                                            ' removed from <' + table + '>',
                                            'success', 4000
                                        );
                                        // Remove deleted entries from the local list
                                        toRemove.forEach(function (e) {
                                            var idx = entries.indexOf(e);
                                            if (idx !== -1) entries.splice(idx, 1);
                                            delete selectedEntries[e];
                                        });
                                        // Re-render the list
                                        renderList && renderList(searchInput ? searchInput.value : '');
                                        updateSelCount && updateSelCount();
                                        // Reload rules viewer
                                        if (RulesLoader && RulesLoader.load) {
                                            setTimeout(function () { RulesLoader.load(); }, 1000);
                                        }
                                        // Reload active addons to update card count
                                        setTimeout(function () { loadActiveAddons && loadActiveAddons(); }, 1500);
                                    } else {
                                        if (statusBar) {
                                            statusBar.className = 'addon-inspect-status addon-inspect-status--error';
                                            statusBar.textContent = 'Failed: ' + (outcome.message || 'Unknown error');
                                        }
                                    }
                                    closeFooterBtn.disabled = false;
                                } catch (e) { /* not ready yet */ }
                            }, 1000);

                        } catch (e) {
                            if (statusBar) {
                                statusBar.className = 'addon-inspect-status addon-inspect-status--error';
                                statusBar.textContent = 'Network error: ' + e.message;
                            }
                            closeFooterBtn.disabled = false;
                        }
                    }
                });
            });
            footer.appendChild(removeBtn);
        }

        content.appendChild(header);
        content.appendChild(body);
        content.appendChild(footer);
        overlay.appendChild(content);
        document.body.appendChild(overlay);

        // Focus search if present
        if (!isCustom && entries.length > 0) {
            setTimeout(function () {
                var s = content.querySelector('.addon-inspect-search');
                if (s) s.focus();
            }, 50);
        }
    }

    // ── Confirm delete modal ──
    function confirmAddonDelete(block, card, customRules) {
        var label = block.label || block.type;
        var count = block.entry_count || 0;

        var bodyText, consequences;

        if (block.type === 'custom' && customRules) {
            var ruleCount = customRules.length;
            bodyText = 'The following rule' + (ruleCount !== 1 ? 's' : '') +
                ' will be removed from the firewall immediately.';
            consequences = customRules;
        } else {
            bodyText = 'This will remove the ' + label + ' block from the live firewall immediately.';
            consequences = [
                'Table <' + (block.table || '') + '> flushed from kernel memory',
                count + ' entr' + (count !== 1 ? 'ies' : 'y') + ' released',
                'Removed from pf-addons.conf',
                'Source queue file updated',
            ];
        }

        UI.confirm({
            title:        'Remove ' + label + '?',
            body:         bodyText,
            consequences: consequences,
            warning:      'This takes effect immediately on the live firewall.',
            confirmLabel: 'Remove Now',
            variant:      'danger',
            onConfirm:    function () {
                executeAddonDelete(block, card, customRules);
            }
        });
    }

    // ── Execute delete -- POST to pf_active_rules.pl ──
    var executeAddonDelete = async function (block, card, customRules) {
        card.classList.add('addon-card--pending');

        try {
            if (!await ensureCSRF()) {
                card.classList.remove('addon-card--pending');
                UI.toast('Security token unavailable - please refresh', 'error');
                return;
            }

            var payload = {
                action:     'delete',
                type:       block.type,
                csrf_token: csrfToken
            };

            if (block.type === 'geoip')   payload.country    = block.country;
            if (block.type === 'feed')     payload.feed_index = block.feed_index;
            if (block.type === 'custom' && customRules && customRules.length > 0) {
                // Send one rule at a time -- server processes one per request
                payload.rule = customRules[0];
            }

            var r = await fetch(CFG.activeRulesApi, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(payload)
            });

            var result = r.ok ? await r.json() : { success: false, error: 'Server error: ' + r.status };

            if (!result.success) {
                card.classList.remove('addon-card--pending');
                UI.toast('Failed to queue deletion: ' + (result.error || 'Unknown error'), 'error');
                return;
            }

            // Request queued -- poll for outcome
            var requestId = result.request_id;
            pollAddonOutcome(requestId, block, card, customRules);

        } catch (e) {
            card.classList.remove('addon-card--pending');
            UI.toast('Network error during deletion', 'error');
        }
    };

    // ── Poll for delete outcome ──
    function pollAddonOutcome(requestId, block, card, customRules) {
        var attempts = 0;
        var maxAttempts = 30;   // 30s -- pf_monitor.sh polls every 2s

        if (addonOutcomePoll) clearInterval(addonOutcomePoll);

        addonOutcomePoll = setInterval(async function () {
            attempts++;
            if (attempts > maxAttempts) {
                clearInterval(addonOutcomePoll);
                card.classList.remove('addon-card--pending');
                UI.toast('Deletion timed out -- check /var/www/tmp/ for details', 'error', 6000);
                return;
            }

            try {
                var pr = await fetch(CFG.activeRulesApi, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({
                        action:     'get_delete_outcome',
                        request_id: String(requestId),
                        csrf_token: csrfToken
                    })
                });
                if (!pr.ok) return; // not ready yet
                var outcome = await pr.json();
                if (outcome.not_ready) return;
                clearInterval(addonOutcomePoll);

                if (outcome.success) {
                    // For custom rules with multiple selected, queue next rule
                    if (block.type === 'custom' && customRules && customRules.length > 1) {
                        var remaining = customRules.slice(1);
                        card.classList.remove('addon-card--pending');
                        UI.toast('Rule removed -- processing next…', 'info', 1500);
                        setTimeout(function () {
                            executeAddonDelete(block, card, remaining);
                        }, 500);
                        return;
                    }

                    // Animate card out
                    card.classList.remove('addon-card--pending');
                    card.classList.add('addon-card--removing');
                    requestAnimationFrame(function () {
                        card.classList.add('addon-card--gone');
                    });

                    setTimeout(function () {
                        card.remove();
                        // If grid is now empty, show status banner
                        var grid = document.getElementById('addon-rules-grid');
                        if (grid && grid.children.length === 0) {
                            var status = document.getElementById('addon-anchor-status');
                            var statusText = document.getElementById('addon-anchor-status-text');
                            if (statusText) statusText.textContent = 'All addon rules have been removed.';
                            if (status) status.classList.remove('tn-hidden');
                        }
                    }, 320);

                    UI.toast((block.label || 'Block') + ' removed from firewall', 'success', 4000);

                    // Reload rules viewer if open
                    if (RulesLoader.load) setTimeout(function () { RulesLoader.load(); }, 1000);

                } else {
                    card.classList.remove('addon-card--pending');
                    UI.toast('Deletion failed: ' + (outcome.message || 'Unknown error'), 'error', 6000);
                }

            } catch (e) {
                // Outcome file not ready yet -- keep polling
            }
        }, 1000);
    }

    // ================================================================
    // SECTION: PARSED CUSTOM RULES (DAG-based deletion)
    //
    // Lifecycle:
    //   init() calls initParsedRules() on every PF tab activation.
    //   All state (parsedRulesData, selectedRuleIds, cascadeRuleIds,
    //   deletionTestPoll, deletionOutcomePoll) is reset at the top
    //   of initParsedRules() so re-activation always starts clean.
    //   All DOM listeners are wired to elements in the current view;
    //   they die with the DOM when view.js does its nuclear cleanup.
    //   No document-level or window-level listeners added here.
    // ================================================================

    function initParsedRules() {
        // Reset all module-level state for this section
        parsedRulesData  = null;
        selectedRuleIds  = {};
        cascadeRuleIds   = {};
        if (deletionTestPoll)    { clearInterval(deletionTestPoll);    deletionTestPoll    = null; }
        if (deletionOutcomePoll) { clearInterval(deletionOutcomePoll); deletionOutcomePoll = null; }

        // Wire refresh button
        var refreshBtn = document.getElementById('parsed-rules-refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', function () {
                refreshBtn.disabled = true;
                refreshBtn.style.opacity = '0.5';
                loadParsedRules().then(function () {
                    refreshBtn.disabled = false;
                    refreshBtn.style.opacity = '';
                });
            });
        }

        // Wire Preview Removal button (lives in current view DOM)
        var previewBtn = document.getElementById('parsed-rules-preview-btn');
        if (previewBtn) {
            previewBtn.addEventListener('click', function () {
                var ids = Object.keys(selectedRuleIds).concat(Object.keys(cascadeRuleIds));
                if (ids.length === 0) {
                    UI.toast('Select at least one rule first', 'warning');
                    return;
                }
                showPreviewModal(ids);
            });
        }

        // Wire diff preview modal buttons (all in current view DOM)
        var closeBtn  = document.getElementById('deletion-preview-close');
        var cancelBtn = document.getElementById('deletion-preview-cancel');
        var modal     = document.getElementById('deletion-preview-modal');

        if (closeBtn)  closeBtn.addEventListener('click',  closePreviewModal);
        if (cancelBtn) cancelBtn.addEventListener('click', closePreviewModal);
        if (modal) {
            modal.addEventListener('click', function (e) {
                if (e.target === modal) {
                    closePreviewModal();
                }
            });
        }

        loadParsedRules();
    }

    // ── Fetch parsed-rules.json and render ──
    var loadParsedRules = async function () {
        var section  = document.getElementById('parsed-rules-section');
        var loading  = document.getElementById('parsed-rules-loading');
        var errorEl  = document.getElementById('parsed-rules-error');
        var list     = document.getElementById('parsed-rules-list');

        if (!section || !list) return;

        if (loading) loading.classList.remove('tn-hidden');
        if (errorEl) errorEl.classList.add('tn-hidden');
        list.innerHTML = '';

        try {
            if (!await ensureCSRF()) {
                if (loading) loading.classList.add('tn-hidden');
                return;
            }
            var r = await fetch(CFG.parsedRulesJson, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                body: JSON.stringify({ action: 'parse', csrf_token: csrfToken })
            });
            if (!r.ok) throw new Error('HTTP ' + r.status);

            var data = await r.json();
            if (loading) loading.classList.add('tn-hidden');

            // Section only shown when there are custom rules
            var sections = data.sections || [];
            var hasRules = sections.some(function (s) {
                return s.rules && s.rules.length > 0;
            });

            if (!hasRules) {
                section.classList.add('tn-hidden');
                return;
            }

            parsedRulesData = data;
            renderParsedRules(data);
            updateSelectionCount();
            section.classList.remove('tn-hidden');

        } catch (e) {
            if (loading) loading.classList.add('tn-hidden');
            // 404 = no custom rules yet -- hide section silently
            if (e.message && e.message.indexOf('404') !== -1) {
                if (section) section.classList.add('tn-hidden');
                return;
            }
            var errText = document.getElementById('parsed-rules-error-text');
            if (errText) errText.textContent = 'Failed to load parsed rules: ' + e.message;
            if (errorEl) errorEl.classList.remove('tn-hidden');
            console.error('[PF] loadParsedRules error:', e);
        }
    };

    // ── Render section list from parsed-rules.json ──
    function renderParsedRules(data) {
        var list = document.getElementById('parsed-rules-list');
        if (!list) return;
        list.innerHTML = '';

        var sections = data.sections || [];

        sections.forEach(function (sec, secIdx) {
            var rules    = sec.rules || [];
            if (rules.length === 0) return;

            var secLabel = sec.label || 'CUSTOM PF RULES';

            if (secIdx > 0) {
                var hr = document.createElement('hr');
                hr.className = 'parsed-rules-section-divider';
                list.appendChild(hr);
            }

            var secEl = document.createElement('section');
            secEl.className       = 'parsed-rules-section-block';
            secEl.dataset.section = secLabel;

            // Section header with select-all toggle
            var secHeader = document.createElement('div');
            secHeader.className = 'parsed-rules-section-header';

            var secToggle = document.createElement('input');
            secToggle.type      = 'checkbox';
            secToggle.className = 'parsed-section-toggle';
            secToggle.id        = 'sec-toggle-' + secIdx;
            secToggle.setAttribute('aria-label', 'Select all in ' + secLabel);

            var secLabelEl = document.createElement('label');
            secLabelEl.className   = 'parsed-rules-section-name';
            secLabelEl.htmlFor     = secToggle.id;
            secLabelEl.textContent = secLabel;

            var secCount = document.createElement('span');
            secCount.className   = 'parsed-rules-section-count';
            secCount.textContent = rules.length + ' rule' + (rules.length !== 1 ? 's' : '');

            secHeader.appendChild(secToggle);
            secHeader.appendChild(secLabelEl);
            secHeader.appendChild(secCount);
            secEl.appendChild(secHeader);

            // Section select-all -- closure captures this section's rules
            (function (sectionRules) {
                secToggle.addEventListener('change', function () {
                    var checked = secToggle.checked;
                    sectionRules.forEach(function (r) {
                        if (checked) {
                            selectedRuleIds[r.id] = true;
                        } else {
                            delete selectedRuleIds[r.id];
                            delete cascadeRuleIds[r.id];
                        }
                        var cb = document.querySelector(
                            '.parsed-rule-checkbox[data-rule-id="' + r.id + '"]');
                        if (cb) cb.checked = checked;
                    });
                    fetchCascade();
                    updateSelectionCount();
                    updateCascadeWarning();
                });
            })(rules);

            // Individual rule rows
            rules.forEach(function (rule) {
                if (!rule.raw) return;

                var ruleEl = document.createElement('div');
                ruleEl.className    = 'parsed-rule-item';
                ruleEl.dataset.id   = rule.id;
                ruleEl.dataset.type = rule.type || 'filter';

                var cb = document.createElement('input');
                cb.type           = 'checkbox';
                cb.className      = 'parsed-rule-checkbox';
                cb.id             = 'rule-cb-' + rule.id;
                cb.dataset.ruleId = rule.id;

                cb.addEventListener('change', function () {
                    if (cb.checked) {
                        selectedRuleIds[rule.id] = true;
                    } else {
                        delete selectedRuleIds[rule.id];
                        delete cascadeRuleIds[rule.id];
                        var el = document.querySelector(
                            '.parsed-rule-item[data-id="' + rule.id + '"]');
                        if (el) el.classList.remove('parsed-rule-item--cascade');
                    }
                    fetchCascade();
                    updateSelectionCount();
                    updateCascadeWarning();
                });

                ruleEl.appendChild(cb);

                // ── TABLE rules: compact summary + Inspect button ──
                // A table definition can have hundreds of IPs. Rendering raw
                // is unreadable. Instead show name + entry count + Inspect button.
                if (rule.type === 'table') {
                    var tableNameMatch = rule.raw.match(/^table\s+<([\w_]+)>/);
                    var tableName  = tableNameMatch ? tableNameMatch[1] : 'unknown';

                    // Parse entries from raw: everything between { and }
                    var entriesRaw = rule.raw.match(/\{([^}]*)\}/);
                    var entries    = entriesRaw
                        ? entriesRaw[1].split(/[\s,]+/).map(function (e) { return e.trim(); })
                                       .filter(function (e) { return e.length > 0; })
                        : [];

                    var lbl = document.createElement('label');
                    lbl.className = 'parsed-rule-label parsed-rule-label--table';
                    lbl.htmlFor   = cb.id;

                    var nameSpan = document.createElement('code');
                    nameSpan.className   = 'parsed-rule-line';
                    nameSpan.textContent = 'table <' + tableName + '> persist';
                    lbl.appendChild(nameSpan);

                    if (entries.length > 0) {
                        var countBadge = document.createElement('span');
                        countBadge.className   = 'parsed-rule-dep-badge';
                        countBadge.textContent = entries.length + ' entr' +
                            (entries.length !== 1 ? 'ies' : 'y');
                        lbl.appendChild(countBadge);
                    }

                    ruleEl.appendChild(lbl);

                    // Inspect button -- opens the entry manager modal
                    if (entries.length > 0) {
                        var inspectBtn = document.createElement('button');
                        inspectBtn.type      = 'button';
                        inspectBtn.className = 'parsed-rule-inspect-btn';
                        inspectBtn.textContent = 'Manage IPs';
                        inspectBtn.addEventListener('click', function (e) {
                            e.stopPropagation();
                            // Build a synthetic block object for showAddonInspectModal
                            showAddonInspectModal({
                                label         : 'table <' + tableName + '>',
                                type          : 'ip_block',
                                table         : tableName,
                                table_entries : entries
                            });
                        });
                        ruleEl.appendChild(inspectBtn);
                    }

                } else {
                    // ── Non-table rules: full raw text ──
                    var lbl = document.createElement('label');
                    lbl.className = 'parsed-rule-label';
                    lbl.htmlFor   = cb.id;

                    var code = document.createElement('code');
                    code.className   = 'parsed-rule-line';
                    code.textContent = rule.raw;
                    lbl.appendChild(code);

                    if (rule.deps && rule.deps.length > 0) {
                        var depBadge = document.createElement('span');
                        depBadge.className   = 'parsed-rule-dep-badge';
                        depBadge.title       = 'Depends on: ' +
                            rule.deps.map(function (d) {
                                return typeof d === 'object' ? d.token : d;
                            }).join(', ');
                        depBadge.textContent = 'has deps';
                        lbl.appendChild(depBadge);
                    }

                    ruleEl.appendChild(lbl);
                }

                secEl.appendChild(ruleEl);
            });

            list.appendChild(secEl);
        });
    }

    // ── Fetch cascade from pf_active_rules.pl action:check ──
    var fetchCascade = async function () {
        var allSelected = Object.keys(selectedRuleIds);

        // Clear previous cascade highlights before re-fetching
        cascadeRuleIds = {};
        document.querySelectorAll('.parsed-rule-item--cascade').forEach(function (el) {
            el.classList.remove('parsed-rule-item--cascade');
            var cb = el.querySelector('.parsed-rule-checkbox');
            if (cb) cb.checked = false;
        });

        if (allSelected.length === 0) {
            updateSelectionCount();
            updateCascadeWarning();
            return;
        }

        try {
            if (!await ensureCSRF()) return;

            var r = await fetch(CFG.activeRulesApi, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    action:     'check',
                    ids:        allSelected,
                    csrf_token: csrfToken
                })
            });

            if (!r.ok) return;
            var result = await r.json();

            if (result.success && result.affected) {
                Object.keys(result.affected).forEach(function (affectedId) {
                    if (!selectedRuleIds[affectedId]) {
                        cascadeRuleIds[affectedId] = true;
                        var el = document.querySelector(
                            '.parsed-rule-item[data-id="' + affectedId + '"]');
                        if (el) {
                            el.classList.add('parsed-rule-item--cascade');
                            var cb = el.querySelector('.parsed-rule-checkbox');
                            if (cb) cb.checked = true;
                        }
                    }
                });
            }
        } catch (e) {
            console.error('[PF] fetchCascade error:', e);
        }

        updateSelectionCount();
        updateCascadeWarning();
    };

    function updateSelectionCount() {
        var total   = Object.keys(selectedRuleIds).length +
                      Object.keys(cascadeRuleIds).length;
        var countEl = document.getElementById('parsed-rules-sel-count');
        var btn     = document.getElementById('parsed-rules-preview-btn');
        if (countEl) {
            countEl.textContent = total > 0
                ? total + ' rule' + (total !== 1 ? 's' : '') + ' selected'
                : '0 selected';
        }
        if (btn) btn.disabled = (total === 0);

        // Inject/remove per-section inline preview buttons so the operator
        // can trigger preview without scrolling to the top of the panel.
        // Each section header gets a button when it has ≥1 selection;
        // the button is removed when its section drops to zero.
        var allSelected = Object.assign({}, selectedRuleIds, cascadeRuleIds);
        document.querySelectorAll('.parsed-rules-section-block').forEach(function (secEl) {
            var header    = secEl.querySelector('.parsed-rules-section-header');
            if (!header) return;

            // Gather selected IDs that belong to this section
            var secIds = [];
            secEl.querySelectorAll('.parsed-rule-checkbox').forEach(function (cb) {
                var id = cb.dataset.ruleId;
                if (id && allSelected[id]) secIds.push(id);
            });

            var existing = header.querySelector('.parsed-section-inline-preview');

            if (secIds.length > 0) {
                if (!existing) {
                    var inlineBtn = document.createElement('button');
                    inlineBtn.type      = 'button';
                    inlineBtn.className = 'parsed-section-inline-preview';
                    inlineBtn.textContent = 'Preview Removal';
                    inlineBtn.addEventListener('click', function () {
                        showPreviewModal(secIds);
                    });
                    header.appendChild(inlineBtn);
                } else {
                    // Update the stale closure with fresh secIds by replacing
                    var fresh = existing.cloneNode(true);
                    fresh.addEventListener('click', function () {
                        showPreviewModal(secIds);
                    });
                    existing.parentNode.replaceChild(fresh, existing);
                }
            } else {
                if (existing) existing.remove();
            }
        });
    }

    function updateCascadeWarning() {
        var banner = document.getElementById('cascade-warning');
        var textEl = document.getElementById('cascade-warning-text');
        var count  = Object.keys(cascadeRuleIds).length;
        if (!banner) return;
        if (count > 0) {
            if (textEl) textEl.textContent =
                count + ' dependent rule' + (count !== 1 ? 's were' : ' was') +
                ' automatically selected because ' +
                (count !== 1 ? 'they depend' : 'it depends') +
                ' on the rules you selected.';
            banner.classList.remove('tn-hidden');
        } else {
            banner.classList.add('tn-hidden');
        }
    }

    // ── Deletion preview status helper ──
    // Sets the dp-status div class and swaps the icon SVG to match native modal style
    function setDpStatus(state, text) {
        var el   = document.getElementById('deletion-preview-status');
        var icon = document.getElementById('deletion-preview-status-icon');
        var txt  = document.getElementById('deletion-preview-status-text');
        if (!el) return;

        // null state = update text only, keep current state class
        if (state === null) {
            if (txt && text !== null) txt.textContent = text || '';
            return;
        }

        el.className = 'dp-status dp-status--' + state;
        if (txt) txt.textContent = text || '';

        if (!icon) return;
        if (state === 'working') {
            icon.innerHTML = '<svg class="dp-spinner" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" stroke-dasharray="40 20" stroke-linecap="round"/></svg>';
        } else if (state === 'pass') {
            icon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:1.25rem;height:1.25rem"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>';
        } else if (state === 'fail') {
            icon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:1.25rem;height:1.25rem"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>';
        }
    }
    var showPreviewModal = async function (ids) {
        var modal      = document.getElementById('deletion-preview-modal');
        var statusEl   = document.getElementById('deletion-preview-status');
        var statusText = document.getElementById('deletion-preview-status-text');
        var diffEl     = document.getElementById('deletion-preview-diff');
        var confirmBtn = document.getElementById('deletion-preview-confirm');
        var delCount   = document.getElementById('deletion-preview-del-count');
        var keepCount  = document.getElementById('deletion-preview-keep-count');
        if (!modal) return;

        // Reset modal state -- replace confirm button to shed any prior listener
        setDpStatus('working', 'Sending to backend…');
        if (diffEl)     diffEl.innerHTML = '';
        if (confirmBtn) {
            confirmBtn.disabled = true;
            var fresh = confirmBtn.cloneNode(true);
            confirmBtn.parentNode.replaceChild(fresh, confirmBtn);
            confirmBtn = fresh;
        }
        if (deletionTestPoll)    { clearInterval(deletionTestPoll);    deletionTestPoll    = null; }
        if (deletionOutcomePoll) { clearInterval(deletionOutcomePoll); deletionOutcomePoll = null; }

        modal.classList.remove('tn-hidden');

        try {
            if (!await ensureCSRF()) {
                closePreviewModal();
                UI.toast('Security token unavailable', 'error');
                return;
            }

            setDpStatus('working', 'Building proposed conf…');

            var r = await fetch(CFG.writeRulesApi, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ ids: ids, csrf_token: csrfToken })
            });

            var result = r.ok ? await r.json()
                              : { success: false, error: 'Server error: ' + r.status };

            if (!result.success) {
                setDpStatus('fail', 'Error: ' + (result.error || 'Unknown error'));
                return;
            }

            if (delCount)  delCount.textContent =
                (result.deleted_count || 0) + ' rule' +
                (result.deleted_count !== 1 ? 's' : '') + ' removed';
            if (keepCount) keepCount.textContent =
                (result.kept_rules || 0) + ' rule' +
                (result.kept_rules !== 1 ? 's' : '') + ' kept';

            renderDiff(result.proposed_conf, ids);

            setDpStatus('working', 'Running syntax check…');
            pollDeletionTest(confirmBtn, statusEl, statusText, ids);

        } catch (e) {
            setDpStatus('fail', 'Network error: ' + e.message);
            console.error('[PF] showPreviewModal error:', e);
        }
    };

    // ── Render diff ──
    function renderDiff(proposedConf, deletedIds) {
        var diffEl = document.getElementById('deletion-preview-diff');
        if (!diffEl || !parsedRulesData) return;

        var allDeleted   = Object.assign({}, selectedRuleIds, cascadeRuleIds);
        var deletedLines = [];
        (parsedRulesData.sections || []).forEach(function (sec) {
            (sec.rules || []).forEach(function (rule) {
                if (allDeleted[rule.id] && rule.raw) {
                    deletedLines.push(rule.raw);
                }
            });
        });

        var frag  = document.createDocumentFragment();
        (proposedConf || '').split('\n').forEach(function (line) {
            var el   = document.createElement('div');
            var t    = line.trim();
            var code = document.createElement('code');
            code.textContent = line;
            if      (!t)                  el.className = 'diff-line diff-line--blank';
            else if (t.charAt(0) === '#') el.className = 'diff-line diff-line--comment';
            else                          el.className = 'diff-line diff-line--keep';
            el.appendChild(code);
            frag.appendChild(el);
        });

        if (deletedLines.length > 0) {
            var sep = document.createElement('div');
            sep.className   = 'diff-separator';
            sep.textContent = '\u2500\u2500 removed \u2500\u2500';
            frag.appendChild(sep);
            deletedLines.forEach(function (line) {
                var el   = document.createElement('div');
                el.className = 'diff-line diff-line--del';
                var code = document.createElement('code');
                code.textContent = '- ' + line;
                el.appendChild(code);
                frag.appendChild(el);
            });
        }

        diffEl.innerHTML = '';
        diffEl.appendChild(frag);
    }

    // ── Poll deletion-test-result.json ──
    function pollDeletionTest(confirmBtn, statusEl, statusText, ids) {
        var attempts    = 0;
        var maxAttempts = 60;
        if (deletionTestPoll) clearInterval(deletionTestPoll);

        deletionTestPoll = setInterval(async function () {
            attempts++;
            if (attempts > maxAttempts) {
                clearInterval(deletionTestPoll);
                deletionTestPoll = null;
                setDpStatus('fail', 'Syntax check timed out');
                return;
            }
            try {
                var r = await fetch(CFG.deletionTestResult, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({ action: 'get_test_result', csrf_token: csrfToken })
                });
                if (!r.ok) return;
                var result = await r.json();
                if (result.not_ready) return;  // file not written yet -- keep polling
                clearInterval(deletionTestPoll);
                deletionTestPoll = null;

                if (result.success) {
                    setDpStatus('pass', 'Syntax OK \u2014 review and confirm');
                    if (confirmBtn) {
                        confirmBtn.disabled = false;
                        confirmBtn.addEventListener('click', function () {
                            applyDeletion(ids);
                        });
                    }
                } else {
                    setDpStatus('fail', 'Syntax error: ' + (result.error || 'pfctl rejected the proposed conf'));
                }
            } catch (e) { /* not ready yet */ }
        }, 1000);
    }

    // ── Apply deletion ──
    var applyDeletion = async function (ids) {
        var confirmBtn = document.getElementById('deletion-preview-confirm');
        var statusEl   = document.getElementById('deletion-preview-status');
        var statusText = document.getElementById('deletion-preview-status-text');

        if (confirmBtn) confirmBtn.disabled = true;
        setDpStatus('working', 'Applying to live firewall…');

        try {
            if (!await ensureCSRF()) {
                setDpStatus('fail', 'Security token unavailable \u2014 please refresh');
                return;
            }
            var r = await fetch(CFG.applyDeletionApi, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ confirm: true, csrf_token: csrfToken })
            });

            var result = r.ok ? await r.json()
                              : { success: false, error: 'Server error: ' + r.status };

            if (!result.success) {
                setDpStatus('fail', 'Error: ' + (result.error || 'Unknown error'));
                return;
            }

            setDpStatus('working', 'Waiting for firewall…');
            pollDeletionOutcome(statusEl, statusText);

        } catch (e) {
            setDpStatus('fail', 'Network error: ' + e.message);
        }
    };

    // ── Poll apply-deletion-outcome.json ──
    function pollDeletionOutcome(statusEl, statusText) {
        var attempts    = 0;
        var maxAttempts = 60;
        if (deletionOutcomePoll) clearInterval(deletionOutcomePoll);

        deletionOutcomePoll = setInterval(async function () {
            attempts++;
            if (attempts > maxAttempts) {
                clearInterval(deletionOutcomePoll);
                deletionOutcomePoll = null;
                setDpStatus('fail', 'Timed out waiting for firewall update');
                return;
            }
            try {
                var r = await fetch(CFG.deletionOutcome, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({ action: 'get_outcome', csrf_token: csrfToken })
                });
                if (!r.ok) return;
                var outcome = await r.json();
                if (outcome.not_ready) return;  // file not written yet -- keep polling
                clearInterval(deletionOutcomePoll);
                deletionOutcomePoll = null;

                if (outcome.success) {
                    setDpStatus('pass', 'Done \u2014 firewall updated');
                    UI.toast('Custom rules removed from firewall', 'success', 5000);

                    // Check staged rules for stale references to deleted objects
                    checkStagedRulesForStaleRefs();

                    // Reset selection state
                    selectedRuleIds = {};
                    cascadeRuleIds  = {};
                    parsedRulesData = null;
                    updateSelectionCount();
                    updateCascadeWarning();

                    // Wait for pf_anchor_sync.sh to finish writing parsed-rules.json
                    // before reloading -- sync takes ~2s, 4s gives comfortable margin
                    setTimeout(function () {
                        closePreviewModal();
                        loadParsedRules();
                        if (RulesLoader && RulesLoader.load) RulesLoader.load();
                    }, 4000);

                } else {
                    setDpStatus('fail', 'Firewall error: ' + (outcome.error || 'Unknown error'));
                }
            } catch (e) { /* outcome not ready yet */ }
        }, 1000);
    }

    // ── Close preview modal ──
    function closePreviewModal() {
        var modal = document.getElementById('deletion-preview-modal');
        if (modal) modal.classList.add('tn-hidden');
        if (deletionTestPoll)    { clearInterval(deletionTestPoll);    deletionTestPoll    = null; }
        if (deletionOutcomePoll) { clearInterval(deletionOutcomePoll); deletionOutcomePoll = null; }
    }

    // ================================================================
    // SECTION: STALE REFERENCE DETECTION
    //
    // Called after a successful DAG deletion.
    // Scans stagedRules for any rule whose raw text references a table
    // or macro that was just removed from the anchor. Warns the operator
    // so they can remove or update those staged rules before applying.
    // ================================================================
    function checkStagedRulesForStaleRefs() {
        if (!stagedRules || stagedRules.length === 0) return;
        if (!selectedRuleIds && !cascadeRuleIds) return;

        // Collect the names of objects that were just deleted
        var deletedNames = {};
        var allDeleted   = Object.assign({}, selectedRuleIds, cascadeRuleIds);

        if (parsedRulesData) {
            (parsedRulesData.sections || []).forEach(function (sec) {
                (sec.rules || []).forEach(function (rule) {
                    if (allDeleted[rule.id] && rule.provides) {
                        deletedNames[rule.provides] = true;
                    }
                });
            });
        }

        if (Object.keys(deletedNames).length === 0) return;

        // Check each staged rule for references to deleted names
        var staleRules = [];
        stagedRules.forEach(function (r, idx) {
            var syntax = r.syntax || '';
            Object.keys(deletedNames).forEach(function (name) {
                // Match <tablename> or $macroname patterns
                if (syntax.indexOf('<' + name + '>') !== -1 ||
                    syntax.indexOf('$' + name) !== -1) {
                    staleRules.push({ idx: idx, syntax: syntax, ref: name });
                }
            });
        });

        if (staleRules.length === 0) return;

        var names = staleRules.map(function (s) { return '"' + s.ref + '"'; });
        var unique = names.filter(function (v, i, a) { return a.indexOf(v) === i; });

        UI.toast(
            staleRules.length + ' staged rule' + (staleRules.length !== 1 ? 's reference' : ' references') +
            ' deleted object' + (unique.length !== 1 ? 's' : '') + ': ' + unique.join(', ') +
            '. Review your staging list.',
            'warning',
            8000
        );

        // Mark stale rules visually in the staging list
        staleRules.forEach(function (s) {
            var items = document.querySelectorAll('#rules-list .rule-item');
            if (items[s.idx]) {
                items[s.idx].classList.add('rule-item--stale');
            }
        });
    }

    // ================================================================
    // SECTION: RULE BUILDER AUTOCOMPLETE
    //
    // Populates <datalist> elements attached to the interface,
    // from_addr, to_addr, from_port, and to_port inputs.
    //
    // Data sources:
    //   1. mirror/pf.conf -- loaded via RulesLoader (CFG.rulesPath)
    //      Parsed client-side for macro defs and table names.
    //   2. parsed-rules.json -- objects map from the addons anchor.
    //      Provides user-defined tables already in the live anchor.
    //
    // Called from init() after RulesLoader.init() so the rules text
    // is already in the DOM when we try to parse it.
    // All DOM work is scoped to elements in the current view.
    // ================================================================
    function initRuleBuilderAutocomplete() {
        var form = document.getElementById('rule-builder-form');
        if (!form) return;

        // ── Build namespace from both sources ──
        var macros     = {};   // name -> value string e.g. ext_if -> "%%EXT_IF%%"
        var baseTables = {};   // name -> true  (tables from pf.conf)
        var interfaces = {};   // bare names e.g. %%EXT_IF%%, %%INT_IF%%, lo, egress
        var addonTables= {};   // user tables from parsed-rules.json objects

        // Source 1: parse the default rules pre element which holds pf.conf content
        var pre = document.getElementById('default-pf-rules');
        if (pre && pre.textContent) {
            parsePfConfNamespace(pre.textContent, macros, baseTables, interfaces);
        }

        // Source 2: parsed-rules.json objects (already in parsedRulesData if loaded)
        if (parsedRulesData && parsedRulesData.objects) {
            Object.keys(parsedRulesData.objects).forEach(function (name) {
                addonTables[name] = true;
            });
        }

        // ── Inject datalists into the DOM ──
        injectDatalist('rb-dl-interface', form);
        injectDatalist('rb-dl-addr',      form);
        injectDatalist('rb-dl-port',      form);

        // Wire inputs to datalists
        wireDatalist(form, '[name="interface"]', 'rb-dl-interface');
        wireDatalist(form, '[name="from_addr"]', 'rb-dl-addr');
        wireDatalist(form, '[name="to_addr"]',   'rb-dl-addr');
        wireDatalist(form, '[name="from_port"]', 'rb-dl-port');
        wireDatalist(form, '[name="to_port"]',   'rb-dl-port');
        wireDatalist(form, '[name="route_gateway"]', 'rb-dl-addr');
        wireDatalist(form, '[name="nat_addr"]',  'rb-dl-addr');

        // ── Populate interface datalist ──
        // Bare interface names from macro values + known static names
        var ifaceList = document.getElementById('rb-dl-interface');
        if (ifaceList) {
            var ifaceNames = Object.keys(interfaces);
            // Always include egress and lo as they appear in pf.conf
	    ['egress', 'ingress', 'lo'].forEach(function (n) {
                if (ifaceNames.indexOf(n) === -1) ifaceNames.push(n);
            });
            // Add macro-name forms too: $ext_if, $int_if etc
            Object.keys(macros).forEach(function (mname) {
                var mval = macros[mname];
                // Only interface-looking macros (quoted single word)
                if (/^"[a-z][a-z0-9]+\d*"$/.test(mval)) {
                    var bare = mval.replace(/"/g, '');
                    if (ifaceNames.indexOf(bare) === -1) ifaceNames.push(bare);
                    var dollarForm = '$' + mname;
                    if (ifaceNames.indexOf(dollarForm) === -1) ifaceNames.push(dollarForm);
                }
            });
            ifaceNames.sort().forEach(function (n) {
                addOption(ifaceList, n);
            });
        }

        // ── Populate address datalist ──
        var addrList = document.getElementById('rb-dl-addr');
        if (addrList) {
            var addrSuggestions = ['any'];

            // Macro refs: $ext_if, $int_if, $int_net etc
            Object.keys(macros).forEach(function (mname) {
                addrSuggestions.push('$' + mname);
                // If macro looks like a CIDR or IP, add the raw value too
                var mval = macros[mname].replace(/"/g, '');
                if (/^[\d.:\/]+$/.test(mval) || /^[a-f0-9:\/]+$/i.test(mval)) {
                    if (addrSuggestions.indexOf(mval) === -1) {
                        addrSuggestions.push(mval);
                    }
                }
            });

            // Base conf table refs: <lan_nets>, <blocklist> etc
            Object.keys(baseTables).forEach(function (tname) {
                addrSuggestions.push('<' + tname + '>');
            });

            // User-defined addon table refs: <user_block_ips>, <geoip_vn> etc
            Object.keys(addonTables).forEach(function (tname) {
                var ref = '<' + tname + '>';
                if (addrSuggestions.indexOf(ref) === -1) {
                    addrSuggestions.push(ref);
                }
            });

            addrSuggestions.sort().forEach(function (s) {
                addOption(addrList, s);
            });
        }

        // ── Populate port datalist ──
        var portList = document.getElementById('rb-dl-port');
        if (portList) {
            var portSuggestions = [];

            // Port macro refs
            Object.keys(macros).forEach(function (mname) {
                var mval = macros[mname];
                // Port-looking macros: numeric or quoted port list
                if (/^\d+$/.test(mval) || /^"[\s\d,{}]+"/.test(mval)) {
                    portSuggestions.push('$' + mname);
                }
            });

            // Common named ports
            ['www', 'https', 'ssh', 'smtp', 'dns', 'ftp',
             'http', 'pop3', 'pop3s', 'imaps', 'submission',
             '80', '443', '22', '53', '25', '465', '587'].forEach(function (p) {
                if (portSuggestions.indexOf(p) === -1) portSuggestions.push(p);
            });

            portSuggestions.sort().forEach(function (p) {
                addOption(portList, p);
            });
        }

        // ── Live autocomplete refresh when parsedRulesData is updated ──
        // Rather than re-wrapping loadParsedRules (which would double-wrap on
        // each tab activation), we hook into the existing parsedRulesData refresh
        // by observing the addr datalist directly after each loadParsedRules call.
        // The datalist is already populated above; this just adds any new tables
        // that arrived after autocomplete init ran. initParsedRules calls
        // loadParsedRules which sets parsedRulesData -- we add a MutationObserver
        // on the parsed-rules-list element to detect when it is re-rendered.
        var parsedList = document.getElementById('parsed-rules-list');
        if (parsedList && addrList) {
            var _acObserver = new MutationObserver(function () {
                if (!parsedRulesData || !parsedRulesData.objects) return;
                Object.keys(parsedRulesData.objects).forEach(function (tname) {
                    var ref = '<' + tname + '>';
                    var exists = Array.from(addrList.options).some(function (o) {
                        return o.value === ref;
                    });
                    if (!exists) addOption(addrList, ref);
                });
            });
            _acObserver.observe(parsedList, { childList: true, subtree: false });
        }
    }

    // ── Parse pf.conf text for macros, tables, and interface names ──
    function parsePfConfNamespace(text, macros, baseTables, interfaces) {
        var lines = text.split('\n');
        lines.forEach(function (line) {
            line = line.trim();
            if (!line || line.charAt(0) === '#') return;

            // Macro: name = "value"  or  name = value
            var macroMatch = line.match(/^([a-zA-Z_]\w*)\s*=\s*(.+)$/);
            if (macroMatch) {
                var mname = macroMatch[1];
                var mval  = macroMatch[2].trim().replace(/\s*#.*$/, '');
                macros[mname] = mval;

                // Extract bare interface name from quoted string: ext_if = "%%EXT_IF%%"
                var ifaceVal = mval.match(/^"([a-z][a-z0-9]*\d*)"$/);
                if (ifaceVal) interfaces[ifaceVal[1]] = true;
                return;
            }

            // Table definition: table <name> ...
            var tableMatch = line.match(/^table\s+<([^>]+)>/);
            if (tableMatch) {
                baseTables[tableMatch[1]] = true;
                return;
            }

            // Interface names appearing in on <iface> positions
            var onMatch = line.match(/\bon\s+\$?([a-z][a-z0-9]*\d*)\b/g);
            if (onMatch) {
                onMatch.forEach(function (m) {
                    var n = m.replace(/^\s*on\s+\$?/, '');
                    if (!/^(lo|egress|ingress)$/.test(n)) interfaces[n] = true;
                });
            }
        });
    }

    // ── Datalist helpers ──
    function injectDatalist(id, container) {
        if (document.getElementById(id)) return;
        var dl = document.createElement('datalist');
        dl.id = id;
        (container || document.body).appendChild(dl);
    }

    function wireDatalist(form, selector, datalistId) {
        var el = form.querySelector(selector);
        if (el && !el.getAttribute('list')) {
            el.setAttribute('list', datalistId);
            el.setAttribute('autocomplete', 'off');
        }
    }

    function addOption(datalist, value) {
        var opt = document.createElement('option');
        opt.value = value;
        datalist.appendChild(opt);
    }

    // ================================================================
    // INIT - single entry point
    // ================================================================
    var init = async function() {
        if (_initInProgress) return;
        _initInProgress = true;

        await fetchCSRFToken();

        initIP();
        initASN();
        await initGeoIP();
        await initFeeds();
        initRuleBuilder();
        initValidation();
        initPanelActions();
        RulesLoader.init();
        initDefaultRules();
        await loadQueueEntries();
        initActiveAddons();
        initParsedRules();
        initRuleBuilderAutocomplete();

        _initInProgress = false;
        console.log('[PF] managepf.js initialised');
    }

    // ================================================================
    // PUBLIC API (used by verdict modal onclick attributes)
    // ================================================================
    window.PF = {
        applyRules:       applyRules,
        closeVerdictModal: closeVerdictModal,
        showFullOutput:   showFullOutput,
        copyOutput:       copyOutput
    };

    // ================================================================
    // BOOT
    // ================================================================
    document.addEventListener('manageTabChanged', function (e) {
        if (e.detail.tab === 'pf') init();
    });

    document.addEventListener('manageTabLeaving', function (e) {
        if (e.detail.tab === 'pf') _initInProgress = false;
    });

    window.addEventListener('beforeunload', function () {
        if (autoRefreshTimer)    clearInterval(autoRefreshTimer);
        if (verdictPoll)         clearInterval(verdictPoll);
        if (addonOutcomePoll)    clearInterval(addonOutcomePoll);
        if (deletionTestPoll)    clearInterval(deletionTestPoll);
        if (deletionOutcomePoll) clearInterval(deletionOutcomePoll);
    });

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            if (document.querySelector('#pf-content.active')) init();
        });
    } else {
        if (document.querySelector('#pf-content.active')) init();
    }

})();
