// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * Firewall Module with Pagination (modeled after WAN)
 * Author: Tangent Networks
 * Date: 2026-01-23
 */

(function() {
    'use strict';

    console.log(' Firewall module initializing...');

    // ============================================
    // CONFIGURATION
    // ============================================
    const CONFIG = Object.freeze({
        API: './cgi-bin/firewall.pl',
        PREVIEW_LIMIT: 15,
        MODAL_PAGE_SIZE: 10,
        AUTO_REFRESH_INTERVAL: 15000,
        MAX_ARCHIVE_DAYS: 7
    });

    // ============================================
    // SHARED STATE
    // ============================================
    let state = {
        logs: [],
        allLogs: [],
        filters: {
            date: getTodayDate(),
            interface: '',
            family: '',
            proto: '',
            port: '',
            action: '',
            limit: 50
        },
        autoRefresh: true,
        refreshInterval: null,
        isLoading: false,
        lastFetchTime: null,
        totalLogs: 0,
        ipv4Logs: 0,
        ipv6Logs: 0,
        blockedLogs: 0
    };

    // ============================================
    // MODAL STATE
    // ============================================
    let modalState = {
        currentModalData: [],
        currentPage: 1,
        totalPages: 1
    };

    // ============================================
    // DOM ELEMENTS CACHE
    // ============================================
    const dom = {
        mainContainer: null,
        totalLogs: null,
        ipv4Logs: null,
        ipv6Logs: null,
        statusIndicator: null,
        statusText: null,
        statusDetail: null,
        statusBadge: null,
        lastUpdate: null,
        currentDate: null,
        viewAllBtn: null,
        
        // Filters
        filterDate: null,
        filterInterface: null,
        filterFamily: null,
        filterProto: null,
        filterPort: null,
        filterAction: null,
        filterLimit: null,
        
        // Filter Modal
        filterModal: null,
        openFilterModal: null,
        closeFilterModal: null,
        applyFilters: null,
        resetFilters: null,
        
        // Paginated Modal
        paginatedModal: null,
        closePaginatedModal: null,
        modalLogsContainer: null,
        prevPageBtn: null,
        nextPageBtn: null,
        currentPageSpan: null,
        totalPagesSpan: null,
        modalShowingSpan: null,
        modalTotalSpan: null,
        
        // Detail Modal
        logModal: null,
        closeLogModal: null,
        copyLogBtn: null,
        toggleJsonView: null,
        logTime: null,
        logAction: null,
        logRule: null,
        logIface: null,
        logSrc: null,
        logDst: null,
        logProto: null,
        logPort: null,
        logDir: null,
        logReason: null,
        logPayload: null,
        logJson: null
    };

    // ============================================
    // INITIALIZATION CONTROL
    // ============================================
    let initAttempts = 0;
    const MAX_INIT_ATTEMPTS = 50;
    let initializationComplete = false;

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================

    function getTodayDate() {
        const today = new Date();
        const year = today.getFullYear();
        const month = String(today.getMonth() + 1).padStart(2, '0');
        const day = String(today.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    }

    function getLast7Days() {
        const dates = [];
        const today = new Date();

        for (let i = 0; i < CONFIG.MAX_ARCHIVE_DAYS; i++) {
            const date = new Date();
            date.setDate(today.getDate() - i);
            const dateString = date.toISOString().split('T')[0];

            let displayText = dateString;
            if (i === 0) {
                displayText = `TODAY (${dateString})`;
            } else if (i === 1) {
                displayText = `YESTERDAY (${dateString})`;
            } else {
                const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
                const dayName = dayNames[date.getDay()];
                displayText = `${dayName} (${dateString})`;
            }

            dates.push({
                value: dateString,
                display: displayText
            });
        }

        return dates;
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function decodeHtmlEntities(text) {
        const textarea = document.createElement('textarea');
        textarea.innerHTML = text;
        return textarea.value;
    }

    function isIPv6(ip) {
        if (!ip) return false;
        return ip.includes(':');
    }

    // ============================================
    // CARD CREATION FUNCTIONS
    // ============================================

    function getActionBadgeClass(action) {
        switch(action) {
            case 'block': return 'fw-action--block';
            case 'match': return 'fw-action--match';
            case 'pass':  return 'fw-action--pass';
            default:      return 'fw-action--default';
        }
    }

    function createLogCard(log) {
        const actionClass = getActionBadgeClass(log.action);

        const div = document.createElement('div');
        div.className = 'card--log-entry';
        div.dataset.logId = log.id || Math.random().toString(36).substr(2, 9);

        const outer = document.createElement('div');
        outer.className = 'fw-card-body';

        const header = document.createElement('div');
        header.className = 'fw-card-header';

        const timeSpan = document.createElement('span');
        timeSpan.className = 'fw-card-time';
        timeSpan.textContent = log.time || 'N/A';

        const actionSpan = document.createElement('span');
        actionSpan.className = actionClass;
        actionSpan.textContent = log.action || 'N/A';

        header.appendChild(timeSpan);
        header.appendChild(actionSpan);

        const payload = document.createElement('div');
        payload.className = 'fw-card-payload';
        payload.textContent = log.payload || 'N/A';

        outer.appendChild(header);
        outer.appendChild(payload);
        div.appendChild(outer);

        div.addEventListener('click', () => openLogDetail(log));
        return div;
    }

    // ============================================
    // PAGINATED MODAL FUNCTIONS
    // ============================================

    function openPaginatedModal(logs = []) {
        if (!dom.paginatedModal) {
            console.error('ERROR:  Paginated modal not found in DOM');
            return;
        }

        console.log('INFO:  Opening paginated modal with', logs.length, 'logs');

        modalState.currentModalData = logs;
        modalState.currentPage = 1;
        modalState.totalPages = Math.max(1, Math.ceil(logs.length / CONFIG.MODAL_PAGE_SIZE));

        dom.paginatedModal.classList.remove('hidden');
        loadModalPage(1);
        updateModalHeaderInfo();
    }

    function loadModalPage(page) {
        if (!dom.modalLogsContainer) return;

        const startIndex = (page - 1) * CONFIG.MODAL_PAGE_SIZE;
        const endIndex = startIndex + CONFIG.MODAL_PAGE_SIZE;
        const pageLogs = modalState.currentModalData.slice(startIndex, endIndex);

        dom.modalLogsContainer.innerHTML = '';

        if (pageLogs.length === 0) {
            const emptyWrap = document.createElement('div');
            emptyWrap.className = 'card--empty-state';

            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('class', 'fw-empty-icon');
            svg.setAttribute('fill', 'none');
            svg.setAttribute('stroke', 'currentColor');
            svg.setAttribute('viewBox', '0 0 24 24');
            const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            path.setAttribute('stroke-linecap', 'round');
            path.setAttribute('stroke-linejoin', 'round');
            path.setAttribute('stroke-width', '2');
            path.setAttribute('d', 'M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z');
            svg.appendChild(path);

            const msg = document.createElement('p');
            msg.className = 'fw-empty-msg';
            msg.textContent = 'No logs to display';

            emptyWrap.appendChild(svg);
            emptyWrap.appendChild(msg);
            dom.modalLogsContainer.appendChild(emptyWrap);
        } else {
            const fragment = document.createDocumentFragment();
            pageLogs.forEach(log => {
                fragment.appendChild(createLogCard(log));
            });
            dom.modalLogsContainer.appendChild(fragment);
        }

        updatePaginationUI(page, pageLogs.length);
    }

    function updateModalHeaderInfo() {
        if (!dom.modalShowingSpan || !dom.modalTotalSpan) return;

        const total = modalState.currentModalData.length;
        const start = Math.min((modalState.currentPage - 1) * CONFIG.MODAL_PAGE_SIZE + 1, total);
        const end = Math.min(modalState.currentPage * CONFIG.MODAL_PAGE_SIZE, total);

        dom.modalShowingSpan.textContent = `${start}-${end}`;
        dom.modalTotalSpan.textContent = total;
    }

    function updatePaginationUI(page, logsLoaded) {
        if (!dom.currentPageSpan || !dom.totalPagesSpan || !dom.prevPageBtn || !dom.nextPageBtn) return;

        modalState.currentPage = page;
        dom.currentPageSpan.textContent = page;
        dom.totalPagesSpan.textContent = modalState.totalPages;
        dom.prevPageBtn.disabled = page <= 1;
        dom.nextPageBtn.disabled = page >= modalState.totalPages;
        updateModalHeaderInfo();
    }

    // ============================================
    // LOG DETAIL MODAL FUNCTIONS
    // ============================================

    function openLogDetail(log) {
        if (!dom.logModal) return;

        console.log(' Opening log detail modal');

        // Update modal elements (data is already HTML-escaped)
        if (dom.logTime) dom.logTime.textContent = log.time || 'N/A';
        if (dom.logRule) dom.logRule.textContent = log.rule || 'N/A';
        if (dom.logIface) dom.logIface.textContent = log.iface || 'N/A';
        if (dom.logSrc) dom.logSrc.textContent = log.src || 'N/A';
        if (dom.logDst) dom.logDst.textContent = log.dst || 'N/A';
        if (dom.logProto) dom.logProto.textContent = log.proto || 'N/A';
        if (dom.logPort) dom.logPort.textContent = log.port || 'N/A';
        if (dom.logDir) dom.logDir.textContent = log.dir || 'N/A';
        if (dom.logReason) dom.logReason.textContent = log.reason || 'N/A';
        if (dom.logPayload) dom.logPayload.textContent = log.payload || 'N/A';

        // Update action badge
        if (dom.logAction) {
            dom.logAction.textContent = log.action || 'N/A';
            dom.logAction.className =
                log.action === 'block' ? 'fw-action--block' :
                log.action === 'match' ? 'fw-action--match' :
                log.action === 'pass'  ? 'fw-action--pass'  :
                'fw-action--default';
        }

        // Store JSON for copying
        if (dom.logJson) {
            try {
                const prettyJson = JSON.stringify(log, null, 2);
                dom.logJson.textContent = prettyJson;
                dom.logJson.dataset.json = prettyJson;
            } catch (e) {
                dom.logJson.textContent = 'Error formatting JSON';
            }
        }

        // Reset JSON view
        if (dom.toggleJsonView && dom.logJson) {
            dom.toggleJsonView.textContent = 'Show Raw JSON';
            dom.logJson.classList.add('hidden');
        }

        // Show modal
        dom.logModal.classList.remove('hidden');
    }

    function copyToClipboard(text) {
        if (!text || text.trim() === '') return;

        const btn = dom.copyLogBtn;
        const originalHTML = btn ? btn.innerHTML : null;
        const originalClass = btn ? btn.className : '';

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text)
                .then(() => showCopyFeedback('Copied!', true, btn, originalHTML, originalClass))
                .catch(() => fallbackCopy(text, btn, originalHTML, originalClass));
        } else {
            fallbackCopy(text, btn, originalHTML, originalClass);
        }
    }

    function fallbackCopy(text, btn, originalHTML, originalClass) {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.className = 'tn-offscreen';
        document.body.appendChild(textArea);
        textArea.select();

        try {
            const successful = document.execCommand('copy');
            showCopyFeedback(successful ? 'Copied!' : 'Copy failed', successful, btn, originalHTML, originalClass);
        } catch (err) {
            console.error('ERROR:  Copy failed:', err);
            showCopyFeedback('Copy failed', false, btn, originalHTML, originalClass);
        } finally {
            document.body.removeChild(textArea);
        }
    }

    function showCopyFeedback(message, success, btn, originalHTML, originalClass) {
        if (!btn) return;

        if (success) {
            btn.innerHTML = `
                <svg class="fw-copy-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
                ${message}
            `;
            btn.classList.add('btn--copied');
        } else {
            btn.innerHTML = `
                <svg class="fw-copy-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                ${message}
            `;
            btn.classList.add('btn--error-state');
        }

        setTimeout(() => {
            if (originalHTML) btn.innerHTML = originalHTML;
            btn.classList.remove('btn--copied', 'btn--error-state');
            if (originalClass) btn.className = originalClass;
        }, 2000);
    }

    // ============================================
    // FETCH FUNCTIONS
    // ============================================

    async function fetchLogs(fetchAll = false) {
        if (state.isLoading) return;

        state.isLoading = true;
        updateStatus('FETCHING', 'Loading logs...', 'blue');

        try {
            const params = new URLSearchParams({
                date: state.filters.date,
                limit: fetchAll ? '500' : state.filters.limit.toString(),
                offset: '0',
                debug: '0',
                _t: Date.now().toString()
            });

            if (state.filters.interface) params.append('interface', state.filters.interface);
            if (state.filters.family) params.append('family', state.filters.family);
            if (state.filters.proto) params.append('proto', state.filters.proto);
            if (state.filters.port) params.append('port', state.filters.port);
            if (state.filters.action === 'block') params.append('blocked', '1');

            console.log(`INFO:  Fetching firewall logs: ${CONFIG.API}?${params}`);

            const response = await fetch(`${CONFIG.API}?${params}`, {
                headers: {
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            // Parse logs from HTML or use data array
            let logs = [];
            if (data.html_logs) {
                logs = parseLogsFromHTML(data.html_logs);
            } else if (data.data) {
                logs = data.data;
            }

            // Update stats
            state.totalLogs = data.total || 0;
            state.ipv4Logs = data.ipv4 || 0;
            state.ipv6Logs = data.ipv6 || 0;
            state.blockedLogs = data.blocked || 0;

            // Calculate IPv4/IPv6 if not provided
            if (!data.ipv4 && !data.ipv6) {
                let ipv4Count = 0;
                let ipv6Count = 0;
                logs.forEach(log => {
                    if (isIPv6(log.src) || isIPv6(log.dst)) {
                        ipv6Count++;
                    } else {
                        ipv4Count++;
                    }
                });
                state.ipv4Logs = ipv4Count;
                state.ipv6Logs = ipv6Count;
            }

            if (fetchAll) {
                state.allLogs = logs;
            } else {
                state.logs = logs.slice(0, CONFIG.PREVIEW_LIMIT);
                state.allLogs = logs;
                renderPreviewLogs(state.logs);
            }

            updateStatsDisplay();
            updateCurrentDate();
            
            const isToday = state.filters.date === getTodayDate();
            updateStatus(
                isToday ? 'LIVE' : 'ARCHIVE',
                isToday ? 'Real-time monitoring' : `Archive: ${state.filters.date}`,
                isToday ? 'green' : 'blue'
            );

            // Show/hide View All button
            if (dom.viewAllBtn) {
                dom.viewAllBtn.classList.toggle('hidden', state.totalLogs <= CONFIG.PREVIEW_LIMIT);
            }

            state.lastFetchTime = Date.now();

        } catch (error) {
            console.error('ERROR:  Failed to fetch logs:', error);
            updateStatus('ERROR', 'Failed to load logs', 'red');

            if (dom.mainContainer) {
                // Build error state without inline onclick (CSP: script-src 'self')
                const errWrap = document.createElement('div');
                errWrap.className = 'card--error-state';

                const errTitle = document.createElement('p');
                errTitle.className = 'card--error-title';
                errTitle.textContent = 'ERROR LOADING LOGS';

                const errMsg = document.createElement('p');
                errMsg.className = 'card--error-msg';
                errMsg.textContent = error.message;

                const retryBtn = document.createElement('button');
                retryBtn.className = 'btn--retry';
                retryBtn.textContent = 'Try Again';
                retryBtn.dataset.action = 'retry-fetch';

                errWrap.appendChild(errTitle);
                errWrap.appendChild(errMsg);
                errWrap.appendChild(retryBtn);

                dom.mainContainer.innerHTML = '';
                dom.mainContainer.appendChild(errWrap);
            }
        } finally {
            state.isLoading = false;
        }
    }

    function parseLogsFromHTML(htmlString) {
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = htmlString;
        const logElements = tempDiv.querySelectorAll('li[data-time]');
        
        const logs = [];
        logElements.forEach((el, index) => {
            logs.push({
                id: index,
                time: el.getAttribute('data-time') || 'N/A',
                rule: el.getAttribute('data-rule') || 'N/A',
                reason: el.getAttribute('data-reason') || 'N/A',
                action: el.getAttribute('data-action') || 'N/A',
                dir: el.getAttribute('data-dir') || 'N/A',
                iface: el.getAttribute('data-iface') || 'N/A',
                src: el.getAttribute('data-src') || 'N/A',
                dst: el.getAttribute('data-dst') || 'N/A',
                port: el.getAttribute('data-port') || 'N/A',
                proto: el.getAttribute('data-proto') || 'N/A',
                payload: el.getAttribute('data-payload') || 'N/A'
            });
        });
        
        return logs;
    }

    function renderPreviewLogs(logs) {
        if (!dom.mainContainer) return;

        const fragment = document.createDocumentFragment();

        if (logs.length === 0) {
            const emptyDiv = document.createElement('div');
            emptyDiv.className = 'card--empty-state';

            const msg1 = document.createElement('p');
            msg1.className = 'fw-empty-msg';
            msg1.textContent = 'NO LOGS FOUND';

            const msg2 = document.createElement('p');
            msg2.className = 'fw-empty-hint';
            msg2.textContent = 'Try adjusting your filters';

            emptyDiv.appendChild(msg1);
            emptyDiv.appendChild(msg2);
            fragment.appendChild(emptyDiv);
        } else {
            logs.forEach(log => {
                fragment.appendChild(createLogCard(log));
            });
        }

        dom.mainContainer.innerHTML = '';
        dom.mainContainer.appendChild(fragment);
    }

    // ============================================
    // UPDATE FUNCTIONS
    // ============================================

    function updateStatsDisplay() {
        if (dom.totalLogs) dom.totalLogs.textContent = state.totalLogs;
        if (dom.ipv4Logs) dom.ipv4Logs.textContent = state.ipv4Logs;
        if (dom.ipv6Logs) dom.ipv6Logs.textContent = state.ipv6Logs;

        if (dom.lastUpdate) {
            const now = new Date();
            dom.lastUpdate.textContent = now.toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }
    }

    function updateCurrentDate() {
        if (!dom.currentDate) return;
        
        const today = getTodayDate();
        if (state.filters.date === today) {
            dom.currentDate.textContent = 'Today';
        } else {
            dom.currentDate.textContent = state.filters.date;
        }
    }

    function updateStatus(status, detail, color = 'gray') {
        if (!dom.statusIndicator || !dom.statusText || !dom.statusDetail) return;

        dom.statusIndicator.innerHTML = '';

        const dot = document.createElement('span');
        dot.className = 'tn-status-dot';
        dot.dataset.color = color;
        dom.statusIndicator.appendChild(dot);

        dom.statusText.textContent = status;
        dom.statusDetail.textContent = detail;

        // Update status badge
        if (dom.statusBadge) {
            const isLive = color === 'green';
            if (isLive) {
                dom.statusBadge.className = 'badge--live';
                const label = document.createElement('span');
                label.className = 'fw-badge-label';
                label.textContent = `Live Logs: Auto-refresh ${state.autoRefresh ? 'ON' : 'OFF'}`;
                dom.statusBadge.innerHTML = '';
                dom.statusBadge.appendChild(label);
            } else {
                dom.statusBadge.className = 'badge--idle';
                const label = document.createElement('span');
                label.className = 'fw-badge-label';
                label.textContent = `Archive Logs \u2022 ${state.filters.date}`;
                dom.statusBadge.innerHTML = '';
                dom.statusBadge.appendChild(label);
            }
        }
    }

    // ============================================
    // AUTO-REFRESH
    // ============================================

    function startAutoRefresh() {
        if (state.refreshInterval) {
            clearInterval(state.refreshInterval);
        }

        const isToday = state.filters.date === getTodayDate();
        if (state.autoRefresh && isToday) {
            state.refreshInterval = setInterval(() => {
                if (!state.isLoading) {
                    fetchLogs(false);
                }
            }, CONFIG.AUTO_REFRESH_INTERVAL);
        }
    }

    function stopAutoRefresh() {
        if (state.refreshInterval) {
            clearInterval(state.refreshInterval);
            state.refreshInterval = null;
        }
    }

    // ============================================
    // DOM CACHING & INITIALIZATION
    // ============================================

    function cacheDOMElements() {
        console.log(' Caching DOM elements...');

        dom.mainContainer = document.getElementById('firewall-main-container');
        dom.totalLogs = document.getElementById('firewall-total-logs');
        dom.ipv4Logs = document.getElementById('firewall-ipv4-logs');
        dom.ipv6Logs = document.getElementById('firewall-ipv6-logs');
        dom.statusIndicator = document.getElementById('firewall-status-indicator');
        dom.statusText = document.getElementById('firewall-status-text');
        dom.statusDetail = document.getElementById('firewall-status-detail');
        dom.statusBadge = document.getElementById('firewall-status-badge');
        dom.lastUpdate = document.getElementById('firewall-last-update');
        dom.currentDate = document.getElementById('firewall-current-date');
        dom.viewAllBtn = document.getElementById('firewall-view-all-btn');

        // Filters
        dom.filterDate = document.getElementById('firewall-filter-date');
        dom.filterInterface = document.getElementById('firewall-filter-interface');
        dom.filterFamily = document.getElementById('firewall-filter-family');
        dom.filterProto = document.getElementById('firewall-filter-proto');
        dom.filterPort = document.getElementById('firewall-filter-port');
        dom.filterAction = document.getElementById('firewall-filter-action');
        dom.filterLimit = document.getElementById('firewall-filter-limit');
        
        // Filter Modal
        dom.filterModal = document.getElementById('firewall-filter-modal');
        dom.openFilterModal = document.getElementById('firewall-open-filter-modal');
        dom.closeFilterModal = document.getElementById('firewall-close-filter-modal');
        dom.applyFilters = document.getElementById('firewall-apply-filters');
        dom.resetFilters = document.getElementById('firewall-reset-filters');

        // Paginated Modal
        dom.paginatedModal = document.getElementById('firewall-paginated-modal');
        dom.closePaginatedModal = document.getElementById('firewall-close-paginated-modal');
        dom.modalLogsContainer = document.getElementById('firewall-modal-logs-container');
        dom.prevPageBtn = document.getElementById('firewall-prev-page');
        dom.nextPageBtn = document.getElementById('firewall-next-page');
        dom.currentPageSpan = document.getElementById('firewall-current-page');
        dom.totalPagesSpan = document.getElementById('firewall-total-pages');
        dom.modalShowingSpan = document.getElementById('firewall-modal-showing');
        dom.modalTotalSpan = document.getElementById('firewall-modal-total');

        // Detail Modal
        dom.logModal = document.getElementById('firewall-log-modal');
        dom.closeLogModal = document.getElementById('firewall-close-log-modal');
        dom.copyLogBtn = document.getElementById('firewall-copy-log-btn');
        dom.toggleJsonView = document.getElementById('firewall-toggle-json-view');
        dom.logTime = document.getElementById('firewall-log-time');
        dom.logAction = document.getElementById('firewall-log-action');
        dom.logRule = document.getElementById('firewall-log-rule');
        dom.logIface = document.getElementById('firewall-log-iface');
        dom.logSrc = document.getElementById('firewall-log-src');
        dom.logDst = document.getElementById('firewall-log-dst');
        dom.logProto = document.getElementById('firewall-log-proto');
        dom.logPort = document.getElementById('firewall-log-port');
        dom.logDir = document.getElementById('firewall-log-dir');
        dom.logReason = document.getElementById('firewall-log-reason');
        dom.logPayload = document.getElementById('firewall-log-payload');
        dom.logJson = document.getElementById('firewall-log-json');

        console.log(`OK:  DOM elements cached: ${Object.keys(dom).length} elements`);
        return !!dom.mainContainer;
    }

    function populateDateSelects() {
        if (!dom.filterDate) {
            console.warn('WARNING:  Date select not found');
            return;
        }

        console.log(' Populating date select');

        const dates = getLast7Days();
        dom.filterDate.innerHTML = '';

        dates.forEach(date => {
            const option = document.createElement('option');
            option.value = date.value;
            option.textContent = date.display;
            dom.filterDate.appendChild(option);
        });

        if (dates.length > 0) {
            dom.filterDate.value = dates[0].value;
        }

        console.log(`OK:  Populated ${dates.length} dates`);
    }

    function setupEventListeners() {
        console.log(' Setting up event listeners...');

        // Filter modal open/close
        if (dom.openFilterModal) {
            dom.openFilterModal.addEventListener('click', () => {
                if (dom.filterModal) {
                    dom.filterModal.classList.remove('hidden');
                }
            });
        }

        if (dom.closeFilterModal) {
            dom.closeFilterModal.addEventListener('click', () => {
                if (dom.filterModal) {
                    dom.filterModal.classList.add('hidden');
                }
            });
        }

        if (dom.filterModal) {
            dom.filterModal.addEventListener('click', (e) => {
                if (e.target === dom.filterModal) {
                    dom.filterModal.classList.add('hidden');
                }
            });
        }

        // Apply filters button
        if (dom.applyFilters) {
            dom.applyFilters.addEventListener('click', () => {
                // Get filter values
                state.filters.date = dom.filterDate ? dom.filterDate.value : getTodayDate();
                state.filters.interface = dom.filterInterface ? dom.filterInterface.value : '';
                state.filters.family = dom.filterFamily ? dom.filterFamily.value : '';
                state.filters.proto = dom.filterProto ? dom.filterProto.value : '';
                state.filters.port = dom.filterPort ? dom.filterPort.value : '';
                state.filters.action = dom.filterAction ? dom.filterAction.value : '';
                state.filters.limit = dom.filterLimit ? parseInt(dom.filterLimit.value) : 50;

                console.log(' Filters applied:', state.filters);

                // Close modal
                if (dom.filterModal) {
                    dom.filterModal.classList.add('hidden');
                }

                // Fetch with new filters
                fetchLogs(false);
                startAutoRefresh();
            });
        }

        // Reset filters button
        if (dom.resetFilters) {
            dom.resetFilters.addEventListener('click', () => {
                const todayDate = getTodayDate();
                
                // Reset filter inputs
                if (dom.filterDate) dom.filterDate.value = todayDate;
                if (dom.filterInterface) dom.filterInterface.value = '';
                if (dom.filterFamily) dom.filterFamily.value = '';
                if (dom.filterProto) dom.filterProto.value = '';
                if (dom.filterPort) dom.filterPort.value = '';
                if (dom.filterAction) dom.filterAction.value = '';
                if (dom.filterLimit) dom.filterLimit.value = '50';

                // Reset state
                state.filters = {
                    date: todayDate,
                    interface: '',
                    family: '',
                    proto: '',
                    port: '',
                    action: '',
                    limit: 50
                };

                console.log('INFO:  Filters reset');

                // Close modal
                if (dom.filterModal) {
                    dom.filterModal.classList.add('hidden');
                }

                // Fetch with reset filters
                fetchLogs(false);
                startAutoRefresh();
            });
        }

        // View All button
        if (dom.viewAllBtn) {
            dom.viewAllBtn.addEventListener('click', () => {
                console.log('INFO:  View All clicked - opening modal with', state.allLogs.length, 'logs');
                openPaginatedModal(state.allLogs);
            });
        }

        // Paginated modal controls
        if (dom.closePaginatedModal) {
            dom.closePaginatedModal.addEventListener('click', () => {
                if (dom.paginatedModal) {
                    dom.paginatedModal.classList.add('hidden');
                }
            });
        }

        if (dom.paginatedModal) {
            dom.paginatedModal.addEventListener('click', (e) => {
                if (e.target === dom.paginatedModal) {
                    dom.paginatedModal.classList.add('hidden');
                }
            });
        }

        if (dom.prevPageBtn) {
            dom.prevPageBtn.addEventListener('click', () => {
                if (modalState.currentPage > 1) {
                    loadModalPage(modalState.currentPage - 1);
                }
            });
        }

        if (dom.nextPageBtn) {
            dom.nextPageBtn.addEventListener('click', () => {
                if (modalState.currentPage < modalState.totalPages) {
                    loadModalPage(modalState.currentPage + 1);
                }
            });
        }

        // Detail modal controls
        if (dom.closeLogModal) {
            dom.closeLogModal.addEventListener('click', () => {
                if (dom.logModal) dom.logModal.classList.add('hidden');
            });
        }

        if (dom.logModal) {
            dom.logModal.addEventListener('click', (e) => {
                if (e.target === dom.logModal) {
                    dom.logModal.classList.add('hidden');
                }
            });
        }

        if (dom.copyLogBtn) {
            dom.copyLogBtn.addEventListener('click', () => {
                if (dom.logJson) {
                    const jsonText = dom.logJson.dataset.json || dom.logJson.textContent;
                    copyToClipboard(jsonText);
                }
            });
        }

        if (dom.toggleJsonView) {
            dom.toggleJsonView.addEventListener('click', () => {
                if (dom.logJson) {
                    dom.logJson.classList.toggle('hidden');
                    dom.toggleJsonView.textContent = dom.logJson.classList.contains('hidden') ?
                        'Show Raw JSON' : 'Hide Raw JSON';
                }
            });
        }

        console.log('OK:  Event listeners set up');

        // Delegated listener for dynamically-created buttons in mainContainer
        // (e.g. the "Try Again" button rendered on fetch error -- no inline onclick)
        if (dom.mainContainer) {
            dom.mainContainer.addEventListener('click', (e) => {
                const btn = e.target.closest('[data-action]');
                if (!btn) return;
                if (btn.dataset.action === 'retry-fetch') {
                    fetchLogs(false);
                }
            });
        }
    }

    function attemptInitialization() {
        if (initializationComplete) return;

        initAttempts++;

        const domCached = cacheDOMElements();

        if (domCached && dom.mainContainer) {
            completeInitialization();
        } else if (initAttempts < MAX_INIT_ATTEMPTS) {
            console.log(` Waiting for DOM (attempt ${initAttempts}/${MAX_INIT_ATTEMPTS})...`);
            setTimeout(attemptInitialization, 100);
        } else {
            console.warn('WARNING:  Could not initialize: DOM not found after max attempts');
            initializationComplete = true;
        }
    }

    function completeInitialization() {
        console.log(' Completing initialization...');

        setupEventListeners();
        populateDateSelects();

        initializationComplete = true;

        console.log('OK:  Firewall interface fully initialized');
        
        // Initial fetch
        fetchLogs(false);
        startAutoRefresh();
    }

    // ============================================
    // GLOBAL EXPORTS
    // ============================================

    window.firewallForceFetch = () => fetchLogs(false);
    window.firewallOpenPaginatedModal = openPaginatedModal;
    window.firewallState = state;

    // ============================================
    // STARTUP
    // ============================================

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', attemptInitialization);
    } else {
        setTimeout(attemptInitialization, 100);
    }

    console.log('OK:  Firewall module loaded (IIFE wrapped)');
})();
