// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * PMACCT LAN Interface Controller
 * Fixed version to handle multicast counts from Perl backend
 *
 * Author: David Peter, Tangent Networks
 * Date: Tue Dec 24 09:42:18 PM IST 2025
 * Web: https://tangentnet.top
 * Email: tangent.net@zohomail.in
 *
 * License: BSD 3-Clause
 */
(function() {
    'use strict';

    console.log(' LAN module initializing...');

    // Configuration
    const CONFIG = Object.freeze({
        API_ENDPOINT: '/cgi-bin/fetch_lan.pl',
        PREVIEW_LIMIT: 20,
        //MODAL_PAGE_SIZE: 50,
        MODAL_PAGE_SIZE: 20,
        AUTO_REFRESH_INTERVAL: 10000
    });

    // State management
    let state = {
        flows: [],
        filters: {},
        autoRefresh: true,
        refreshInterval: null,
        modalPage: 1,
        totalLogFlows: 0,
        totalIPv4: 0,
        totalIPv6: 0,
        totalMulticast: 0,
        lastFetchTime: null,
        isLoading: false
    };

    // DOM elements cache
    const dom = {
        flowsContainer: null,
        totalFlows: null,
        ipv4Flows: null,
        ipv6Flows: null,
        multicastFlows: null,  // Keep this for display
        lastUpdate: null,
        totalCount: null,
        filterBtn: null,
        viewAllBtn: null,
        autoRefreshBtn: null,
        autoRefreshStatus: null,
        clearFiltersBtn: null,
        paginatedModal: null,
        closeModalBtn: null,
        modalFlowsContainer: null,
        prevPageBtn: null,
        nextPageBtn: null,
        currentPage: null,
        totalPages: null,
        modalShowing: null,
        modalTotal: null,
        flowDetailModal: null,
        closeDetailBtn: null,
        flowDetailContent: null,
        copyJsonBtn: null,
        activeFilters: null,
        filterBadges: null,
        filterModal: null,
        closeFilterModal: null,
        applyFilters: null,
        resetFilters: null,
        filterProto: null,
        filterSrcCustom: null,
        filterDstCustom: null,
        filterSrcPort: null,
        filterDstPort: null,
        filterFamily: null,
        filterMac: null
    };

    // Status UI Helper 
    function refreshStatusUI() {
        const indicator = document.getElementById("lan-status-indicator");
        const statusText = document.getElementById("lan-status-text");
        if (statusText) {
            statusText.textContent = "ACTIVE";
            statusText.className = 'tn-status-label';
        }
        if (indicator) {
            indicator.className = 'tn-status-dot';
            indicator.dataset.color = 'green';
        }
    }

    // Utility functions
    function updateLastUpdateTime() {
        if (dom.lastUpdate && state.lastFetchTime) {
            const seconds = Math.floor((Date.now() - state.lastFetchTime) / 1000);
            if (seconds < 60) {
                dom.lastUpdate.textContent = 'Just now';
            } else {
                const mins = Math.floor(seconds / 60);
                dom.lastUpdate.textContent = `${mins}m ago`;
            }
        }
    }

    function updateDashboardCounters() {
        // Update all counters from state
        if (dom.totalFlows) dom.totalFlows.textContent = state.totalLogFlows || 0;
        if (dom.ipv4Flows) dom.ipv4Flows.textContent = state.totalIPv4 || 0;
        if (dom.ipv6Flows) dom.ipv6Flows.textContent = state.totalIPv6 || 0;
        if (dom.multicastFlows) dom.multicastFlows.textContent = state.totalMulticast || 0;
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / 1048576).toFixed(1)} MB`;
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function getFlowClass(flow) {
        // Check for IPv6 first
        if (flow.ip_src?.includes(':') || flow.ip_dst?.includes(':')) {
            // Check if it's multicast
            if (flow.ip_dst?.startsWith('ff') || flow.ip_dst?.startsWith('224.')) {
                return 'multicast';
            }
            return 'ipv6';
        }
        // Check for IPv4 multicast
        if (flow.ip_dst?.startsWith('224.')) {
            return 'multicast';
        }
        return 'ipv4';
    }

    function getIconClass(displayClass) {
        switch (displayClass) {
            case 'ipv6':      return 'fw-flow-icon--ipv6';
            case 'ipv4':      return 'fw-flow-icon--ipv4';
            case 'multicast': return 'fw-flow-icon--multicast';
            default:          return 'fw-flow-icon--default';
        }
    }

    function createFlowCard(flow) {
        const displayClass = getFlowClass(flow);
        const iconClass = getIconClass(displayClass);

        const srcPort = flow.port_src && flow.port_src !== 0 ? `:${flow.port_src}` : '';
        const dstPort = flow.port_dst && flow.port_dst !== 0 ? `:${flow.port_dst}` : '';

        const card = document.createElement('div');
        card.className = 'lan-flow-card';

        // Left: icon + address block
        const left = document.createElement('div');
        left.className = 'lan-flow-left';

        // Icon badge
        const iconBadge = document.createElement('div');
        iconBadge.className = 'fw-flow-icon ' + iconClass;

        const iconSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        iconSvg.setAttribute('fill', 'none');
        iconSvg.setAttribute('stroke', 'currentColor');
        iconSvg.setAttribute('viewBox', '0 0 24 24');
        const iconPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        iconPath.setAttribute('stroke-linecap', 'round');
        iconPath.setAttribute('stroke-linejoin', 'round');
        iconPath.setAttribute('stroke-width', '2');
        iconPath.setAttribute('d', 'M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4');
        iconSvg.appendChild(iconPath);
        iconBadge.appendChild(iconSvg);

        // Address block
        const addrBlock = document.createElement('div');
        addrBlock.className = 'lan-flow-addr-block';

        const addrP = document.createElement('p');
        addrP.className = 'lan-flow-addr';
        addrP.appendChild(document.createTextNode(
            (flow.ip_src || '0.0.0.0') + srcPort + ' '
        ));

        const arrowSpan = document.createElement('span');
        arrowSpan.className = 'lan-flow-arrow';
        const arrowSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        arrowSvg.setAttribute('aria-hidden', 'true');
        arrowSvg.setAttribute('fill', 'none');
        arrowSvg.setAttribute('viewBox', '0 0 24 24');
        arrowSvg.setAttribute('class', 'fw-flow-svg');
        const arrowPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        arrowPath.setAttribute('stroke', 'currentColor');
        arrowPath.setAttribute('stroke-linecap', 'round');
        arrowPath.setAttribute('stroke-linejoin', 'round');
        arrowPath.setAttribute('stroke-width', '2.5');
        arrowPath.setAttribute('d', 'M19 12H5m14 0-4 4m4-4-4-4');
        arrowSvg.appendChild(arrowPath);
        arrowSpan.appendChild(arrowSvg);
        addrP.appendChild(arrowSpan);
        addrP.appendChild(document.createTextNode(
            ' ' + (flow.ip_dst || '0.0.0.0') + dstPort
        ));

        const metaP = document.createElement('p');
        metaP.className = 'lan-flow-meta';
        metaP.textContent = (flow.ip_proto || 'UNK') + ' • ' + (flow.stamp_updated || '');

        addrBlock.appendChild(addrP);
        addrBlock.appendChild(metaP);

        left.appendChild(iconBadge);
        left.appendChild(addrBlock);

        // Right: bytes
        const right = document.createElement('div');
        right.className = 'lan-flow-bytes';

        const bytesP = document.createElement('p');
        bytesP.className = 'lan-flow-bytes-value';
        bytesP.textContent = flow.bytes_formatted || formatBytes(flow.bytes);

        right.appendChild(bytesP);

        card.appendChild(left);
        card.appendChild(right);

        card.addEventListener('click', () => showFlowDetail(flow));
        return card;
    }

    function showFlowDetail(flow) {
        if (!dom.flowDetailModal || !dom.flowDetailContent) return;

        const formattedJson = JSON.stringify(flow, null, 2);
        dom.flowDetailContent.textContent = formattedJson;
        dom.flowDetailContent.dataset.json = formattedJson;
        dom.flowDetailModal.classList.remove('hidden');
    }

    // API functions
    async function fetchFlows(limit = 200, offset = 0) {
        try {
            const params = new URLSearchParams({
                limit,
                offset,
                ...state.filters
            });

            const response = await fetch(`${CONFIG.API_ENDPOINT}?${params}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);

            const data = await response.json();
            if (data && data.error) throw new Error(data.message || data.error);

            // Update state with backend data - USE WHAT PERL PROVIDES
            if (data && typeof data.total !== 'undefined') {
                state.totalLogFlows = data.total || 0;
                state.totalIPv4 = data.ipv4 || 0;      // Pure IPv4 (non-multicast)
                state.totalIPv6 = data.ipv6 || 0;      // Pure IPv6 (non-multicast)
                state.totalMulticast = data.multicast || 0; // All multicast (IPv4 + IPv6)

                console.log(`Backend stats: Total=${state.totalLogFlows}, IPv4=${state.totalIPv4}, IPv6=${state.totalIPv6}, Multicast=${state.totalMulticast}`);
            }

            return data.data || (Array.isArray(data) ? data : []);
        } catch (error) {
            console.error("Fetch error:", error);
            throw error;
        }
    }

    // Update preview
    async function updatePreview() {
        if (state.isLoading || !dom.flowsContainer) return;

        state.isLoading = true;

        try {
            const flows = await fetchFlows(CONFIG.PREVIEW_LIMIT, 0);
            state.flows = flows;
            state.lastFetchTime = Date.now();

            // Build cards
            const fragment = document.createDocumentFragment();

            if (flows.length > 0) {
                flows.forEach(flow => fragment.appendChild(createFlowCard(flow)));
            } else {
                const emptyDiv = document.createElement('div');
                emptyDiv.className = 'lan-empty-state';
                const emptyTitle = document.createElement('p');
                emptyTitle.className = 'lan-empty-title';
                emptyTitle.textContent = 'NO TRAFFIC FOUND';
                const emptyHint = document.createElement('p');
                emptyHint.className = 'lan-empty-hint';
                emptyHint.textContent = Object.keys(state.filters).length > 0
                    ? 'Try different filters'
                    : 'Waiting for LAN traffic...';
                emptyDiv.appendChild(emptyTitle);
                emptyDiv.appendChild(emptyHint);
                fragment.appendChild(emptyDiv);
            }

            dom.flowsContainer.innerHTML = '';
            dom.flowsContainer.appendChild(fragment);

            updateDashboardCounters();
            updateLastUpdateTime();
            refreshStatusUI();

            if (dom.totalCount) {
                dom.totalCount.textContent = state.totalLogFlows;
            }

        } catch (error) {
            console.error('ERROR:  Fetch error:', error);
            if (dom.flowsContainer) {
                const errWrap = document.createElement('div');
                errWrap.className = 'card--error-state';
                const errTitle = document.createElement('p');
                errTitle.className = 'card--error-title';
                errTitle.textContent = 'ERROR';
                const errMsg = document.createElement('p');
                errMsg.className = 'card--error-msg';
                errMsg.textContent = error.message;
                const retryBtn = document.createElement('button');
                retryBtn.className = 'btn btn-sm btn-secondary';
                retryBtn.dataset.action = 'retry';
                retryBtn.textContent = 'Try Again';
                retryBtn.addEventListener('click', () => window.lanRetry());
                errWrap.appendChild(errTitle);
                errWrap.appendChild(errMsg);
                errWrap.appendChild(retryBtn);
                dom.flowsContainer.innerHTML = '';
                dom.flowsContainer.appendChild(errWrap);
            }
        } finally {
            state.isLoading = false;
        }
    }

    // Filter functions
    function updateActiveFiltersDisplay() {
        const filters = Object.entries(state.filters);

        if (filters.length > 0 && dom.activeFilters && dom.filterBadges) {
            dom.filterBadges.innerHTML = '';
            filters.forEach(([key, value]) => {
                const badge = document.createElement('span');
                badge.className = 'badge badge-secondary';
                badge.textContent = `${key}: ${value}`;
                dom.filterBadges.appendChild(badge);
            });
            dom.activeFilters.classList.remove('hidden');
        } else if (dom.activeFilters) {
            dom.activeFilters.classList.add('hidden');
        }
    }

    function applyFilters() {
        const filters = {
            family: dom.filterFamily ? dom.filterFamily.value : '',
            proto: dom.filterProto ? dom.filterProto.value : '',
            src: dom.filterSrcCustom ? dom.filterSrcCustom.value : '',
            src_mac: dom.filterMac ? dom.filterMac.value : '',
            src_port: dom.filterSrcPort ? dom.filterSrcPort.value : '',
            dst_port: dom.filterDstPort ? dom.filterDstPort.value : ''
        };

        Object.keys(filters).forEach(key => {
            if (!filters[key]) delete filters[key];
        });

        state.filters = filters;
        updateActiveFiltersDisplay();

        if (dom.filterModal) dom.filterModal.classList.add('hidden');
        updatePreview();
    }

    function resetFilters() {
        ['lan-filter-family', 'lan-filter-proto', 'lan-filter-src-custom', 'lan-filter-mac', 'lan-filter-src-port', 'lan-filter-dst-port']
            .forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = '';
            });

        state.filters = {};
        updateActiveFiltersDisplay();
        updatePreview();
    }

    // Modal pagination
    async function openPaginatedModal() {
        if (!dom.paginatedModal) return;
        state.modalPage = 1;
        dom.paginatedModal.classList.remove('hidden');
        await loadModalPage(1);
    }

    async function loadModalPage(page) {
        if (!dom.modalFlowsContainer) return;

        const offset = (page - 1) * CONFIG.MODAL_PAGE_SIZE;
        const loadingDiv = document.createElement('div');
        loadingDiv.className = 'lan-modal-loading';
        const spinner = document.createElement('div');
        spinner.className = 'spinner spinner-primary';
        loadingDiv.appendChild(spinner);
        dom.modalFlowsContainer.innerHTML = '';
        dom.modalFlowsContainer.appendChild(loadingDiv);

        try {
            const flows = await fetchFlows(CONFIG.MODAL_PAGE_SIZE, offset);
            const fragment = document.createDocumentFragment();
            flows.forEach(flow => fragment.appendChild(createFlowCard(flow)));

            dom.modalFlowsContainer.innerHTML = '';
            dom.modalFlowsContainer.appendChild(fragment);

            state.modalPage = page;
            updatePaginationUI(page, flows.length);

        } catch (error) {
            console.error('ERROR:  Modal fetch error:', error);
            const modalErrWrap = document.createElement('div');
            modalErrWrap.className = 'card--error-state';
            const modalErrTitle = document.createElement('p');
            modalErrTitle.className = 'card--error-title';
            modalErrTitle.textContent = 'ERROR';
            const modalErrMsg = document.createElement('p');
            modalErrMsg.className = 'card--error-msg';
            modalErrMsg.textContent = error.message;
            modalErrWrap.appendChild(modalErrTitle);
            modalErrWrap.appendChild(modalErrMsg);
            dom.modalFlowsContainer.innerHTML = '';
            dom.modalFlowsContainer.appendChild(modalErrWrap);
        }
    }

    function updatePaginationUI(page, flowsLoaded) {
        if (dom.currentPage) dom.currentPage.textContent = page;

        const estimatedTotal = Math.ceil(state.totalLogFlows / CONFIG.MODAL_PAGE_SIZE);
        if (dom.totalPages) dom.totalPages.textContent = estimatedTotal;

        const start = (page - 1) * CONFIG.MODAL_PAGE_SIZE + 1;
        const end = start + flowsLoaded - 1;
        if (dom.modalShowing) dom.modalShowing.textContent = `${start}-${end}`;
        if (dom.modalTotal) dom.modalTotal.textContent = state.totalLogFlows;

        if (dom.prevPageBtn) dom.prevPageBtn.disabled = page <= 1;
        if (dom.nextPageBtn) dom.nextPageBtn.disabled = flowsLoaded < CONFIG.MODAL_PAGE_SIZE;
    }

    // Auto-refresh
    function startAutoRefresh() {
        if (state.refreshInterval) clearInterval(state.refreshInterval);
        state.refreshInterval = setInterval(() => {
            if (!state.isLoading && Object.keys(state.filters).length === 0) {
                updatePreview();
            }
        }, CONFIG.AUTO_REFRESH_INTERVAL);
    }

    function stopAutoRefresh() {
        if (state.refreshInterval) {
            clearInterval(state.refreshInterval);
            state.refreshInterval = null;
        }
    }

    function toggleAutoRefresh() {
        state.autoRefresh = !state.autoRefresh;
        if (dom.autoRefreshBtn && dom.autoRefreshStatus) {
            if (state.autoRefresh) {
                dom.autoRefreshBtn.classList.remove('btn-secondary');
                dom.autoRefreshBtn.classList.add('btn-success');
                dom.autoRefreshStatus.textContent = 'ON';
                startAutoRefresh();
            } else {
                dom.autoRefreshBtn.classList.remove('btn-success');
                dom.autoRefreshBtn.classList.add('btn-secondary');
                dom.autoRefreshStatus.textContent = 'OFF';
                stopAutoRefresh();
            }
        }
    }

    // Copy to clipboard
    function copyToClipboard(text) {
        const btn = dom.copyJsonBtn;
        const showSuccess = () => {
            if (!btn) return;
            btn.classList.add('btn--copied');
            setTimeout(() => {
                btn.classList.remove('btn--copied');
            }, 2000);
        };

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(showSuccess).catch(() => fallbackCopy(text, showSuccess));
        } else {
            fallbackCopy(text, showSuccess);
        }
    }

    function fallbackCopy(text, callback) {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.className = 'tn-offscreen';
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            callback();
        } catch (err) {
            console.error('Copy failed', err);
        }
        document.body.removeChild(textArea);
    }

    // Event listeners setup
    function setupEventListeners() {
        console.log(' Setting up event listeners...');

        // View All button
        if (dom.viewAllBtn) dom.viewAllBtn.addEventListener('click', openPaginatedModal);

        // Paginated modal controls
        if (dom.closeModalBtn) dom.closeModalBtn.addEventListener('click', () => {
            if (dom.paginatedModal) dom.paginatedModal.classList.add('hidden');
        });

        if (dom.prevPageBtn) dom.prevPageBtn.addEventListener('click', () => {
            if (state.modalPage > 1) loadModalPage(state.modalPage - 1);
        });

        if (dom.nextPageBtn) dom.nextPageBtn.addEventListener('click', () => {
            loadModalPage(state.modalPage + 1);
        });

        // Flow detail modal
        if (dom.closeDetailBtn) dom.closeDetailBtn.addEventListener('click', () => {
            if (dom.flowDetailModal) dom.flowDetailModal.classList.add('hidden');
        });

        if (dom.copyJsonBtn) dom.copyJsonBtn.addEventListener('click', () => {
            if (dom.flowDetailContent) {
                const jsonText = dom.flowDetailContent.dataset.json || dom.flowDetailContent.textContent;
                copyToClipboard(jsonText);
            }
        });

        // Auto-refresh toggle
        if (dom.autoRefreshBtn) dom.autoRefreshBtn.addEventListener('click', toggleAutoRefresh);

        // Filter modal
        if (dom.filterBtn) dom.filterBtn.addEventListener('click', () => {
            if (dom.filterModal) {
                dom.filterModal.classList.add('filter-modal--open');
            }
        });

        if (dom.closeFilterModal) dom.closeFilterModal.addEventListener('click', () => {
            if (dom.filterModal) {
                dom.filterModal.classList.remove('filter-modal--open');
            }
        });

        if (dom.applyFilters) dom.applyFilters.addEventListener('click', applyFilters);
        if (dom.resetFilters) dom.resetFilters.addEventListener('click', resetFilters);
        if (dom.clearFiltersBtn) dom.clearFiltersBtn.addEventListener('click', resetFilters);

        // Close modals on backdrop click
        if (dom.paginatedModal) dom.paginatedModal.addEventListener('click', (e) => {
            if (e.target === dom.paginatedModal) dom.paginatedModal.classList.add('hidden');
        });

        if (dom.flowDetailModal) dom.flowDetailModal.addEventListener('click', (e) => {
            if (e.target === dom.flowDetailModal) dom.flowDetailModal.classList.add('hidden');
        });

        if (dom.filterModal) dom.filterModal.addEventListener('click', (e) => {
            if (e.target === dom.filterModal) {
                dom.filterModal.classList.remove('filter-modal--open');
            }
        });

        console.log('OK:  Event listeners set up');
    }

    // Initialize DOM cache
    function cacheDOMElements() {
        console.log(' Caching DOM elements...');

        // Main containers
        dom.flowsContainer = document.getElementById('lan-main-container');

        // Stats - KEEP ORIGINAL IDs
        dom.totalFlows = document.getElementById('lan-total-flows');
        dom.ipv4Flows = document.getElementById('lan-ipv4-flows'); // This might not exist yet
        dom.ipv6Flows = document.getElementById('lan-ipv6-flows');
        dom.multicastFlows = document.getElementById('lan-multicast-flows'); // Keep this
        dom.lastUpdate = document.getElementById('lan-last-update');
        dom.totalCount = document.getElementById('lan-total-count');

        // Controls
        dom.filterBtn = document.getElementById('lan-open-filter-modal');
        dom.viewAllBtn = document.getElementById('lan-view-all-btn');
        dom.autoRefreshBtn = document.getElementById('lan-toggle-auto-refresh');
        dom.autoRefreshStatus = document.getElementById('lan-refresh-status');
        dom.clearFiltersBtn = document.getElementById('lan-clear-all-filters');

        // Paginated modal
        dom.paginatedModal = document.getElementById('lan-paginated-modal');
        dom.closeModalBtn = document.getElementById('lan-close-paginated-modal');
        dom.modalFlowsContainer = document.getElementById('lan-modal-flows-container');
        dom.prevPageBtn = document.getElementById('lan-prev-page');
        dom.nextPageBtn = document.getElementById('lan-next-page');
        dom.currentPage = document.getElementById('lan-current-page');
        dom.totalPages = document.getElementById('lan-total-pages');
        dom.modalShowing = document.getElementById('lan-modal-showing');
        dom.modalTotal = document.getElementById('lan-modal-total');

        // Flow detail modal
        dom.flowDetailModal = document.getElementById('lan-json-modal');
        dom.closeDetailBtn = document.getElementById('lan-close-modal');
        dom.flowDetailContent = document.getElementById('lan-json-beautified');
        dom.copyJsonBtn = document.getElementById('lan-copy-json-btn');

        // Filters
        dom.activeFilters = document.getElementById('lan-active-filters-indicator');
        dom.filterBadges = document.getElementById('lan-active-filters-list');

        // Filter modal
        dom.filterModal = document.getElementById('lan-filter-modal');
        dom.closeFilterModal = document.getElementById('lan-close-filter-modal');
        dom.applyFilters = document.getElementById('lan-apply-filters');
        dom.resetFilters = document.getElementById('lan-reset-filters');
        dom.filterProto = document.getElementById('lan-filter-proto');
        dom.filterSrcCustom = document.getElementById('lan-filter-src-custom');
        dom.filterDstCustom = document.getElementById('lan-filter-dst-custom');
        dom.filterSrcPort = document.getElementById('lan-filter-src-port');
        dom.filterDstPort = document.getElementById('lan-filter-dst-port');
        dom.filterFamily = document.getElementById('lan-filter-family');
        dom.filterMac = document.getElementById('lan-filter-mac');
        console.log('OK:  DOM elements cached');
    }

    // Initialize
    function init() {
        console.log(' Initializing LAN interface...');
        cacheDOMElements();

        if (!dom.flowsContainer) {
            console.log('WARNING:  Not on LAN page or container not found');
            return;
        }

        setupEventListeners();
        updatePreview();

        if (state.autoRefresh) startAutoRefresh();
        console.log('OK:  LAN interface initialized');
    }

    // Expose API
    window.lanEnhanced = {
        refresh: updatePreview,
        toggleAutoRefresh: toggleAutoRefresh,
        openModal: openPaginatedModal,
        state: () => ({ ...state })
    };

    window.lanRetry = updatePreview;

    // Initialize based on DOM readiness
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        setTimeout(init, 100);
    }

    console.log('OK:  LAN module loaded');
})();
