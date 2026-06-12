// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * External Interface (WAN) - Complete Module
 * Merged from ext-core.js, ext-modals.js, ext-live.js
 * Author: Tangent Networks
 * Date: 2026-01-20
 * FIXED VERSION - Clean architecture, no mode switching bugs
 */

(function() {
	'use strict';

	console.log(' EXTERNAL interface initializing...');

	// ============================================
	// CONFIGURATION
	// ============================================
	const CONFIG = Object.freeze({
		API: Object.freeze({
			LIVE: '/cgi-bin/fetch_wan.pl',
			ARCHIVE: '/cgi-bin/search_wan.pl'
		}),
		PREVIEW_LIMIT: 20,
		MODAL_PAGE_SIZE: 20,
		AUTO_REFRESH_INTERVAL: 10000,
		MAX_ARCHIVE_DAYS: 7
	});

	// ============================================
	// SHARED STATE
	// ============================================
	let state = {
		flows: [],
		allFlows: [],
		filters: {},
		autoRefresh: true,
		refreshInterval: null,
		isLoading: false,
		lastFetchTime: null,
		totalFlows: 0,
		ipv4Flows: 0,
		ipv6Flows: 0,
		isViewReady: false
	};

	// ============================================
	// DOM ELEMENTS CACHE
	// ============================================
	const dom = {
		mainContainer: null,
		totalFlows: null,
		ipv4Flows: null,
		ipv6Flows: null,
		statusIndicator: null,
		statusText: null,
		statusDetail: null,
		statusBadge: null,
		lastUpdateTime: null,
		viewAllBtn: null,
		viewLiveBtn: null,
		openSearchModalBtn: null,
		searchModal: null,
		closeSearchModalBtn: null,
		searchForm: null,
		dateFromSelect: null,
		dateToSelect: null,
		paginatedModal: null,
		closePaginatedModalBtn: null,
		modalFlowsContainer: null,
		prevPageBtn: null,
		nextPageBtn: null,
		currentPageSpan: null,
		totalPagesSpan: null,
		modalShowingSpan: null,
		modalTotalSpan: null,
		jsonModal: null,
		closeModalBtn: null,
		jsonBeautified: null,
		copyJsonBtn: null
	};

	// ============================================
	// MODAL STATE
	// ============================================
	let modalState = {
		currentModalData: [],
		currentPage: 1,
		totalPages: 1,
		modalType: null,
		liveTotal: 0
	};

	// ============================================
	// LIVE STATE
	// ============================================
	let liveState = {
		isPolling: false,
		lastPollTime: null,
		errorCount: 0,
		maxErrors: 3,
		currentRequest: null
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

	function isIPv6(ip) {
		if (!ip) return false;
		return ip.includes(':');
	}

	function getTodayDate() {
		const today = new Date();
		return today.toISOString().split('T')[0];
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

	function extractFiltersFromForm(form) {
		const formData = new FormData(form);
		const filters = {};

		const fields = [
			'date_from', 'date_to', 'start_hr', 'start_min', 'end_hr', 'end_min',
			'proto', 'src', 'dst', 'src_port', 'dst_port', 'bytes_min'
		];

		fields.forEach(field => {
			const value = formData.get(field);
			if (value && value.trim() !== '') {
				filters[field] = value;
			}
		});

		return filters;
	}

	// ============================================
	// CARD CREATION FUNCTIONS
	// ============================================

	function getFlowClass(flow) {
		if (isIPv6(flow.ip_src) || isIPv6(flow.ip_dst)) {
			return 'ipv6';
		}
		return 'ipv4';
	}

	function getIconClass(displayClass) {
		switch (displayClass) {
			case 'ipv6':  return 'fw-flow-icon--ipv6';
			case 'ipv4':  return 'fw-flow-icon--ipv4';
			default:      return 'fw-flow-icon--default';
		}
	}

	function createFlowCard(flow) {
		const displayClass = getFlowClass(flow);
		const iconClass = getIconClass(displayClass);

		const srcPort = flow.port_src && flow.port_src !== 0 ? `:${flow.port_src}` : '';
		const dstPort = flow.port_dst && flow.port_dst !== 0 ? `:${flow.port_dst}` : '';

		const div = document.createElement('div');
		div.className = 'card--flow-entry';
		div.dataset.flowId = flow.id || Math.random().toString(36).substr(2, 9);

		// Left: icon + address block
		const left = document.createElement('div');
		left.className = 'fw-flow-left';

		const iconWrap = document.createElement('div');
		iconWrap.className = 'fw-flow-icon ' + iconClass;

		const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
		svg.setAttribute('class', 'fw-flow-svg');
		svg.setAttribute('fill', 'none');
		svg.setAttribute('stroke', 'currentColor');
		svg.setAttribute('viewBox', '0 0 24 24');
		const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
		path.setAttribute('stroke-linecap', 'round');
		path.setAttribute('stroke-linejoin', 'round');
		path.setAttribute('stroke-width', '2');
		path.setAttribute('d', 'M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4');
		svg.appendChild(path);
		iconWrap.appendChild(svg);

		const addrBlock = document.createElement('div');
		addrBlock.className = 'fw-flow-addr-block';

		const addrLine = document.createElement('p');
		addrLine.className = 'fw-flow-addr';

		// arrow SVG between src and dst
		const arrowSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
		arrowSvg.setAttribute('class', 'fw-flow-arrow');
		arrowSvg.setAttribute('aria-hidden', 'true');
		arrowSvg.setAttribute('fill', 'none');
		arrowSvg.setAttribute('viewBox', '0 0 24 24');
		const arrowPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
		arrowPath.setAttribute('stroke', 'currentColor');
		arrowPath.setAttribute('stroke-linecap', 'round');
		arrowPath.setAttribute('stroke-linejoin', 'round');
		arrowPath.setAttribute('stroke-width', '2.5');
		arrowPath.setAttribute('d', 'M19 12H5m14 0-4 4m4-4-4-4');
		arrowSvg.appendChild(arrowPath);

		addrLine.appendChild(document.createTextNode(
			(flow.ip_src || '0.0.0.0') + srcPort + '\u00a0'
		));
		addrLine.appendChild(arrowSvg);
		addrLine.appendChild(document.createTextNode(
			'\u00a0' + (flow.ip_dst || '0.0.0.0') + dstPort
		));

		const metaLine = document.createElement('p');
		metaLine.className = 'fw-flow-meta';
		metaLine.textContent =
			(flow.ip_proto || 'UNK') + ' \u2022 ' + (flow.stamp_updated || '');

		addrBlock.appendChild(addrLine);
		addrBlock.appendChild(metaLine);

		left.appendChild(iconWrap);
		left.appendChild(addrBlock);

		// Right: bytes
		const right = document.createElement('div');
		right.className = 'fw-flow-right';

		const bytes = document.createElement('p');
		bytes.className = 'fw-flow-bytes';
		bytes.textContent = flow.bytes_formatted || formatBytes(flow.bytes);

		right.appendChild(bytes);

		div.appendChild(left);
		div.appendChild(right);

		div.addEventListener('click', () => openFlowDetail(flow));
		return div;
	}

	// ============================================
	// PAGINATED MODAL FUNCTIONS
	// ============================================

	function openPaginatedModal(flows = [], type = 'live') {
		if (!dom.paginatedModal) {
			console.error('ERROR:  Paginated modal not found in DOM');
			return;
		}

		console.log('INFO:  Opening paginated modal with', flows.length, 'flows, type:', type);

		modalState.currentModalData = flows;
		modalState.modalType = type;
		modalState.currentPage = 1;

		// For live mode the preview array only holds PREVIEW_LIMIT rows.
		// Use the true total returned by the API (state.totalFlows) so that
		// totalPages is computed correctly and the Next button is enabled.
		const trueTotal = (type === 'live') ? state.totalFlows : flows.length;
		modalState.totalPages = Math.max(1, Math.ceil(trueTotal / CONFIG.MODAL_PAGE_SIZE));
		modalState.liveTotal  = (type === 'live') ? trueTotal : 0;

		console.log('INFO:  totalPages =', modalState.totalPages, ', trueTotal =', trueTotal);

		dom.paginatedModal.classList.remove('hidden');
		loadModalPage(1);
		updateModalHeaderInfo();
	}

	async function loadModalPage(page) {
		if (!dom.modalFlowsContainer) return;

		// For live mode: re-fetch from API at correct offset so all pages work,
		// not just the first 20 rows that were loaded into the preview.
		if (modalState.modalType === 'live') {
			const offset = (page - 1) * CONFIG.MODAL_PAGE_SIZE;

			// Show loading spinner
			const loadingDiv = document.createElement('div');
			loadingDiv.className = 'lan-modal-loading';
			const spinner = document.createElement('div');
			spinner.className = 'spinner spinner-primary';
			loadingDiv.appendChild(spinner);
			dom.modalFlowsContainer.innerHTML = '';
			dom.modalFlowsContainer.appendChild(loadingDiv);

			try {
				const response = await fetchLiveData(CONFIG.MODAL_PAGE_SIZE, offset);
				const flows = response.flows;

				dom.modalFlowsContainer.innerHTML = '';

				if (flows.length === 0) {
					const emptyWrap = document.createElement('div');
					emptyWrap.className = 'card--empty-state';
					const msg = document.createElement('p');
					msg.className = 'fw-empty-msg';
					msg.textContent = 'No flows to display';
					emptyWrap.appendChild(msg);
					dom.modalFlowsContainer.appendChild(emptyWrap);
				} else {
					const fragment = document.createDocumentFragment();
					flows.forEach(flow => fragment.appendChild(createFlowCard(flow)));
					dom.modalFlowsContainer.appendChild(fragment);
				}

				modalState.currentPage = page;
				updatePaginationUI(page, flows.length);

			} catch (error) {
				console.error('ERROR:  Modal fetch error:', error);
				const errWrap = document.createElement('div');
				errWrap.className = 'card--error-state';
				const errTitle = document.createElement('p');
				errTitle.className = 'card--error-title';
				errTitle.textContent = 'ERROR';
				const errMsg = document.createElement('p');
				errMsg.className = 'card--error-msg';
				errMsg.textContent = error.message;
				errWrap.appendChild(errTitle);
				errWrap.appendChild(errMsg);
				dom.modalFlowsContainer.innerHTML = '';
				dom.modalFlowsContainer.appendChild(errWrap);
			}
			return;
		}

		// For archive mode: slice in-memory (all results already fetched)
		const startIndex = (page - 1) * CONFIG.MODAL_PAGE_SIZE;
		const endIndex = startIndex + CONFIG.MODAL_PAGE_SIZE;
		const pageFlows = modalState.currentModalData.slice(startIndex, endIndex);

		dom.modalFlowsContainer.innerHTML = '';

		if (pageFlows.length === 0) {
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
			msg.textContent = 'No flows to display';

			emptyWrap.appendChild(svg);
			emptyWrap.appendChild(msg);
			dom.modalFlowsContainer.appendChild(emptyWrap);
		} else {
			const fragment = document.createDocumentFragment();
			pageFlows.forEach(flow => {
				fragment.appendChild(createFlowCard(flow));
			});
			dom.modalFlowsContainer.appendChild(fragment);
		}

		updatePaginationUI(page, pageFlows.length);
	}

	function updateModalHeaderInfo() {
		if (!dom.modalShowingSpan || !dom.modalTotalSpan) return;

		// For live mode use the API-reported total, not the preview array length
		const total = (modalState.modalType === 'live' && modalState.liveTotal)
			? modalState.liveTotal
			: modalState.currentModalData.length;

		const start = Math.min((modalState.currentPage - 1) * CONFIG.MODAL_PAGE_SIZE + 1, total);
		const end   = Math.min(modalState.currentPage * CONFIG.MODAL_PAGE_SIZE, total);

		dom.modalShowingSpan.textContent = `${start}-${end}`;
		dom.modalTotalSpan.textContent   = total;
	}

	function updatePaginationUI(page, flowsLoaded) {
		if (!dom.currentPageSpan || !dom.totalPagesSpan || !dom.prevPageBtn || !dom.nextPageBtn) return;

		modalState.currentPage = page;
		dom.currentPageSpan.textContent = page;
		dom.totalPagesSpan.textContent = modalState.totalPages;
		dom.prevPageBtn.disabled = page <= 1;
		dom.nextPageBtn.disabled = page >= modalState.totalPages;
		updateModalHeaderInfo();
	}

	// ============================================
	// FLOW DETAIL MODAL FUNCTIONS
	// ============================================

	function openFlowDetail(flow) {
		if (!dom.jsonModal || !dom.jsonBeautified) return;

		console.log(' Opening flow detail modal');

		try {
			const formattedJson = JSON.stringify(flow, null, 2);
			dom.jsonBeautified.textContent = formattedJson;
			dom.jsonBeautified.dataset.json = formattedJson;
			dom.jsonModal.classList.remove('hidden');
		} catch (error) {
			console.error('ERROR:  Failed to display flow detail:', error);
			dom.jsonBeautified.textContent = 'Error: Could not display flow data';
		}
	}

	function copyToClipboard(text) {
		if (!text || text.trim() === '') return;

		const btn = dom.copyJsonBtn;
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
	// LIVE FEED FUNCTIONS
	// ============================================

	async function fetchLiveData(limit = CONFIG.PREVIEW_LIMIT, offset = 0) {
		if (liveState.currentRequest) {
			try {
				liveState.currentRequest.controller?.abort();
			} catch (e) {}
		}

		const controller = new AbortController();
		const signal = controller.signal;
		liveState.currentRequest = {
			controller
		};

		try {
			const params = new URLSearchParams({
				limit: limit.toString(),
				offset: offset.toString(),
				_t: Date.now().toString()
			});

			const response = await fetch(`${CONFIG.API.LIVE}?${params}`, {
				signal: signal,
				headers: {
					'Cache-Control': 'no-cache, no-store, must-revalidate',
					'Pragma': 'no-cache',
					'Expires': '0'
				}
			});

			if (!response.ok) {
				throw new Error(`HTTP ${response.status}: ${response.statusText}`);
			}

			const result = await response.json();

			if (result && result.error) {
				throw new Error(result.message || result.error);
			}

			liveState.errorCount = 0;
			liveState.lastPollTime = Date.now();

			return {
				flows: Array.isArray(result) ? result : (result.data || []),
				counts: Array.isArray(result) ? null : result
			};

		} catch (error) {
			if (error.name === 'AbortError') {
				console.log('WARNING:  Live data request aborted');
				return {
					flows: [],
					counts: null
				};
			}

			console.error('ERROR:  Live fetch error:', error);
			liveState.errorCount++;

			if (liveState.errorCount >= liveState.maxErrors) {
				console.warn(`WARNING:  Stopping live polling after ${liveState.maxErrors} errors`);
				stopPolling();
				updateStatus('ERROR', 'Too many errors, polling stopped', 'red');
			}

			throw error;
		} finally {
			liveState.currentRequest = null;
		}
	}

	async function updateLivePreview() {
		if (state.isLoading) return;

		state.isLoading = true;

		try {
			const response = await fetchLiveData(CONFIG.PREVIEW_LIMIT, 0);
			const flows = response.flows;
			const counts = response.counts;

			state.flows = flows;
			state.allFlows = flows;
			state.lastFetchTime = Date.now();
			state.isLoading = false;

			// Update state with total counts from API
			if (counts) {
				state.totalFlows = counts.total || 0;
				state.ipv4Flows = counts.ipv4 || 0;
				state.ipv6Flows = counts.ipv6 || 0;
			} else {
				// Fallback: count from preview flows
				state.totalFlows = flows.length;
				let ipv4Count = 0;
				let ipv6Count = 0;

				flows.forEach(flow => {
					if (isIPv6(flow.ip_src) || isIPv6(flow.ip_dst)) {
						ipv6Count++;
					} else {
						ipv4Count++;
					}
				});

				state.ipv4Flows = ipv4Count;
				state.ipv6Flows = ipv6Count;
			}

			renderPreviewFlows(flows);
			updateStatsDisplay();
			updateStatus('LIVE', 'Real-time feed active', 'green');

			if (dom.viewAllBtn) {
				dom.viewAllBtn.classList.toggle('hidden', flows.length <= CONFIG.PREVIEW_LIMIT);
			}

		} catch (error) {
			console.error('ERROR:  Failed to update live preview:', error);
			state.isLoading = false;

			if (dom.mainContainer) {
				// Build error state -- no inline onclick (CSP: script-src 'self')
				const errWrap = document.createElement('div');
				errWrap.className = 'card--error-state';

				const errTitle = document.createElement('p');
				errTitle.className = 'card--error-title';
				errTitle.textContent = 'ERROR';

				const errMsg = document.createElement('p');
				errMsg.className = 'card--error-msg';
				errMsg.textContent = error.message;

				const retryBtn = document.createElement('button');
				retryBtn.className = 'btn--retry';
				retryBtn.textContent = 'Try Again';
				retryBtn.dataset.action = 'retry-live';

				errWrap.appendChild(errTitle);
				errWrap.appendChild(errMsg);
				errWrap.appendChild(retryBtn);

				dom.mainContainer.innerHTML = '';
				dom.mainContainer.appendChild(errWrap);
			}

			updateStatus('ERROR', 'Failed to fetch live data', 'red');
		}
	}

	function renderPreviewFlows(flows) {
		if (!dom.mainContainer) return;

		const fragment = document.createDocumentFragment();

		if (flows.length === 0) {
			const emptyDiv = document.createElement('div');
			emptyDiv.className = 'card--empty-state';

			const msg1 = document.createElement('p');
			msg1.className = 'fw-empty-msg';
			msg1.textContent = 'NO LIVE TRAFFIC';

			const msg2 = document.createElement('p');
			msg2.className = 'fw-empty-hint';
			msg2.textContent = 'Waiting for external traffic...';

			emptyDiv.appendChild(msg1);
			emptyDiv.appendChild(msg2);
			fragment.appendChild(emptyDiv);
		} else {
			flows.forEach(flow => {
				fragment.appendChild(createFlowCard(flow));
			});
		}

		dom.mainContainer.innerHTML = '';
		dom.mainContainer.appendChild(fragment);
	}

	function startPolling() {
		if (liveState.isPolling) return;

		console.log('INFO:  Starting live polling...');
		liveState.isPolling = true;

		updateLivePreview();

		state.refreshInterval = setInterval(() => {
			if (!state.isLoading) {
				updateLivePreview();
			}
		}, CONFIG.AUTO_REFRESH_INTERVAL);

		updateStatus('LIVE', 'Polling every 10s', 'green');

		// Reset button to live state
		if (dom.viewLiveBtn) {
			dom.viewLiveBtn.classList.add('tab-btn--active');
			dom.viewLiveBtn.classList.remove('tab-btn--inactive');
		}
		// Reset the search button too
		if (dom.openSearchModalBtn) {
			dom.openSearchModalBtn.classList.add('tab-btn--inactive');
			dom.openSearchModalBtn.classList.remove('tab-btn--active');
		}
		if (dom.statusBadge) dom.statusBadge.classList.remove('hidden');
	}

	function stopPolling() {
		if (!liveState.isPolling) return;

		console.log(' Stopping live polling...');
		liveState.isPolling = false;

		if (state.refreshInterval) {
			clearInterval(state.refreshInterval);
			state.refreshInterval = null;
		}

		if (liveState.currentRequest) {
			try {
				liveState.currentRequest.controller?.abort();
			} catch (e) {}
			liveState.currentRequest = null;
		}
	}

	function forceRefresh() {
		console.log('INFO:  Manual refresh triggered');
		updateLivePreview();
	}

	// ============================================
	// STATS FUNCTIONS
	// ============================================

	function updateStatsDisplay() {
		if (!dom.totalFlows || !dom.ipv4Flows || !dom.ipv6Flows) return;

		dom.totalFlows.textContent = state.totalFlows;
		dom.ipv4Flows.textContent = state.ipv4Flows;
		dom.ipv6Flows.textContent = state.ipv6Flows;

		if (dom.lastUpdateTime) {
			const now = new Date();
			dom.lastUpdateTime.textContent = now.toLocaleTimeString([], {
				hour: '2-digit',
				minute: '2-digit',
				second: '2-digit'
			});
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
	}

	// ============================================
	// FILTER FUNCTIONS
	// ============================================

	function resetFilters() {
		console.log(' Clearing all filters');
		state.filters = {};
		startPolling();
	}

	// ============================================
	// DOM CACHING & INITIALIZATION
	// ============================================

	function cacheDOMElements() {
		console.log(' Caching DOM elements...');

		try {
			dom.mainContainer = document.getElementById('main-container');
			dom.totalFlows = document.getElementById('total-flows');
			dom.ipv4Flows = document.getElementById('ipv4-flows');
			dom.ipv6Flows = document.getElementById('ipv6-flows');
			dom.statusIndicator = document.getElementById('status-indicator');
			dom.statusText = document.getElementById('status-text');
			dom.statusDetail = document.getElementById('status-detail');
			dom.statusBadge = document.getElementById('status-badge');
			dom.lastUpdateTime = document.getElementById('last-update-time');
			dom.viewAllBtn = document.getElementById('view-all-btn');
			dom.viewLiveBtn = document.getElementById('view-live-btn');
			dom.openSearchModalBtn = document.getElementById('open-search-modal');
			dom.searchModal = document.getElementById('search-modal');
			dom.closeSearchModalBtn = document.getElementById('close-search-modal');
			dom.searchForm = document.getElementById('search-form');
			dom.dateFromSelect = document.getElementById('date-from');
			dom.dateToSelect = document.getElementById('date-to');
			dom.paginatedModal = document.getElementById('paginated-modal');
			dom.closePaginatedModalBtn = document.getElementById('close-paginated-modal');
			dom.modalFlowsContainer = document.getElementById('modal-flows-container');
			dom.prevPageBtn = document.getElementById('prev-page');
			dom.nextPageBtn = document.getElementById('next-page');
			dom.currentPageSpan = document.getElementById('current-page');
			dom.totalPagesSpan = document.getElementById('total-pages');
			dom.modalShowingSpan = document.getElementById('modal-showing');
			dom.modalTotalSpan = document.getElementById('modal-total');
			dom.jsonModal = document.getElementById('json-modal');
			dom.closeModalBtn = document.getElementById('close-modal');
			dom.jsonBeautified = document.getElementById('json-beautified');
			dom.copyJsonBtn = document.getElementById('copy-json-btn');

			console.log(`OK:  DOM elements cached: ${Object.keys(dom).length} elements`);
			console.log(`OK:  Main container found: ${!!dom.mainContainer}`);
			console.log(`OK:  Search modal found: ${!!dom.searchModal}`);
			console.log(`OK:  Open search button found: ${!!dom.openSearchModalBtn}`);

			return !!dom.mainContainer;
		} catch (error) {
			console.error('ERROR:  Failed to cache DOM elements:', error);
			return false;
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

		state.isViewReady = true;
		initializationComplete = true;

		console.log('OK:  EXTERNAL interface fully initialized');
		startPolling();
	}

	function populateDateSelects() {
		if (!dom.dateFromSelect || !dom.dateToSelect) {
			console.warn('WARNING:  Date selects not found, skipping population');
			return;
		}

		console.log(' Populating date selects with last 7 days');

		const dates = getLast7Days();

		dom.dateFromSelect.innerHTML = '';
		dom.dateToSelect.innerHTML = '';

		dates.forEach(date => {
			const optionFrom = document.createElement('option');
			optionFrom.value = date.value;
			optionFrom.textContent = date.display;
			dom.dateFromSelect.appendChild(optionFrom);

			const optionTo = document.createElement('option');
			optionTo.value = date.value;
			optionTo.textContent = date.display;
			dom.dateToSelect.appendChild(optionTo);
		});

		if (dates.length > 0) {
			dom.dateFromSelect.value = dates[1].value;
			dom.dateToSelect.value = dates[0].value;
		}

		console.log(`OK:  Populated ${dates.length} dates`);
	}

	// ============================================
	// EVENT LISTENERS - CLEAN VERSION
	// ============================================

	function setupEventListeners() {
		console.log(' Setting up event listeners...');

		// Core modal closing
		if (dom.searchModal) {
			dom.searchModal.addEventListener('click', (e) => {
				if (e.target === dom.searchModal) {
					dom.searchModal.classList.remove('filter-modal--open');
				}
			});
		}

		if (dom.paginatedModal) {
			dom.paginatedModal.addEventListener('click', (e) => {
				if (e.target === dom.paginatedModal) {
					dom.paginatedModal.classList.add('hidden');
					startPolling(); // Restart live feed when modal closes
				}
			});
		}

		if (dom.jsonModal) {
			dom.jsonModal.addEventListener('click', (e) => {
				if (e.target === dom.jsonModal) {
					dom.jsonModal.classList.add('hidden');
				}
			});
		}

		// Source toggle buttons
		if (dom.viewLiveBtn) {
			dom.viewLiveBtn.addEventListener('click', () => {
				startPolling();
				updateStatus('LIVE', 'Real-time feed active', 'green');
			});
		}

		if (dom.openSearchModalBtn) {
			dom.openSearchModalBtn.addEventListener('click', () => {
				console.log(' Open search modal button clicked');
				if (dom.searchModal) {
					dom.searchModal.classList.add('filter-modal--open');
				}
			});
		}

		// Close buttons
		if (dom.closeSearchModalBtn) {
			dom.closeSearchModalBtn.addEventListener('click', () => {
				if (dom.searchModal) {
					dom.searchModal.classList.remove('filter-modal--open');
				}
			});
		}

		// Footer cancel button (close-search-modal-footer)
		const closeSearchFooterBtn = document.getElementById('close-search-modal-footer');
		if (closeSearchFooterBtn) {
			closeSearchFooterBtn.addEventListener('click', () => {
				if (dom.searchModal) {
					dom.searchModal.classList.remove('filter-modal--open');
				}
			});
		}

		if (dom.closePaginatedModalBtn) {
			dom.closePaginatedModalBtn.addEventListener('click', () => {
				if (dom.paginatedModal) {
					dom.paginatedModal.classList.add('hidden');
					startPolling(); // Restart live feed
				}
			});
		}

		if (dom.closeModalBtn) {
			dom.closeModalBtn.addEventListener('click', () => {
				if (dom.jsonModal) dom.jsonModal.classList.add('hidden');
			});
		}

		// Pagination controls
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

		// Copy JSON button
		if (dom.copyJsonBtn) {
			dom.copyJsonBtn.addEventListener('click', () => {
				if (dom.jsonBeautified) {
					const jsonText = dom.jsonBeautified.dataset.json || dom.jsonBeautified.textContent;
					copyToClipboard(jsonText);
				}
			});
		}

		// View All button
		if (dom.viewAllBtn) {
			dom.viewAllBtn.addEventListener('click', () => {
				openPaginatedModal(state.allFlows, 'live');
			});
		}

		// Search form submission - CLEAN VERSION
		if (dom.searchForm) {
			console.log(' Adding submit listener to search form');
			dom.searchForm.addEventListener('submit', async function(e) {
				e.preventDefault();
				console.log(' Filter search submitted');

				if (dom.searchModal) {
					dom.searchModal.classList.remove('filter-modal--open');
				}

				// Extract filters
				state.filters = extractFiltersFromForm(this);
				console.log(' Applied filters:', state.filters);

				// Stop polling for search
				stopPolling();

				// Update UI for search state
				if (dom.viewLiveBtn) {
					dom.viewLiveBtn.classList.remove('tab-btn--active');
					dom.viewLiveBtn.classList.add('tab-btn--inactive');
				}
				if (dom.openSearchModalBtn) {
					dom.openSearchModalBtn.classList.remove('tab-btn--inactive');
					dom.openSearchModalBtn.classList.add('tab-btn--active');
				}
				if (dom.statusBadge) dom.statusBadge.classList.add('hidden');

				updateStatus('SEARCHING', 'Querying archives...', 'blue');

				// Build query for API
				const params = new URLSearchParams();
				params.append('limit', 200);
				params.append('offset', '0');

				if (state.filters.date_from) {
					params.append('date', state.filters.date_from);
				}
				if (state.filters.start_hr) {
					params.append('hr', state.filters.start_hr);
				}
				if (state.filters.start_min) {
					params.append('min', state.filters.start_min);
				}
				if (state.filters.proto) {
					params.append('proto', state.filters.proto);
				}
				if (state.filters.src) {
					params.append('src', state.filters.src);
				}
				if (state.filters.dst) {
					params.append('dst', state.filters.dst);
				}
				if (state.filters.src_port) {
					params.append('port', state.filters.src_port);
				} else if (state.filters.dst_port) {
					params.append('port', state.filters.dst_port);
				}

				console.log(' Archive search params:', params.toString());

				// Fetch archive data
				try {
					state.isLoading = true;

					params.append('_t', Date.now().toString());

					console.log(' Fetching archive data from:', `${CONFIG.API.ARCHIVE}?${params.toString()}`);

					const response = await fetch(`${CONFIG.API.ARCHIVE}?${params}`, {
						headers: {
							'Cache-Control': 'no-cache, no-store, must-revalidate',
							'Pragma': 'no-cache',
							'Expires': '0'
						}
					});

					if (!response.ok) {
						throw new Error(`HTTP ${response.status}: ${response.statusText}`);
					}

					const result = await response.json();

					if (result && result.error) {
						throw new Error(result.message || result.error);
					}

					const allFlows = Array.isArray(result) ? result : (result.data || []);

					console.log(' Found', allFlows.length, 'archive flows');

					// Store all flows
					state.allFlows = allFlows;

					// Update counts
					if (result && result.metadata && result.metadata.total_matches !== undefined) {
						state.totalFlows = result.metadata.total_matches;
					} else {
						state.totalFlows = allFlows.length;
					}

					// Count IPv4/IPv6
					let ipv4Count = 0;
					let ipv6Count = 0;

					allFlows.forEach(flow => {
						if (isIPv6(flow.ip_src) || isIPv6(flow.ip_dst)) {
							ipv6Count++;
						} else {
							ipv4Count++;
						}
					});

					state.ipv4Flows = ipv4Count;
					state.ipv6Flows = ipv6Count;

					updateStatsDisplay();
					updateStatus('ARCHIVE', `Found ${allFlows.length} historical flows`, 'blue');

					// Show "View All" button
					if (dom.viewAllBtn) {
						dom.viewAllBtn.classList.toggle('hidden', allFlows.length <= CONFIG.PREVIEW_LIMIT);
					}

					// AUTO-OPEN MODAL WITH RESULTS
					if (allFlows.length > 0) {
						console.log('INFO:  Auto-opening paginated modal with archive results');
						openPaginatedModal(allFlows, 'archive');
					} else {
						// If no results, show message and restart live
						const noResultsWrap = document.createElement('div');
						noResultsWrap.className = 'card--empty-state';

						const noMsg1 = document.createElement('p');
						noMsg1.className = 'fw-empty-msg';
						noMsg1.textContent = 'NO ARCHIVE RESULTS FOUND';

						const noMsg2 = document.createElement('p');
						noMsg2.className = 'fw-empty-hint';
						noMsg2.textContent = 'Try different date/time or filter criteria';

						noResultsWrap.appendChild(noMsg1);
						noResultsWrap.appendChild(noMsg2);
						dom.mainContainer.innerHTML = '';
						dom.mainContainer.appendChild(noResultsWrap);

						// Restart live polling after showing message
						setTimeout(() => startPolling(), 3000);
					}

				} catch (error) {
					console.error('ERROR:  Failed to fetch archive data:', error);

					// Show error and restart live
					const archErrWrap = document.createElement('div');
					archErrWrap.className = 'card--error-state';

					const archErrTitle = document.createElement('p');
					archErrTitle.className = 'card--error-title';
					archErrTitle.textContent = 'ARCHIVE SEARCH ERROR';

					const archErrMsg = document.createElement('p');
					archErrMsg.className = 'card--error-msg';
					archErrMsg.textContent = error.message;

					archErrWrap.appendChild(archErrTitle);
					archErrWrap.appendChild(archErrMsg);
					dom.mainContainer.innerHTML = '';
					dom.mainContainer.appendChild(archErrWrap);

					// Restart live polling after error
					setTimeout(() => startPolling(), 3000);
				} finally {
					state.isLoading = false;
				}
			});
		}

		// Delegated listener for dynamically-created buttons in mainContainer
		// (e.g. the "Try Again" button rendered on fetch error -- no inline onclick)
		if (dom.mainContainer) {
			dom.mainContainer.addEventListener('click', (e) => {
				const btn = e.target.closest('[data-action]');
				if (!btn) return;
				if (btn.dataset.action === 'retry-live') {
					forceRefresh();
				}
			});
		}

		console.log('OK:  Event listeners set up');
	}

	// ============================================
	// GLOBAL EXPORTS
	// ============================================

	window.initializeExternalView = attemptInitialization;
	window.forceRefresh = forceRefresh;
	window.openPaginatedModal = openPaginatedModal;
	window.resetFilters = resetFilters;

	// ============================================
	// STARTUP
	// ============================================

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', attemptInitialization);
	} else {
		setTimeout(attemptInitialization, 100);
	}

	console.log('OK:  EXTERNAL interface loaded');
})();
