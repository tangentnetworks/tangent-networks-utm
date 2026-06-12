// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

// System Mail Viewer Module - Full Production Logic Restored
(function() {
	'use strict';

	if (!document.getElementById('mail-list')) {
		console.log('LOG: Mail list element not found, exiting.');
		return;
	}

	const CONFIG = Object.freeze({
		refreshInterval: 30000,
		apiEndpoint: '/cgi-bin/mail.pl',
		csrfEndpoint: '/cgi-bin/control.pl/api/csrf',
		itemsPerPageDesktop: 20,
		itemsPerPageMobile: 10
	});

	const state = {
		allMail: [],
		currentMailId: null,
		currentPage: 1,
		totalPages: 1,
		itemsPerPage: 20,
		selectedIds: new Set(),
		autoRefreshInterval: null,
		isInitialized: false,
		csrfToken: null,
		isLoading: false,
		deleteCallback: null
	};

	const elements = {};

	function isMobile() {
		const result = window.innerWidth < 768;
		console.log('DEBUG: isMobile() ->', result);
		return result;
	}

	function updateItemsPerPage() {
		console.log('INFO: Updating items per page.');
		state.itemsPerPage = isMobile() ? CONFIG.itemsPerPageMobile : CONFIG.itemsPerPageDesktop;
		state.totalPages = Math.ceil(state.allMail.length / state.itemsPerPage);
		if (state.currentPage > state.totalPages) state.currentPage = Math.max(1, state.totalPages);
		console.log('DEBUG: Items per page:', state.itemsPerPage, 'Total pages:', state.totalPages);
	}

	async function fetchCSRFToken() {
		console.log('INFO: Fetching CSRF token...');
		try {
			const response = await fetch(CONFIG.csrfEndpoint, { credentials: 'same-origin' });
			const data = await response.json();
			if (data.success && data.token) {
				state.csrfToken = data.token;
				console.log('INFO: CSRF token fetched successfully.');
				return true;
			} else {
				console.log('ERROR: CSRF token not found in response.');
			}
		} catch (e) {
			console.error('ERROR: CSRF fetch failed:', e);
		}
		return false;
	}

	function cacheElements() {
		console.log('INFO: Caching DOM elements.');
		const ids = [
			'mail-list', 'no-mail', 'stat-total', 'stat-unread', 'stat-high', 'stat-size',
			'mail-count', 'mail-modal', 'modal-subject', 'modal-from', 'modal-from-full',
			'modal-date', 'modal-size', 'modal-body', 'refresh-mail-btn', 'copy-email-btn',
			'close-modal-btn', 'select-all-checkbox', 'batch-toolbar', 'selected-count',
			'deselect-all-btn', 'batch-mark-read-btn', 'batch-delete-btn', 'pagination-controls',
			'prev-page-btn', 'next-page-btn', 'current-page', 'total-pages', 'page-showing',
			'page-total', 'delete-confirm-modal', 'delete-confirm-message', 'delete-confirm-btn', 'delete-cancel-btn'
		];
		ids.forEach(id => {
			elements[id] = document.getElementById(id);
			if (!elements[id]) console.log('NOTICE: Element not found:', id);
		});
	}

	function bindEvents() {
		console.log('INFO: Binding UI events.');
		if (elements['refresh-mail-btn']) elements['refresh-mail-btn'].addEventListener('click', () => {
			console.log('LOG: Refresh button clicked.');
			const btn = elements['refresh-mail-btn'];
			const svg = btn.querySelector('svg');
			btn.classList.add('btn--active');
			if (svg) svg.classList.add('icon--spinning');

			loadMail().finally(() => {
				btn.classList.remove('btn--active');
				if (svg) svg.classList.remove('icon--spinning');
			});
		});
		if (elements['select-all-checkbox']) elements['select-all-checkbox'].addEventListener('change', handleSelectAll);
		if (elements['deselect-all-btn']) elements['deselect-all-btn'].addEventListener('click', () => {
			console.log('LOG: Deselect all button clicked.');
			deselectAll();
		});
		if (elements['batch-mark-read-btn']) elements['batch-mark-read-btn'].addEventListener('click', () => {
			console.log('LOG: Batch mark as read button clicked.');
			batchMarkAsRead();
		});
		if (elements['batch-delete-btn']) elements['batch-delete-btn'].addEventListener('click', () => {
			console.log('LOG: Batch delete button clicked.');
			batchDelete();
		});
		if (elements['prev-page-btn']) elements['prev-page-btn'].addEventListener('click', () => {
			console.log('LOG: Previous page button clicked.');
			changePage(-1);
		});
		if (elements['next-page-btn']) elements['next-page-btn'].addEventListener('click', () => {
			console.log('LOG: Next page button clicked.');
			changePage(1);
		});
		if (elements['copy-email-btn']) elements['copy-email-btn'].addEventListener('click', () => {
			console.log('LOG: Copy email button clicked.');
			copyEmail();
		});
		if (elements['close-modal-btn']) elements['close-modal-btn'].addEventListener('click', () => {
			console.log('LOG: Close modal button clicked.');
			closeViewModal();
		});
		if (elements['delete-confirm-btn']) elements['delete-confirm-btn'].addEventListener('click', confirmDelete);
		if (elements['delete-cancel-btn']) elements['delete-cancel-btn'].addEventListener('click', () => {
			console.log('LOG: Delete cancel button clicked.');
			closeDeleteModal();
		});

		window.addEventListener('resize', debounce(() => {
			console.log('DEBUG: Window resized, updating items per page.');
			const old = state.itemsPerPage;
			updateItemsPerPage();
			if (old !== state.itemsPerPage) renderCurrentPage();
		}, 250));
	}

	async function loadMail() {
		if (state.isLoading) {
			console.log('NOTICE: Load already in progress, skipping.');
			return;
		}
		state.isLoading = true;
		console.log('INFO: Loading mail...');
		try {
			const response = await fetch(`${CONFIG.apiEndpoint}?action=list`, { credentials: 'same-origin' });
			const data = await response.json();
			if (data.status === 'success') {
				state.allMail = data.emails || [];
				console.log('INFO: Mail loaded successfully. Total:', state.allMail.length);
				updateItemsPerPage();
				updateUI();
			} else {
				console.log('ERROR: Failed to load mail:', data.message);
				showNoMail();
			}
		} catch (e) {
			console.error('ERROR: Exception while loading mail:', e);
			showNoMail();
		} finally {
			state.isLoading = false;
			console.log('INFO: Mail load complete.');
		}
	}

	function showDeleteModal(msg, onConfirm) {
		console.log('INFO: Showing delete confirmation modal:', msg);
		if (elements['delete-confirm-message']) elements['delete-confirm-message'].textContent = msg;
		state.deleteCallback = onConfirm;
		elements['delete-confirm-modal'].classList.remove('hidden');
		document.body.classList.add('tn-modal-open');
	}

	function closeDeleteModal() {
		console.log('LOG: Closing delete confirmation modal.');
		elements['delete-confirm-modal'].classList.add('hidden');
		document.body.classList.remove('tn-modal-open');
	}

	async function confirmDelete() {
		console.log('LOG: Delete confirmed.');
		if (state.deleteCallback) {
			closeDeleteModal();
			await state.deleteCallback();
		}
	}

	async function deleteEmail(file) {
		console.log('INFO: Deleting email:', file);
		try {
			if (!state.csrfToken) {
				console.log('NOTICE: No CSRF token, fetching...');
				await fetchCSRFToken();
			}
			const response = await fetch(CONFIG.apiEndpoint, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ action: 'delete', file: file, csrf_token: state.csrfToken }),
				credentials: 'same-origin'
			});
			const data = await response.json();
			if (data.status === 'success') {
				console.log('INFO: Email deleted successfully:', file);
				state.allMail = state.allMail.filter(m => m.file !== file);
				state.selectedIds.delete(file);
				updateItemsPerPage();
				updateUI();
				if (state.currentMailId === file) closeViewModal();
			} else {
				console.log('ERROR: Failed to delete email:', data.message);
			}
		} catch (e) {
			console.error('ERROR: Exception while deleting email:', e);
		}
	}

	async function batchDelete() {
		if (state.selectedIds.size === 0) {
			console.log('NOTICE: No emails selected for batch delete.');
			return;
		}
		console.log('INFO: Batch deleting', state.selectedIds.size, 'emails.');
		showDeleteModal(`Delete ${state.selectedIds.size} messages?`, async () => {
			const ids = Array.from(state.selectedIds);
			for (const id of ids) await deleteEmail(id);
			state.selectedIds.clear();
			updateUI();
		});
	}

	function batchMarkAsRead() {
		console.log('INFO: Marking', state.selectedIds.size, 'emails as read.');
		state.selectedIds.forEach(id => {
			const m = state.allMail.find(x => x.file === id);
			if (m) m.read = true;
		});
		state.selectedIds.clear();
		updateUI();
	}

	function handleSelectAll(e) {
		console.log('LOG: Select all checkbox changed:', e.target.checked);
		const start = (state.currentPage - 1) * state.itemsPerPage;
		const end = Math.min(start + state.itemsPerPage, state.allMail.length);
		const page = state.allMail.slice(start, end);
		page.forEach(m => e.target.checked ? state.selectedIds.add(m.file) : state.selectedIds.delete(m.file));
		updateSelectionUI();
	}

	function deselectAll() {
		console.log('LOG: Deselecting all emails.');
		state.selectedIds.clear();
		if (elements['select-all-checkbox']) elements['select-all-checkbox'].checked = false;
		updateSelectionUI();
	}

	function handleCheckboxChange(e, id) {
		e.stopPropagation();
		console.log('LOG: Mail checkbox changed:', id, e.target.checked);
		e.target.checked ? state.selectedIds.add(id) : state.selectedIds.delete(id);
		updateSelectionUI();
	}

	function updateSelectionUI() {
		console.log('DEBUG: Updating selection UI. Selected:', state.selectedIds.size);
		if (elements['batch-toolbar']) {
			state.selectedIds.size > 0 ? elements['batch-toolbar'].classList.remove('hidden') : elements['batch-toolbar'].classList.add('hidden');
		}
		if (elements['selected-count']) elements['selected-count'].textContent = state.selectedIds.size;
		
		// Update all checkboxes and their parent rows
		document.querySelectorAll('.mail-checkbox').forEach(cb => {
			const mailId = cb.dataset.mailId;
			const isSelected = state.selectedIds.has(mailId);
			const listItem = cb.closest('li');
			
			// Update checkbox
			cb.checked = isSelected;
			
			// Update row background
			if (listItem) {
				if (isSelected) {
					listItem.classList.add('mail-item--selected');
					listItem.classList.remove('mail-item--unread');
				} else {
					listItem.classList.remove('mail-item--selected');
					// Restore unread styling if applicable
					const mail = state.allMail.find(m => m.file === mailId);
					if (mail && !mail.read) {
						listItem.classList.add('mail-item--unread');
					}
				}
			}
		});
		
		// Update select-all checkbox state
		if (elements['select-all-checkbox']) {
			const start = (state.currentPage - 1) * state.itemsPerPage;
			const end = Math.min(start + state.itemsPerPage, state.allMail.length);
			const pageItems = state.allMail.slice(start, end);
			const allPageSelected = pageItems.length > 0 && pageItems.every(m => state.selectedIds.has(m.file));
			elements['select-all-checkbox'].checked = allPageSelected;
		}
	}

	function updateUI() {
		if (!state.isInitialized) {
			console.log('NOTICE: UI update skipped, not initialized.');
			return;
		}
		console.log('INFO: Updating UI.');
		updateStats();
		renderCurrentPage();
		updateSelectionUI();
	}

	function updateStats() {
		console.log('DEBUG: Updating stats.');
		const unread = state.allMail.filter(m => !m.read).length;
		const highPriority = state.allMail.filter(m => m.priority === 'high').length;
		const totalSize = state.allMail.reduce((sum, m) => sum + (m.size || 0), 0);
		
		if (elements['stat-total']) elements['stat-total'].textContent = state.allMail.length;
		if (elements['stat-unread']) elements['stat-unread'].textContent = unread;
		if (elements['stat-high']) elements['stat-high'].textContent = highPriority;
		if (elements['stat-size']) elements['stat-size'].textContent = formatBytes(totalSize);
		if (elements['mail-count']) elements['mail-count'].textContent = `${state.allMail.length} messages`;
	}

	function renderCurrentPage() {
		if (!elements['mail-list']) {
			console.log('ERROR: Mail list element not found.');
			return;
		}
		console.log('INFO: Rendering current page:', state.currentPage);
		const start = (state.currentPage - 1) * state.itemsPerPage;
		const end = Math.min(start + state.itemsPerPage, state.allMail.length);
		const data = state.allMail.slice(start, end);

		if (state.allMail.length === 0) {
			showNoMail();
			return;
		}

		elements['no-mail'].classList.add('hidden');
		const fragment = document.createDocumentFragment();
		data.forEach(m => fragment.appendChild(createMailItem(m)));
		elements['mail-list'].innerHTML = '';
		elements['mail-list'].appendChild(fragment);
		bindMailItemEvents();

		if (elements['pagination-controls']) {
			state.allMail.length > state.itemsPerPage ? elements['pagination-controls'].classList.remove('hidden') : elements['pagination-controls'].classList.add('hidden');
		}
		if (elements['page-showing']) elements['page-showing'].textContent = `${start + 1}-${end}`;
		if (elements['page-total']) elements['page-total'].textContent = state.allMail.length;
		if (elements['current-page']) elements['current-page'].textContent = state.currentPage;
		if (elements['total-pages']) elements['total-pages'].textContent = state.totalPages;

		// Update pagination button states
		updatePaginationButtons();
	}

	function createMailItem(m) {
		const isSelected = state.selectedIds.has(m.file);

		const li = document.createElement('li');
		li.className = 'mail-item';
		if (!m.read)    li.classList.add('mail-item--unread');
		if (isSelected) li.classList.add('mail-item--selected');
		li.dataset.mailId = m.file;

		const row = document.createElement('div');
		row.className = 'mail-item-row';

		// Checkbox
		const cb = document.createElement('input');
		cb.type = 'checkbox';
		cb.className = 'mail-checkbox';
		cb.dataset.mailId = m.file;
		if (isSelected) cb.checked = true;

		// Clickable content area
		const content = document.createElement('div');
		content.className = 'mail-item-content';
		content.dataset.action = 'view';

		const subjectLine = document.createElement('div');
		subjectLine.className = 'mail-item-subject-line';

		const dot = document.createElement('span');
		dot.className = m.read ? 'mail-dot--read' : 'mail-dot--unread';

		const subject = document.createElement('span');
		subject.className = 'mail-item-subject';
		subject.textContent = m.subject;

		subjectLine.appendChild(dot);
		subjectLine.appendChild(subject);

		const from = document.createElement('div');
		from.className = 'mail-item-from';
		from.textContent = m.from;

		content.appendChild(subjectLine);
		content.appendChild(from);

		// Delete button
		const actions = document.createElement('div');
		actions.className = 'mail-item-actions';

		const delBtn = document.createElement('button');
		delBtn.className = 'delete-mail-btn';
		delBtn.dataset.file = m.file;

		const delSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
		delSvg.setAttribute('width', '16');
		delSvg.setAttribute('height', '16');
		delSvg.setAttribute('fill', 'none');
		delSvg.setAttribute('stroke', 'currentColor');
		delSvg.setAttribute('stroke-width', '2');
		delSvg.setAttribute('viewBox', '0 0 24 24');
		const delPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
		delPath.setAttribute('d', 'M3 6h18m-2 0v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6m3 0V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2');
		delSvg.appendChild(delPath);
		delBtn.appendChild(delSvg);
		actions.appendChild(delBtn);

		row.appendChild(cb);
		row.appendChild(content);
		row.appendChild(actions);
		li.appendChild(row);

		return li;
	}

	function bindMailItemEvents() {
		console.log('INFO: Binding mail item events.');
		document.querySelectorAll('.mail-checkbox').forEach(cb => cb.addEventListener('change', e => handleCheckboxChange(e, cb.dataset.mailId)));
		document.querySelectorAll('[data-action="view"]').forEach(row => row.addEventListener('click', () => {
			console.log('LOG: Mail item clicked:', row.closest('li').dataset.mailId);
			viewMail(row.closest('li').dataset.mailId);
		}));
		document.querySelectorAll('.delete-mail-btn').forEach(btn => btn.addEventListener('click', e => {
			e.stopPropagation();
			console.log('LOG: Delete mail button clicked:', btn.dataset.file);
			showDeleteModal('Delete this message?', () => deleteEmail(btn.dataset.file));
		}));
	}

	async function viewMail(id) {
		console.log('INFO: Viewing mail:', id);
		const m = state.allMail.find(x => x.file === id);
		if (!m) {
			console.log('ERROR: Mail not found:', id);
			return;
		}
		state.currentMailId = id;
		if (!m.read) {
			m.read = true;
			updateUI();
		}
		try {
			const res = await fetch(`/data/inbox/mail/${id}`);
			const content = await res.text();
			elements['modal-subject'].textContent = m.subject;
			elements['modal-from-full'].textContent = m.from;
			elements['modal-date'].textContent = new Date(m.timestamp * 1000).toLocaleString();
			elements['modal-size'].textContent = formatBytes(m.size);
			elements['modal-body'].textContent = content;
			elements['mail-modal'].classList.remove('hidden');
			document.body.classList.add('tn-modal-open');
		} catch (e) {
			console.error('ERROR: Failed to load mail content:', e);
		}
	}

	function closeViewModal() {
		console.log('LOG: Closing mail view modal.');
		elements['mail-modal'].classList.add('hidden');
		document.body.classList.remove('tn-modal-open');
	}

	function copyEmail() {
		console.log('LOG: Copying email content to clipboard.');
		navigator.clipboard.writeText(elements['modal-body'].textContent).then(() => alert('Copied!'));
	}

	function updatePaginationButtons() {
		console.log('DEBUG: Updating pagination button states.');
		const prevBtn = elements['prev-page-btn'];
		const nextBtn = elements['next-page-btn'];

		if (!prevBtn || !nextBtn) return;

		// Update Previous button
		if (state.currentPage <= 1) {
			prevBtn.disabled = true;
			prevBtn.classList.remove('btn--paginate-on');
			prevBtn.classList.add('btn--paginate-off');
		} else {
			prevBtn.disabled = false;
			prevBtn.classList.remove('btn--paginate-off');
			prevBtn.classList.add('btn--paginate-on');
		}

		// Update Next button
		if (state.currentPage >= state.totalPages) {
			nextBtn.disabled = true;
		} else {
			nextBtn.disabled = false;
		}
	}

	function changePage(delta) {
		const n = state.currentPage + delta;
		console.log('LOG: Changing page by', delta, 'New page:', n);
		if (n >= 1 && n <= state.totalPages) {
			state.currentPage = n;
			renderCurrentPage();
		} else {
			console.log('NOTICE: Page change out of bounds.');
		}
	}

	function showNoMail() {
		console.log('INFO: Showing "no mail" message.');
		elements['mail-list'].innerHTML = '';
		elements['no-mail'].classList.remove('hidden');
	}

	function formatBytes(b) {
		if (b === 0) return '0 B';
		const k = 1024, s = ['B', 'KB', 'MB', 'GB'], i = Math.floor(Math.log(b) / Math.log(k));
		return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + s[i];
	}

	function escapeHtml(t) {
		const d = document.createElement('div');
		d.textContent = t;
		return d.innerHTML;
	}

	function debounce(f, w) {
		let t;
		return (...a) => { clearTimeout(t); t = setTimeout(() => f(...a), w); };
	}

	async function init() {
		console.log('INFO: Initializing mail viewer.');
		cacheElements();
		bindEvents();
		state.isInitialized = true;
		updateItemsPerPage();
		await fetchCSRFToken();
		await loadMail();
		state.autoRefreshInterval = setInterval(() => {
			console.log('INFO: Auto-refreshing mail.');
			loadMail();
		}, CONFIG.refreshInterval);
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
