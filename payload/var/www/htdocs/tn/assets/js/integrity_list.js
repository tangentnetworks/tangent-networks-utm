// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * File List Accordion Module - Standalone
 * Handles all file list rendering without polling
 */

(function() {
	'use strict';

	const CONFIG = {
		FILES_API: '/cgi-bin/integrity_files.pl',
		CSRF_API: '/cgi-bin/control.pl/api/csrf'
	};

	let csrfToken = null;

	const FileAccordion = {
		initialized: false,
		loadedChecks: new Set()
	};

	async function fetchCSRFToken() {
		if (csrfToken) return csrfToken;
		try {
			const response = await fetch(CONFIG.CSRF_API);
			if (!response.ok) throw new Error('CSRF fetch failed');
			const data = await response.json();
			if (data.token) {
				csrfToken = data.token;
				window.csrfToken = csrfToken;
			}
			return csrfToken;
		} catch (err) {
			console.error('[FileAccordion] Failed to fetch CSRF token:', err);
			return null;
		}
	}

	async function init() {
		if (FileAccordion.initialized) return;

		console.log('[FileAccordion] Initializing');

		await fetchCSRFToken();

		const accordionButtons = document.querySelectorAll('.files-accordion-btn');
		accordionButtons.forEach(button => {
			if (button.dataset.accordionBound) return;
			button.addEventListener('click', handleAccordionClick);
			button.dataset.accordionBound = 'true';
		});

		FileAccordion.initialized = true;
		console.log('[FileAccordion] Initialized');
	}

	async function handleAccordionClick(event) {
		const button = event.currentTarget;
		const check = button.dataset.check || 'all';
		const isExpanded = button.getAttribute('aria-expanded') === 'true';
		const content = button.nextElementSibling;
		const icon = button.querySelector('.accordion-icon');

		if (isExpanded) {
			button.setAttribute('aria-expanded', 'false');
			content.classList.add('hidden');
			if (icon) icon.classList.remove('tn-rotate-180');
		} else {
			button.setAttribute('aria-expanded', 'true');
			content.classList.remove('hidden');
			if (icon) icon.classList.add('tn-rotate-180');

			if (!FileAccordion.loadedChecks.has(check)) {
				const container = content.querySelector('.files-list-container');
				if (container) {
					container.innerHTML = '<div class="loading-spinner">Loading files...</div>';
					await loadFileList(check, container);
					FileAccordion.loadedChecks.add(check);
				}
			}
		}
	}

	async function loadFileList(check, container) {
		console.log(`[FileAccordion] Loading files for: ${check}`);

		try {
			const response = await fetch(CONFIG.FILES_API, {
				method: 'POST',
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					'X-Requested-With': 'XMLHttpRequest',
					'Cache-Control': 'no-cache, no-store'
				},
				body: JSON.stringify({
					check: check,
					csrf_token: csrfToken
				})
			});

			if (!response.ok) {
				throw new Error(`HTTP ${response.status}`);
			}

			const data = await response.json();

			if (!data.success) {
				showError(container, data.message || 'Failed to load files');
				return;
			}

			// Grouped response (check === 'all') -- data.groups may be {}
			// when there are zero violations; handle that as clean state.
			if (data.groups !== undefined) {
				renderFileList(data.groups, container, true);
				return;
			}

			// Flat response (specific check) -- data.files may be []
			if (data.files !== undefined) {
				renderFileList(data.files, container, false);
				return;
			}

			// Legacy: server wrote a static JSON file instead of inlining
			if (data.file_generated) {
				await fetchStaticFileList(container);
				return;
			}

			// success:1 but no data payload -- treat as clean
			showEmptyState(container);

		} catch (error) {
			console.error('[FileAccordion] Error:', error);
			showError(container, 'Error loading files');
		}
	}

	async function fetchStaticFileList(container) {
		try {
			const response = await fetch('/data/db/TNAuditFilesList.json?_=' + Date.now(), {
				cache: 'no-store'
			});

			if (!response.ok) {
				throw new Error('Failed to fetch file list');
			}

			const data = await response.json();

			if (data.success && data.files) {
				renderFileList(data.files, container, false);
			} else if (data.success && data.groups) {
				renderFileList(data.groups, container, true);
			} else {
				showError(container, 'No file data available');
			}
		} catch (error) {
			console.error('[FileAccordion] Static fetch error:', error);
			showError(container, 'Could not load file list');
		}
	}

	function renderFileList(files, container, isGrouped) {
		if (isGrouped) {
			renderGroupedFileList(files, container);
		} else {
			renderFlatFileList(files, container);
		}
	}

	function renderGroupedFileList(groups, container) {
		const allFiles = [];

		// Flatten groups to count total files
		Object.keys(groups).forEach(checkName => {
			const files = groups[checkName];
			if (files && files.length) {
				allFiles.push(...files);
			}
		});

		if (allFiles.length === 0) {
			showEmptyState(container);
			return;
		}

		const wrapper = document.createElement('div');
		wrapper.className = 'grouped-files-list';

		const checkNames = Object.keys(groups).sort();

		checkNames.forEach(checkName => {
			const files = groups[checkName];
			if (!files || files.length === 0) return;

			const header = document.createElement('div');
			header.className = 'file-group-header';
			header.innerHTML = `
                <h4 class="file-group-title">${escapeHtml(checkName)}</h4>
                <span class="file-group-count">${files.length} file${files.length !== 1 ? 's' : ''}</span>
            `;
			wrapper.appendChild(header);

			const ol = document.createElement('ol');
			ol.className = 'monitored-files-list';

			files.forEach((file, index) => {
				ol.appendChild(createFileItem(file, index + 1));
			});

			wrapper.appendChild(ol);
		});

		container.innerHTML = '';
		container.appendChild(wrapper);
	}

	function renderFlatFileList(files, container) {
		if (!files || files.length === 0) {
			showEmptyState(container);
			return;
		}

		const ol = document.createElement('ol');
		ol.className = 'monitored-files-list';

		files.forEach((file, index) => {
			ol.appendChild(createFileItem(file, index + 1));
		});

		container.innerHTML = '';
		container.appendChild(ol);
	}

	function showEmptyState(container) {
		const div = document.createElement('div');
		div.className = 'integrity-clean-state';
		div.innerHTML = `
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" class="integrity-clean-state__icon">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            <p class="integrity-clean-state__msg">All monitored files verified -- no integrity violations detected.</p>
        `;
		container.innerHTML = '';
		container.appendChild(div);
	}

	function createFileItem(file, number) {
		const li = document.createElement('li');
		li.className = 'file-item';
		li.value = number;

		const statusIcon = getStatusIcon(file.status);
		const statusClass = file.status || 'unknown';

		li.innerHTML = `
            <div class="file-path">${escapeHtml(file.filepath)}</div>
            <div class="file-meta">
                <span class="file-meta-item">
                    <svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                    ${escapeHtml(file.size)}
                </span>
                <span class="file-meta-item">
                    <svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                    </svg>
                    ${escapeHtml(file.mode)}
                </span>
                <span class="file-status-badge ${statusClass}">
                    ${statusIcon} ${escapeHtml(file.status)}
                </span>
            </div>
            <div class="file-sha">SHA256: ${escapeHtml(file.sha256_short || (file.sha256 ? file.sha256.substring(0, 16) + '...' : 'N/A'))}</div>
        `;

		return li;
	}

	function showError(container, message) {
		container.innerHTML = `<div class="loading-spinner">⚠️ ${escapeHtml(message)}</div>`;
	}

	function getStatusIcon(status) {
		const icons = {
			'verified': '✓',
			'modified': '⚠',
			'missing': '✗',
			'baseline': '●',
			'ok': '✓'
		};
		return icons[status] || '?';
	}

	function escapeHtml(text) {
		if (text === null || text === undefined) return '';
		const div = document.createElement('div');
		div.textContent = String(text);
		return div.innerHTML;
	}

	function refreshViolations(forceClearAll = false) {
		console.log('[FileAccordion] Refreshing violations cache, forceClearAll:', forceClearAll);

		if (forceClearAll) {
			// Clear the loaded-checks cache so every accordion re-fetches
			// fresh data from the server on next open.
			FileAccordion.loadedChecks.clear();

			// Wipe the DOM content of ALL accordion containers so stale
			// violation entries are not visible if the panel is open or
			// is re-opened before the reload finishes.
			document.querySelectorAll('.files-list-container').forEach(function(c) {
				c.innerHTML = '<div class="loading-spinner">Refreshing\u2026</div>';
			});
		}

		// If a panel is currently expanded, reload it immediately so the
		// operator sees fresh data without closing and reopening.
		const expandedBtn = document.querySelector('.files-accordion-btn[aria-expanded="true"]');
		if (expandedBtn) {
			const check = expandedBtn.dataset.check;
			const content = expandedBtn.nextElementSibling;
			const container = content && content.querySelector('.files-list-container');
			if (container && check) {
				FileAccordion.loadedChecks.delete(check);
				container.innerHTML = '<div class="loading-spinner">Reloading\u2026</div>';
				loadFileList(check, container).then(function() {
					FileAccordion.loadedChecks.add(check);
				});
			}
		}
	}

	// Expose public API
	window.IntegrityFileAccordion = {
		init: init,
		refreshViolations: refreshViolations
	};

	// Auto-initialize when DOM is ready
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}

})();
