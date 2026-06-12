// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * LogVisualizer - Optimized for Mobile & Raspberry Pi 5
 * Server does heavy lifting, JS is a simple renderer
 * Battery-conscious: No auto-refresh on mobile, minimal DOM manipulation
 */
(function() {
	'use strict';

	class LogVisualizer {
		constructor() {
			this.state = {
				source: 'system/messages',
				date: 'live',
				filter: 'default', // Use server's default filter
				search: '',
				autoRefresh: true,
				refreshRate: 8000,
				showTimestamp: true,
				availableDates: [],
				gaps: [],
				gapRanges: [],
				lastRotation: null,
				metadata: {},
				isLoadingDates: false,
				isMobile: false
			};
			this.timer = null;
			this.rawLogs = [];
			this.init();
		}

		el(id) {
			return document.getElementById(id);
		}

		init() {
			// Detect mobile first
			this.detectMobile();

			this.setupListeners();
			this.loadAvailableDates();
			this.loadLogs();

			// Only start timer if not mobile
			if (!this.state.isMobile) {
				this.startTimer();
			}
		}

		detectMobile() {
			const isMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
			const isSmallScreen = window.innerWidth < 768;

			this.state.isMobile = isMobileUA || isSmallScreen;

			if (this.state.isMobile) {
				// Disable auto-refresh on mobile (battery saver)
				this.state.autoRefresh = false;

				const autoRefreshEl = this.el('autoRefresh');
				if (autoRefreshEl) {
					autoRefreshEl.checked = false;
					autoRefreshEl.disabled = true;
				}

				console.log('Mobile device detected - auto-refresh disabled for battery conservation');
			}
		}

		setupListeners() {
			this.el('loadLogs')?.addEventListener('click', () => {
				this.loadLogs();
			});

			this.el('clearLogs')?.addEventListener('click', () => {
				const container = this.el('logContainer');
				if (container) container.innerHTML = '';
				this.rawLogs = [];
				this.updateStats(0, 0);
				this.showEmptyState();
			});

			this.el('copyLogs')?.addEventListener('click', () => this.copyToClipboard());

			// Source change: reset date and filter state, sync DOM selectors,
			// then load dates and logs in sequence.
			this.el('logSource')?.addEventListener('change', (e) => {
				this.state.source = e.target.value;
				this.state.filter = 'default';
				this.state.date = 'live';

				// Sync DOM selectors immediately so there is no visual mismatch
				// while the async date list loads.
				const dateSelect = this.el('logDate');
				const filterSelect = this.el('logFilter');
				if (dateSelect) dateSelect.value = 'live';
				if (filterSelect) filterSelect.value = 'default';

				this.loadAvailableDates().then(() => this.loadLogs());
			});

			// Date change: value is a YYYY-MM-DD string or 'live'.
			this.el('logDate')?.addEventListener('change', (e) => {
				this.state.date = e.target.value;
				this.loadLogs();
			});

			this.el('logFilter')?.addEventListener('change', (e) => {
				this.state.filter = e.target.value;
				this.loadLogs();
			});

			this.el('logSearch')?.addEventListener('input', (e) => {
				this.state.search = e.target.value;
				this.filterLines();
			});

			this.el('clearSearch')?.addEventListener('click', () => {
				const searchInput = this.el('logSearch');
				if (searchInput) {
					searchInput.value = '';
					this.state.search = '';
					this.filterLines();
				}
			});

			this.el('showTimestamp')?.addEventListener('change', (e) => {
				this.state.showTimestamp = e.target.checked;
				this.render(this.rawLogs);
			});

			this.el('autoRefresh')?.addEventListener('change', (e) => {
				// Prevent enabling on mobile
				if (this.state.isMobile && e.target.checked) {
					e.target.checked = false;
					alert('Auto-refresh is disabled on mobile devices to save battery');
					return;
				}

				this.state.autoRefresh = e.target.checked;
				if (e.target.checked) {
					this.startTimer();
				} else {
					this.stopTimer();
				}
			});

			this.el('scrollTop')?.addEventListener('click', () => {
				const container = this.el('logContainer');
				if (!container) return;
				const first = container.firstElementChild;
				if (first) {
					first.scrollIntoView({
						behavior: 'smooth',
						block: 'start'
					});
				} else {
					container.scrollTop = 0;
				}
			});

			this.el('scrollBottom')?.addEventListener('click', () => {
				const container = this.el('logContainer');
				if (!container) return;
				const last = container.lastElementChild;
				if (last) {
					last.scrollIntoView({
						behavior: 'smooth',
						block: 'end'
					});
				} else {
					container.scrollTop = container.scrollHeight;
				}
			});
		}

		async loadAvailableDates() {
			this.state.isLoadingDates = true;
			const dateSelect = this.el('logDate');

			if (dateSelect) {
				dateSelect.disabled = true;
			}

			try {
				const params = new URLSearchParams({
					action: 'available_dates',
					source: this.state.source
				});

				const response = await fetch(`cgi-bin/logs.pl?${params.toString()}`);
				if (!response.ok) throw new Error(`HTTP ${response.status}`);

				const data = await response.json();

				if (data.success) {
					this.state.availableDates = data.available_dates || [];
					this.state.gaps = data.gaps || [];
					this.state.gapRanges = data.gap_ranges || [];
					this.state.lastRotation = data.last_rotation;
					this.state.metadata = data.metadata || {};

					this.updateDateSelector();
					this.updateRotationStatus();
				}
			} catch (e) {
				console.error('Failed to load available dates:', e);
			} finally {
				this.state.isLoadingDates = false;
				if (dateSelect) {
					dateSelect.disabled = false;
				}
			}
		}

		updateRotationStatus() {
			let statusEl = this.el('rotationStatus');

			if (!statusEl) {
				const dateSelect = this.el('logDate');
				if (!dateSelect || !dateSelect.parentElement) return;

				statusEl = document.createElement('div');
				statusEl.id = 'rotationStatus';
				statusEl.className = 'log-rotation-status';
				dateSelect.parentElement.insertBefore(statusEl, dateSelect.nextSibling);
			}

			statusEl.innerHTML = '';

			if (this.state.lastRotation) {
				// Rotation known row
				const rotRow = document.createElement('div');
				rotRow.className = 'log-rotation-row';

				const rotSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
				rotSvg.setAttribute('class', 'log-rotation-icon log-rotation-icon--ok');
				rotSvg.setAttribute('fill', 'none');
				rotSvg.setAttribute('stroke', 'currentColor');
				rotSvg.setAttribute('viewBox', '0 0 24 24');
				const rotPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
				rotPath.setAttribute('stroke-linecap', 'round');
				rotPath.setAttribute('stroke-linejoin', 'round');
				rotPath.setAttribute('stroke-width', '2');
				rotPath.setAttribute('d', 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z');
				rotSvg.appendChild(rotPath);

				const rotSpan = document.createElement('span');
				rotSpan.textContent = 'Last rotation: ';
				const rotStrong = document.createElement('strong');
				rotStrong.textContent = this.state.lastRotation;
				rotSpan.appendChild(rotStrong);

				rotRow.appendChild(rotSvg);
				rotRow.appendChild(rotSpan);
				statusEl.appendChild(rotRow);

				if (this.state.gapRanges.length > 0) {
					const gapSummary = this.formatGapSummary();
					const gapRow = document.createElement('div');
					gapRow.className = 'log-rotation-row';

					const gapSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
					gapSvg.setAttribute('class', 'log-rotation-icon log-rotation-icon--warn');
					gapSvg.setAttribute('fill', 'none');
					gapSvg.setAttribute('stroke', 'currentColor');
					gapSvg.setAttribute('viewBox', '0 0 24 24');
					const gapPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
					gapPath.setAttribute('stroke-linecap', 'round');
					gapPath.setAttribute('stroke-linejoin', 'round');
					gapPath.setAttribute('stroke-width', '2');
					gapPath.setAttribute('d', 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z');
					gapSvg.appendChild(gapPath);

					const gapSpan = document.createElement('span');
					gapSpan.textContent = gapSummary;

					gapRow.appendChild(gapSvg);
					gapRow.appendChild(gapSpan);
					statusEl.appendChild(gapRow);
				}
			} else {
				// Unknown rotation row
				const unkRow = document.createElement('div');
				unkRow.className = 'log-rotation-row';

				const unkSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
				unkSvg.setAttribute('class', 'log-rotation-icon log-rotation-icon--unknown');
				unkSvg.setAttribute('fill', 'none');
				unkSvg.setAttribute('stroke', 'currentColor');
				unkSvg.setAttribute('viewBox', '0 0 24 24');
				const unkPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
				unkPath.setAttribute('stroke-linecap', 'round');
				unkPath.setAttribute('stroke-linejoin', 'round');
				unkPath.setAttribute('stroke-width', '2');
				unkPath.setAttribute('d', 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z');
				unkSvg.appendChild(unkPath);

				const unkSpan = document.createElement('span');
				unkSpan.textContent = 'Rotation status unknown';

				unkRow.appendChild(unkSvg);
				unkRow.appendChild(unkSpan);
				statusEl.appendChild(unkRow);
			}
		}

		formatGapSummary() {
			const totalGapDays = this.state.gaps.length;
			const rangeCount = this.state.gapRanges.length;

			if (rangeCount === 0) return '';

			const offlineRanges = this.state.gapRanges.filter(r => r.reason === 'system_offline');
			const emptyRanges = this.state.gapRanges.filter(r => r.reason === 'empty_not_rotated');

			if (offlineRanges.length > 0) {
				const offlineText = offlineRanges.map(range => {
					if (range.count === 1) {
						return range.start;
					} else {
						return `${range.start} to ${range.end}`;
					}
				}).join(', ');

				return `System offline: ${offlineText} (${totalGapDays} day${totalGapDays > 1 ? 's' : ''})`;
			} else if (emptyRanges.length > 0) {
				return `${totalGapDays} day${totalGapDays > 1 ? 's' : ''} with empty logs (quiet mode)`;
			} else {
				return `${totalGapDays} missing archive${totalGapDays > 1 ? 's' : ''}`;
			}
		}

		updateDateSelector() {
			const dateSelect = this.el('logDate');
			if (!dateSelect) return;

			// Remove all options except the first (the hardcoded 'live' option)
			while (dateSelect.options.length > 1) {
				dateSelect.remove(1);
			}

			// Add available date entries.
			// option.value is the YYYY-MM-DD date string -- sent directly to the
			// CGI as the 'date' parameter.
			this.state.availableDates.forEach(item => {
				const option = document.createElement('option');
				option.value = item.date;
				const sizeKB = Math.round(item.size / 1024);
				option.textContent = `${item.date} (${sizeKB} KB)`;
				dateSelect.appendChild(option);
			});

			// Gap entries (disabled) -- grouped by type with a separator
			const offlineGaps = this.state.gaps.filter(g => g.reason === 'system_offline');
			const emptyGaps = this.state.gaps.filter(g => g.reason === 'empty_not_rotated');
			const missingGaps = this.state.gaps.filter(g => g.reason === 'missing_archive');

			if (this.state.gaps.length > 0 && this.state.availableDates.length > 0) {
				const separator = document.createElement('option');
				separator.disabled = true;
				separator.textContent = '─────────────────';
				dateSelect.appendChild(separator);
			}

			offlineGaps.forEach(gap => {
				const option = document.createElement('option');
				option.value = gap.date;
				option.disabled = true;
				option.dataset.gapType = 'offline';
				option.textContent = `${gap.date} [System Offline]`;
				dateSelect.appendChild(option);
			});

			emptyGaps.forEach(gap => {
				const option = document.createElement('option');
				option.value = gap.date;
				option.disabled = true;
				option.dataset.gapType = 'empty';
				option.textContent = `${gap.date} [Empty Log]`;
				dateSelect.appendChild(option);
			});

			missingGaps.forEach(gap => {
				const option = document.createElement('option');
				option.value = gap.date;
				option.disabled = true;
				option.dataset.gapType = 'missing';
				option.textContent = `${gap.date} [Archive Missing]`;
				dateSelect.appendChild(option);
			});

			// Sync the DOM selector value to current state.
			dateSelect.value = this.state.date;
		}

		async loadLogs() {
			const container = this.el('logContainer');
			const btn = this.el('loadLogs');
			if (!container) return;

			try {
				if (btn) btn.disabled = true;

				const params = new URLSearchParams({
					action: 'fetch',
					source: this.state.source,
					date: this.state.date,
					filter: this.state.filter
				});

				const response = await fetch(`cgi-bin/logs.pl?${params.toString()}`);

				if (!response.ok) throw new Error(`HTTP ${response.status}`);

				const data = await response.json();

				if (data.success) {
					if (data.empty_file) {
						this.showEmptyFileWarning(data.meta);
						this.rawLogs = [];
						this.updateLogInfo(data.meta);
						return;
					}

					const newLogs = data.logs || [];
					this.rawLogs = newLogs;

					// If the server-side filter returned nothing from a non-empty
					// file, show the same banner as the client-side search so the
					// admin gets a clear signal rather than a blank container.
					if (newLogs.length === 0 && data.meta && data.meta.filter_applied) {
						this._showFilterNoResultsNotice(container, data.meta);
						this.updateLogInfo(data.meta);
						return;
					}

					// If a previous filter-notice is still in the container from a
					// prior request, clear it before rendering fresh results.
					this._clearNoResultsNotice(container);

					this.render(this.rawLogs);
					this.updateLogInfo(data.meta);
				} else {
					this.showSmartError(data);
				}
			} catch (e) {
				this.showError(`Failed to load logs: ${e.message}`);
			} finally {
				if (btn) btn.disabled = false;
				const updated = this.el('lastUpdated');
				if (updated) updated.textContent = new Date().toLocaleTimeString();
			}
		}

		showSmartError(errorData) {
			const container = this.el('logContainer');
			if (!container) return;

			container.innerHTML = '';
			this.hideEmptyState();

			const errDiv = document.createElement('div');
			errDiv.className = 'log-error-wrap';

			const errorVariants = {
				system_offline: {
					cls: 'log-smart-error--offline',
					title: 'System Was Offline',
					iconD: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
				},
				empty_not_rotated: {
					cls: 'log-smart-error--empty',
					title: 'Log File Was Empty',
					iconD: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
				},
				missing_archive: {
					cls: 'log-smart-error--missing',
					title: 'Archive Missing',
					iconD: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z'
				},
				future_date: {
					cls: 'log-smart-error--future',
					title: 'Future Date Selected',
					iconD: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z'
				},
				live_not_found: {
					cls: 'log-smart-error--default',
					title: 'Service Not Running',
					iconD: 'M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
				}
			};
			const variant = errorVariants[errorData.error_type] || {
				cls: 'log-smart-error--default',
				title: 'Error',
				iconD: 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z'
			};

			const suggestions = {
				system_offline: 'The system was not running on this date, so no logs were captured.',
				empty_not_rotated: 'The log file was empty (0 bytes) on this date. This is normal for services running in quiet mode.',
				missing_archive: 'The archive file may have been manually deleted or corrupted.',
				future_date: 'You cannot view logs from the future. Please select today or an earlier date.',
				live_not_found: 'The service may not be running. Check service status.'
			};
			const suggestion = suggestions[errorData.error_type] || 'Try selecting a different date or log source.';

			const panel = document.createElement('div');
			panel.className = `log-smart-error ${variant.cls}`;

			const iconSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
			iconSvg.setAttribute('class', 'log-smart-error-icon');
			iconSvg.setAttribute('fill', 'none');
			iconSvg.setAttribute('stroke', 'currentColor');
			iconSvg.setAttribute('viewBox', '0 0 24 24');
			const iconPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
			iconPath.setAttribute('stroke-linecap', 'round');
			iconPath.setAttribute('stroke-linejoin', 'round');
			iconPath.setAttribute('stroke-width', '2');
			iconPath.setAttribute('d', variant.iconD);
			iconSvg.appendChild(iconPath);

			const body = document.createElement('div');
			body.className = 'log-smart-error-body';

			const titleEl = document.createElement('h3');
			titleEl.className = 'log-smart-error-title';
			titleEl.textContent = variant.title;

			const msgEl = document.createElement('p');
			msgEl.className = 'log-smart-error-msg';
			msgEl.textContent = errorData.message;

			body.appendChild(titleEl);
			body.appendChild(msgEl);

			if (errorData.details) {
				const detailsWrap = document.createElement('div');
				detailsWrap.className = 'log-smart-error-details';
				const dl = document.createElement('dl');
				dl.className = 'log-smart-error-dl';

				for (const [key, value] of Object.entries(errorData.details)) {
					const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
					const row = document.createElement('div');
					row.className = 'log-smart-error-row';
					const dt = document.createElement('dt');
					dt.className = 'log-smart-error-dt';
					dt.textContent = label + ':';
					const dd = document.createElement('dd');
					dd.className = 'log-smart-error-dd';
					dd.textContent = value;
					row.appendChild(dt);
					row.appendChild(dd);
					dl.appendChild(row);
				}

				detailsWrap.appendChild(dl);
				body.appendChild(detailsWrap);
			}

			const suggBox = document.createElement('div');
			suggBox.className = 'log-smart-error-suggestion';
			const suggP = document.createElement('p');
			const suggStrong = document.createElement('strong');
			suggStrong.textContent = 'INFO:  Suggestion: ';
			suggP.appendChild(suggStrong);
			suggP.appendChild(document.createTextNode(suggestion));
			suggBox.appendChild(suggP);
			body.appendChild(suggBox);

			panel.appendChild(iconSvg);
			panel.appendChild(body);
			errDiv.appendChild(panel);
			container.appendChild(errDiv);

			if (errorData.meta) {
				this.updateLogInfo(errorData.meta);
			}
		}

		showEmptyFileWarning(meta) {
			const container = this.el('logContainer');
			if (!container) return;

			container.innerHTML = '';
			this.hideEmptyState();

			const warnDiv = document.createElement('div');
			warnDiv.className = 'log-warn-wrap';

			const warnPanel = document.createElement('div');
			warnPanel.className = 'log-empty-file-warn';

			const warnSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
			warnSvg.setAttribute('class', 'log-smart-error-icon');
			warnSvg.setAttribute('fill', 'none');
			warnSvg.setAttribute('stroke', 'currentColor');
			warnSvg.setAttribute('viewBox', '0 0 24 24');
			const warnPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
			warnPath.setAttribute('stroke-linecap', 'round');
			warnPath.setAttribute('stroke-linejoin', 'round');
			warnPath.setAttribute('stroke-width', '2');
			warnPath.setAttribute('d', 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z');
			warnSvg.appendChild(warnPath);

			const warnBody = document.createElement('div');
			warnBody.className = 'log-empty-file-body';

			const warnTitle = document.createElement('h3');
			warnTitle.className = 'log-empty-file-title';
			warnTitle.textContent = 'Empty Log File';

			const warnMsg = document.createElement('p');
			warnMsg.className = 'log-empty-file-msg';
			warnMsg.textContent = 'The log file exists but contains no entries (0 bytes).';

			warnBody.appendChild(warnTitle);
			warnBody.appendChild(warnMsg);

			const noteDiv = document.createElement('div');
			noteDiv.className = meta.quiet_mode ?
				'log-empty-file-note log-empty-file-note--quiet' :
				'log-empty-file-note log-empty-file-note--default';

			const noteP = document.createElement('p');
			if (meta.quiet_mode) {
				const noteStrong = document.createElement('strong');
				noteStrong.textContent = 'INFO:  Note: ';
				noteP.appendChild(noteStrong);
				noteP.appendChild(document.createTextNode('This service runs in '));
				const modeStrong = document.createElement('strong');
				modeStrong.textContent = 'quiet mode';
				noteP.appendChild(modeStrong);
				noteP.appendChild(document.createTextNode('. An empty log file does '));
				const notEm = document.createElement('em');
				notEm.textContent = 'not';
				noteP.appendChild(notEm);
				noteP.appendChild(document.createTextNode(' mean the service is dead. Many services only log errors and warnings.'));
			} else {
				noteP.textContent = 'This could mean the service just started, or there has been no activity to log.';
			}
			noteDiv.appendChild(noteP);
			warnBody.appendChild(noteDiv);

			warnPanel.appendChild(warnSvg);
			warnPanel.appendChild(warnBody);
			warnDiv.appendChild(warnPanel);
			container.appendChild(warnDiv);
		}

		render(logs) {
			const container = this.el('logContainer');
			if (!container) return;

			if (logs.length === 0) {
				this.showEmptyState();
				return;
			}

			this.hideEmptyState();

			const fragment = document.createDocumentFragment();
			let errorCount = 0;

			logs.forEach(log => {
				const line = document.createElement('div');

				const isError = log.level === 'error';
				const isWarning = log.level === 'warning';
				if (isError) errorCount++;

				let cleanText = log.text;
				if (log.timestamp && log.text.startsWith(log.timestamp)) {
					cleanText = log.text.substring(log.timestamp.length).trim();
					if (cleanText.startsWith(':')) cleanText = cleanText.substring(1).trim();
				}
				if (log.timestamp && log.text.startsWith(`[${log.timestamp}]`)) {
					cleanText = log.text.substring(log.timestamp.length + 2).trim();
				}

				line.className = 'log-line';
				if (isError) line.classList.add('error');
				if (isWarning) line.classList.add('warning');

				const lineContent = document.createElement('div');
				lineContent.className = 'log-content';

				if (this.state.showTimestamp && log.timestamp) {
					const ts = document.createElement('span');
					ts.className = 'log-timestamp';
					ts.textContent = '[' + log.timestamp + ']';
					lineContent.appendChild(ts);
					lineContent.appendChild(document.createTextNode(' '));
				}

				if (log.service) {
					const svc = document.createElement('span');
					svc.className = 'log-service';
					svc.textContent = log.service + ':';
					lineContent.appendChild(svc);
					lineContent.appendChild(document.createTextNode(' '));
				}

				const txt = document.createElement('span');
				txt.className = 'log-text';
				txt.textContent = cleanText;
				lineContent.appendChild(txt);

				line.appendChild(lineContent);
				fragment.appendChild(line);
			});

			container.innerHTML = '';
			container.appendChild(fragment);

			this.updateStats(logs.length, errorCount);

			// Apply client-side search filter if active
			if (this.state.search) this.filterLines();
		}

		updateStats(total, errors) {
			const lCount = this.el('lineCount');
			const eCount = this.el('errorCount');
			const indicator = this.el('statusIndicator');

			if (lCount) lCount.textContent = total;
			if (eCount) eCount.textContent = errors;

			if (indicator) {
				indicator.className = 'tn-health-dot';
				if (errors > 20) {
					indicator.dataset.health = 'error';
				} else if (errors > 0) {
					indicator.dataset.health = 'warn';
				} else {
					indicator.dataset.health = 'ok';
				}
			}
		}

		updateLogInfo(meta) {
			if (!meta) return;

			const titleEl = this.el('currentLogTitle');
			const infoEl = this.el('logInfo');

			if (titleEl) {
				const sourceNames = {
					'system/messages': 'System Messages',
					'system/daemon': 'System Daemon',
					'bootlog/rc.local.log': 'Boot Sequence',
					'bootlog/manager': 'Boot Manager',
					'doas/doas.log': 'Privilege Elevation',
					'snort/alert.log': 'Snort Alerts',
					'snort/snort.log': 'Snort IDS',
					'snort/snortinline.log': 'Snort IPS',
					'pmacct/pmacct': 'pmacct',
					'waf/access': 'WAF Access'
				};
				titleEl.textContent = sourceNames[meta.source] || meta.source;
			}

			if (infoEl) {
				let info = meta.type === 'boot' ? 'Boot Log' :
					this.state.date === 'live' ? 'Live Log' : 'Archived Log';
				info += ` • ${meta.count} entries`;

				if (meta.total_lines && meta.total_lines > meta.count) {
					info += ` of ${meta.total_lines} total`;
				}

				if (meta.filter && meta.filter !== 'all') {
					info += ` • Filtered: ${meta.filter}`;
				}

				if (meta.size) {
					const sizeKB = Math.round(meta.size / 1024);
					info += ` • ${sizeKB} KB`;
				}

				infoEl.textContent = info;
			}
		}

		showError(msg) {
			const container = this.el('logContainer');
			if (!container) return;

			this.hideEmptyState();

			const errDiv = document.createElement('div');
			errDiv.className = 'log-fetch-error';
			const errStrong = document.createElement('strong');
			errStrong.textContent = '[ERROR]';
			errDiv.appendChild(errStrong);
			errDiv.appendChild(document.createTextNode(' ' + msg));
			container.prepend(errDiv);
		}

		showEmptyState() {
			const empty = this.el('emptyState');
			if (empty) empty.classList.add('log-empty--visible');
		}

		hideEmptyState() {
			const empty = this.el('emptyState');
			if (empty) empty.classList.remove('log-empty--visible');
		}

		filterLines() {
			const container = this.el('logContainer');
			if (!container) return;

			const lines = container.querySelectorAll('.log-line');
			const term = this.state.search.toLowerCase();

			// Clear search: restore all lines and remove any no-results notice
			if (!term) {
				lines.forEach(line => delete line.dataset.logVisible);
				this._clearNoResultsNotice(container);
				return;
			}

			let visibleCount = 0;
			try {
				const regex = new RegExp(term, 'i');
				lines.forEach(line => {
					const match = regex.test(line.textContent);
					line.dataset.logVisible = match ? 'true' : 'false';
					if (match) visibleCount++;
				});
			} catch (e) {
				// Invalid regex -- fall back to plain substring match
				lines.forEach(line => {
					const match = line.textContent.toLowerCase().includes(term);
					line.dataset.logVisible = match ? 'true' : 'false';
					if (match) visibleCount++;
				});
			}

			if (visibleCount === 0) {
				this._showNoResultsNotice(container, term);
			} else {
				this._clearNoResultsNotice(container);
			}
		}

		_showFilterNoResultsNotice(container, meta) {
			this._clearNoResultsNotice(container);
			container.innerHTML = '';
			this.hideEmptyState();

			const filterLabels = {
				error: 'Errors / Failures',
				warning: 'Warnings & Errors',
				auth: 'Auth Events',
				blocked: 'Blocked / Denied',
				connection: 'Connections'
			};
			const filterLabel = filterLabels[meta.filter] || meta.filter;

			const warnDiv = document.createElement('div');
			warnDiv.id = 'logSearchNotice';
			warnDiv.className = 'log-warn-wrap';

			const warnPanel = document.createElement('div');
			warnPanel.className = 'log-empty-file-warn';

			const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
			svg.setAttribute('class', 'log-smart-error-icon');
			svg.setAttribute('fill', 'none');
			svg.setAttribute('stroke', 'currentColor');
			svg.setAttribute('viewBox', '0 0 24 24');
			const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
			path.setAttribute('stroke-linecap', 'round');
			path.setAttribute('stroke-linejoin', 'round');
			path.setAttribute('stroke-width', '2');
			path.setAttribute('d', 'M3 4a1 1 0 011-1h16a1 1 0 011 1v2a1 1 0 01-.293.707L13 13.414V19a1 1 0 01-.553.894l-4 2A1 1 0 017 21v-7.586L3.293 6.707A1 1 0 013 6V4z');
			svg.appendChild(path);

			const warnBody = document.createElement('div');
			warnBody.className = 'log-empty-file-body';

			const warnTitle = document.createElement('h3');
			warnTitle.className = 'log-empty-file-title';
			warnTitle.textContent = 'No matching entries';

			const warnMsg = document.createElement('p');
			warnMsg.className = 'log-empty-file-msg';
			const checkedLines = meta.total_lines || 'all';
			warnMsg.textContent = 'The "' + filterLabel + '" filter matched nothing in ' + checkedLines + ' lines from ' + (meta.file || 'this log') + '.';

			const noteDiv = document.createElement('div');
			noteDiv.className = 'log-empty-file-note log-empty-file-note--default';
			const noteP = document.createElement('p');
			noteP.textContent = 'This is normal -- the service may have been quiet during this period. Switch the filter to All to see every line, or use the search box to query specific terms.';
			noteDiv.appendChild(noteP);

			warnBody.appendChild(warnTitle);
			warnBody.appendChild(warnMsg);
			warnBody.appendChild(noteDiv);
			warnPanel.appendChild(svg);
			warnPanel.appendChild(warnBody);
			warnDiv.appendChild(warnPanel);
			container.appendChild(warnDiv);
		}

		_showNoResultsNotice(container, term) {
			this._clearNoResultsNotice(container);

			// Reuse log-warn-wrap / log-empty-file-warn CSS -- same structure as
			// showEmptyFileWarning so it looks native without any new styles.
			const warnDiv = document.createElement('div');
			warnDiv.id = 'logSearchNotice';
			warnDiv.className = 'log-warn-wrap';

			const warnPanel = document.createElement('div');
			warnPanel.className = 'log-empty-file-warn';

			const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
			svg.setAttribute('class', 'log-smart-error-icon');
			svg.setAttribute('fill', 'none');
			svg.setAttribute('stroke', 'currentColor');
			svg.setAttribute('viewBox', '0 0 24 24');
			const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
			path.setAttribute('stroke-linecap', 'round');
			path.setAttribute('stroke-linejoin', 'round');
			path.setAttribute('stroke-width', '2');
			path.setAttribute('d', 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z');
			svg.appendChild(path);

			const warnBody = document.createElement('div');
			warnBody.className = 'log-empty-file-body';

			const warnTitle = document.createElement('h3');
			warnTitle.className = 'log-empty-file-title';
			warnTitle.textContent = 'No matches found';

			const warnMsg = document.createElement('p');
			warnMsg.className = 'log-empty-file-msg';
			const displayTerm = term.length > 60 ? term.slice(0, 60) + '\u2026' : term;
			const total = container.querySelectorAll('.log-line').length;
			warnMsg.textContent = '"' + displayTerm + '" does not appear in any of the ' + total + ' loaded lines.';

			const noteDiv = document.createElement('div');
			noteDiv.className = 'log-empty-file-note log-empty-file-note--default';
			const noteP = document.createElement('p');
			noteP.textContent = 'Try broadening your search term, switching the server filter to All, or selecting a different date.';
			noteDiv.appendChild(noteP);

			warnBody.appendChild(warnTitle);
			warnBody.appendChild(warnMsg);
			warnBody.appendChild(noteDiv);
			warnPanel.appendChild(svg);
			warnPanel.appendChild(warnBody);
			warnDiv.appendChild(warnPanel);

			// prepend -- banner sits at top of container, hidden lines stay below
			container.prepend(warnDiv);
		}

		_clearNoResultsNotice(container) {
			const existing = container.querySelector('#logSearchNotice');
			if (existing) existing.remove();
		}

		async copyToClipboard() {
			const container = this.el('logContainer');
			const btn = this.el('copyLogs');
			if (!container) return;

			try {
				const lines = container.querySelectorAll('.log-line:not([data-log-visible="false"])');
				const text = Array.from(lines)
					.map(line => line.textContent.trim())
					.join('\n');

				if (!text) {
					alert('No logs to copy');
					return;
				}

				await navigator.clipboard.writeText(text);

				btn.classList.add('btn--copied');
				setTimeout(() => {
					btn.classList.remove('btn--copied');
				}, 2000);
			} catch (e) {
				alert('Failed to copy: ' + e.message);
			}
		}

		startTimer() {
			this.stopTimer();

			if (this.state.isMobile) return;

			this.timer = setInterval(() => {
				if (this.state.autoRefresh &&
					this.state.date === 'live' &&
					document.contains(this.el('logContainer'))) {
					this.loadLogs();
				} else if (!document.contains(this.el('logContainer'))) {
					this.stopTimer();
				}
			}, this.state.refreshRate);
		}

		stopTimer() {
			if (this.timer) clearInterval(this.timer);
		}

		escape(str) {
			const map = {
				'&': '&amp;',
				'<': '&lt;',
				'>': '&gt;',
				'"': '&quot;',
				"'": '&#039;'
			};
			return String(str).replace(/[&<>"']/g, m => map[m]);
		}
	}

	new LogVisualizer();
})();
