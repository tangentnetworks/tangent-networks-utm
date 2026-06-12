// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * System Integrity Check -- Queue-based verification UI
 * Handles verification requests, acceptance of changes, and stats rendering.
 * File list rendering is delegated to integrity_list.js (IntegrityFileAccordion).
 *
 * Request lifecycle
 * ─────────────────
 * 1. POST to integrity_request.pl with { check, action, request_time }.
 *    The CGI queues the job and immediately flushes HTTP 200 headers, then
 *    streams ASCII-space heartbeats every 20 s while the daemon works, and
 *    finally writes the JSON outcome as the response body.
 *
 * 2. readStreamingJson() pumps the ReadableStream chunk-by-chunk so each
 *    arriving heartbeat byte resets the browser's body-idle watchdog.
 *
 * 3. If the streaming connection is killed mid-flight by OpenBSD httpd's
 *    FastCGI proxy timeout (surfaces as "TypeError: Error in input stream"),
 *    pollForOutcome() takes over: it polls integrity_status.pl every
 *    POLL_INTERVAL_MS using the original request_time as a correlation key,
 *    until the daemon writes the outcome file (up to POLL_MAX_MS total).
 *    The daemon continues running regardless of the broken HTTP connection,
 *    so the outcome will eventually appear.
 */

(function() {
	'use strict';

	const CONFIG = Object.freeze({
		REQUEST_API: '/cgi-bin/integrity_request.pl',
		STATUS_API: '/cgi-bin/integrity_status.pl',
		CSRF_API: '/cgi-bin/control.pl/api/csrf',
		// Hard abort for the initial streaming fetch.
		// Must exceed the server max_wait (540 s) + a small grace margin.
		REQUEST_TIMEOUT_MS: 600000,
		// Status-poll fallback: interval and total ceiling.
		POLL_INTERVAL_MS: 3000,
		POLL_MAX_MS: 600000,
	});

	let csrfToken = null;
	let activeChecks = new Map(); // checkType → { modal, startTime, requestTime }

	// Single source of truth for all check status / stats
	let checksData = {};

	// Prevent the violation accordion from auto-expanding more than once
	// per page load unless violations are fully cleared first
	let violationsAutoExpanded = false;

	// ============================================
	// INITIALIZATION
	// ============================================
	async function initialize() {
		console.log('[Integrity] Initializing...');

		const grid = await waitForElement('#integrity-grid', 5000);
		if (!grid) {
			console.error('[Integrity] Required #integrity-grid element not found');
			return;
		}

		await fetchCSRFToken();
		await loadInitialStatus();
		setupEventListeners();

		console.log('[Integrity] Ready');
	}

	function waitForElement(selector, timeout) {
		timeout = timeout || 5000;
		return new Promise(function(resolve) {
			const el = document.querySelector(selector);
			if (el) return resolve(el);

			const observer = new MutationObserver(function() {
				const found = document.querySelector(selector);
				if (found) {
					observer.disconnect();
					resolve(found);
				}
			});
			observer.observe(document.body, {
				childList: true,
				subtree: true
			});
			setTimeout(function() {
				observer.disconnect();
				resolve(null);
			}, timeout);
		});
	}

	// ============================================
	// CSRF TOKEN MANAGEMENT
	// ============================================
	async function fetchCSRFToken() {
		try {
			const response = await fetch(CONFIG.CSRF_API);
			if (!response.ok) throw new Error('CSRF fetch failed: ' + response.status);
			const data = await response.json();
			if (data.token) {
				csrfToken = data.token;
				window.csrfToken = csrfToken;
				console.log('[Integrity] CSRF token obtained');
				return csrfToken;
			}
			return null;
		} catch (err) {
			console.error('[Integrity] Failed to fetch CSRF token:', err);
			return null;
		}
	}

	// ============================================
	// STREAMING JSON READER
	//
	// Pumps the response ReadableStream chunk-by-chunk. Each arriving chunk
	// (heartbeat spaces or the final JSON body) resets the browser's
	// response-body idle timer. Throws on stream error so the caller can
	// switch to the polling fallback.
	// ============================================
	async function readStreamingJson(response) {
		if (!response.body) {
			// ReadableStream not available in this environment
			return response.json();
		}

		const reader = response.body.getReader();
		const decoder = new TextDecoder('utf-8');
		let text = '';

		while (true) {
			const {
				done,
				value
			} = await reader.read();
			if (done) break;
			text += decoder.decode(value, {
				stream: true
			});
		}
		text += decoder.decode(); // flush decoder

		const trimmed = text.trim();
		if (!trimmed) throw new Error('Empty response body from streaming read');
		return JSON.parse(trimmed);
	}

	// ============================================
	// STATUS-POLL FALLBACK
	//
	// Called when the streaming connection dies before the outcome arrives.
	// The daemon keeps running and will eventually write the outcome file.
	// integrity_status.pl serves it by request_time correlation key.
	// ============================================
	async function pollForOutcome(checkType, requestTime, modal) {
		console.log('[Integrity] Streaming failed for ' + checkType +
			' -- switching to status-poll fallback (request: ' + requestTime + ')');

		updateModal(modal, 'polling', 'Connection interrupted -- polling for result\u2026');

		const deadline = Date.now() + CONFIG.POLL_MAX_MS;

		while (Date.now() < deadline) {
			await sleep(CONFIG.POLL_INTERVAL_MS);

			try {
				const response = await fetch(CONFIG.STATUS_API, {
					method: 'POST',
					credentials: 'same-origin',
					headers: {
						'Content-Type': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
					},
					body: JSON.stringify({
						action: 'poll',
						check: checkType,
						request_time: requestTime,
						csrf_token: csrfToken,
					}),
				});

				if (!response.ok) continue; // transient error -- keep polling

				const data = await response.json();

				if (data.pending) {
					const elapsed = Math.round(
						(Date.now() - (deadline - CONFIG.POLL_MAX_MS)) / 1000);
					updateModal(modal, 'polling',
						'Verification in progress\u2026 (' + elapsed + ' s elapsed)');
					continue;
				}

				// Outcome available
				return data;

			} catch (pollErr) {
				console.warn('[Integrity] Poll attempt failed:', pollErr);
				// Network blip -- continue until deadline
			}
		}

		return {
			success: false,
			message: 'Verification timed out waiting for outcome'
		};
	}

	function sleep(ms) {
		return new Promise(function(resolve) {
			setTimeout(resolve, ms);
		});
	}

	// ============================================
	// EVENT LISTENERS
	// ============================================
	function setupEventListeners() {
		document.getElementById('integrity-grid').addEventListener('click', function(e) {
			const btn = e.target.closest('.ctrl-btn');
			if (!btn) return;
			if (btn.dataset.action === 'verify') {
				handleVerifyRequest(btn.dataset.check);
			} else if (btn.dataset.action === 'accept') {
				handleAcceptRequest(btn.dataset.check);
			}
		});

		document.getElementById('verify-all').addEventListener('click', function() {
			handleVerifyAll();
		});

		document.getElementById('refresh-status').addEventListener('click', function() {
			loadInitialStatus();
		});
	}

	// ============================================
	// LOAD INITIAL STATUS
	// ============================================
	async function loadInitialStatus() {
		console.log('[Integrity] Loading initial status...');
		try {
			const response = await fetch(CONFIG.STATUS_API, {
				method: 'POST',
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					'X-Requested-With': 'XMLHttpRequest',
				},
				body: JSON.stringify({
					action: 'summary',
					csrf_token: csrfToken
				}),
			});

			if (!response.ok) throw new Error('Status API error: ' + response.status);

			const data = await response.json();

			if (data.checks) {
				checksData = data.checks;
				renderCards(checksData);

				Object.keys(checksData).forEach(function(checkType) {
					const info = checksData[checkType];
					const status = info.status || 'pending';
					updateCardState(checkType, status, getDisplayStatus(status));
					updateCardStats(checkType, info);
				});

				updateGlobalStats();

				Object.keys(checksData).forEach(function(ct) {
					updateCardButtons(ct);
				});

				// Update the banner subtitle with the most recent check time
				const lastCheckEl = document.getElementById('last-updated');
				if (lastCheckEl) {
					let latestCheck = null;
					Object.values(checksData).forEach(function(c) {
						if (!c.last_check) return;
						const t = typeof c.last_check === 'number' ?
							c.last_check * 1000 :
							Date.parse(c.last_check.replace(' ', 'T'));
						if (!isNaN(t) && (!latestCheck || t > latestCheck)) latestCheck = t;
					});
					lastCheckEl.textContent = latestCheck ?
						'Last checked: ' + new Date(latestCheck).toLocaleString() :
						'No checks run yet';
				}
			}
		} catch (err) {
			console.error('[Integrity] Failed to load initial status:', err);
		}
	}

	function getDisplayStatus(status) {
		const display = {
			'verified': 'VERIFIED',
			'baseline': 'BASELINE',
			'failed': 'FAILED',
			'pending': 'PENDING',
			'checking': 'CHECKING',
		};
		return display[status] || status.toUpperCase();
	}

	// ============================================
	// RENDER CARDS FROM TEMPLATE
	// ============================================
	function renderCards(checks) {
		const grid = document.getElementById('integrity-grid');
		const tpl = document.getElementById('check-card-tpl');

		if (!grid || !tpl) {
			console.error('[Integrity] renderCards: missing #integrity-grid or #check-card-tpl');
			return;
		}

		grid.innerHTML = '';

		const names = Object.keys(checks);
		if (names.length === 0) {
			const msg = document.createElement('p');
			msg.className = 'integrity-empty-msg';
			msg.textContent = 'No checks configured.';
			grid.appendChild(msg);
			return;
		}

		names.forEach(function(name) {
			const info = checks[name];
			const clone = tpl.content.cloneNode(true);

			const card = clone.querySelector('.syscheck-card');
			card.dataset.check = name;

			const displayName = info.display_name || name.replace(/_/g, ' ').toUpperCase();
			clone.querySelector('.check-name').textContent = displayName;

			const pathText = clone.querySelector('.path-text');
			if (pathText) pathText.textContent = info.path ? 'Location: ' + info.path : '';

			const descText = clone.querySelector('.desc-text');
			if (descText) descText.textContent = info.description || '';

			const verifyBtn = clone.querySelector('[data-action="verify"]');
			if (verifyBtn) verifyBtn.dataset.check = name;

			grid.appendChild(clone);
		});

		console.log('[Integrity] Rendered ' + names.length + ' cards');
	}

	// ============================================
	// VERIFY REQUEST HANDLER
	// ============================================
	async function handleVerifyRequest(checkType) {
		console.log('[Integrity] Verify request for: ' + checkType);

		if (!csrfToken) {
			await fetchCSRFToken();
			if (!csrfToken) {
				alert('Security token unavailable. Please refresh the page.');
				return;
			}
		}

		if (activeChecks.has(checkType)) {
			console.log('[Integrity] Check already active: ' + checkType);
			// Restore a minimised modal if the operator closed it and
			// is clicking verify again to check on progress.
			const existing = activeChecks.get(checkType);
			if (existing && existing.modal) {
				existing.modal.classList.remove('modal-minimised');
			}
			return;
		}

		updateCardState(checkType, 'checking', 'CHECKING');
		const modal = createModal('VERIFYING', checkType, 'Running integrity verification\u2026');
		const requestTime = getRequestTimestamp();

		activeChecks.set(checkType, {
			modal,
			startTime: Date.now(),
			requestTime
		});

		// For long-running checks, tick the card badge every 5 s so the
		// operator can see progress rather than a frozen CHECKING label.
		const elapsedTimer = setInterval(function() {
			if (!activeChecks.has(checkType)) {
				clearInterval(elapsedTimer);
				return;
			}
			const elapsed = Math.round((Date.now() - activeChecks.get(checkType).startTime) / 1000);
			updateCardState(checkType, 'checking', 'CHECKING ' + elapsed + 's');
		}, 5000);
		activeChecks.get(checkType).elapsedTimer = elapsedTimer;

		const controller = new AbortController();
		const timeoutId = setTimeout(function() {
				controller.abort();
			},
			CONFIG.REQUEST_TIMEOUT_MS);

		let result;
		try {
			const response = await fetch(CONFIG.REQUEST_API, {
				method: 'POST',
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					'X-Requested-With': 'XMLHttpRequest',
				},
				body: JSON.stringify({
					check: checkType,
					action: 'verify',
					csrf_token: csrfToken,
					request_time: requestTime,
				}),
				signal: controller.signal,
			});

			clearTimeout(timeoutId);

			if (!response.ok) throw new Error('Request failed: ' + response.status);

			result = await readStreamingJson(response);

		} catch (streamErr) {
			clearTimeout(timeoutId);

			if (streamErr.name === 'AbortError') {
				// Hard 10-minute abort fired -- nothing to poll
				console.error('[Integrity] Hard timeout for ' + checkType);
				applyVerifyFailure(checkType, modal,
					'Verification timed out \u2014 check daemon logs');
				activeChecks.delete(checkType);
				return;
			}

			// Connection killed by httpd proxy timeout or network error.
			// The daemon is still running -- switch to polling.
			console.warn('[Integrity] Stream error for ' + checkType + ':',
				streamErr.message);
			result = await pollForOutcome(checkType, requestTime, modal);
		}

		const finishedEntry = activeChecks.get(checkType);
		if (finishedEntry && finishedEntry.elapsedTimer) {
			clearInterval(finishedEntry.elapsedTimer);
		}
		activeChecks.delete(checkType);
		applyVerifyResult(checkType, modal, result);
	}

	function applyVerifyResult(checkType, modal, result) {
		if (result.success) {
			if (!checksData[checkType]) checksData[checkType] = {};
			checksData[checkType].files = result.files || 0;
			checksData[checkType].status = result.status || 'verified';
			checksData[checkType].changes = result.changes || 0;
			checksData[checkType].last_check = result.last_check || null;

			updateCardState(checkType, checksData[checkType].status,
				getDisplayStatus(checksData[checkType].status));
			updateCardStats(checkType, checksData[checkType]);
			updateCardButtons(checkType);
			updateModal(modal, 'success', 'Verification completed successfully', result);
			updateGlobalStats();
			refreshFileAccordion();

			// Keep banner subtitle current
			const lastCheckEl = document.getElementById('last-updated');
			if (lastCheckEl) {
				lastCheckEl.textContent = 'Last checked: ' + new Date().toLocaleString();
			}

			setTimeout(function() {
				modal.remove();
			}, 3000);
		} else {
			if (!checksData[checkType]) checksData[checkType] = {};
			checksData[checkType].status = 'failed';
			checksData[checkType].changes = result.changes || 0;

			updateCardState(checkType, 'failed', 'FAILED');
			updateCardButtons(checkType);
			updateModal(modal, 'error',
				result.error || result.message || 'Verification failed', result);
			updateGlobalStats();
			refreshFileAccordion();
		}
	}

	function applyVerifyFailure(checkType, modal, message) {
		if (!checksData[checkType]) checksData[checkType] = {};
		checksData[checkType].status = 'failed';
		updateCardState(checkType, 'failed', 'ERROR');
		updateCardButtons(checkType);
		updateModal(modal, 'error', message);
		updateGlobalStats();
	}

	// ============================================
	// ACCEPT CHANGES REQUEST HANDLER
	// ============================================
	async function handleAcceptRequest(checkType) {
		console.log('[Integrity] Accept changes for: ' + checkType);

		if (!csrfToken) {
			await fetchCSRFToken();
			if (!csrfToken) {
				alert('Security token unavailable. Please refresh the page.');
				return;
			}
		}

		if (activeChecks.has(checkType)) {
			console.log('[Integrity] Check already active: ' + checkType);
			return;
		}

		updateCardState(checkType, 'checking', 'ACCEPTING');
		const modal = createModal('ACCEPTING CHANGES', checkType,
			'Updating baseline hashes\u2026');
		const requestTime = getRequestTimestamp();

		activeChecks.set(checkType, {
			modal,
			startTime: Date.now(),
			requestTime
		});

		const controller = new AbortController();
		const timeoutId = setTimeout(function() {
				controller.abort();
			},
			CONFIG.REQUEST_TIMEOUT_MS);

		let result;
		try {
			const response = await fetch(CONFIG.REQUEST_API, {
				method: 'POST',
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					'X-Requested-With': 'XMLHttpRequest',
				},
				body: JSON.stringify({
					check: checkType,
					action: 'update',
					csrf_token: csrfToken,
					request_time: requestTime,
				}),
				signal: controller.signal,
			});

			clearTimeout(timeoutId);

			if (!response.ok) throw new Error('Request failed: ' + response.status);

			result = await readStreamingJson(response);

		} catch (streamErr) {
			clearTimeout(timeoutId);

			if (streamErr.name === 'AbortError') {
				console.error('[Integrity] Hard timeout for accept on ' + checkType);
				applyAcceptFailure(checkType, modal,
					'Baseline update timed out \u2014 check daemon logs');
				activeChecks.delete(checkType);
				return;
			}

			console.warn('[Integrity] Stream error on accept for ' + checkType + ':',
				streamErr.message);
			result = await pollForOutcome(checkType, requestTime, modal);
		}

		activeChecks.delete(checkType);
		applyAcceptResult(checkType, modal, result);
	}

	function applyAcceptResult(checkType, modal, result) {
		if (result.success) {
			const newStatus = 'baseline';
			const newChanges = result.changes || 0;

			if (!checksData[checkType]) checksData[checkType] = {};
			checksData[checkType].status = newStatus;
			checksData[checkType].changes = newChanges;
			checksData[checkType].last_check = result.last_check || null;
			if (result.files) checksData[checkType].files = result.files;

			// Immediately zero out changes in checksData so updateCardButtons
			// removes the Accept button right now -- before the auto-verify runs.
			// This is not cosmetic: the baseline IS updated at this point.
			// The verify that follows confirms the hash matches; it does not
			// gate the acceptance, which already happened on the server.
			checksData[checkType].changes = 0;
			checksData[checkType].status = newStatus;

			updateCardState(checkType, newStatus, getDisplayStatus(newStatus));
			updateCardStats(checkType, {
				files: checksData[checkType].files || 0,
				changes: 0,
				status: newStatus,
			});
			// Explicitly remove the Accept button before auto-verify fires.
			// updateCardButtons alone could race if verify returns before
			// the DOM has settled.
			removeAcceptButton(checkType);
			updateCardButtons(checkType);
			updateModal(modal, 'success', 'Baseline updated \u2014 running verification\u2026', result);
			updateGlobalStats();

			// Force-clear all accordion caches -- violations have been accepted
			if (window.IntegrityFileAccordion && window.IntegrityFileAccordion.refreshViolations) {
				window.IntegrityFileAccordion.refreshViolations(true);
			}

			// Auto-verify after accept to confirm the new baseline matches disk.
			// 2 s delay gives the SQLite WAL checkpoint time to settle before
			// the verify daemon re-reads the files table -- avoids a race where
			// verify sees the old hash and immediately re-flags the file.
			setTimeout(function() {
				modal.remove();
				handleVerifyRequest(checkType);
			}, 2000);
		} else {
			applyAcceptFailure(checkType, modal,
				result.error || result.message || 'Accept failed');
		}
	}

	function applyAcceptFailure(checkType, modal, message) {
		if (!checksData[checkType]) checksData[checkType] = {};
		checksData[checkType].status = 'failed';
		updateCardState(checkType, 'failed', 'FAILED');
		updateCardButtons(checkType);
		updateModal(modal, 'error', message);
		updateGlobalStats();
	}

	// ============================================
	// VERIFY ALL -- sequential to avoid saturating the daemon queue
	// ============================================
	async function handleVerifyAll() {
		const checkTypes = Object.keys(checksData);

		if (checkTypes.length === 0) {
			console.log('[Integrity] No checks loaded -- cannot run Verify All');
			return;
		}

		const btn = document.getElementById('verify-all');
		btn.disabled = true;
		btn.textContent = 'VERIFYING\u2026';

		for (let i = 0; i < checkTypes.length; i++) {
			await handleVerifyRequest(checkTypes[i]);
			await sleep(500);
		}

		btn.disabled = false;
		btn.textContent = 'VERIFY ALL';
	}

	// ============================================
	// BUTTON MANAGEMENT
	// ============================================
	function addAcceptButton(checkType) {
		const card = document.querySelector('.syscheck-card[data-check="' + checkType + '"]');
		if (!card) return;
		if (card.querySelector('[data-action="accept"]')) return;

		const btn = document.createElement('button');
		btn.className = 'ctrl-btn accept';
		btn.dataset.action = 'accept';
		btn.dataset.check = checkType;
		btn.textContent = 'Accept Changes';

		const container = card.querySelector('.button-container');
		if (container) container.appendChild(btn);
	}

	function removeAcceptButton(checkType) {
		const card = document.querySelector('.syscheck-card[data-check="' + checkType + '"]');
		if (!card) return;
		const btn = card.querySelector('[data-action="accept"]');
		if (btn) btn.remove();
	}

	function updateCardButtons(checkType) {
		const info = checksData[checkType];
		if (!info) return;
		// Show Accept button only when there are actual tracked changes to accept
		if (info.status === 'failed' && info.changes > 0) {
			addAcceptButton(checkType);
		} else {
			removeAcceptButton(checkType);
		}
	}

	// ============================================
	// UI UPDATE HELPERS
	// ============================================
	function updateCardState(checkType, state, badgeText) {
		const card = document.querySelector('.syscheck-card[data-check="' + checkType + '"]');
		if (!card) return;

		const dot = card.querySelector('.status-dot');
		if (dot) dot.className = 'status-dot ' + state;

		const badge = card.querySelector('.status-badge');
		if (badge) {
			badge.className = 'status-badge ' + state;
			badge.textContent = badgeText;
		}
	}

	function updateCardStats(checkType, data) {
		const card = document.querySelector('.syscheck-card[data-check="' + checkType + '"]');
		if (!card) return;

		const filesEl = card.querySelector('[data-stat="files"]');
		const changesEl = card.querySelector('[data-stat="changes"]');
		const statusEl = card.querySelector('[data-stat="status"]');

		if (filesEl) filesEl.textContent = (data.files != null) ? data.files : '--';
		if (changesEl) changesEl.textContent = (data.changes != null) ? data.changes : '0';
		if (statusEl) statusEl.textContent = getDisplayStatus(data.status || '--');
	}

	function updateGlobalStats() {
		const entries = Object.values(checksData);
		let totalFiles = 0;
		let violations = 0;
		let goodChecks = 0;

		entries.forEach(function(c) {
			totalFiles += parseInt(c.files) || 0;
			if (c.status === 'failed' && c.changes > 0) violations++;
			if (c.status === 'verified' || c.status === 'baseline') goodChecks++;
		});

		// A check is "run" when it has a last_check timestamp or a non-pending status.
		// Only count checks that have actually been executed when deciding whether
		// the system is clean -- unrun checks should not force the global status
		// to PENDING when all executed checks have passed.
		const runEntries = entries.filter(function(c) {
			return c.last_check || (c.status && c.status !== 'pending');
		});
		const allRunGood = runEntries.length > 0 &&
			runEntries.every(function(c) {
				return c.status === 'verified' || c.status === 'baseline';
			});
		const noneRun = runEntries.length === 0;

		// Legacy alias kept for the allGood branch below -- now means
		// "all checks that have been run are clean".
		const allGood = allRunGood;

		document.getElementById('stat-files').textContent = totalFiles;
		document.getElementById('stat-violations').textContent = violations;

		// Show the most recent last_check timestamp across all checks
		let latestCheck = null;
		entries.forEach(function(c) {
			if (!c.last_check) return;
			const t = typeof c.last_check === 'number' ?
				c.last_check * 1000 :
				Date.parse(c.last_check.replace(' ', 'T'));
			if (!isNaN(t) && (!latestCheck || t > latestCheck)) latestCheck = t;
		});

		const lastCheckEl = document.getElementById('stat-lastcheck');
		if (lastCheckEl) {
			lastCheckEl.textContent = latestCheck ?
				new Date(latestCheck).toLocaleString() : '--';
		}

		const statusEl = document.getElementById('stat-status');
		if (statusEl) {
			if (violations > 0) {
				statusEl.textContent = 'FAILED';
				statusEl.className = 'tn-status-text';
				statusEl.dataset.result = 'fail';
			} else if (allGood) {
				statusEl.textContent = 'VERIFIED';
				statusEl.className = 'tn-status-text';
				statusEl.dataset.result = 'pass';
			} else if (noneRun) {
				statusEl.textContent = 'PENDING';
				statusEl.className = 'tn-status-text';
				statusEl.dataset.result = 'warn';
			} else {
				// Some checks run clean, some not yet run -- no violations
				// but not fully verified. Distinguish from PENDING (nothing run)
				// and VERIFIED (everything clean).
				statusEl.textContent = 'PARTIAL';
				statusEl.className = 'tn-status-text';
				statusEl.dataset.result = 'warn';
			}
		}

		updateViolationAccordion(violations);

		console.log('[Integrity] Stats \u2014 files:', totalFiles,
			'failed checks:', violations, 'good:', goodChecks, '/', entries.length);
	}

	// ============================================
	// VIOLATION ACCORDION INTEGRATION
	// ============================================
	function updateViolationAccordion(violationCount) {
		const badge = document.getElementById('violation-count-badge');
		if (badge) {
			badge.textContent = violationCount > 0 ?
				'(' + violationCount + ' check' + (violationCount !== 1 ? 's' : '') + ' failed)' :
				'(all clear)';
			badge.dataset.state = violationCount > 0 ? 'violations' : 'clean';
		}

		if (violationCount > 0 && !violationsAutoExpanded) {
			violationsAutoExpanded = true;
			const btn = document.querySelector('.files-accordion-btn');
			if (btn && btn.getAttribute('aria-expanded') !== 'true') {
				setTimeout(function() {
					btn.click();
				}, 100);
			}
		} else if (violationCount === 0) {
			violationsAutoExpanded = false;
		}
	}

	function refreshFileAccordion(forceClearAll) {
		if (window.IntegrityFileAccordion && window.IntegrityFileAccordion.refreshViolations) {
			window.IntegrityFileAccordion.refreshViolations(forceClearAll || false);
		}
	}

	// ============================================
	// MODAL HELPERS
	// ============================================
	function createModal(title, checkType, statusText) {
		const modal = document.createElement('div');
		modal.className = 'modal-overlay';

		const content = document.createElement('div');
		content.className = 'modal-content';

		const header = document.createElement('div');
		header.className = 'modal-header';

		const h2 = document.createElement('h2');
		h2.textContent = title + ': ' + checkType.toUpperCase();

		const closeBtn = document.createElement('button');
		closeBtn.className = 'modal-close';
		closeBtn.textContent = '\u00d7';
		closeBtn.addEventListener('click', function() {
			// If this check is still running, minimise the modal to a small
			// progress indicator rather than destroying it -- the result will
			// arrive and update the card when the daemon finishes.
			// If it is not active (already finished), remove it outright.
			const checkAttr = modal.dataset && modal.dataset.check;
			if (checkAttr && activeChecks.has(checkAttr)) {
				modal.classList.add('modal-minimised');
				closeBtn.textContent = '\u25a1'; // restore icon
				closeBtn.title = 'Verification still running -- click card badge to restore';
				closeBtn.removeEventListener('click', arguments.callee);
				closeBtn.addEventListener('click', function() {
					modal.classList.remove('modal-minimised');
					closeBtn.textContent = '\u00d7';
					closeBtn.title = '';
				});
			} else {
				modal.remove();
			}
		});

		header.appendChild(h2);
		header.appendChild(closeBtn);

		const body = document.createElement('div');
		body.className = 'modal-body';

		const statusDiv = document.createElement('div');
		statusDiv.className = 'modal-status';

		const spinner = document.createElement('div');
		spinner.className = 'spinner';

		const statusP = document.createElement('p');
		statusP.className = 'status-text';
		statusP.textContent = statusText;

		statusDiv.appendChild(spinner);
		statusDiv.appendChild(statusP);

		const resultsDiv = document.createElement('div');
		resultsDiv.className = 'verification-results hidden';

		body.appendChild(statusDiv);
		body.appendChild(resultsDiv);
		content.appendChild(header);
		content.appendChild(body);
		modal.appendChild(content);

		modal.dataset.check = checkType;
		document.body.appendChild(modal);
		return modal;
	}

	function updateModal(modal, status, message, data) {
		const statusDiv = modal.querySelector('.modal-status');
		const resultsDiv = modal.querySelector('.verification-results');
		if (!statusDiv) return;

		statusDiv.innerHTML = '';

		const icon = document.createElement('div');
		const msgP = document.createElement('p');
		msgP.className = 'status-text';
		msgP.textContent = message;

		if (status === 'success') {
			icon.className = 'status-icon success';
			icon.textContent = '\u2713';
			statusDiv.appendChild(icon);
			statusDiv.appendChild(msgP);

			if (data && resultsDiv) {
				resultsDiv.classList.remove('hidden');
				resultsDiv.innerHTML = '';
				const fragment = data.action === 'update-baseline' ?
					buildAcceptResults(data) :
					buildVerificationResults(data);
				resultsDiv.appendChild(fragment);
			}
		} else if (status === 'error') {
			icon.className = 'status-icon error';
			icon.textContent = '\u2717';
			statusDiv.appendChild(icon);
			statusDiv.appendChild(msgP);
		} else if (status === 'polling') {
			// Streaming dropped -- show spinner + updated message while polling
			const spin = document.createElement('div');
			spin.className = 'spinner';
			statusDiv.appendChild(spin);
			statusDiv.appendChild(msgP);
		}
	}

	function buildVerificationResults(data) {
		const frag = document.createDocumentFragment();

		const title = document.createElement('h3');
		title.textContent = 'Verification Results';
		frag.appendChild(title);

		function addRow(label, value, isError) {
			const row = document.createElement('div');
			row.className = isError ? 'result-item error' : 'result-item';
			const lbl = document.createElement('div');
			lbl.className = 'result-label';
			lbl.textContent = label;
			const val = document.createElement('div');
			val.className = 'result-value';
			val.textContent = String(value);
			row.appendChild(lbl);
			row.appendChild(val);
			frag.appendChild(row);
		}

		addRow('Files Checked:', data.files || 0);
		addRow('Changes Detected:', data.changes || 0);
		addRow('Duration:', data.duration || 'N/A');

		if (data.changes > 0 && data.changed_files && data.changed_files.length > 0) {
			const row = document.createElement('div');
			row.className = 'result-item error';
			const lbl = document.createElement('div');
			lbl.className = 'result-label';
			lbl.textContent = 'Modified Files:';
			row.appendChild(lbl);
			data.changed_files.slice(0, 10).forEach(function(file) {
				const val = document.createElement('div');
				val.className = 'result-value';
				val.textContent = '\u2022 ' + (file.filepath || file);
				row.appendChild(val);
			});
			if (data.changed_files.length > 10) {
				const val = document.createElement('div');
				val.className = 'result-value';
				val.textContent = '\u2026 and ' + (data.changed_files.length - 10) + ' more';
				row.appendChild(val);
			}
			frag.appendChild(row);
		}

		return frag;
	}

	function buildAcceptResults(data) {
		const frag = document.createDocumentFragment();

		const title = document.createElement('h3');
		title.textContent = 'Baseline Update Results';
		frag.appendChild(title);

		function addRow(label, value) {
			const row = document.createElement('div');
			row.className = 'result-item';
			const lbl = document.createElement('div');
			lbl.className = 'result-label';
			lbl.textContent = label;
			const val = document.createElement('div');
			val.className = 'result-value';
			val.textContent = String(value);
			row.appendChild(lbl);
			row.appendChild(val);
			frag.appendChild(row);
		}

		addRow('Accepted:', (data.accepted || 0) + ' file(s)');
		addRow('Skipped (missing on disk):', (data.skipped_missing || 0) + ' file(s)');
		addRow('Errors:', (data.errors || 0) + ' file(s)');
		addRow('Duration:', data.duration || 'N/A');

		return frag;
	}

	// ============================================
	// UTILITY
	// ============================================
	function getRequestTimestamp() {
		const now = new Date();
		return now.getFullYear() + '-' +
			String(now.getMonth() + 1).padStart(2, '0') + '-' +
			String(now.getDate()).padStart(2, '0') + '-' +
			String(now.getHours()).padStart(2, '0') + '-' +
			String(now.getMinutes()).padStart(2, '0') + '-' +
			String(now.getSeconds()).padStart(2, '0');
	}

	// ============================================
	// BOOT
	// ============================================
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initialize);
	} else {
		initialize();
	}

	console.log('[Integrity] Module loaded');

})();
