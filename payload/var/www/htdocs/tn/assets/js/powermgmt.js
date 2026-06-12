// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * Power Management Module
 * Handles logout, restart, and poweroff actions from sidebar
 *
 * Logout   TO  control.pl/auth/logout  (session destruction, cookie clear)
 * Restart  TO  power_mgmt.pl           (queued via shell runner)
 * Shutdown TO  power_mgmt.pl           (queued via shell runner)
 *
 * Flow for restart/shutdown:
 *   1. User confirms via modal
 *   2. POST power action  TO  on success:
 *   3. POST logout (silent, no redirect)
 *   4. Redirect to /maintenance.html?action=restart|shutdown
 */
(function() {
	'use strict';

	const CONFIG = Object.freeze({
		LOGOUT_API: '/cgi-bin/control.pl/auth/logout',
		POWER_API: '/cgi-bin/power_mgmt.pl',
		MAINTENANCE_PAGE: '/maintenance.html'
	});

	// ============================================
	// CSRF TOKEN HELPER
	// Waits for window.TNToken to be populated
	// by token.js before proceeding with any action
	// ============================================

	function getCsrfToken(timeout = 5000) {
		return new Promise((resolve, reject) => {
			if (window.TNToken && window.TNToken.has()) {
				return resolve(window.TNToken.get());
			}

			const interval = setInterval(() => {
				if (window.TNToken && window.TNToken.has()) {
					clearInterval(interval);
					resolve(window.TNToken.get());
				}
			}, 100);

			setTimeout(() => {
				clearInterval(interval);
				reject(new Error('CSRF token not available'));
			}, timeout);
		});
	}

	// ============================================
	// INITIALIZATION
	// ============================================

	function init() {
		console.log('[PowerMgmt] Initializing...');
		setupLogoutButton();
		setupRestartButton();
		setupPoweroffButton();
		console.log('[PowerMgmt] Ready');
	}

	// ============================================
	// BUTTON SETUP
	// ============================================

	function setupLogoutButton() {
		const btn = document.getElementById('logout-btn');
		if (btn) btn.addEventListener('click', handleLogout);
	}

	function setupRestartButton() {
		const btn = document.getElementById('restart-btn');
		if (btn) btn.addEventListener('click', handleRestart);
	}

	function setupPoweroffButton() {
		const btn = document.getElementById('poweroff-btn');
		if (btn) btn.addEventListener('click', handlePoweroff);
	}

	// ============================================
	// ACTION HANDLERS
	// ============================================

	async function handleLogout(event) {
		event.preventDefault();

		const confirmed = await showConfirmModal({
			title: 'Logout',
			message: 'Are you sure you want to logout?',
			confirmText: 'Logout',
			confirmVariant: 'safe'
		});
		if (!confirmed) return;

		try {
			const token = await getCsrfToken();
			const response = await fetch(CONFIG.LOGOUT_API, {
				method: 'POST',
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					'X-Requested-With': 'XMLHttpRequest'
				},
				body: JSON.stringify({
					csrf_token: token
				})
			});

			if (response.ok) {
				window.location.href = '/index.html';
			} else {
				throw new Error('Logout failed');
			}
		} catch (error) {
			console.error('[PowerMgmt] Logout error:', error);
			await showAlertModal('Error', 'Logout failed: ' + error.message);
		}
	}

	async function handleRestart(event) {
		event.preventDefault();

		const step1 = await showConfirmModal({
			title: 'WARNING:  Restart System',
			message: 'This will restart the system. All network connections will be interrupted. Are you sure you want to continue?',
			confirmText: 'Continue',
			confirmVariant: 'primary'
		});
		if (!step1) return;

		const step2 = await showConfirmModal({
			title: 'WARNING:  Final Confirmation',
			message: 'Click Restart to reboot the system now.',
			confirmText: 'Restart',
			confirmVariant: 'primary'
		});
		if (!step2) return;

		await executePowerAction('restart');
	}

	async function handlePoweroff(event) {
		event.preventDefault();

		const step1 = await showConfirmModal({
			title: 'WARNING:  Shutdown System',
			message: 'This will completely power off the system. You will need physical access to turn it back on. Are you absolutely sure?',
			confirmText: 'Continue',
			confirmVariant: 'danger'
		});
		if (!step1) return;

		const step2 = await showPromptModal({
			title: 'WARNING:  Type to Confirm',
			message: 'Type POWEROFF in capital letters to confirm shutdown:',
			expected: 'POWEROFF',
			confirmText: 'Shut Down',
			confirmVariant: 'danger'
		});
		if (!step2) return;

		await executePowerAction('shutdown');
	}

	// ============================================
	// SHARED POWER ACTION
	// POST power action  TO  silent logout  TO  maintenance page
	// ============================================

	async function executePowerAction(action) {
		// Show spinner while we process
		const spinner = showSpinnerModal('Processing', 'Sending command to system...');

		try {
			const token = await getCsrfToken();

			const response = await fetch(CONFIG.POWER_API, {
				method: 'POST',
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					'X-Requested-With': 'XMLHttpRequest'
				},
				body: JSON.stringify({
					action: action,
					csrf_token: token
				})
			});

			const data = await response.json();

			if (!data.success) {
				throw new Error(data.error || data.message || 'Action failed');
			}

			// Power action queued -- now silently destroy the session
			// so no authenticated requests fire after redirect
			try {
				await fetch(CONFIG.LOGOUT_API, {
					method: 'POST',
					credentials: 'same-origin',
					headers: {
						'Content-Type': 'application/json',
						'X-Requested-With': 'XMLHttpRequest'
					},
					body: JSON.stringify({
						csrf_token: token,
						silent: true
					})
				});
			} catch (e) {
				// Silent logout failure is non-fatal -- system is going down anyway
			}

			// Clear token from memory
			if (window.TNToken && window.TNToken.clear) {
				window.TNToken.clear();
			}

			// Disable all buttons to prevent any further requests
			document.querySelectorAll('button').forEach(btn => btn.disabled = true);

			// Redirect to maintenance page
			window.location.href = CONFIG.MAINTENANCE_PAGE + '?action=' + action;

		} catch (error) {
			spinner.remove();
			console.error('[PowerMgmt] ' + action + ' error:', error);
			await showAlertModal(
				'Error',
				action.charAt(0).toUpperCase() + action.slice(1) + ' failed: ' + error.message
			);
		}
	}

	// ============================================
	// MODAL HELPERS
	// All modals share the same visual style:
	// dark overlay + centered card, matching the
	// system status modal shown post-action.
	// ============================================

	/**
	 * Base overlay + card scaffold
	 */
	function createModalShell() {
		const overlay = document.createElement('div');
		overlay.className = 'modal-overlay';
		return overlay;
	}

	/**
	 * Spinner modal - non-interactive, used during async operations
	 * Returns the overlay element so caller can remove it on error
	 */
	function showSpinnerModal(title, message) {
		const overlay = createModalShell();

		const card = document.createElement('div');
		card.className = 'powermgmt-card powermgmt-card--center';

		const spinnerWrap = document.createElement('div');
		spinnerWrap.className = 'powermgmt-spinner-wrap';
		const spinner = document.createElement('div');
		spinner.className = 'powermgmt-spinner';
		spinnerWrap.appendChild(spinner);

		const h2 = document.createElement('h2');
		h2.className = 'powermgmt-title';
		h2.textContent = title;

		const p = document.createElement('p');
		p.className = 'powermgmt-subtitle';
		p.textContent = message;

		card.appendChild(spinnerWrap);
		card.appendChild(h2);
		card.appendChild(p);
		overlay.appendChild(card);
		document.body.appendChild(overlay);
		return overlay;
	}

	/**
	 * Confirm modal - replaces browser confirm()
	 * Returns Promise<boolean>
	 */
	function showConfirmModal({
		title,
		message,
		confirmText = 'Confirm',
		confirmVariant = 'primary',
		cancelText = 'Cancel'
	}) {
		return new Promise((resolve) => {
			const overlay = createModalShell();

			const card = document.createElement('div');
			card.className = 'powermgmt-card';

			const h2 = document.createElement('h2');
			h2.className = 'powermgmt-title';
			h2.textContent = title;

			const p = document.createElement('p');
			p.className = 'powermgmt-subtitle powermgmt-msg--lg';
			p.textContent = message;

			const actions = document.createElement('div');
			actions.className = 'powermgmt-actions';

			let cancelBtn = null;
			if (cancelText) {
				cancelBtn = document.createElement('button');
				cancelBtn.className = 'powermgmt-btn--cancel cancel-btn';
				cancelBtn.textContent = cancelText;
				actions.appendChild(cancelBtn);
			}

			const confirmBtn = document.createElement('button');
			confirmBtn.className = 'powermgmt-btn--confirm confirm-btn';
			confirmBtn.dataset.variant = confirmVariant;
			confirmBtn.textContent = confirmText;
			actions.appendChild(confirmBtn);

			card.appendChild(h2);
			card.appendChild(p);
			card.appendChild(actions);
			overlay.appendChild(card);

			document.body.appendChild(overlay);

			function cleanup(result) {
				overlay.remove();
				resolve(result);
			}

			confirmBtn.addEventListener('click', () => cleanup(true));
			if (cancelText) cancelBtn.addEventListener('click', () => cleanup(false));

			overlay.addEventListener('click', (e) => {
				if (e.target === overlay) cleanup(false);
			});

			overlay.addEventListener('keydown', (e) => {
				if (e.key === 'Escape') cleanup(false);
			});

			confirmBtn.focus();
		});
	}

	/**
	 * Alert modal - replaces browser alert()
	 * Returns Promise<void>
	 */
	function showAlertModal(title, message) {
		return showConfirmModal({
			title,
			message,
			confirmText: 'OK',
			confirmVariant: 'neutral',
			cancelText: null
		});
	}

	/**
	 * Prompt modal - replaces browser prompt()
	 * Returns Promise<boolean> (true only if input matches expected)
	 */
	function showPromptModal({
		title,
		message,
		expected,
		confirmText = 'Confirm',
		confirmVariant = 'danger'
	}) {
		return new Promise((resolve) => {
			const overlay = createModalShell();

			const card = document.createElement('div');
			card.className = 'powermgmt-card';

			const h2 = document.createElement('h2');
			h2.className = 'powermgmt-title';
			h2.textContent = title;

			const p = document.createElement('p');
			p.className = 'powermgmt-subtitle powermgmt-msg--sm';
			p.textContent = message;

			const input = document.createElement('input');
			input.type = 'text';
			input.className = 'powermgmt-input';
			input.placeholder = expected;
			input.autocomplete = 'off';
			input.spellcheck = false;

			const errorMsg = document.createElement('p');
			errorMsg.className = 'powermgmt-error-msg hidden';
			errorMsg.textContent = 'Incorrect -- please try again.';

			const actions = document.createElement('div');
			actions.className = 'powermgmt-actions';

			const cancelBtn = document.createElement('button');
			cancelBtn.className = 'powermgmt-btn--cancel';
			cancelBtn.textContent = 'Cancel';

			const confirmBtn = document.createElement('button');
			confirmBtn.className = 'powermgmt-btn--confirm';
			confirmBtn.dataset.variant = confirmVariant;
			confirmBtn.textContent = confirmText;

			actions.appendChild(cancelBtn);
			actions.appendChild(confirmBtn);

			card.appendChild(h2);
			card.appendChild(p);
			card.appendChild(input);
			card.appendChild(errorMsg);
			card.appendChild(actions);
			overlay.appendChild(card);
			document.body.appendChild(overlay);

			function cleanup(result) {
				overlay.remove();
				resolve(result);
			}

			function tryConfirm() {
				if (input.value === expected) {
					cleanup(true);
				} else {
					errorMsg.classList.remove('hidden');
					input.value = '';
					input.focus();
				}
			}

			confirmBtn.addEventListener('click', tryConfirm);
			cancelBtn.addEventListener('click', () => cleanup(false));

			overlay.addEventListener('click', (e) => {
				if (e.target === overlay) cleanup(false);
			});

			input.addEventListener('keydown', (e) => {
				if (e.key === 'Enter') tryConfirm();
				if (e.key === 'Escape') cleanup(false);
			});

			input.focus();
		});
	}

	// ============================================
	// AUTO-INITIALIZE
	// ============================================

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}

	console.log('[PowerMgmt] Module loaded');

})();
