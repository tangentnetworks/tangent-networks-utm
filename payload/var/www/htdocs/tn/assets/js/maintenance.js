// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

(function() {
	'use strict';

	const POLL_INTERVAL = 5000; // ms between health checks
	const POLL_ENDPOINT = '/cgi-bin/control.pl/api/health';
	const REDIRECT_TO = 'index.html';

	// Read ?action= from URL
	const params = new URLSearchParams(window.location.search);
	const action = params.get('action') || 'restart';

	if (action === 'shutdown') {
		document.getElementById('view-shutdown').classList.remove('hidden');
		// Nothing more to do - static message only
		return;
	}

	// Restart flow - show spinner and begin polling
	document.getElementById('view-restart').classList.remove('hidden');

	const statusText = document.getElementById('status-text');
	const countdownEl = document.getElementById('countdown');
	let attempts = 0;

	function updateCountdown(seconds) {
		let remaining = seconds;
		countdownEl.textContent = remaining;
		const timer = setInterval(() => {
			remaining--;
			countdownEl.textContent = remaining;
			if (remaining <= 0) clearInterval(timer);
		}, 1000);
		return timer;
	}

	async function checkHealth() {
		attempts++;
		statusText.textContent = 'Waiting for system... (attempt ' + attempts + ')';

		let countdownTimer = updateCountdown(POLL_INTERVAL / 1000);

		try {
			await fetch(POLL_ENDPOINT, {
				method: 'GET',
				cache: 'no-store',
				credentials: 'same-origin'
			});

			// Any response at all = server is back up, redirect to login
			clearInterval(countdownTimer);
			statusText.textContent = 'System online -- redirecting...';
			setTimeout(() => {
				window.location.href = REDIRECT_TO;
			}, 800);
			return;

		} catch (e) {
			// fetch() throws only on network error - system still down, keep polling
		}

		clearInterval(countdownTimer);
		setTimeout(checkHealth, POLL_INTERVAL);
	}

	// Give the system a few seconds head start before first check
	setTimeout(checkHealth, POLL_INTERVAL);
	updateCountdown(POLL_INTERVAL / 1000);

})();
