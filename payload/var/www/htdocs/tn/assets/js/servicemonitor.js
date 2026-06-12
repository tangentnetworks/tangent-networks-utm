// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * Service Monitor Controller
 * Security and Network Services Status Dashboard
 *
 * File: servicemonitor.js
 *
 * Author: David Peter, Tangent Networks
 * Web: https://tangentnet.top
 * Email: tangent.net@zohomail.in
 * Date: Wed Jan 07 09:10:35 PM IST 2026
 *
 * Description:
 * Centralized service status monitor for security and core
 * network daemons on OpenBSD-based systems. This module
 * aggregates runtime state information for IDS, IPS,
 * antivirus, DNS, DHCP, IPv6 router advertisements, and
 * content filtering services, and exposes them to the
 * dashboard layer for real-time visibility and health checks.
 */

(function() {
	const SECURITY_SERVICES = [{
			key: 'snort',
			path: '/data/services/status/snort/status',
			display: 'Snort IDS'
		},
		{
			key: 'snortinline',
			path: '/data/services/status/snortinline/status',
			display: 'Snort IPS'
		},
		{
			key: 'snortsentry',
			path: '/data/services/status/snortsentry/status',
			display: 'Snort Sentry'
		},
		{
			key: 'clamd',
			path: '/data/services/status/clamd/status',
			display: 'ClamAV'
		},
		{
			key: 'unbound',
			path: '/data/services/status/unbound/status',
			display: 'Unbound DNS'
		},
		{
			key: 'dhcpd',
			path: '/data/services/status/dhcpd/status',
			display: 'DHCPv4 Server'
		},
		{
			key: 'rad',
			path: '/data/services/status/rad/status',
			display: 'IPv6 Router Adv'
		},
		{
			key: 'e2guardian',
			path: '/data/services/status/e2guardian/status',
			display: 'E2Guardian'
		}
	];

	async function fetchServiceStatus(service) {
		try {
			// Ensure path is correct relative to your tn folder
			//const response = await fetch(`./${service.path}?t=${Date.now()}`);
			const response = await fetch(`${service.path.replace(/^\/+/, '/')}?t=${Date.now()}`);
			if (!response.ok) throw new Error();
			const data = await response.json();
			return {
				...data,
				display_name: service.display
			};
		} catch (e) {
			return {
				display_name: service.display,
				status: 'down',
				pid: '--',
				cpu: 0,
				mem: 0
			};
		}
	}

	window.refreshDashboard = async function() {
		const desktopTbody = document.getElementById('security-service-table');
		const mobileContainer = document.getElementById('mobile-service-view');
		const syncEl = document.getElementById('service-last-sync');

		// Check if we can find the elements. If not, don't execute.
		if (!desktopTbody && !mobileContainer) return;

		try {
			const servicesData = await Promise.all(SECURITY_SERVICES.map(fetchServiceStatus));

			// Render Desktop Table
			if (desktopTbody) {
				desktopTbody.innerHTML = servicesData.map(svc => {
					const isUp = svc.status === 'running';
					const colorClass = isUp ? 'bg-green-100 text-green-800' : 'bg-red-600 text-white';
					const dotClass = isUp ? 'bg-green-500' : 'bg-red-500';

					return `
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
                            <td class="px-6 py-4 font-medium text-gray-900 dark:text-white">${svc.display_name}</td>
                            <td class="px-6 py-4">
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold ${colorClass}">
                                    <span class="mr-1.5 h-1.5 w-1.5 rounded-full ${dotClass}"></span>
                                    ${svc.status.toUpperCase()}
                                </span>
                            </td>
                            <td class="px-6 py-4 font-mono text-sm text-gray-500 dark:text-white">${svc.pid || '--'}</td>
                            <td class="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                                ${svc.cpu}% CPU / ${svc.mem}% RAM
                            </td>
                        </tr>`;
				}).join('');
			}

			// Render Mobile Cards
			if (mobileContainer) {
				mobileContainer.innerHTML = servicesData.map(svc => {
					const isUp = svc.status === 'running';
					const colorClass = isUp ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800';
					const dotClass = isUp ? 'bg-green-500' : 'bg-red-500';

					return `
                        <div class="p-4 bg-white dark:bg-gray-800">
                            <div class="flex justify-between items-start">
                                <span class="font-medium text-gray-900 dark:text-white">${svc.display_name}</span>
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold ${colorClass}">
                                    <span class="mr-1.5 h-1.5 w-1.5 rounded-full ${dotClass}"></span>
                                    ${svc.status.toUpperCase()}
                                </span>
                            </div>
                            <div class="mt-2 grid grid-cols-2 gap-2 text-xs text-gray-500 dark:text-gray-400">
                                <div>PID: <span class="font-mono">${svc.pid || '--'}</span></div>
                                <div class="text-right">${svc.cpu}% CPU / ${svc.mem}% RAM</div>
                            </div>
                        </div>`;
				}).join('');
			}

			if (syncEl) syncEl.innerText = new Date().toLocaleTimeString();

		} catch (err) {
			console.error("Fetch process failed:", err);
		}
	};

	// SELF-STARTING LOGIC
	// Instead of DOMContentLoaded, we poll briefly until the elements exist.
	// This is safer for deferred scripts in SPAs.
	let retryCount = 0;
	const checkExist = setInterval(() => {
		if (document.getElementById('security-service-table') || document.getElementById('mobile-service-view')) {
			window.refreshDashboard();
			clearInterval(checkExist);

			// Set regular update interval
			if (window.dashServiceInterval) clearInterval(window.dashServiceInterval);
			window.dashServiceInterval = setInterval(window.refreshDashboard, 30000);
		}
		if (++retryCount > 10) clearInterval(checkExist); // Stop trying after 5 seconds
	}, 500);

})();
