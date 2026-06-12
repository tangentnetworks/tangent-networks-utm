// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * Dashboard Controller - OpenBSD collectd Metrics (Fixed)
 * Preserving 'tangent' hostname for RRD/Unixsock compatibility
 *
 * Author: David Peter, Tangent Networks
 * Web: https://tangentnet.top
 * Email: tangent.net@zohomail.in
 * Date: Mon Dec 22 09:30:00 PM IST 2025
 *
 * Description:
 * Central controller for rendering and managing collectd-derived
 * system metrics on OpenBSD. Designed to maintain strict compatibility
 * with existing RRD layouts and unixsock expectations while enabling
 * dashboard-level aggregation and visualization logic.
 *
 * Polling behaviour:
 * If a stats file is missing, empty, or mid-write (invalid JSON), that card is
 * silently skipped for the current cycle -- no console noise. The existing card
 * value is left untouched and the next 10s poll will pick it up once collectd
 * has finished writing.
 */

(function() {

    // 1. Define the Metrics Source Map (The Unix Truth)
    const METRICS_CONFIG = [
        {
            id:   'card-cpu',
            path: '/data/stats/collectd/cpu/metrics',
            key:  'tangent/cpu_avg-cpu-average/cpu'
        },
        {
            id:   'card-mem',
            path: '/data/stats/collectd/memory/metrics',
            key:  'tangent/memory/memory-active'
        },
        {
            id:   'card-disk',
            path: '/data/stats/collectd/df/metrics',
            key:  'tangent/df-root/df_complex-used'
        },
        {
            id:   'card-net',
            path: '/data/stats/collectd/interfaces/metrics',
            key:  'tangent/interface-%%EXT_IF%%/if_octets'
        }
    ];

    /**
     * fetchMetric
     * Fetches cfg.path and parses JSON.
     * Returns parsed JSON on success, or null for ANY failure condition:
     *   - file not found / HTTP error (collectd hasn't written yet)
     *   - empty or whitespace-only body (collectd mid-write)
     *   - invalid JSON (collectd mid-write / partial flush)
     * Nothing is logged. Caller silently skips the card and waits for next poll.
     */
    async function fetchMetric(cfg) {
        try {
            const response = await fetch(`${cfg.path}?t=${Date.now()}`);
            if (!response.ok) return null;

            const text = await response.text();
            if (!text || !text.trim()) return null;

            return JSON.parse(text);
        } catch (_) {
            // Network error, JSON parse error -- not our problem right now.
            // collectd will finish writing. Next 10s tick will pick it up.
            return null;
        }
    }

    // 2. Main refresh function
    window.refreshSystemMetrics = async function() {
        for (const cfg of METRICS_CONFIG) {
            const json = await fetchMetric(cfg);
            if (!json) continue; // gave up -- skip this card this cycle

            const card = document.getElementById(cfg.id);
            if (!card) continue;

            const valueSlot = card.querySelector('.metric-value');
            if (!valueSlot) continue;

            try {
                // Handle Network differently because it has 'rx' and 'tx'
                if (cfg.id === 'card-net') {
                    const rx = json.data[cfg.key]?.values?.rx?.display || '--';
                    const tx = json.data[cfg.key]?.values?.tx?.display || '--';
                    valueSlot.textContent = rx; // Main card value is RX

                    // WAN Interface (%%EXT_IF%%)
                    const wanFooter = card.querySelector('.metric-footer-wan');
                    if (wanFooter) wanFooter.textContent = `${tx} ↑ / ${rx} ↓`;

                    // LAN Interface (%%INT_IF%%)
                    const vio1Key = 'tangent/interface-%%INT_IF%%/if_octets';
                    const vio1Rx  = json.data[vio1Key]?.values?.rx?.display || '--';
                    const vio1Tx  = json.data[vio1Key]?.values?.tx?.display || '--';
                    const lanFooter = card.querySelector('.metric-footer-lan');
                    if (lanFooter) lanFooter.textContent = `${vio1Tx} ↑ / ${vio1Rx} ↓`;

                } else if (cfg.id === 'card-disk') {
                    const displayVal = json.data[cfg.key]?.values?.value?.display;
                    if (displayVal) valueSlot.textContent = displayVal;

                    const usedRaw     = json.data['tangent/df-root/df_complex-used']?.values?.value?.raw     || 0;
                    const freeRaw     = json.data['tangent/df-root/df_complex-free']?.values?.value?.raw     || 0;
                    const reservedRaw = json.data['tangent/df-root/df_complex-reserved']?.values?.value?.raw || 0;

                    const totalSpace  = usedRaw + freeRaw + reservedRaw;
                    const percentUsed = totalSpace > 0 ? Math.round((usedRaw / totalSpace) * 100) : 0;

                    const pctFooter = card.querySelector('.metric-footer-pct');
                    if (pctFooter) {
                        const pctText = pctFooter.querySelector('svg')?.nextSibling;
                        if (pctText) {
                            pctText.textContent = `${percentUsed}% Used`;
                        } else {
                            const svg = pctFooter.querySelector('svg');
                            pctFooter.innerHTML = (svg ? svg.outerHTML : '') + ` ${percentUsed}% Used`;
                        }
                    }

                } else {
                    // Standard display value for CPU, Mem
                    const displayVal = json.data[cfg.key]?.values?.value?.display;
                    if (displayVal) valueSlot.textContent = displayVal;
                }

                // Special Case: Update Memory Footer with Free space
                if (cfg.id === 'card-mem') {
                    const free   = json.data['tangent/memory/memory-free']?.values?.value?.display;
                    const footer = card.querySelector('.metric-footer-label');
                    if (footer && free) footer.textContent = `${free} Free`;
                }

            } catch (e) {
                // DOM update errors -- these are real bugs, always log them
                console.error(`[metrics] DOM update failed for ${cfg.id}:`, e);
            }
        }
    };

    // 3. SELF-STARTING LOGIC
    let metricsRetryCount = 0;
    const checkMetricsExist = setInterval(() => {
        if (document.getElementById('card-cpu')) {
            window.refreshSystemMetrics();
            clearInterval(checkMetricsExist);

            if (window.dashMetricsInterval) clearInterval(window.dashMetricsInterval);
            window.dashMetricsInterval = setInterval(window.refreshSystemMetrics, 10000);
            console.log('[metrics] Unix Metrics Pipe: Connected.');
        }
        if (++metricsRetryCount > 20) clearInterval(checkMetricsExist);
    }, 500);

})();
