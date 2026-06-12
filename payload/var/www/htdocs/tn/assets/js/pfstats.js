// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * PF Stats Controller
 * IIFE compliant for SPA view system
 *
 * Author: David Peter, Tangent Networks
 * Web: https://tangentnet.top
 * Email: tangent.net@zohomail.in
 * Date: Fri Jan 09 08:15:40 PM IST 2026
 *
 * Description:
 * This JavaScript module provides real-time visualization of
 * OpenBSD Packet Filter (PF) firewall statistics. It renders
 * firewall state metrics, rule performance analytics, and
 * traffic throughput data within an auto-refreshing dashboard
 * interface suitable for single-page application workflows.
 */

(function() {
    const CONFIG = Object.freeze({
        refreshInterval: 15000,
        endpoint: '/data/stats/pf_stats.json'
    });

    async function refreshPFData() {
        try {
            const response = await fetch(`${CONFIG.endpoint}?t=${Date.now()}`);
            if (!response.ok) return;

            const pf = await response.json();
            if (!pf.rules || !pf.metrics) return;

            // 1. TOP VITALS - with null checks
            const statStates = document.getElementById('stat-states');
            if (statStates) {
                statStates.innerText = (pf.metrics.current || 0).toLocaleString();
            }

            const statSearch = document.getElementById('stat-search');
            if (statSearch) {
                statSearch.innerText = (pf.metrics.searches || 0).toLocaleString();
            }

            const healthEl = document.getElementById('stat-health');
            if (healthEl) {
                const status = pf.pf?.status || 'Unknown';
                healthEl.innerText = status.toUpperCase();
                healthEl.className = 'tn-status-text';
                healthEl.dataset.result = status === 'Enabled' ? 'enabled' : 'disabled';
            }

            const uptimeEl = document.getElementById('stat-uptime');
            if (uptimeEl) {
                uptimeEl.innerText = `Since: ${pf.pf?.since || '--:--:--'}`;
            }

            const churnEl = document.getElementById('stat-churn');
            if (churnEl) {
                const churn = (pf.metrics.inserts || 0) - (pf.metrics.removals || 0);
                churnEl.innerText = (churn >= 0 ? '+' : '') + churn;
            }

            // 2. RULE AUDIT TABLE
            const auditBody = document.getElementById('rule-audit-body');
            if (auditBody) {
                // Inject <colgroup> once to force fixed column widths
                const table = auditBody.closest('table');
                if (table && !table.querySelector('colgroup')) {
                    table.style.tableLayout = 'fixed';
                    const cg = document.createElement('colgroup');
                    [22, 20, 16, 18, 24].forEach(pct => {
                        const col = document.createElement('col');
                        col.style.width = pct + '%';
                        cg.appendChild(col);
                    });
                    table.insertBefore(cg, table.firstChild);
                }
                // Show top 15 rules by packet count for the audit
                const auditRules = [...pf.rules].sort((a,b) => b.packets - a.packets).slice(0, 15);
                const fragment = document.createDocumentFragment();
                auditRules.forEach(rule => {
                    const statusText = rule.status_text || 'Unused';
                    const statusCls = statusText === 'Efficient' ? 'pf-audit-status--efficient'
                                    : statusText === 'Review'    ? 'pf-audit-status--review'
                                    :                              'pf-audit-status--unused';

                    const tr = document.createElement('tr');

                    const tdId = document.createElement('td');
                    tdId.className = 'pf-audit-id py-4';
                    tdId.textContent = 'Rule ' + rule.id;

                    const tdPkts = document.createElement('td');
                    tdPkts.className = 'pf-audit-packets py-4 text-right';
                    tdPkts.textContent = (rule.packets || 0).toLocaleString();

                    const tdEvals = document.createElement('td');
                    tdEvals.className = 'pf-audit-evals py-4 text-right';
                    tdEvals.textContent = (rule.evaluations || 0).toLocaleString();

                    const tdRatio = document.createElement('td');
                    tdRatio.className = 'pf-audit-ratio py-4 text-right';
                    tdRatio.textContent = '(' + parseFloat(rule.ratio || 0).toFixed(2) + ':1)';

                    const tdStatus = document.createElement('td');
                    tdStatus.className = 'pf-audit-status-cell py-4 text-right';

                    const badge = document.createElement('span');
                    badge.className = 'pf-audit-badge ' + statusCls;

                    const dot = document.createElement('span');
                    dot.className = 'pf-audit-dot';

                    const label = document.createElement('span');
                    label.className = 'pf-audit-label';
                    label.textContent = statusText;

                    badge.appendChild(dot);
                    badge.appendChild(label);
                    tdStatus.appendChild(badge);

                    tr.appendChild(tdId);
                    tr.appendChild(tdPkts);
                    tr.appendChild(tdEvals);
                    tr.appendChild(tdRatio);
                    tr.appendChild(tdStatus);
                    fragment.appendChild(tr);
                });
                auditBody.innerHTML = '';
                auditBody.appendChild(fragment);

                // Mobile list mirror
                const auditList = document.getElementById('rule-audit-list');
                if (auditList) {
                    auditList.innerHTML = '';
                    const listFrag = document.createDocumentFragment();
                    auditRules.forEach(rule => {
                        const statusText = rule.status_text || 'Unused';
                        const statusCls = statusText === 'Efficient' ? 'pf-audit-status--efficient'
                                        : statusText === 'Review'    ? 'pf-audit-status--review'
                                        :                              'pf-audit-status--unused';

                        const li = document.createElement('li');
                        li.className = 'pf-audit-li';

                        const left = document.createElement('div');
                        left.className = 'pf-audit-li-left';

                        const ruleLabel = document.createElement('div');
                        ruleLabel.className   = 'pf-audit-li-rule';
                        ruleLabel.textContent = 'Rule ' + rule.id;

                        const nums = document.createElement('div');
                        nums.className = 'pf-audit-li-nums';

                        const pkts = document.createElement('span');
                        pkts.className   = 'pf-audit-li-pkts';
                        pkts.textContent = (rule.packets || 0).toLocaleString() + ' pkts';

                        const evals = document.createElement('span');
                        evals.className   = 'pf-audit-li-evals';
                        evals.textContent = (rule.evaluations || 0).toLocaleString() + ' evals';

                        const ratio = document.createElement('span');
                        ratio.className   = 'pf-audit-li-ratio';
                        ratio.textContent = '(' + parseFloat(rule.ratio || 0).toFixed(2) + ':1)';

                        nums.appendChild(pkts);
                        nums.appendChild(evals);
                        nums.appendChild(ratio);
                        left.appendChild(ruleLabel);
                        left.appendChild(nums);

                        const badge = document.createElement('span');
                        badge.className = 'pf-audit-badge ' + statusCls;

                        const dot = document.createElement('span');
                        dot.className = 'pf-audit-dot';

                        const lbl = document.createElement('span');
                        lbl.className   = 'pf-audit-label';
                        lbl.textContent = statusText;

                        badge.appendChild(dot);
                        badge.appendChild(lbl);

                        li.appendChild(left);
                        li.appendChild(badge);
                        listFrag.appendChild(li);
                    });
                    auditList.appendChild(listFrag);
                }
            }

            // 3. THROUGHPUT BARS
            const volumeList = document.getElementById('traffic-volume-list');
            if (volumeList) {
                // Get top 10 rules by volume
                const topRules = [...pf.rules]
                    .filter(r => (r.raw_bytes || 0) > 0)
                    .sort((a,b) => b.raw_bytes - a.raw_bytes)
                    .slice(0, 10);

                // Calculate the max value in the set to use as 100% width reference
                const maxRaw = topRules.length > 0 ? topRules[0].raw_bytes : 1;

                const volFragment = document.createDocumentFragment();
                topRules.forEach(rule => {
                    const pct = ((rule.raw_bytes / maxRaw) * 100).toFixed(1);

                    const row = document.createElement('div');
                    row.className = 'pf-vol-row';

                    // Header: rule label + bytes
                    const header = document.createElement('div');
                    header.className = 'pf-vol-header';

                    const ruleLabel = document.createElement('span');
                    ruleLabel.className = 'pf-vol-rule-label';
                    ruleLabel.textContent = 'Rule ' + rule.id;

                    const bytesLabel = document.createElement('span');
                    bytesLabel.className = 'pf-vol-bytes-label';
                    bytesLabel.textContent = rule.bytes;

                    header.appendChild(ruleLabel);
                    header.appendChild(bytesLabel);

                    // Track + bar
                    const track = document.createElement('div');
                    track.className = 'pf-vol-track';

                    const bar = document.createElement('div');
                    bar.className = 'pf-vol-bar';
                    bar.style.width = pct + '%';
                    track.appendChild(bar);

                    // Footer: label + pct
                    const footer = document.createElement('div');
                    footer.className = 'pf-vol-footer';

                    const footLeft = document.createElement('span');
                    footLeft.textContent = 'Relative Load';
                    const footRight = document.createElement('span');
                    footRight.textContent = pct + '%';

                    footer.appendChild(footLeft);
                    footer.appendChild(footRight);

                    row.appendChild(header);
                    row.appendChild(track);
                    row.appendChild(footer);
                    volFragment.appendChild(row);
                });
                volumeList.innerHTML = '';
                volumeList.appendChild(volFragment);
            }

            // Time Sync
            const lastUpdate = document.getElementById('last-update');
            if (lastUpdate) {
                lastUpdate.innerText = pf.TS.split(' ')[1];
            }

        } catch (err) {
            console.error("PF Dashboard Rascal Error:", err);
        }
    }

    // Auto-init logic
    const pfInit = setInterval(() => {
        if (document.getElementById('stat-states')) {
            refreshPFData();
            setInterval(refreshPFData, CONFIG.refreshInterval);
            clearInterval(pfInit);
        }
    }, 500);
})();
