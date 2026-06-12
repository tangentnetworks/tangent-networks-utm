// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * Service Manager - Clean synchronous architecture with smart badge states
 * Perl backend handles waiting, JS displays results + handles transitional states
 */
(function() {
    const CONFIG = Object.freeze({
        STATUS_API: '/cgi-bin/services.pl',
        CONTROL_API: '/cgi-bin/manage_services.pl',
        CSRF_API: '/cgi-bin/control.pl/api/csrf',
        REFRESH_MS: 15000,
        GRID_ID: 'services-grid',
        STARTING_GRACE_PERIOD: 15000,  // Keep "Starting..." for 15 seconds
        PMACCT_GRACE_PERIOD: 30000     // pmacct needs longer (aggregated, 3 processes)
    });

    // Services that need grace period for startup (rc.local services)
    const SLOW_START_SERVICES = new Set([
        'snort', 'snortinline', 'snortsentry', 
        'e2guardian', 'collectd', 'p3scan', 'clamd', 
        'freshclam', 'sockd', 'spamd', 'smtp-gated',
        'sslproxy', 'imspector', 'tcpdump'
    ]);
    
    // pmacct is special - aggregated service with 3 processes + background jobs
    const PMACCT_SERVICE = 'pmacct';

    let refreshTimer = null;
    let currentData = null;
    let csrfToken = null;
    let startingServices = {};  // Track services in "Starting..." state
    const inFlight = new Set(); // Services with an in-flight control request

    // ============================================
    // DATA FETCHING WITH RETRY
    // ============================================
    async function fetchStatus(retryCount = 0) {
        const grid = document.getElementById(CONFIG.GRID_ID);
        if (!grid) {
            stopMonitoring();
            return;
        }

        try {
            const response = await fetch(CONFIG.STATUS_API);
            if (!response.ok) throw new Error('CGI Unreachable');
            const data = await response.json();

            updateDashboard(data.services, data.timestamp);
        } catch (err) {
            // Retry on network errors (up to 3 times)
            if (retryCount < 3 && err.message.includes('NetworkError')) {
                console.log(`Network error, retrying (${retryCount + 1}/3)...`);
                setTimeout(() => fetchStatus(retryCount + 1), 1000);
            } else {
                handleFetchError(grid, err);
            }
        }
    }

    // Fetch status and return raw service data -- used by pollUntilRunning
    // so the modal can get real state without a separate API
    async function fetchStatusData() {
        const response = await fetch(CONFIG.STATUS_API);
        if (!response.ok) throw new Error('CGI Unreachable');
        const data = await response.json();
        updateDashboard(data.services, data.timestamp);
        return data.services;
    }

    // Poll status every 2s until the service is running, then show the
    // success state panel in the modal -- identical UX to rcctl services.
    // If the modal is closed by the user first, polling stops cleanly.
    function pollUntilRunning(service, action, modal) {
        let stopped = false;

        // Stop polling if user closes modal manually
        const origOnClick = modal.onclick;
        modal.addEventListener('click', () => { stopped = true; });
        const closeBtn = modal.querySelector('.modal-close');
        if (closeBtn) {
            const orig = closeBtn.onclick;
            closeBtn.onclick = (e) => { stopped = true; if (orig) orig(e); };
        }

        async function poll() {
            if (stopped || !document.body.contains(modal)) return;

            try {
                const services = await fetchStatusData();
                const svc = services[service];

                if (svc && svc.status === 'running') {
                    // Service is up -- show the same success panel as rcctl services
                    updateModal(
                        modal,
                        'success',
                        `${action.toUpperCase()} completed -- ${service} is running`,
                        svc  // pass full service object as state
                    );
                    // fetchStatus already called inside fetchStatusData
                    return;
                }
            } catch (e) {
                // network blip -- keep polling
            }

            if (!stopped && document.body.contains(modal)) {
                setTimeout(poll, 2000);
            }
        }

        // First poll after a short delay to let the service settle
        setTimeout(poll, 2000);
    }

    function handleFetchError(grid, err) {
        if (!grid.querySelector('.service-card')) {
            const errCard = document.createElement('div');
            errCard.className = 'error-card';
            const errH3 = document.createElement('h3');
            errH3.textContent = 'Connection Error';
            const errP = document.createElement('p');
            errP.textContent = 'Unable to fetch service status: ' + err.message;
            errCard.appendChild(errH3);
            errCard.appendChild(errP);
            grid.innerHTML = '';
            grid.appendChild(errCard);
        }
        console.error('Fetch error:', err);
    }

    // ============================================
    // DASHBOARD RENDERING
    // ============================================
    function updateDashboard(services, ts) {
        const grid = document.getElementById(CONFIG.GRID_ID);
        if (!grid) return;

        const keys = Object.keys(services).sort();
        const existingCards = grid.querySelectorAll('.service-card');

        // Full render on first load or if service count changed
        if (existingCards.length === 0 || existingCards.length !== keys.length) {
            renderFullDashboard(services, ts);
            return;
        }

        // Incremental update for existing cards (no flicker)
        updateExistingCards(services, keys, existingCards, ts);
    }

    function renderFullDashboard(services, ts) {
        const grid = document.getElementById(CONFIG.GRID_ID);
        if (!grid) return;

        const keys = Object.keys(services).sort();
        let stats = { running: 0, cpu: 0, mem: 0 };

        const frag = document.createDocumentFragment();
        keys.forEach(key => {
            const s = services[key];
            const isRunning = s.status === 'running';
            if (isRunning) stats.running++;

            const cpu = getServiceCPU(s);
            const mem = getServiceMemory(s);
            stats.cpu += cpu;
            stats.mem += mem;

            frag.appendChild(buildServiceCard(key, s, cpu, mem, isRunning));
        });

        grid.innerHTML = '';
        grid.appendChild(frag);
        updateStatsDisplay(stats, keys.length);
        updateTimestamp(ts);
    }

    function updateExistingCards(services, keys, existingCards, ts) {
        let stats = { running: 0, cpu: 0, mem: 0 };

        keys.forEach((key, index) => {
            const s = services[key];
            const isRunning = s.status === 'running';
            if (isRunning) stats.running++;

            const cpu = getServiceCPU(s);
            const mem = getServiceMemory(s);
            stats.cpu += cpu;
            stats.mem += mem;

            const card = existingCards[index];
            if (card) updateCard(card, key, s, cpu, mem, isRunning);
        });

        updateStatsDisplay(stats, keys.length);
        updateTimestamp(ts);
    }

    // ============================================
    // CARD BUILDING & UPDATING
    // ============================================
    function buildServiceCard(key, s, cpu, mem, isRunning) {
        const pid = s.pid || (s.type === 'aggregated' ? 'MULTI' : 'N/A');
        const actionType = isRunning ? 'stop' : 'start';
        const statusState = isRunning ? 'running' : 'stopped';

        const card = document.createElement('div');
        card.className = 'service-card';
        card.dataset.service = key;

        // Header
        const header = document.createElement('div');
        header.className = 'card-header';

        const titleContainer = document.createElement('div');
        titleContainer.className = 'title-container';

        const dot = document.createElement('div');
        dot.className = 'status-dot ' + statusState;

        const h3 = document.createElement('h3');
        h3.className = 'service-name';
        h3.title = s.display_name;
        h3.textContent = s.display_name;

        titleContainer.appendChild(dot);
        titleContainer.appendChild(h3);

        const badge = document.createElement('span');
        badge.className = 'status-badge ' + statusState;
        badge.textContent = s.status;

        header.appendChild(titleContainer);
        header.appendChild(badge);

        // Stats grid
        const statsGrid = document.createElement('div');
        statsGrid.className = 'stats-grid';

        [['CPU', cpu.toFixed(1) + '%'], ['MEMORY', mem.toFixed(1) + '%'], ['PROCESS', pid]].forEach(([label, value]) => {
            const box = document.createElement('div');
            box.className = 'stat-box';
            const lp = document.createElement('p');
            lp.className = 'stat-label';
            lp.textContent = label;
            const vp = document.createElement('p');
            vp.className = 'stat-value';
            vp.textContent = value;
            box.appendChild(lp);
            box.appendChild(vp);
            statsGrid.appendChild(box);
        });

        // Buttons
        const btnContainer = document.createElement('div');
        btnContainer.className = 'button-container';

        const restartBtn = document.createElement('button');
        restartBtn.className = 'ctrl-btn restart';
        restartBtn.dataset.action = 'restart';
        restartBtn.dataset.service = key;
        restartBtn.textContent = 'Restart';

        const actionBtn = document.createElement('button');
        actionBtn.className = 'ctrl-btn ' + actionType;
        actionBtn.dataset.action = actionType;
        actionBtn.dataset.service = key;
        actionBtn.textContent = actionType === 'stop' ? 'Stop' : 'Start';

        btnContainer.appendChild(restartBtn);
        btnContainer.appendChild(actionBtn);

        card.appendChild(header);
        card.appendChild(statsGrid);
        card.appendChild(btnContainer);
        return card;
    }

    function updateCard(card, serviceName, s, cpu, mem, isRunning) {
        // Check if this service is in "Starting..." grace period
        if (startingServices[serviceName]) {
            const elapsed = Date.now() - startingServices[serviceName].startTime;
            
            // Determine grace period based on service type
            let gracePeriod = CONFIG.STARTING_GRACE_PERIOD;
            if (serviceName === PMACCT_SERVICE) {
                gracePeriod = CONFIG.PMACCT_GRACE_PERIOD;  // 30 seconds for pmacct
            }
            
            // If still within grace period and status is "stopped", keep showing "Starting..."
            if (elapsed < gracePeriod && s.status === 'stopped') {
                setCardToStarting(card, serviceName);
                return;  // Don't update with actual "stopped" status yet
            } else {
                // Grace period expired or service is now running
                delete startingServices[serviceName];
            }
        }

        // Normal update
        updateCardNormal(card, s, cpu, mem, isRunning);
    }

    function updateCardNormal(card, s, cpu, mem, isRunning) {
        // Update status dot
        const statusDot = card.querySelector('.status-dot');
        if (statusDot) {
            statusDot.className = `status-dot ${isRunning ? 'running' : 'stopped'}`;
        }

        // Update status badge
        const statusBadge = card.querySelector('.status-badge');
        if (statusBadge) {
            statusBadge.className = `status-badge ${isRunning ? 'running' : 'stopped'}`;
            statusBadge.textContent = s.status;
        }

        // Update stat values
        const statValues = card.querySelectorAll('.stat-value');
        if (statValues.length >= 3) {
            statValues[0].textContent = `${cpu.toFixed(1)}%`;
            statValues[1].textContent = `${mem.toFixed(1)}%`;
            statValues[2].textContent = s.pid || (s.type === 'aggregated' ? 'MULTI' : 'N/A');
        }

        // Update action button -- never re-enable if a control request is in flight
        const actionBtn = card.querySelector('.button-container .ctrl-btn:last-child');
        if (actionBtn) {
            const actionType = isRunning ? 'stop' : 'start';
            actionBtn.dataset.action = actionType;
            actionBtn.className = `ctrl-btn ${actionType}`;
            actionBtn.textContent = actionType === 'stop' ? 'Stop' : 'Start';
            const serviceName = card.dataset.service;
            if (!inFlight.has(serviceName)) {
                card.querySelectorAll('.ctrl-btn').forEach(b => b.disabled = false);
            }
        }
    }

    function setCardToStarting(card, serviceName) {
        // Update status dot to starting (yellow/orange)
        const statusDot = card.querySelector('.status-dot');
        if (statusDot) {
            statusDot.className = 'status-dot starting';
        }

        // Update status badge to "Starting..."
        const statusBadge = card.querySelector('.status-badge');
        if (statusBadge) {
            statusBadge.className = 'status-badge starting';
            statusBadge.textContent = 'Starting';
            const dots = document.createElement('span');
            dots.className = 'dots';
            dots.textContent = '...';
            statusBadge.appendChild(dots);
        }

        // Disable buttons during startup
        const buttons = card.querySelectorAll('.ctrl-btn');
        buttons.forEach(btn => btn.disabled = true);
    }

    // ============================================
    // STATS & TIMESTAMP UPDATES
    // ============================================
    function updateStatsDisplay(stats, totalServices) {
        setElementText('stat-total',   totalServices,         'primary');
        setElementText('stat-running', stats.running,         'success');
        setElementText('stat-cpu',     stats.cpu.toFixed(1),  'info');
        setElementText('stat-mem',     stats.mem.toFixed(1),  'warning');
    }

    function updateTimestamp(ts) {
        const lastUpdated = document.getElementById('last-updated');
        if (lastUpdated) {
            lastUpdated.textContent = `Last Updated: ${new Date(ts).toLocaleTimeString()}`;
            lastUpdated.className = 'service-timestamp';
        }
    }

    // ============================================
    // CSRF TOKEN MANAGEMENT
    // ============================================
    async function fetchCSRFToken() {
        try {
            const response = await fetch(CONFIG.CSRF_API);
            if (!response.ok) return null;
            const data = await response.json();
            csrfToken = data.token;
            return csrfToken;
        } catch (err) {
            console.error('CSRF fetch error:', err);
            return null;
        }
    }

    // ============================================
    // MODAL MANAGEMENT
    // ============================================
    function createModal(service, action) {
        // Remove any existing modals
        document.querySelectorAll('.modal-overlay').forEach(m => m.remove());

        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        const content = document.createElement('div');
        content.className = 'modal-content';

        const mHeader = document.createElement('div');
        mHeader.className = 'modal-header';
        const mTitle = document.createElement('h2');
        mTitle.textContent = action.toUpperCase() + ': ' + service;
        const closeBtn = document.createElement('button');
        closeBtn.className = 'modal-close';
        closeBtn.textContent = '×';
        mHeader.appendChild(mTitle);
        mHeader.appendChild(closeBtn);

        const mBody = document.createElement('div');
        mBody.className = 'modal-body';

        const statusDiv = document.createElement('div');
        statusDiv.className = 'modal-status';
        const initSpinner = document.createElement('div');
        initSpinner.className = 'spinner';
        const initText = document.createElement('p');
        initText.className = 'status-text';
        initText.textContent = 'Processing ' + action + ' command...';
        statusDiv.appendChild(initSpinner);
        statusDiv.appendChild(initText);

        const detailsDiv = document.createElement('div');
        detailsDiv.className = 'modal-details';
        detailsDiv.classList.add('hidden');

        mBody.appendChild(statusDiv);
        mBody.appendChild(detailsDiv);
        content.appendChild(mHeader);
        content.appendChild(mBody);
        modal.appendChild(content);

        // Close button handler
        closeBtn.onclick = () => modal.remove();
        
        // Click overlay background to close
        modal.onclick = (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        };

        document.body.appendChild(modal);
        return modal;
    }

    function updateModal(modal, status, message, serviceState = null) {
        const statusDiv = modal.querySelector('.modal-status');
        const detailsDiv = modal.querySelector('.modal-details');

        statusDiv.innerHTML = '';

        if (status === 'processing') {
            const spinner = document.createElement('div');
            spinner.className = 'spinner';
            const p = document.createElement('p');
            p.className = 'status-text';
            p.textContent = message;
            statusDiv.appendChild(spinner);
            statusDiv.appendChild(p);
        } else if (status === 'success') {
            const icon = document.createElement('div');
            icon.className = 'status-icon success';
            icon.textContent = 'OK:';
            const p = document.createElement('p');
            p.className = 'status-text success';
            p.textContent = message;
            statusDiv.appendChild(icon);
            statusDiv.appendChild(p);

            if (serviceState) {
                detailsDiv.classList.remove('hidden');
                detailsDiv.appendChild(buildServiceStatePanel(serviceState));
            }

            setTimeout(() => modal.remove(), 8000);
        } else if (status === 'error') {
            const icon = document.createElement('div');
            icon.className = 'status-icon error';
            icon.textContent = 'ERROR:';
            const p = document.createElement('p');
            p.className = 'status-text error';
            p.textContent = message;
            statusDiv.appendChild(icon);
            statusDiv.appendChild(p);

            if (serviceState) {
                detailsDiv.classList.remove('hidden');
                detailsDiv.appendChild(buildServiceStatePanel(serviceState));
            }
        }
    }

    function buildServiceStatePanel(state) {
        const panel = document.createElement('div');
        panel.className = 'state-panel';
        const h3 = document.createElement('h3');
        h3.textContent = 'CURRENT STATE';
        const table = document.createElement('table');
        table.className = 'state-table';

        const rows = [
            ['Status',  state.status || 'unknown'],
            ['PID',     state.pid || 'N/A'],
            ['User',    state.user || 'N/A'],
            ['CPU',     (state.cpu || '0.0') + '%'],
            ['Memory',  (state.mem || '0.0') + '%'],
            ['RSS',     (state.rss || 'N/A') + ' KB'],
            ['VSZ',     (state.vsz || 'N/A') + ' KB'],
            ['Command', state.command || state.arguments || 'N/A'],
            ['Type',    state.type || 'N/A']
        ];
        rows.forEach(([label, value]) => {
            const tr = document.createElement('tr');
            const tdL = document.createElement('td');
            tdL.textContent = label + ':';
            const tdV = document.createElement('td');
            tdV.className = 'state-value';
            tdV.textContent = value;
            tr.appendChild(tdL);
            tr.appendChild(tdV);
            table.appendChild(tr);
        });

        panel.appendChild(h3);
        panel.appendChild(table);
        return panel;
    }

    // ============================================
    // SERVICE CONTROL HANDLER
    // ============================================
    async function handleControlRequest(e) {
        const btn = e.target.closest('.ctrl-btn');
        if (!btn) return;

        const { service, action } = btn.dataset;
        
        // Prevent double-clicks
        if (btn.disabled) return;
        
        // Ensure we have a CSRF token
        if (!csrfToken) {
            csrfToken = await fetchCSRFToken();
            if (!csrfToken) {
                alert('Security token unavailable. Please refresh the page.');
                return;
            }
        }

        // Open modal immediately
        const modal = createModal(service, action);
        
        // Visual feedback on button -- stays disabled for entire fetch duration
        const originalText = btn.textContent;
        btn.disabled = true;
        btn.classList.add('btn--dimmed');
        // Also lock the restart button on the same card
        const card = document.querySelector(`[data-service="${service}"]`);
        if (card) card.querySelectorAll('.ctrl-btn').forEach(b => b.disabled = true);
        // Mark in-flight so auto-refresh cannot re-enable buttons underneath us
        inFlight.add(service);

        try {
            // Single request -- Perl either returns immediately (async services)
            // or waits for the outcome file (fast/stop operations)
            const response = await fetch(CONFIG.CONTROL_API, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    service, 
                    action,
                    csrf_token: csrfToken 
                })
            });

            if (response.ok) {
                const result = await response.json();
                
                if (result.success && result.data) {

                    // Async dispatch -- Perl returned immediately after queuing.
                    // Show spinner with informational message, then poll until
                    // the service is running and show the full state panel.
                    if (result.data.queued) {
                        updateModal(
                            modal,
                            'processing',
                            `${service} is starting -- checking every 2s until running…`
                        );
                        handlePostSuccessState(service, action);
                        pollUntilRunning(service, action, modal);

                    // Normal completed outcome from Perl
                    } else if (result.data.success !== undefined) {
                        if (result.data.success) {
                            updateModal(
                                modal, 
                                'success', 
                                `${action.toUpperCase()} completed successfully`,
                                result.data.state
                            );
                            handlePostSuccessState(service, action);
                        } else {
                            updateModal(
                                modal, 
                                'error', 
                                `${action.toUpperCase()} failed: ${result.data.error || result.data.manager_output || 'Unknown error'}`,
                                result.data.state
                            );
                            fetchStatus();
                        }
                    } else {
                        updateModal(modal, 'error', result.message || 'Unexpected response from server');
                        fetchStatus();
                    }
                } else {
                    throw new Error(result.message || 'Failed to execute command');
                }
            } else {
                csrfToken = await fetchCSRFToken();
                throw new Error('Request failed -- please try again');
            }
        } catch (err) {
            updateModal(modal, 'error', `Error: ${err.message}`);
            console.error("Control error:", err);
            fetchStatus();
        } finally {
            // Clear in-flight guard and re-enable buttons
            inFlight.delete(service);
            btn.textContent = originalText;
            btn.classList.remove('btn--dimmed');
            btn.disabled = false;
            if (card) card.querySelectorAll('.ctrl-btn').forEach(b => b.disabled = false);
        }
    }

    // ============================================
    // POST-SUCCESS STATE HANDLING (OPTION D)
    // ============================================
    function handlePostSuccessState(service, action) {
        // Handle start/restart for slow-start services
        const isSlowStart = SLOW_START_SERVICES.has(service) || service === PMACCT_SERVICE;
        
        if ((action === 'start' || action === 'restart') && isSlowStart) {
            // Mark service as "Starting..."
            startingServices[service] = {
                startTime: Date.now(),
                action: action
            };
            
            // Find the card and set it to "Starting..." immediately
            const card = document.querySelector(`[data-service="${service}"]`);
            if (card) {
                setCardToStarting(card, service);
            }
            
            // Determine grace period
            const gracePeriod = service === PMACCT_SERVICE ? 
                CONFIG.PMACCT_GRACE_PERIOD : CONFIG.STARTING_GRACE_PERIOD;
            
            // Trigger immediate status refresh
            setTimeout(() => fetchStatus(), 500);
            
            // Trigger another refresh after 3 seconds
            setTimeout(() => fetchStatus(), 3000);
            
            // For pmacct, add more intermediate checks (every 5 seconds)
            if (service === PMACCT_SERVICE) {
                setTimeout(() => fetchStatus(), 8000);
                setTimeout(() => fetchStatus(), 15000);
                setTimeout(() => fetchStatus(), 22000);
            }
            
            // Final check after grace period
            setTimeout(() => {
                delete startingServices[service];
                fetchStatus();
            }, gracePeriod);
        } else {
            // For rcctl services or stop operations, just refresh immediately
            setTimeout(() => fetchStatus(), 500);
        }
    }

    // ============================================
    // MANUAL REFRESH HANDLER
    // ============================================
    async function handleManualRefresh(e) {
    const btn = e.currentTarget;
    if (!btn) return;
    
    const idleSpan = btn.querySelector('.refresh-idle');
    const workingSpan = btn.querySelector('.refresh-working');
    // Disable and show WORKING state
    btn.disabled = true;
    idleSpan.classList.add('hidden');
    workingSpan.classList.remove('hidden');
    btn.classList.add('btn--working');

    try {
        await fetchStatus();

        // Success state clears after brief pause
        setTimeout(() => {
            btn.classList.remove('btn--working');
        }, 500);
    } catch (err) {
        console.error('Manual refresh error:', err);

        btn.classList.remove('btn--working');
        btn.classList.add('btn--failed');
        setTimeout(() => {
            btn.classList.remove('btn--failed');
        }, 500);
    } finally {
        // Re-enable and restore REFRESH text
        setTimeout(() => {
            idleSpan.classList.remove('hidden');
            workingSpan.classList.add('hidden');
            btn.disabled = false;
        }, 600);
    }
}

    // ============================================
    // MONITORING LIFECYCLE
    // ============================================
    async function startMonitoring() {
        if (refreshTimer) clearInterval(refreshTimer);

        const grid = document.getElementById(CONFIG.GRID_ID);
        if (!grid) return;

        grid.addEventListener('click', handleControlRequest);

        // Attach refresh button handler
        const refreshBtn = document.getElementById('refresh-services');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', handleManualRefresh);
        }

        // Show loading only if empty
        if (!grid.querySelector('.service-card')) {
            showLoadingPlaceholders(grid);
        }

        // Fetch CSRF token first
        await fetchCSRFToken();

        fetchStatus();
        refreshTimer = setInterval(fetchStatus, CONFIG.REFRESH_MS);
    }

    function stopMonitoring() {
        clearInterval(refreshTimer);
        refreshTimer = null;
        const grid = document.getElementById(CONFIG.GRID_ID);
        if (grid) grid.removeEventListener('click', handleControlRequest);
        
        const refreshBtn = document.getElementById('refresh-services');
        if (refreshBtn) refreshBtn.removeEventListener('click', handleManualRefresh);
    }

    function showLoadingPlaceholders(grid) {
        const frag = document.createDocumentFragment();
        for (let i = 0; i < 6; i++) {
            const ph = document.createElement('div');
            ph.className = 'loading-placeholder';
            frag.appendChild(ph);
        }
        grid.innerHTML = '';
        grid.appendChild(frag);
    }

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================
    function getServiceCPU(s) {
        return s.type === 'aggregated' 
            ? parseFloat(s.aggregated_metrics.total_cpu) 
            : parseFloat(s.cpu || 0);
    }

    function getServiceMemory(s) {
        return s.type === 'aggregated' 
            ? parseFloat(s.aggregated_metrics.total_mem) 
            : parseFloat(s.mem || 0);
    }

    function setElementText(id, value, colorRole) {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = value;
            if (colorRole) el.dataset.colorRole = colorRole;
        }
    }

    // ============================================
    // INITIALIZATION
    // ============================================
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => startMonitoring());
    } else {
        startMonitoring();
    }

    // Expose refresh for manual trigger
    window.fetchStatus = fetchStatus;
})();
