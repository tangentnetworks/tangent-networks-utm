// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

// =============================================
// token.js - CSRF Token Management System
// =============================================
// Handles CSRF token fetching, storage, validation,
// and automatic refresh for Tangent Networks.
//
// AUTHOR: David Peter, Tangent Networks
// VERSION: 2.0.0
// =============================================

(function() {
    'use strict';

    // =============================================
    // CONFIGURATION
    // =============================================

    const CONFIG = Object.freeze({
        CSRF_ENDPOINT: '/cgi-bin/control.pl/api/csrf',
        REFRESH_INTERVAL: 1800000, // 30 minutes in milliseconds
        RETRY_ATTEMPTS: 3,
        RETRY_DELAY: 1000, // 1 second
    });

    // =============================================
    // STATE
    // =============================================

    let csrfToken = null;
    let refreshTimer = null;
    let isRefreshing = false;

    // =============================================
    // CORE FUNCTIONS
    // =============================================

    /**
     * Fetches a fresh CSRF token from the server
     * @param {number} retries - Number of retry attempts remaining
     * @returns {Promise<string>} The CSRF token
     * @throws {Error} If all retry attempts fail
     */
    async function fetchCSRFToken(retries = CONFIG.RETRY_ATTEMPTS) {
    try {
        console.log('[Token] Fetching CSRF token...');

        const response = await fetch(CONFIG.CSRF_ENDPOINT, {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        if (!data.token) {
            throw new Error('Server did not return a token');
        }

        csrfToken = data.token;
        console.log('[Token] CSRF token fetched successfully');

        return csrfToken;

    } catch (error) {
        console.error('[Token] Fetch failed:', error.message);

        if (retries > 0) {
            console.log(`[Token] Retrying... (${retries} attempts left)`);
            await sleep(CONFIG.RETRY_DELAY);
            return fetchCSRFToken(retries - 1);
        }

        throw new Error('Failed to fetch CSRF token after all retry attempts');
    }
}

    /**
     * Gets the current CSRF token
     * @returns {string|null} The current token or null if not loaded
     */
    function getCSRFToken() {
        if (!csrfToken) {
            console.warn('[Token] CSRF token requested but not loaded. Call fetchCSRFToken() first.');
        }
        return csrfToken;
    }

    /**
     * Checks if a valid CSRF token is loaded
     * @returns {boolean} True if token exists
     */
    function hasCSRFToken() {
        return csrfToken !== null && csrfToken.length > 0;
    }

    /**
     * Refreshes the CSRF token
     * @returns {Promise<string>} The new token
     */
    async function refreshCSRFToken() {
        if (isRefreshing) {
            console.log('[Token] Refresh already in progress, skipping...');
            return csrfToken;
        }

        isRefreshing = true;

        try {
            await fetchCSRFToken();
            console.log('[Token] Token refreshed successfully');
            return csrfToken;
        } catch (error) {
            console.error('[Token] Token refresh failed:', error);
            throw error;
        } finally {
            isRefreshing = false;
        }
    }

    /**
     * Starts automatic token refresh interval
     */
    function startAutoRefresh() {
        if (refreshTimer) {
            console.log('[Token] Auto-refresh already running');
            return;
        }

        console.log(`[Token] Starting auto-refresh (every ${CONFIG.REFRESH_INTERVAL / 60000} minutes)`);

        refreshTimer = setInterval(async () => {
            try {
                console.log('[Token] Auto-refresh triggered');
                await refreshCSRFToken();
            } catch (error) {
                console.error('[Token] Auto-refresh failed:', error);
                // Don't stop the timer - will retry on next interval
            }
        }, CONFIG.REFRESH_INTERVAL);
    }

    /**
     * Stops automatic token refresh
     */
    function stopAutoRefresh() {
        if (refreshTimer) {
            clearInterval(refreshTimer);
            refreshTimer = null;
            console.log('[Token] Auto-refresh stopped');
        }
    }

    /**
     * Clears the current token (for logout)
     */
    function clearCSRFToken() {
        csrfToken = null;
        stopAutoRefresh();
        console.log('[Token] Token cleared');
    }

    /**
     * Initializes the token system
     * @returns {Promise<void>}
     */
    async function initialize() {
        try {
            await fetchCSRFToken();
            startAutoRefresh();
            console.log('[Token] Token system initialized');
        } catch (error) {
            console.error('[Token] Initialization failed:', error);
            throw error;
        }
    }

    // =============================================
    // UTILITY FUNCTIONS
    // =============================================

    /**
     * Sleep helper for retry delays
     * @param {number} ms - Milliseconds to sleep
     * @returns {Promise<void>}
     */
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // =============================================
    // PUBLIC API
    // =============================================

    window.TNToken = {
        // Core functions
        fetch: fetchCSRFToken,
        get: getCSRFToken,
        has: hasCSRFToken,
        refresh: refreshCSRFToken,
        clear: clearCSRFToken,
        initialize: initialize,

        // Control functions
        startAutoRefresh: startAutoRefresh,
        stopAutoRefresh: stopAutoRefresh,

        // Configuration
        config: CONFIG,
    };



    // =============================================
    // AUTO-INITIALIZATION
    // =============================================

    // Initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', async () => {
            try {
                await initialize();
            } catch (error) {
                console.error('[Token] Auto-initialization failed:', error);
            }
        });
    } else {
        // DOM already loaded
        initialize().catch(error => {
            console.error('[Token] Auto-initialization failed:', error);
        });
    }

    console.log('[Token] Token manager loaded');

})();
