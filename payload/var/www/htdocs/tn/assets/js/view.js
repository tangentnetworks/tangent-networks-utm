// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * ============================================================================
 * VIEW MANAGEMENT SYSTEM - PHASED IMPLEMENTATION
 * ============================================================================
 *
 * NOTE: This is a phased implementation to prevent confusion when resuming work.
 * Phase 1: Active link styling only (UI works without backend)
 * Phase 2: AJAX content loading (when Perl views are ready)
 *
 * AUTHOR: David Peter, Tangent Networks
 * CREATED: Mon Dec 15 10:18:30 AM IST 2025
 * LAST MODIFIED: Wed Dec 25 17:45:00 IST 2025
 * STATUS: Phase 2 Complete with Script Cleanup
 *
 * WORK LOG:
 * Mon Dec 16 07:37:08 PM IST 2025 - Created Phase 1 (link styling)
 * Sat Dec 20 11:22:32 AM IST 2025 - Complete: Phase 2 (AJAX content loading)
 * Wed Dec 25 17:45:00 IST 2025 - Added: Script cleanup and error handling
 *
 * ARCHITECTURE:
 * ├── Phase 1: UI Styling Only
 * │   ├── Active link highlighting
 * │   ├── Click event handling
 * │   └── State management
 * └── Phase 2: Content Loading (COMPLETE)
 *     ├── AJAX to Perl backend
 *     ├── Content swapping in <main>
 *     ├── Loading/error states
 *     └── Script cleanup between views
 *
 * IMPORTANT: This script follows the principle of "JS for UI, Perl for HTML".
 * JS NEVER generates HTML - only manipulates CSS classes and fetches from Perl.
 * ============================================================================
 */

// ----------------------------------------------------------------------------
// BEGIN: CONFIGURATION SECTION
// ----------------------------------------------------------------------------
const VIEW_SYSTEM_CONFIG = {
    ENABLE_AJAX_LOADING: true,
    AJAX_TIMEOUT_MS: 10000,
    ACTIVE_LINK_CLASSES: ['border-l-4', 'border-blue-400', 'bg-blue-50', 'dark:bg-blue-900/20'],
    INACTIVE_LINK_CLASSES: ['border-l-0', 'bg-transparent'],
    DEFAULT_VIEW_SELECTOR: 'a[href*="/view/dashboard"]',

    VIEWS: {
        'dashboard': { title: 'Dashboard', template: '/view/dashboard' },
        'logs': { title: 'Logs', template: '/view/logs' },
        'firewall': { title: 'Firewall', template: '/view/firewall' },
        'services': { title: 'Services', template: '/view/services' },
        'mail': { title: 'System Mail', template: '/view/mail' },
        'external': { title: 'External Traffic', template: '/view/external' },
        'internal': { title: 'Internal Traffic', template: '/view/internal' },
	'manage': { title: 'System Setup', template: '/view/manage' },
	'integrity': { title: 'System Setup', template: '/view/integrity' },
    },
};

// ----------------------------------------------------------------------------
// VIEW STATE MANAGEMENT
// ----------------------------------------------------------------------------
const ViewState = (() => {
    let currentView = null;
    let currentActiveLink = null;

    return {
        getCurrentView: () => currentView,
        setCurrentView: (viewId) => {
            currentView = viewId;
            console.log(`[ViewState] Current view changed to: ${viewId}`);
        },
        getActiveLink: () => currentActiveLink,
        setActiveLink: (linkElement) => {
            currentActiveLink = linkElement;
        },
        reset: () => {
            currentView = null;
            currentActiveLink = null;
            console.log('[ViewState] State reset');
        }
    };
})();

// ----------------------------------------------------------------------------
// ACTIVE LINK MANAGER
// ----------------------------------------------------------------------------
const ActiveLinkManager = (() => {
    const _deactivateCurrentLink = () => {
        const currentLink = ViewState.getActiveLink();
        if (currentLink) {
            currentLink.classList.remove(...VIEW_SYSTEM_CONFIG.ACTIVE_LINK_CLASSES);
            currentLink.classList.add(...VIEW_SYSTEM_CONFIG.INACTIVE_LINK_CLASSES);
            currentLink.setAttribute('aria-current', 'false');
            console.log(`[ActiveLinkManager] Deactivated: ${currentLink.href}`);
        }
    };

    const _activateLink = (linkElement) => {
        if (!linkElement) {
            console.error('[ActiveLinkManager] Cannot activate null link');
            return;
        }

        _deactivateCurrentLink();
        linkElement.classList.remove(...VIEW_SYSTEM_CONFIG.INACTIVE_LINK_CLASSES);
        linkElement.classList.add(...VIEW_SYSTEM_CONFIG.ACTIVE_LINK_CLASSES);
        linkElement.setAttribute('aria-current', 'page');
        ViewState.setActiveLink(linkElement);
        console.log(`[ActiveLinkManager] Activated: ${linkElement.href}`);
    };

    const extractViewFromHref = (href) => {
        try {
            const url = new URL(href, window.location.origin);
            const pathSegments = url.pathname.split('/').filter(Boolean);

            const viewIndex = pathSegments.indexOf('view');
            if (viewIndex !== -1 && viewIndex + 1 < pathSegments.length) {
                return pathSegments[viewIndex + 1];
            }

            return pathSegments[pathSegments.length - 1] || 'unknown';
        } catch (error) {
            console.error('[ActiveLinkManager] Error parsing href:', href, error);
            return 'unknown';
        }
    };

    return {
        initializeDefaultView: () => {
            const defaultLink = document.querySelector(VIEW_SYSTEM_CONFIG.DEFAULT_VIEW_SELECTOR);
            if (defaultLink) {
                _activateLink(defaultLink);
                const viewId = extractViewFromHref(defaultLink.href);
                ViewState.setCurrentView(viewId);
                console.log(`[ActiveLinkManager] Default view initialized: ${viewId}`);
            } else {
                console.warn('[ActiveLinkManager] Default view link not found');
            }
        },

        handleLinkClick: (linkElement, event) => {
            event.preventDefault();

            const viewId = extractViewFromHref(linkElement.href);
            const currentViewId = ViewState.getCurrentView();

            if (viewId === currentViewId) {
                console.log(`[ActiveLinkManager] Already on view: ${viewId}`);
                return;
            }

            _activateLink(linkElement);
            ViewState.setCurrentView(viewId);
            console.log(`[ActiveLinkManager] View changed to: ${viewId}`);

            if (VIEW_SYSTEM_CONFIG.ENABLE_AJAX_LOADING) {
                ContentLoader.loadViewContent(viewId);
            }
        }
    };
})();

// ----------------------------------------------------------------------------
// CONTENT LOADER WITH SCRIPT CLEANUP
// ----------------------------------------------------------------------------
const ContentLoader = (() => {
    let mainContentArea = null;

    const initialize = () => {
        mainContentArea = document.getElementById('main-content');
        if (!mainContentArea) {
            console.error('[ContentLoader] Main content area (#main-content) not found');
            return false;
        }
        console.log('[ContentLoader] Initialized');
        return true;
    };

    const _showLoadingState = () => {
        if (!mainContentArea) return;
        mainContentArea.innerHTML = `
            <div class="flex items-center justify-center h-64">
                <div class="text-center">
                    <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
                    <p class="mt-4 text-gray-600 dark:text-gray-400">Loading ${ViewState.getCurrentView()}...</p>
                </div>
            </div>
        `;
    };

    const _showErrorState = (errorMessage) => {
        if (!mainContentArea) return;
        mainContentArea.innerHTML = `
            <div class="flex items-center justify-center h-64">
                <div class="text-center text-red-600 dark:text-red-400">
                    <svg class="h-12 w-12 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <p class="text-lg font-semibold">Error loading view</p>
                    <p class="mt-2 text-sm">${errorMessage}</p>
                </div>
            </div>
        `;
    };

    /**
     * NUCLEAR CLEANUP: Stop ALL scripts from previous view
     * This is the most aggressive approach to prevent zombie scripts
     */
    const _cleanupPreviousView = () => {
        if (!mainContentArea) return;

        console.log('[ContentLoader] NUCLEAR CLEANUP: Destroying previous view...');

        // Dispatch cleanup event BEFORE removing content
        const cleanupEvent = new CustomEvent('viewCleanup', { 
            detail: { previousView: ViewState.getCurrentView() }
        });
        mainContentArea.dispatchEvent(cleanupEvent);

        // NUCLEAR OPTION: Completely destroy and recreate the main content area
        // This ensures NO references to old DOM elements survive
        const parent = mainContentArea.parentNode;
        const newMainContent = document.createElement('main');

        // Copy all attributes
        Array.from(mainContentArea.attributes).forEach(attr => {
            newMainContent.setAttribute(attr.name, attr.value);
        });

        // Replace the entire element
        parent.replaceChild(newMainContent, mainContentArea);
        mainContentArea = newMainContent;

        console.log('[ContentLoader] Previous view completely destroyed and recreated');
    };

    /**
     * Execute scripts from the new view with proper error handling
     * Each script is wrapped in a try-catch to prevent one broken script
     * from breaking the entire view
     */
    const _executeViewScripts = (viewId) => {
        const scripts = mainContentArea.querySelectorAll('script');

        if (scripts.length === 0) {
            console.log(`[ContentLoader] No scripts to execute in ${viewId}`);
            return;
        }

        console.log(`[ContentLoader] Executing ${scripts.length} script(s) for ${viewId}`);

        scripts.forEach((oldScript, index) => {
            try {
                const newScript = document.createElement('script');

                // Copy all attributes (src, type, etc.)
                Array.from(oldScript.attributes).forEach(attr => {
                    newScript.setAttribute(attr.name, attr.value);
                });

                // For inline scripts, wrap in error handler
                if (!oldScript.src) {
                    newScript.textContent = `
                        (function() {
                            try {
                                ${oldScript.textContent}
                            } catch (error) {
                                console.error('[ViewScript:${viewId}:${index}] Error:', error.message);
                                console.error('[ViewScript:${viewId}:${index}] Stack:', error.stack);
                            }
                        })();
                    `;
                } else {
                    // For external scripts, add error handler AND scope guard
                    newScript.setAttribute('data-view', viewId);
                    newScript.onerror = function(e) {
                        console.error(`[ViewScript:${viewId}:${index}] Failed to load external script:`, oldScript.src);
                        // Don't let the error propagate
                        return true;
                    };
                    newScript.onload = function() {
                        console.log(`[ViewScript:${viewId}:${index}] Loaded external script:`, oldScript.src);
                    };
                }

                // Replace old script with new one
                oldScript.parentNode.replaceChild(newScript, oldScript);

            } catch (error) {
                console.error(`[ContentLoader] Failed to execute script ${index} in ${viewId}:`, error);
                // Don't let this error stop other scripts from loading
            }
        });
    };

    /**
     * Main content loading function with complete cleanup cycle
     */
    const loadViewContent = async (viewId) => {
        console.log(`[ContentLoader] Loading view: ${viewId}`);

        // STEP 1: Cleanup previous view first (CRITICAL)
        _cleanupPreviousView();

        // STEP 2: Show loading state
        _showLoadingState();

        try {
            // STEP 3: Validate view configuration
            const viewConfig = VIEW_SYSTEM_CONFIG.VIEWS[viewId];
            if (!viewConfig) {
                throw new Error(`View "${viewId}" not configured in VIEW_SYSTEM_CONFIG.VIEWS`);
            }

            // STEP 4: Fetch new content from server
            const response = await fetch(viewConfig.template, {
                method: 'GET',
                headers: {
                    'Accept': 'text/html',
                    'X-Requested-With': 'XMLHttpRequest' // Helps server identify AJAX requests
                },
                cache: 'no-cache' // Prevent stale content
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            // STEP 5: Insert new content
            const htmlContent = await response.text();
            mainContentArea.innerHTML = htmlContent;
            console.log(`[ContentLoader] View content loaded: ${viewId}`);

            // STEP 6: Execute view-specific scripts with error handling
            _executeViewScripts(viewId);

            // STEP 7: Dispatch load event for the new view
            const loadEvent = new CustomEvent('viewLoaded', {
                detail: { viewId: viewId, timestamp: Date.now() }
            });
            mainContentArea.dispatchEvent(loadEvent);

            console.log(`[ContentLoader] View fully initialized: ${viewId}`);

        } catch (error) {
            console.error('[ContentLoader] Error loading view:', error);
            _showErrorState(error.message);
        }
    };

    return {
        initialize,
        loadViewContent
    };
})();

// ----------------------------------------------------------------------------
// EVENT HANDLER
// ----------------------------------------------------------------------------
const EventHandler = (() => {
    const setupSidebarListeners = () => {
        const sidebarLinks = document.querySelectorAll('#nav-system a[href^="/view/"]');

        if (sidebarLinks.length === 0) {
            console.warn('[EventHandler] No sidebar links found');
            return;
        }

        sidebarLinks.forEach(link => {
            link.removeEventListener('click', handleLinkClick);
            link.addEventListener('click', handleLinkClick);
        });

        console.log(`[EventHandler] ${sidebarLinks.length} sidebar links configured`);
    };

    const handleLinkClick = (event) => {
        const linkElement = event.currentTarget;
        ActiveLinkManager.handleLinkClick(linkElement, event);
    };

    return {
        setupSidebarListeners,
        handleLinkClick
    };
})();

// ----------------------------------------------------------------------------
// INITIALIZATION
// ----------------------------------------------------------------------------
function initializeViewSystem() {
    console.log('[ViewSystem] Initializing...');

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    function init() {
        console.log('[ViewSystem] DOM ready, starting initialization');

        EventHandler.setupSidebarListeners();
        ActiveLinkManager.initializeDefaultView();

        if (VIEW_SYSTEM_CONFIG.ENABLE_AJAX_LOADING) {
            console.log('[ViewSystem] AJAX enabled - loading default view');
            if (ContentLoader.initialize()) {
                const defaultView = ViewState.getCurrentView() || 'dashboard';
                ContentLoader.loadViewContent(defaultView);
            }
        } else {
            console.log('[ViewSystem] AJAX disabled - UI only mode');
        }

        console.log('[ViewSystem] Initialization complete');
    }
}

// ----------------------------------------------------------------------------
// PUBLIC API
// ----------------------------------------------------------------------------
window.ViewSystem = {
    getCurrentView: ViewState.getCurrentView,
    initialize: initializeViewSystem,

    loadView: (viewId) => {
        if (VIEW_SYSTEM_CONFIG.ENABLE_AJAX_LOADING) {
            ContentLoader.loadViewContent(viewId);
        } else {
            console.warn('[ViewSystem] AJAX loading is disabled');
        }
    },

    debug: {
        getState: () => ({
            currentView: ViewState.getCurrentView(),
            config: VIEW_SYSTEM_CONFIG
        }),
        reset: ViewState.reset
    }
};

// Auto-initialize
initializeViewSystem();
