// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * ============================================================================
 * MANAGE TAB NAVIGATION SYSTEM
 * ============================================================================
 *
 * AUTHOR: David Peter, Tangent Networks
 * CREATED: Sat Feb 21 2026
 *
 * ARCHITECTURE (mirrors view.js pattern):
 * ├── TabState        -- tracks current active tab
 * ├── TabRegistry     -- scripts register onActivate/onDeactivate lifecycle hooks
 * ├── TabSwitcher     -- handles DOM show/hide and fires lifecycle hooks
 * └── window.ManageNav -- public API
 *
 * SCRIPT REGISTRATION:
 *   window.ManageNav.register('pf', {
 *       onActivate:   () => { startPolling(); },
 *       onDeactivate: () => { stopPolling();  }
 *   });
 *
 * Tab IDs: 'pf' | 'e2guardian' | 'unbound'
 *
 * EVENTS DISPATCHED:
 *   manageTabChanged  -- { tab: tabId } -- on every tab switch (legacy compat)
 *   manageTabLeaving  -- { tab: tabId } -- before leaving a tab
 * ============================================================================
 */

(function () {
    'use strict';

    // -------------------------------------------------------------------------
    // TAB STATE
    // -------------------------------------------------------------------------
    const TabState = (() => {
        let _current = null;

        return {
            get: () => _current,
            set: (tabId) => {
                console.log(`[TabState] ${_current}  TO  ${tabId}`);
                _current = tabId;
            }
        };
    })();

    // -------------------------------------------------------------------------
    // TAB REGISTRY
    // Scripts call window.ManageNav.register() to hook into tab lifecycle.
    // -------------------------------------------------------------------------
    const TabRegistry = (() => {
        // { tabId: [ { onActivate, onDeactivate }, ... ] }
        const _hooks = {};

        const register = (tabId, { onActivate, onDeactivate } = {}) => {
            if (!_hooks[tabId]) _hooks[tabId] = [];
            _hooks[tabId].push({ onActivate, onDeactivate });
            console.log(`[TabRegistry] Registered hook for tab: ${tabId}`);

            // If this tab is already active, fire onActivate immediately
            if (TabState.get() === tabId && typeof onActivate === 'function') {
                console.log(`[TabRegistry] Tab "${tabId}" already active -- firing onActivate`);
                try { onActivate(); } catch (e) { console.error(`[TabRegistry] onActivate error (${tabId}):`, e); }
            }
        };

        const activate = (tabId) => {
            const hooks = _hooks[tabId] || [];
            hooks.forEach(({ onActivate }) => {
                if (typeof onActivate === 'function') {
                    try { onActivate(); } catch (e) { console.error(`[TabRegistry] onActivate error (${tabId}):`, e); }
                }
            });
        };

        const deactivate = (tabId) => {
            if (!tabId) return;
            const hooks = _hooks[tabId] || [];
            hooks.forEach(({ onDeactivate }) => {
                if (typeof onDeactivate === 'function') {
                    try { onDeactivate(); } catch (e) { console.error(`[TabRegistry] onDeactivate error (${tabId}):`, e); }
                }
            });
        };

        return { register, activate, deactivate };
    })();

    // -------------------------------------------------------------------------
    // TAB SWITCHER
    // -------------------------------------------------------------------------
    const TabSwitcher = (() => {
        const switchTo = (tabId) => {
            if (!tabId) {
                console.error('[TabSwitcher] No tab ID provided');
                return;
            }

            const previous = TabState.get();

            if (previous === tabId) {
                console.log(`[TabSwitcher] Already on tab: ${tabId}`);
                return;
            }

            console.log(`[TabSwitcher] Switching: ${previous}  TO  ${tabId}`);

            // 1. Dispatch leaving event and fire deactivate hooks for previous tab
            if (previous) {
                document.dispatchEvent(new CustomEvent('manageTabLeaving', {
                    detail: { tab: previous }
                }));
                TabRegistry.deactivate(previous);
            }

            // 2. Update DOM -- deactivate all
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));

            // 3. Activate selected tab DOM
            const content = document.getElementById(tabId + '-content');
            const button  = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);

            if (content) {
                content.classList.add('active');
            } else {
                console.error(`[TabSwitcher] Content not found: #${tabId}-content`);
            }

            if (button) {
                button.classList.add('active');
            } else {
                console.error(`[TabSwitcher] Button not found: [data-tab="${tabId}"]`);
            }

            // 4. Update state
            TabState.set(tabId);

            // 5. Fire activate hooks for new tab
            TabRegistry.activate(tabId);

            // 6. Dispatch changed event (legacy compat -- existing scripts listen for this)
            document.dispatchEvent(new CustomEvent('manageTabChanged', {
                detail: { tab: tabId }
            }));

            console.log(`[TabSwitcher] Tab ready: ${tabId}`);
        };

        return { switchTo };
    })();

    // -------------------------------------------------------------------------
    // INIT -- bind buttons and set initial state
    // -------------------------------------------------------------------------
    function init() {
        if (!document.querySelector('#app')) {
            console.log('[ManageNav] Not in manage view, skipping');
            return;
        }

        console.log('[ManageNav] Initializing...');

        // Bind tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            const fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', function (e) {
                e.preventDefault();
                TabSwitcher.switchTo(this.getAttribute('data-tab'));
            });
        });

        console.log(`[ManageNav] Bound ${document.querySelectorAll('.tab-btn').length} tab buttons`);

        // Determine initial active tab
        const activeContent = document.querySelector('.tab-content.active');
        const activeButton  = document.querySelector('.tab-btn.active');

        if (activeContent) {
            const tabId = activeContent.id.replace('-content', '');
            TabState.set(tabId);

            // Sync button if needed
            if (!activeButton) {
                const btn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
                if (btn) btn.classList.add('active');
            }

            // Fire activate hooks for the initially visible tab
            TabRegistry.activate(tabId);

            // Dispatch initial event so scripts that listen for manageTabChanged
            // on load also get their init call
            document.dispatchEvent(new CustomEvent('manageTabChanged', {
                detail: { tab: tabId }
            }));

            console.log(`[ManageNav] Initial tab: ${tabId}`);
        } else {
            // Nothing active -- activate first tab
            const first = document.querySelector('.tab-btn');
            if (first) {
                TabSwitcher.switchTo(first.getAttribute('data-tab'));
            }
        }

        document.dispatchEvent(new CustomEvent('manageNavReady'));
        console.log('[ManageNav] Ready');
    }

    // -------------------------------------------------------------------------
    // BOOT
    // -------------------------------------------------------------------------
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        setTimeout(init, 100);
    }

    // -------------------------------------------------------------------------
    // PUBLIC API  (mirrors view.js window.ViewSystem pattern)
    // -------------------------------------------------------------------------
    window.ManageNav = {
        /**
         * Register lifecycle hooks for a tab.
         *
         * @param {string} tabId         - 'pf' | 'e2guardian' | 'unbound'
         * @param {object} hooks
         * @param {function} hooks.onActivate   - called when tab becomes visible
         * @param {function} hooks.onDeactivate - called when tab is left
         *
         * Example:
         *   window.ManageNav.register('pf', {
         *       onActivate:   () => startMyPolling(),
         *       onDeactivate: () => clearMyPolling()
         *   });
         */
        register: TabRegistry.register,

        switchTo: TabSwitcher.switchTo,

        getCurrentTab: TabState.get,

        debug: {
            getState: () => ({
                currentTab: TabState.get()
            })
        }
    };

    // Legacy compat -- keep window.switchManageTab working
    window.switchManageTab = TabSwitcher.switchTo;

})();
