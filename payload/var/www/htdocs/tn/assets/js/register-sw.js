// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

(function () {
    'use strict';

    var SW_VERSION = 'tn-sw-v1'

    /* ---- Service Worker Registration -------------------------------------------- */
    function registerSW() {
        if (!('serviceWorker' in navigator)) return;

        navigator.serviceWorker.register('/sw.js')
            .then(function (reg) {
                console.log('[TN] SW registered, scope:', reg.scope);
            })
            .catch(function (err) {
                console.warn('[TN] SW registration failed:', err);
            });
    }

    /* ---- Android Chrome Install Prompt -------------------------------------------- */
    var _installPrompt = null;

    function onBeforeInstallPrompt(event) {
        event.preventDefault();
        _installPrompt = event;
        _showInstallButton();
    }

    function _showInstallButton() {
        var btn = document.getElementById('tn-install-btn');
        if (btn) btn.style.display = 'block';
    }

    function _hideInstallButton() {
        var btn = document.getElementById('tn-install-btn');
        if (btn) btn.style.display = 'none';
    }

    async function triggerInstall() {
        if (!_installPrompt) return;
        _installPrompt.prompt();
        var result = await _installPrompt.userChoice;
        console.log('[TN] Install outcome:', result.outcome);
        _installPrompt = null;
        _hideInstallButton();
    }

    /* ---- iOS Detection -------------------------------------------- */
    function _isIOS() {
        return /iphone|ipad|ipod/i.test(navigator.userAgent);
    }

    function _isInStandaloneMode() {
        return window.navigator.standalone === true;
    }

    function _showIOSBanner() {
        var banner = document.getElementById('tn-ios-install-banner');
        if (banner) banner.style.display = 'block';
    }

    function _initIOS() {
        if (_isIOS() && !_isInStandaloneMode()) {
            _showIOSBanner();
        }
    }

    /* ---- Expose only what SPA needs under TN.pwa ------------------------------ */
    window.TN       = window.TN       || {};
    window.TN.pwa   = window.TN.pwa   || {};

    window.TN.pwa.triggerInstall = triggerInstall;
    window.TN.pwa.isIOS          = _isIOS();
    window.TN.pwa.isStandalone   = _isInStandaloneMode();
    window.TN.pwa.version        = SW_VERSION;

    /* ---- Boot -------------------------------------------- */
    window.addEventListener('load', registerSW);
    window.addEventListener('beforeinstallprompt', onBeforeInstallPrompt);
    window.addEventListener('appinstalled', function () {
        console.log('[TN] PWA installed successfully');
        _installPrompt = null;
        _hideInstallButton();
    });

    document.addEventListener('DOMContentLoaded', _initIOS);

}());
