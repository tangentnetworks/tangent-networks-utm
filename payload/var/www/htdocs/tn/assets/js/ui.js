// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

// ui.js
// Shared UI primitives: themed modal confirm, toast notifications,
// and error banners. Replaces all native confirm() / alert() calls.
//
// Usage:
//   UI.confirm({ ... })         -- destructive action confirmation
//   UI.toast(message, type)     -- auto-dismissing success/info/error
//   UI.error(message, anchor)   -- inline error banner near an element
//
// Dark mode: reads .dark on <html> -- same mechanism as the rest of the app.
// No Tailwind dark: utilities used -- all colours explicit in CSS vars.

(function (global) {
    'use strict';

    // ============================================================
    // INJECT BASE STYLES (once)
    // ============================================================
    function injectStyles() {
        if (document.getElementById('ui-js-styles')) return;

        const style = document.createElement('style');
        style.id = 'ui-js-styles';
        style.textContent = `

        /* ── Overlay ── */
        .ui-overlay {
            position: fixed;
            inset: 0;
            z-index: 10000;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            background: rgba(0, 0, 0, 0.55);
            backdrop-filter: blur(2px);
            animation: ui-fade-in 120ms ease;
        }

        /* ── Dialog card ── */
        .ui-dialog {
            width: 100%;
            max-width: 440px;
            border-radius: 0.875rem;
            box-shadow: 0 24px 64px rgba(0,0,0,0.35);
            overflow: hidden;
            animation: ui-slide-up 160ms cubic-bezier(0.16, 1, 0.3, 1);
            background: #ffffff;
            border: 1px solid #e5e7eb;
            color: #111827;
        }
        .dark .ui-dialog {
            background: #1f2937;
            border-color: #374151;
            color: #f9fafb;
        }

        /* ── Dialog header ── */
        .ui-dialog-header {
            display: flex;
            align-items: flex-start;
            gap: 0.875rem;
            padding: 1.25rem 1.5rem 1rem;
            border-bottom: 1px solid #f3f4f6;
        }
        .dark .ui-dialog-header {
            border-bottom-color: #374151;
        }

        .ui-dialog-icon {
            flex-shrink: 0;
            width: 2.5rem;
            height: 2.5rem;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.125rem;
        }
        .ui-icon-danger  { background: #fef2f2; color: #dc2626; }
        .ui-icon-warning { background: #fffbeb; color: #d97706; }
        .ui-icon-info    { background: #eff6ff; color: #2563eb; }
        .dark .ui-icon-danger  { background: #450a0a; color: #fca5a5; }
        .dark .ui-icon-warning { background: #451a03; color: #fcd34d; }
        .dark .ui-icon-info    { background: #0c1a2e; color: #93c5fd; }

        .ui-dialog-title {
            font-size: 1rem;
            font-weight: 700;
            line-height: 1.4;
            margin: 0;
            padding-top: 0.35rem;
        }

        /* ── Dialog body ── */
        .ui-dialog-body {
            padding: 1rem 1.5rem 1.25rem;
            font-size: 0.875rem;
            line-height: 1.6;
            color: #4b5563;
        }
        .dark .ui-dialog-body {
            color: #d1d5db;
        }

        /* Consequence list inside body */
        .ui-consequence-list {
            margin: 0.75rem 0 0;
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            list-style: none;
            font-size: 0.8125rem;
        }
        .dark .ui-consequence-list {
            background: #111827;
            border-color: #374151;
        }
        .ui-consequence-list li {
            padding: 0.2rem 0;
            display: flex;
            align-items: baseline;
            gap: 0.5rem;
        }
        .ui-consequence-list li::before {
            content: '•';
            flex-shrink: 0;
            color: #9ca3af;
        }

        /* Warning callout */
        .ui-warning-callout {
            margin-top: 0.875rem;
            padding: 0.625rem 0.875rem;
            border-radius: 0.5rem;
            background: #fffbeb;
            border: 1px solid #fde68a;
            color: #92400e;
            font-size: 0.8125rem;
            display: flex;
            align-items: flex-start;
            gap: 0.625rem;
        }
        .dark .ui-warning-callout {
            background: #1c1208;
            border-color: #78350f;
            color: #fcd34d;
        }
        .ui-warning-label {
            flex-shrink: 0;
            font-size: 0.625rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            background: #d97706;
            color: #ffffff;
            border-radius: 0.25rem;
            padding: 0.125rem 0.375rem;
            margin-top: 0.0625rem;
        }
        .dark .ui-warning-label {
            background: #b45309;
        }

        /* ── Dialog footer ── */
        .ui-dialog-footer {
            display: flex;
            justify-content: flex-end;
            gap: 0.625rem;
            padding: 0.875rem 1.5rem;
            border-top: 1px solid #f3f4f6;
            background: #f9fafb;
        }
        .dark .ui-dialog-footer {
            border-top-color: #374151;
            background: #111827;
        }

        /* ── Buttons ── */
        .ui-btn {
            padding: 0.5rem 1.125rem;
            border-radius: 0.5rem;
            font-size: 0.8125rem;
            font-weight: 600;
            border: none;
            cursor: pointer;
            transition: opacity 120ms, transform 80ms;
            letter-spacing: 0.01em;
        }
        .ui-btn:active { transform: scale(0.97); }

        .ui-btn-cancel {
            background: #f3f4f6;
            color: #374151;
        }
        .ui-btn-cancel:hover { background: #e5e7eb; }
        .dark .ui-btn-cancel {
            background: #374151;
            color: #d1d5db;
        }
        .dark .ui-btn-cancel:hover { background: #4b5563; }

        .ui-btn-danger {
            background: #dc2626;
            color: #ffffff;
        }
        .ui-btn-danger:hover { background: #b91c1c; }

        .ui-btn-warning {
            background: #d97706;
            color: #ffffff;
        }
        .ui-btn-warning:hover { background: #b45309; }

        .ui-btn-primary {
            background: #2563eb;
            color: #ffffff;
        }
        .ui-btn-primary:hover { background: #1d4ed8; }

        /* ── Toast ── */
        .ui-toast-container {
            position: fixed;
            bottom: 1.25rem;
            right: 1.25rem;
            z-index: 9100;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            pointer-events: none;
        }

        .ui-toast {
            pointer-events: auto;
            display: flex;
            align-items: center;
            gap: 0.625rem;
            padding: 0.75rem 1rem;
            border-radius: 0.625rem;
            font-size: 0.875rem;
            font-weight: 500;
            box-shadow: 0 8px 24px rgba(0,0,0,0.18);
            max-width: 340px;
            animation: ui-toast-in 220ms cubic-bezier(0.16, 1, 0.3, 1);
            border: 1px solid transparent;
        }
        .ui-toast-success {
            background: #f0fdf4;
            color: #14532d;
            border-color: #bbf7d0;
        }
        .ui-toast-error {
            background: #fef2f2;
            color: #7f1d1d;
            border-color: #fecaca;
        }
        .ui-toast-info {
            background: #eff6ff;
            color: #1e3a5f;
            border-color: #bfdbfe;
        }
        .ui-toast-warning {
            background: #fffbeb;
            color: #78350f;
            border-color: #fde68a;
        }

        .dark .ui-toast-success {
            background: #14291a;
            color: #86efac;
            border-color: #14532d;
        }
        .dark .ui-toast-error {
            background: #2d1515;
            color: #fca5a5;
            border-color: #7f1d1d;
        }
        .dark .ui-toast-info {
            background: #0c1a2e;
            color: #93c5fd;
            border-color: #1e3a5f;
        }
        .dark .ui-toast-warning {
            background: #1c1208;
            color: #fcd34d;
            border-color: #78350f;
        }

        .ui-toast-icon { font-size: 1rem; flex-shrink: 0; }
        .ui-toast-exit {
            animation: ui-toast-out 200ms ease forwards;
        }

        .ui-error-label {
            flex-shrink: 0;
            font-size: 0.625rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            background: #dc2626;
            color: #ffffff;
            border-radius: 0.25rem;
            padding: 0.125rem 0.375rem;
            margin-top: 0.0625rem;
        }
        .dark .ui-error-label {
            background: #b91c1c;
        }

        /* ── Error banner ── */
        .ui-error-banner {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.625rem 0.875rem;
            border-radius: 0.5rem;
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #7f1d1d;
            font-size: 0.8125rem;
            margin-top: 0.5rem;
            animation: ui-fade-in 150ms ease;
        }
        .dark .ui-error-banner {
            background: #2d1515;
            border-color: #7f1d1d;
            color: #fca5a5;
        }

        /* ── Animations ── */
        @keyframes ui-fade-in {
            from { opacity: 0; }
            to   { opacity: 1; }
        }
        @keyframes ui-slide-up {
            from { opacity: 0; transform: translateY(12px) scale(0.97); }
            to   { opacity: 1; transform: translateY(0)    scale(1);    }
        }
        @keyframes ui-toast-in {
            from { opacity: 0; transform: translateX(16px); }
            to   { opacity: 1; transform: translateX(0);    }
        }
        @keyframes ui-toast-out {
            from { opacity: 1; transform: translateX(0);    }
            to   { opacity: 0; transform: translateX(16px); }
        }
        `;

        document.head.appendChild(style);
    }

    // ============================================================
    // HELPERS
    // ============================================================
    function isDark() {
        return document.documentElement.classList.contains('dark');
    }

    function escHtml(text) {
        const d = document.createElement('div');
        d.textContent = String(text);
        return d.innerHTML;
    }

    function iconFor(variant) {
        var icons = {
            danger:  '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
            warning: '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            info:    '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
        };
        return icons[variant] || icons.info;
    }

    function btnClassFor(variant) {
        return { danger: 'ui-btn-danger', warning: 'ui-btn-warning', info: 'ui-btn-primary' }[variant] || 'ui-btn-primary';
    }

    // ============================================================
    // UI.confirm(options)
    //
    // options = {
    //   title:        string  -- bold heading
    //   body:         string  -- explanatory sentence
    //   consequences: string[] -- bullet list of what will happen
    //   warning:      string  -- optional WARNING:  callout at the bottom
    //   confirmLabel: string  -- confirm button text (default "Confirm")
    //   cancelLabel:  string  -- cancel button text  (default "Cancel")
    //   variant:      'danger' | 'warning' | 'info'  (default 'danger')
    //   onConfirm:    function
    //   onCancel:     function (optional)
    // }
    // ============================================================
    function confirm(options) {
        injectStyles();

        const variant      = options.variant      || 'danger';
        const confirmLabel = options.confirmLabel  || 'Confirm';
        const cancelLabel  = options.cancelLabel   || 'Cancel';

        const overlay = document.createElement('div');
        overlay.className = 'ui-overlay';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'ui-dialog-title');

        const consequencesHtml = options.consequences && options.consequences.length
            ? `<ul class="ui-consequence-list">
                   ${options.consequences.map(c => `<li>${escHtml(c)}</li>`).join('')}
               </ul>`
            : '';

        const warningHtml = options.warning
            ? `<div class="ui-warning-callout">
                   <span class="ui-warning-label">Warning</span>
                   <span>${escHtml(options.warning)}</span>
               </div>`
            : '';

        overlay.innerHTML = `
            <div class="ui-dialog">
                <div class="ui-dialog-header">
                    <div class="ui-dialog-icon ui-icon-${variant}">
                        ${iconFor(variant)}
                    </div>
                    <h2 class="ui-dialog-title" id="ui-dialog-title">
                        ${escHtml(options.title || 'Are you sure?')}
                    </h2>
                </div>
                <div class="ui-dialog-body">
                    ${escHtml(options.body || '')}
                    ${consequencesHtml}
                    ${warningHtml}
                </div>
                <div class="ui-dialog-footer">
                    <button class="ui-btn ui-btn-cancel" id="ui-cancel-btn">
                        ${escHtml(cancelLabel)}
                    </button>
                    <button class="ui-btn ${btnClassFor(variant)}" id="ui-confirm-btn">
                        ${escHtml(confirmLabel)}
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        function close() { overlay.remove(); }

        overlay.querySelector('#ui-confirm-btn').addEventListener('click', () => {
            close();
            if (typeof options.onConfirm === 'function') options.onConfirm();
        });

        overlay.querySelector('#ui-cancel-btn').addEventListener('click', () => {
            close();
            if (typeof options.onCancel === 'function') options.onCancel();
        });

        // Escape key
        function onKey(e) {
            if (e.key === 'Escape') {
                close();
                document.removeEventListener('keydown', onKey);
                if (typeof options.onCancel === 'function') options.onCancel();
            }
        }
        document.addEventListener('keydown', onKey);

        // Focus confirm button
        overlay.querySelector('#ui-confirm-btn').focus();
    }

    // ============================================================
    // UI.toast(message, type, duration)
    //
    // type:     'success' | 'error' | 'info' | 'warning'
    // duration: ms before auto-dismiss (default 3500)
    // ============================================================
    function toast(message, type, duration) {
        injectStyles();

        type     = type     || 'success';
        duration = duration || 3500;

        // Ensure container exists
        let container = document.getElementById('ui-toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'ui-toast-container';
            container.className = 'ui-toast-container';
            document.body.appendChild(container);
        }

        const icons = {
            success: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
            error:   '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
            info:    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
            warning: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        };

        const el = document.createElement('div');
        el.className = `ui-toast ui-toast-${type}`;
        el.innerHTML = `
            <span class="ui-toast-icon">${icons[type] || 'INFO: '}</span>
            <span>${escHtml(message)}</span>
        `;

        container.appendChild(el);

        // Auto-dismiss
        setTimeout(() => {
            el.classList.add('ui-toast-exit');
            el.addEventListener('animationend', () => el.remove(), { once: true });
        }, duration);
    }

    // ============================================================
    // UI.error(message, anchorElement)
    //
    // Inserts an inline error banner after anchorElement.
    // Removes any previous banner first.
    // Pass anchorElement = null to remove without adding.
    // ============================================================
    function error(message, anchorEl) {
        injectStyles();

        // Remove any existing banner attached to this anchor
        if (anchorEl) {
            const prev = anchorEl.parentNode.querySelector('.ui-error-banner');
            if (prev) prev.remove();
        }

        if (!message || !anchorEl) return;

        const banner = document.createElement('div');
        banner.className = 'ui-error-banner';
        banner.innerHTML = `<span class="ui-error-label">Error</span><span>${escHtml(message)}</span>`;

        anchorEl.insertAdjacentElement('afterend', banner);

        // Auto-remove after 6 seconds
        setTimeout(() => banner.remove(), 6000);
    }

    // ============================================================
    // EXPORT
    // ============================================================
    global.UI = { confirm, toast, error };

})(window);
