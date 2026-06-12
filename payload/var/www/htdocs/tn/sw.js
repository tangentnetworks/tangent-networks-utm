// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/*
 * Tangent Networks UTM -- Service Worker
 * Online-only mode: network first, no caching
 * Purpose: satisfy PWA install prompt requirements on Android and iOS
 */

const SW_VERSION = 'tn-sw-v1';

/* Install -- activate immediately, no cache population */
self.addEventListener('install', event => {
    self.skipWaiting();
});

/* Activate -- take control of all clients immediately */
self.addEventListener('activate', event => {
    event.waitUntil(clients.claim());
});

/*
 * Fetch -- pure network passthrough
 * No caching: this is an online-only admin panel on a LAN,
 * caching would serve stale firewall state which is dangerous
 */
self.addEventListener('fetch', event => {
    event.respondWith(
        fetch(event.request).catch(error => {
            /*
             * Network failure fallback:
             * Return a clean error page rather than browser default
             */
            if (event.request.mode === 'navigate') {
                return new Response(
                    `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tangent Networks - Offline</title>
    <style>
        body {
            font-family: sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            background: #2EC6FE;
            color: #fff;
        }
        h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
        p  { font-size: 1rem; opacity: 0.85; }
        button {
            margin-top: 1.5rem;
            padding: 0.75rem 2rem;
            background: #8936FF;
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <h1>Tangent Networks</h1>
    <p>Cannot reach the appliance. Check your connection.</p>
    <button onclick="window.location.reload()">Retry</button>
</body>
</html>`,
                    {
                        status: 503,
                        headers: { 'Content-Type': 'text/html; charset=utf-8' }
                    }
                );
            }
            /* For non-navigation requests just propagate the error */
            return Promise.reject(error);
        })
    );
});
