// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * ============================================================================
 * Tangent Networks -- Documentation SPA
 * Version: 2.0
 *
 * CSP: script-src 'self' compliant.
 *   - Zero inline styles set via JS
 *   - Zero event handlers in HTML (all wired via addEventListener)
 *   - Zero eval / innerHTML for script execution
 *   - All DOM queries use data-doc / data-* attributes
 *
 * Adapted from vs.js (ViewSystem) -- stripped to docs requirements only.
 *
 * Responsibilities:
 *   - Load doc fragment on nav click, inject into #doc-main-content
 *   - Collapsible sidebar sections
 *   - Active nav link tracking
 *   - Light/dark theme toggle (localStorage key: tn-docs-theme)
 *     Falls back to OS prefers-color-scheme on first visit.
 *   - Copy buttons auto-wired on all .doc-code-block elements after load
 *   - Sidebar open/close on mobile
 *   - Hash-based routing (#quick-reference, #boot, etc.)
 * ============================================================================
 */

(function () {
  'use strict';

  /* --------------------------------------------------------------------------
     THEME
     -------------------------------------------------------------------------- */
  var THEME_KEY = 'tn-docs-theme';

  function getInitialTheme() {
    var stored = localStorage.getItem(THEME_KEY);
    if (stored === 'dark' || stored === 'light') return stored;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
    updateThemeIcon(theme);
  }

  function updateThemeIcon(theme) {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    var use = btn.querySelector('use');
    if (use) {
      use.setAttribute('href', theme === 'dark' ? '#icon-sun' : '#icon-moon');
    }
    btn.setAttribute('aria-label',
      theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  }

  function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme') || 'light';
    applyTheme(current === 'dark' ? 'light' : 'dark');
  }

  /* --------------------------------------------------------------------------
     DOC CONFIG -- maps data-doc value to fragment path
     -------------------------------------------------------------------------- */
  var DOCS = {
    /* Getting Started */
    'preface':         { title: 'Preface',              path: 'docs/preface.html'         },
    'quick-reference': { title: 'Quick Reference',      path: 'docs/quick-reference.html' },
    'metrics':         { title: 'Metrics & Discovery',  path: 'docs/metrics.html'         },
    'orchestration':   { title: 'System Orchestration', path: 'docs/orchestration.html'   },

    /* System & Network */
    'network':         { title: 'Network Overview',     path: 'docs/network.html'         },
    'firewall':        { title: 'Firewall',             path: 'docs/firewall.html'        },
    'content-filter':  { title: 'Content Filtering',    path: 'docs/content-filter.html'  },
    'flow-accounting': { title: 'Flow Accounting',      path: 'docs/flow-accounting.html' },
    'daemons':         { title: 'Runners & Daemons',    path: 'docs/daemons.html'         },

    /* Integrity & Alerting */
    'tnaudit':         { title: 'TNAudit',              path: 'docs/tnaudit.html'         },
    'tnwatch':         { title: 'TNWatch',              path: 'docs/tnwatch.html'         },

    /* UI Infrastructure & Auth */
    'database':        { title: 'Database & Schema',    path: 'docs/database.html'        },
    'tnenv':           { title: 'TNEnv',                path: 'docs/tnenv.html'           },
    'tnconfig':        { title: 'TNConfig',             path: 'docs/tnconfig.html'        },
    'tnauth':          { title: 'TNAuth',               path: 'docs/tnauth.html'          },
    'tnsecurity':      { title: 'TNSecurity',           path: 'docs/tnsecurity.html'      },
    'tnsecuritycheck': { title: 'TNSecurityCheck',      path: 'docs/tnsecuritycheck.html' },
    'tnwaf':           { title: 'TNWAF',                path: 'docs/tnwaf.html'           },

    /* Backend */
    'backend':         { title: 'CGI Scripts',          path: 'docs/backend.html'         },

    /* Frontend */
    'frontend-spa':    { title: 'SPA Architecture',     path: 'docs/frontend-spa.html'    },
    'frontend-css':    { title: 'CSS',                  path: 'docs/frontend-css.html'    },
    'frontend-js':     { title: 'JavaScript',           path: 'docs/frontend-js.html'     },

    /* Installation -- last */
    'installation':    { title: 'Installation',         path: 'docs/installation.html'    }
  };

  /* --------------------------------------------------------------------------
     STATE
     -------------------------------------------------------------------------- */
  var currentDoc    = null;
  var activeNavLink = null;
  var mainContent   = null;
  var sidebarEl     = null;
  var sidebarOpen   = false;

  /* --------------------------------------------------------------------------
     CONTENT LOADER
     -------------------------------------------------------------------------- */
  function loadDoc(docId) {
    var cfg = DOCS[docId];
    if (!cfg) {
      console.warn('[DocSPA] Unknown doc:', docId);
      return;
    }
    if (docId === currentDoc) return;

    showLoading();

    fetch(cfg.path, {
      method: 'GET',
      headers: {
        'Accept': 'text/html',
        'X-Requested-With': 'XMLHttpRequest'
      },
      cache: 'no-cache'
    })
    .then(function (res) {
      if (!res.ok) throw new Error('HTTP ' + res.status + ': ' + res.statusText);
      return res.text();
    })
    .then(function (html) {
      var wrapper = document.createElement('div');
      wrapper.className = 'doc-content';
      wrapper.innerHTML = html;
      mainContent.innerHTML = '';
      mainContent.appendChild(wrapper);
      currentDoc = docId;
      document.title = 'TN Docs \u2014 ' + cfg.title;
      history.replaceState(null, '', '#' + docId);
      wireCodeCopyButtons();
      window.scrollTo(0, 0);
    })
    .catch(function (err) {
      showError(err.message);
      console.error('[DocSPA] Load error:', err);
    });
  }

  function showLoading() {
    mainContent.innerHTML = '';
    var el = document.createElement('div');
    el.className = 'doc-loading';
    el.innerHTML =
      '<div class="doc-spinner"></div>' +
      '<span>Loading\u2026</span>';
    mainContent.appendChild(el);
  }

  function showError(msg) {
    mainContent.innerHTML = '';
    var wrapper = document.createElement('div');
    wrapper.className = 'doc-content';
    var callout = document.createElement('div');
    callout.className = 'callout callout-danger';
    callout.innerHTML =
      '<svg class="callout-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" ' +
          'aria-hidden="true">' +
        '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" ' +
          'd="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>' +
      '</svg>' +
      '<div class="callout-body">' +
        '<strong>Failed to load document</strong><br>' +
        document.createTextNode(msg).textContent +
      '</div>';
    wrapper.appendChild(callout);
    mainContent.appendChild(wrapper);
  }

  /* --------------------------------------------------------------------------
     ACTIVE NAV LINK
     -------------------------------------------------------------------------- */
  function setActiveLink(el) {
    if (activeNavLink) activeNavLink.classList.remove('active');
    el.classList.add('active');
    activeNavLink = el;
  }

  /* --------------------------------------------------------------------------
     COLLAPSIBLE SECTIONS
     -------------------------------------------------------------------------- */
  function initNavSections() {
    var toggles = document.querySelectorAll('.doc-nav-section-toggle');
    toggles.forEach(function (btn) {
      var items = btn.nextElementSibling;
      btn.classList.add('open');
      btn.setAttribute('aria-expanded', 'true');
      btn.addEventListener('click', function () {
        var isOpen = !items.classList.contains('closed');
        items.classList.toggle('closed', isOpen);
        btn.classList.toggle('open', !isOpen);
        btn.setAttribute('aria-expanded', String(!isOpen));
      });
    });
  }

  /* --------------------------------------------------------------------------
     NAV LINKS
     -------------------------------------------------------------------------- */
  function initNavLinks() {
    var links = document.querySelectorAll('.doc-nav-link[data-doc]');
    links.forEach(function (link) {
      link.addEventListener('click', function (e) {
        e.preventDefault();
        var docId = link.getAttribute('data-doc');
        setActiveLink(link);
        loadDoc(docId);
        if (window.innerWidth <= 768) closeSidebar();
      });
    });
  }

  /* --------------------------------------------------------------------------
     COPY BUTTONS -- wired after every fragment load
     -------------------------------------------------------------------------- */
  function wireCodeCopyButtons() {
    var blocks = mainContent.querySelectorAll('.doc-code-block');
    blocks.forEach(function (block) {
      var btn = block.querySelector('.doc-code-copy');
      if (!btn || btn.dataset.wired) return;
      btn.dataset.wired = '1';
      btn.addEventListener('click', function () {
        var pre = block.querySelector('pre');
        if (!pre) return;
        var text = pre.innerText || pre.textContent || '';
        copyToClipboard(text, btn);
      });
    });
  }

  function copyToClipboard(text, btn) {
    var labelSpan = btn.querySelector('.doc-code-copy-label');
    function onSuccess() {
      btn.classList.add('copied');
      if (labelSpan) labelSpan.textContent = 'Copied';
      setTimeout(function () {
        btn.classList.remove('copied');
        if (labelSpan) labelSpan.textContent = 'Copy';
      }, 2000);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(onSuccess).catch(fallback);
    } else {
      fallback();
    }
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'doc-clipboard-scratch';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); onSuccess(); } catch (e) {}
      document.body.removeChild(ta);
    }
  }

  /* --------------------------------------------------------------------------
     SIDEBAR MOBILE
     -------------------------------------------------------------------------- */
  function openSidebar() {
    sidebarEl.classList.add('open');
    sidebarOpen = true;
  }

  function closeSidebar() {
    sidebarEl.classList.remove('open');
    sidebarOpen = false;
  }

  function initSidebarToggle() {
    var btn = document.getElementById('sidebar-toggle');
    if (btn) {
      btn.addEventListener('click', function () {
        sidebarOpen ? closeSidebar() : openSidebar();
      });
    }
    document.addEventListener('click', function (e) {
      if (window.innerWidth > 768) return;
      if (!sidebarOpen) return;
      if (sidebarEl && sidebarEl.contains(e.target)) return;
      if (e.target.id === 'sidebar-toggle') return;
      closeSidebar();
    });
  }

  /* --------------------------------------------------------------------------
     HASH ROUTING
     -------------------------------------------------------------------------- */
  function resolveInitialDoc() {
    var hash = window.location.hash.replace('#', '');
    return (hash && DOCS[hash]) ? hash : 'preface';
  }

  /* --------------------------------------------------------------------------
     INIT
     -------------------------------------------------------------------------- */
  function init() {
    mainContent = document.getElementById('doc-main-content');
    sidebarEl   = document.getElementById('doc-sidebar');

    if (!mainContent || !sidebarEl) {
      console.error('[DocSPA] Required elements #doc-main-content or #doc-sidebar not found');
      return;
    }

    applyTheme(getInitialTheme());

    var themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

    initNavSections();
    initNavLinks();
    initSidebarToggle();

    var initialDoc = resolveInitialDoc();
    var initialLink = document.querySelector(
      '.doc-nav-link[data-doc="' + initialDoc + '"]'
    );
    if (initialLink) setActiveLink(initialLink);
    loadDoc(initialDoc);

    console.log('[DocSPA] Ready. Loading:', initialDoc);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

}());
