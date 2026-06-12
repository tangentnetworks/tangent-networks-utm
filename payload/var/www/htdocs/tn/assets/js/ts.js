// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

(function() {
    'use strict';

    document.addEventListener('DOMContentLoaded', () => {
        const htmlElement = document.documentElement;
        initializeThemeToggle(htmlElement);
        initializeSidebarToggle();
        initializeUserDropdown();
        initializeBackToTopButton();
    });

    function initializeThemeToggle(htmlElement) {
        const themeToggleBtn = document.getElementById('theme-toggle');
        const darkIcon = document.getElementById('theme-toggle-dark-icon');
        const lightIcon = document.getElementById('theme-toggle-light-icon');
        if (themeToggleBtn && darkIcon && lightIcon) {
            const updateThemeIcons = () => {
                if (htmlElement.classList.contains('dark')) {
                    darkIcon.classList.remove('hidden');
                    lightIcon.classList.add('hidden');
                } else {
                    darkIcon.classList.add('hidden');
                    lightIcon.classList.remove('hidden');
                }
            };
            updateThemeIcons();
            themeToggleBtn.addEventListener('click', () => {
                htmlElement.classList.toggle('dark');
                updateThemeIcons();
            });
        }
    }

    function initializeSidebarToggle() {
        const sidebar = document.getElementById('top-bar-sidebar');
        const toggleBtn = document.getElementById('sidebar-toggle-btn');
        const backdrop = document.getElementById('sidebar-backdrop');
        if (!sidebar || !toggleBtn) return;
        const isMobileOpen = () => !sidebar.classList.contains('sidebar--closed');
        const openSidebar = () => {
            sidebar.classList.remove('sidebar--closed');
            toggleBtn.setAttribute('aria-expanded', 'true');
            sidebar.setAttribute('aria-hidden', 'false');
            if (backdrop) backdrop.classList.remove('hidden');
        };
        const closeSidebar = () => {
            sidebar.classList.add('sidebar--closed');
            toggleBtn.setAttribute('aria-expanded', 'false');
            sidebar.setAttribute('aria-hidden', 'true');
            if (backdrop) backdrop.classList.add('hidden');
        };
        const toggleSidebar = (e) => {
            e.stopPropagation();
            isMobileOpen() ? closeSidebar() : openSidebar();
        };
        toggleBtn.addEventListener('click', toggleSidebar);
        if (backdrop) {
            backdrop.addEventListener('click', closeSidebar);
        }
        const navLinks = sidebar.querySelectorAll('a[href]');
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                if (window.innerWidth < 640) closeSidebar();
            });
        });
        document.addEventListener('click', (e) => {
            if (!isMobileOpen()) return;
            if (sidebar.contains(e.target)) return;
            if (toggleBtn.contains(e.target)) return;
            closeSidebar();
        });
    }

    function initializeUserDropdown() {
        const userMenuButton = document.getElementById('user-menu-button');
        const userMenu = document.getElementById('dropdown-user');
        if (userMenuButton && userMenu) {
            const userMenuLinks = userMenu.querySelectorAll('a[href]');
            userMenuLinks.forEach(link => {
                link.addEventListener('click', () => {
                    userMenu.classList.add('hidden');
                    userMenuButton.setAttribute('aria-expanded', 'false');
                });
            });
            const toggleUserMenu = (event) => {
                userMenu.classList.toggle('hidden');
                const isExpanded = userMenu.classList.contains('hidden') ? 'false' : 'true';
                userMenuButton.setAttribute('aria-expanded', isExpanded);
                if (event) event.stopPropagation();
            };
            userMenuButton.addEventListener('click', toggleUserMenu);
            document.addEventListener('click', (event) => {
                const isMenuVisible = !userMenu.classList.contains('hidden');
                const isClickOutsideMenu = !userMenu.contains(event.target);
                const isClickNotOnButton = event.target !== userMenuButton;
                if (isMenuVisible && isClickOutsideMenu && isClickNotOnButton) {
                    userMenu.classList.add('hidden');
                    userMenuButton.setAttribute('aria-expanded', 'false');
                }
            });
        }
    }

    function initializeBackToTopButton() {
        const backToTopBtn = document.getElementById('backToTop');
        if (backToTopBtn) {
            const scrollThreshold = 300;
            const handleScroll = () => {
                if (window.scrollY > scrollThreshold) {
                    backToTopBtn.classList.remove('tn-invisible');
                } else {
                    backToTopBtn.classList.add('tn-invisible');
                }
            };
            const scrollToTop = () => {
                window.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            };
            handleScroll();
            window.addEventListener('scroll', handleScroll);
            backToTopBtn.addEventListener('click', scrollToTop);
        }
        
        // BANNER DISMISSAL SYSTEM 
        document.addEventListener('click', function(event) {
            var closeBtn = event.target.closest('.close-banner-btn');
            if (!closeBtn) return;
            var banner = closeBtn.closest('.dismissible-banner');
            if (banner) {
                var bannerId = banner.getAttribute('id');
                if (bannerId) {
                    try {
                        localStorage.setItem('dismissed_' + bannerId, 'true');
                    } catch (e) {}
                }
                banner.style.transition = 'opacity 0.2s ease-out';
                banner.style.opacity = '0';
                setTimeout(function() {
                    banner.remove();
                }, 200);
            }
        });
        
        window.TNUI = window.TNUI || {};
        window.TNUI.cleanupBanners = function() {
            var banners = document.querySelectorAll('.dismissible-banner[id]');
            for (var i = 0; i < banners.length; i++) {
                if (localStorage.getItem('dismissed_' + banners[i].id) === 'true') {
                    banners[i].remove();
                }
            }
        };
    }

})();
