// SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
//
// SPDX-License-Identifier: BSD-3-Clause

// =============================================
// auth.js - Complete Authentication System
// =============================================
// Handles login, registration, and password reset
// for Tangent Networks Dashboard.
//
// AUTHOR: David Peter, Tangent Networks
// VERSION: 2.0.1
// =============================================

(function() {
	'use strict';

	// =============================================
	// CONFIGURATION
	// =============================================

	// Single authoritative minimum -- must match TNSecurity::validate_password() server-side
	const MIN_PASSWORD_LENGTH = 12;

	const API = {
		LOGIN: '/cgi-bin/control.pl/auth/login',
		REGISTER: '/cgi-bin/control.pl/auth/register',
		LOGOUT: '/cgi-bin/control.pl/auth/logout',
		RESET_GET_QUESTIONS: '/cgi-bin/control.pl/auth/reset/get_questions',
		RESET_VERIFY_ANSWERS: '/cgi-bin/control.pl/auth/reset/verify_answers',
		RESET_VERIFY_CODE: '/cgi-bin/control.pl/auth/reset/verify_code',
		RESET_UPDATE_PASSWORD: '/cgi-bin/control.pl/auth/reset/update_password',
		QUESTIONS: '/cgi-bin/control.pl/api/questions',
		REGISTRATION_STATUS: '/cgi-bin/control.pl/api/registration/status',
	};

	// Password reset state
	const resetState = {
		step: 1,
		username: null,
		userId: null,
		resetToken: null,
	};

	// =============================================
	// UTILITY FUNCTIONS
	// =============================================

	/**
	 * Sanitizes user input to prevent XSS
	 * @param {string} str - Input string
	 * @returns {string} Sanitized string
	 */
	function sanitize(str) {
		if (!str) return '';
		return String(str)
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#x27;')
			.replace(/\//g, '&#x2F;')
			.trim();
	}

	/**
	 * Shows error message in a container
	 * @param {string} containerId - Error container ID
	 * @param {string} message - Error message
	 */
	function showError(containerId, message) {
		const container = document.getElementById(containerId);
		if (!container) return;

		const paragraph = container.querySelector('p');
		if (paragraph) {
			paragraph.textContent = message;
		} else {
			container.textContent = message;
		}

		container.classList.remove('hidden');
		container.scrollIntoView({
			behavior: 'smooth',
			block: 'nearest'
		});
	}

	/**
	 * Clears error message
	 * @param {string} containerId - Error container ID
	 */
	function clearError(containerId) {
		const container = document.getElementById(containerId);
		if (container) {
			container.classList.add('hidden');
		}
	}

	/**
	 * Shows success message in a container
	 * @param {string} containerId - Success container ID
	 * @param {string|HTMLElement} content - Success message or HTML element
	 */
	function showSuccess(containerId, content) {
		const container = document.getElementById(containerId);
		if (!container) return;

		if (typeof content === 'string') {
			const paragraph = container.querySelector('p') || container.querySelector('div');
			if (paragraph) {
				paragraph.textContent = content;
			} else {
				container.textContent = content;
			}
		} else {
			const target = container.querySelector('div') || container;
			target.innerHTML = '';
			target.appendChild(content);
		}

		container.classList.remove('hidden');
		container.scrollIntoView({
			behavior: 'smooth',
			block: 'nearest'
		});
	}

	/**
	 * Sets loading state for a button
	 * @param {string} buttonId - Button ID
	 * @param {boolean} isLoading - Loading state
	 */
	function setButtonLoading(buttonId, isLoading) {
		const button = document.getElementById(buttonId);
		if (!button) return;

		const textSpan = button.querySelector('[id$="Text"]') || button.querySelector('span:first-child');
		const spinnerSpan = button.querySelector('[id$="Spinner"]') || button.querySelector('span:last-child');

		button.disabled = isLoading;

		if (textSpan && spinnerSpan) {
			if (isLoading) {
				textSpan.classList.add('hidden');
				spinnerSpan.classList.remove('hidden');
			} else {
				textSpan.classList.remove('hidden');
				spinnerSpan.classList.add('hidden');
			}
		} else {
			button.textContent = isLoading ? 'Loading...' : button.dataset.originalText || 'Submit';
		}
	}

	/**
	 * Maps backend errors to user-friendly messages
	 * @param {string} error - Backend error message
	 * @returns {string} User-friendly message
	 */
	function getUserFriendlyError(error) {
		const errorMap = {
			'Invalid credentials': 'Incorrect username or password.',
			'Rate limit exceeded': 'Too many attempts. Please try again in 15 minutes.',
			'Too many login attempts': 'Too many login attempts. Please try again later.',
			'Incorrect answers': 'One or more security answers are incorrect.',
			'Invalid recovery code': 'The recovery code is invalid or has already been used.',
			'User not found': 'Username not found in the system.',
			'Password requirement not met': 'Password does not meet security requirements.',
			'Password too weak': 'Password is too weak. Please choose a stronger password.',
			'Invalid username format': 'Username must be 3-32 characters (letters, numbers, dash, underscore only).',
			'Username already taken': 'This username is already registered.',
			'Invalid request format': 'Invalid request. Please refresh and try again.',
			'Invalid security token': 'Security token expired. Please refresh the page.',
			'Registration token required': 'A registration token is required to create an account.',
			'Invalid token': 'The registration token is invalid or has been used.',
		};

		return errorMap[error] || error || 'An unexpected error occurred. Please try again.';
	}

	/**
	 * Makes an authenticated API call
	 * @param {string} url - API endpoint
	 * @param {object} options - Fetch options
	 * @returns {Promise<object>} Response data
	 */
	async function apiCall(url, options = {}) {
		const defaultOptions = {
			credentials: 'same-origin',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
			},
		};

		const response = await fetch(url, {
			...defaultOptions,
			...options
		});
		const data = await response.json();

		return data;
	}

	// =============================================
	// LOGIN FUNCTIONALITY
	// =============================================

	async function handleLogin(event) {
		event.preventDefault();

		clearError('loginError');
		setButtonLoading('loginBtn', true);

		try {
			const username = sanitize(document.getElementById('username').value);
			const password = document.getElementById('password').value;
			const remember = document.getElementById('remember')?.checked || false;

			if (!username || username.length < 3) {
				showError('loginError', 'Please enter a valid username.');
				return;
			}

			if (!password || password.length < MIN_PASSWORD_LENGTH) {
				showError('loginError', 'Please enter your password (minimum 12 characters).');
				return;
			}

			const csrfToken = window.TNToken.get();
			if (!csrfToken) {
				showError('loginError', 'Security token not loaded. Please refresh the page.');
				return;
			}

			const data = await apiCall(API.LOGIN, {
				method: 'POST',
				body: JSON.stringify({
					username: username,
					password: password,
					remember: remember,
					csrf_token: csrfToken,
				}),
			});

			if (data.success) {
				window.location.href = '/view.html';
			} else {
				showError('loginError', getUserFriendlyError(data.error));
			}

		} catch (error) {
			console.error('Login error:', error);
			showError('loginError', 'Network error. Please check your connection and try again.');
		} finally {
			setButtonLoading('loginBtn', false);
		}
	}

	// =============================================
	// REGISTRATION FUNCTIONALITY
	// =============================================

	/**
	 * Checks registration status (first user or token required)
	 */
	async function checkRegistrationStatus() {
		try {
			const data = await apiCall(API.REGISTRATION_STATUS);

			const tokenField = document.getElementById('tokenField');
			const firstUserMessage = document.getElementById('firstUserMessage');

			// FIX: Check for is_first_user (not first_user)
			if (data.is_first_user === 1 || data.is_first_user === true) {
				// First user - show welcome message, hide token field
				console.log('[Auth] First user registration - no token required');
				if (firstUserMessage) firstUserMessage.classList.remove('hidden');
				if (tokenField) tokenField.classList.add('hidden');
			} else {
				// Not first user - require token
				console.log('[Auth] Subsequent user registration - token required');
				if (tokenField) tokenField.classList.remove('hidden');
				if (firstUserMessage) firstUserMessage.classList.add('hidden');
			}

		} catch (error) {
			console.error('Failed to check registration status:', error);
			// On error, default to showing token field (safer)
			const tokenField = document.getElementById('tokenField');
			const firstUserMessage = document.getElementById('firstUserMessage');
			if (tokenField) tokenField.classList.remove('hidden');
			if (firstUserMessage) firstUserMessage.classList.add('hidden');
		}
	}

	/**
	 * Loads available security questions
	 */
	async function loadSecurityQuestions() {
		try {
			const data = await apiCall(API.QUESTIONS);

			if (!data.questions || !Array.isArray(data.questions)) {
				console.error('Invalid questions data:', data);
				return;
			}

			const container = document.getElementById('securityQuestions');
			if (!container) return;

			container.innerHTML = '';

			for (let i = 0; i < 5; i++) {
				const questionDiv = document.createElement('div');
				questionDiv.className = 'auth-question-wrap';

				const label = document.createElement('label');
				label.htmlFor = 'question' + i;
				label.className = 'auth-form-label';
				label.textContent = 'Question ' + (i + 1);

				const select = document.createElement('select');
				select.id = 'question' + i;
				select.name = 'question' + i;
				select.required = true;
				select.className = 'auth-form-input';
				const defaultOpt = document.createElement('option');
				defaultOpt.value = '';
				defaultOpt.textContent = 'Select a question...';
				select.appendChild(defaultOpt);
				data.questions.forEach((q, idx) => {
					const opt = document.createElement('option');
					opt.value = idx;
					opt.textContent = q;
					select.appendChild(opt);
				});

				const answerInput = document.createElement('input');
				answerInput.type = 'text';
				answerInput.id = 'answer' + i;
				answerInput.name = 'answer' + i;
				answerInput.required = true;
				answerInput.className = 'auth-form-input';
				answerInput.placeholder = 'Your answer';

				questionDiv.appendChild(label);
				questionDiv.appendChild(select);
				questionDiv.appendChild(answerInput);
				container.appendChild(questionDiv);
			}

		} catch (error) {
			console.error('Failed to load security questions:', error);
			showError('registerError', 'Failed to load security questions. Please refresh the page.');
		}
	}

	/**
	 * Validates password strength and updates UI
	 */
	function validatePasswordStrength(password) {
		const requirements = {
			length: password.length >= MIN_PASSWORD_LENGTH,
			upper: /[A-Z]/.test(password),
			lower: /[a-z]/.test(password),
			number: /[0-9]/.test(password),
			special: /[^A-Za-z0-9]/.test(password),
		};

		for (const [key, valid] of Object.entries(requirements)) {
			const indicator = document.getElementById(`req-${key}`);
			if (indicator) {
				indicator.classList.toggle('auth-req--met', valid);
				indicator.classList.toggle('auth-req--unmet', !valid);
			}
		}

		return Object.values(requirements).every(v => v);
	}

	/**
	 * Handles registration form submission
	 */
	async function handleRegister(event) {
		event.preventDefault();

		clearError('registerError');
		setButtonLoading('submitBtn', true);

		try {
			const username = sanitize(document.getElementById('username').value);
			const email = sanitize(document.getElementById('email').value);
			const password = document.getElementById('password').value;
			const confirmPassword = document.getElementById('confirmPassword').value;
			const registrationTokenInput = document.getElementById('registrationToken');
			const registrationToken = registrationTokenInput ? registrationTokenInput.value.trim() : null;

			if (!username || username.length < 3 || username.length > 32) {
				showError('registerError', 'Username must be 3-32 characters.');
				return;
			}

			if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
				showError('registerError', 'Username can only contain letters, numbers, dash, and underscore.');
				return;
			}

			if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
				showError('registerError', 'Please enter a valid email address.');
				return;
			}

			if (!validatePasswordStrength(password)) {
				showError('registerError', 'Password does not meet all requirements.');
				return;
			}

			if (password !== confirmPassword) {
				showError('registerError', 'Passwords do not match.');
				return;
			}

			const securityQuestions = [];
			const selectedQuestions = new Set();

			for (let i = 0; i < 5; i++) {
				const questionSelect = document.getElementById(`question${i}`);
				const answerInput = document.getElementById(`answer${i}`);

				if (!questionSelect || !answerInput) continue;

				const questionIdx = questionSelect.value;
				const answer = answerInput.value.trim();

				if (!questionIdx || !answer) {
					showError('registerError', `Please complete security question ${i + 1}.`);
					return;
				}

				if (selectedQuestions.has(questionIdx)) {
					showError('registerError', 'Please select different questions for each slot.');
					return;
				}

				selectedQuestions.add(questionIdx);

				const questionText = questionSelect.options[questionSelect.selectedIndex].text;
				securityQuestions.push({
					question: questionText,
					answer: answer,
				});
			}

			const csrfToken = window.TNToken.get();
			if (!csrfToken) {
				showError('registerError', 'Security token not loaded. Please refresh the page.');
				return;
			}

			const data = await apiCall(API.REGISTER, {
				method: 'POST',
				body: JSON.stringify({
					username: username,
					password: password,
					email: email || undefined,
					security_questions: securityQuestions,
					token: registrationToken || '',
					csrf_token: csrfToken,
				}),
			});

			if (data.success) {
				displayRecoveryCodes(data.recovery_codes, data.registration_tokens);
			} else {
				showError('registerError', getUserFriendlyError(data.error));
			}

		} catch (error) {
			console.error('Registration error:', error);
			showError('registerError', 'Network error. Please check your connection and try again.');
		} finally {
			setButtonLoading('submitBtn', false);
		}
	}

	/**
	 * Displays recovery codes after successful registration
	 * Mobile: Auto-downloads and redirects
	 * Desktop: Renders UI for manual saving/copying
	 */
	function displayRecoveryCodes(recoveryCodes, registrationTokens) {
		const successContainer = document.getElementById('registerSuccess');
		if (!successContainer) return;

		// --- MOBILE WORKFLOW: Auto-download and Redirect ---
		// Using 768px as the standard tablet/desktop breakpoint
		// --- MOBILE WORKFLOW: Trigger Tailwind Modal ---
		if (window.innerWidth < 768) {
			const modal = document.getElementById('successModal');
			const downloadBtn = document.getElementById('modalDownloadBtn');

			// Show the modal
			modal.classList.remove('hidden');

			downloadBtn.addEventListener('click', () => {
				const allContent = [
					'--- RECOVERY CODES ---',
					...recoveryCodes,
					registrationTokens?.length > 0 ? '\n--- REGISTRATION TOKENS ---' : '',
					...(registrationTokens || [])
				].filter(Boolean).join('\n');

				_downloadCodes([allContent], 'tangent_network_credentials.txt');

				// Redirect after user clicks download
				window.location.href = '/index.html';
			});
			return;
		}

		// --- DESKTOP WORKFLOW: Render Interactive UI ---
		const content = document.createElement('div');
		content.className = 'space-y-6';

		// Recovery Codes Section
		content.appendChild(_buildCodeSection({
			title: 'WARNING: Save Your Recovery Codes',
			bodyHtml: 'These codes are the <strong>only way</strong> to recover your account...',
			codes: recoveryCodes,
			modifier: 'green',
			copyLabel: 'Copy All Recovery Codes',
		}));

		// Registration Tokens Section
		if (registrationTokens && registrationTokens.length > 0) {
			content.appendChild(_buildCodeSection({
				title: 'Registration Tokens',
				bodyHtml: 'Share these with trusted users.',
				codes: registrationTokens,
				modifier: 'blue',
				copyLabel: 'Copy All Tokens',
			}));
		}

		// Continue Button
		const continueBtn = document.createElement('button');
		continueBtn.className = 'w-full mt-6 px-6 py-3 bg-blue-700 text-white rounded-lg hover:bg-blue-800 transition-colors';
		continueBtn.textContent = 'I Have Saved These Codes - Continue to Login';
		continueBtn.addEventListener('click', () => {
			window.location.href = '/index.html';
		});
		content.appendChild(continueBtn);

		showSuccess('registerSuccess', content);

		const form = document.getElementById('registerForm');
		if (form) form.classList.add('hidden');
	}

	function _downloadCodes(codes, filename) {
		const blob = new Blob([codes.join('\n')], {
			type: 'text/plain'
		});
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = filename;
		a.click();
		URL.revokeObjectURL(url);
	}
	/**
	 * Builds a styled code section with individual copy buttons and a Copy All button.
	 * @param {object} opts
	 * @param {string}   opts.title
	 * @param {string}   opts.bodyHtml
	 * @param {string[]} opts.codes
	 * @param {string}   opts.modifier  - 'gray' or 'blue'
	 * @param {string}   opts.copyLabel - label for the Copy All button
	 * @returns {HTMLElement}
	 */
	function _buildCodeSection({
		title,
		bodyHtml,
		codes,
		modifier,
		copyLabel
	}) {
		const section = document.createElement('div');
		section.className = "p-4 rounded-lg border bg-gray-50 dark:bg-gray-800 border-blue-200";

		// Title
		const h3 = document.createElement('h3');
		h3.className = `auth-section-title auth-section-title--${modifier}`;
		h3.textContent = title;
		section.appendChild(h3);

		// Body
		const p = document.createElement('p');
		p.className = `auth-section-body auth-section-body--${modifier}`;
		p.innerHTML = bodyHtml;
		section.appendChild(p);

		// Code block
		const block = document.createElement('div');
		block.className = `auth-code-block auth-code-block--${modifier} overflow-x-auto whitespace-nowrap`;

		codes.forEach(code => {
			const row = document.createElement('div');
			// Added min-w-max to ensure long tokens don't wrap and break layout
			row.className = 'auth-code-row flex items-center justify-between min-w-max';

			const span = document.createElement('span');
			span.className = 'auth-code-text font-mono text-sm';
			span.textContent = code;

			const copyBtn = document.createElement('button');
			copyBtn.className = `auth-copy-btn auth-copy-btn--${modifier}`;
			copyBtn.type = 'button';
			copyBtn.title = 'Copy';
			copyBtn.innerHTML = _copyIcon();
			copyBtn.addEventListener('click', () => _copyToClipboard(code, copyBtn));

			row.appendChild(span);
			row.appendChild(copyBtn);
			block.appendChild(row);
		});

		section.appendChild(block);

		const downloadBtn = document.createElement('button');
		downloadBtn.className = 'mt-4 w-full text-sm underline text-blue-600 dark:text-blue-400';
		downloadBtn.textContent = 'Download as Text File';
		downloadBtn.addEventListener('click', () => _downloadCodes(codes, 'recovery_codes.txt'));
		section.appendChild(downloadBtn);

		// Copy All button
		const copyAllBtn = document.createElement('button');
		copyAllBtn.className = `auth-copy-all-btn auth-copy-all-btn--${modifier}`;
		copyAllBtn.type = 'button';
		copyAllBtn.innerHTML = _copyIcon() + ` <span>${sanitize(copyLabel)}</span>`;
		copyAllBtn.addEventListener('click', () => {
			_copyToClipboard(codes.join('\n'), copyAllBtn);
		});
		section.appendChild(copyAllBtn);

		return section;
	}

	/**
	 * Copies text to clipboard and shows brief feedback on the button.
	 */
	function _copyToClipboard(text, btn) {
		navigator.clipboard.writeText(text).then(() => {
			const original = btn.innerHTML;
			btn.innerHTML = _checkIcon() + (btn.querySelector('span') ? ' <span>Copied!</span>' : '');
			btn.classList.add('auth-copy-btn--copied');
			setTimeout(() => {
				btn.innerHTML = original;
				btn.classList.remove('auth-copy-btn--copied');
			}, 2000);
		}).catch(() => {
			// Fallback for older browsers
			const ta = document.createElement('textarea');
			ta.value = text;
			ta.style.position = 'fixed';
			ta.style.left = '-9999px';
			document.body.appendChild(ta);
			ta.select();
			document.execCommand('copy');
			document.body.removeChild(ta);
		});
	}

	function _copyIcon() {
		return '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
	}

	function _checkIcon() {
		return '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
	}

	// =============================================
	// PASSWORD RESET FUNCTIONALITY
	// =============================================

	function showResetStep(stepNumber) {
		for (let i = 1; i <= 4; i++) {
			const step = document.getElementById(`step${i}`);
			if (step) {
				if (i === stepNumber) {
					step.classList.remove('hidden');
				} else {
					step.classList.add('hidden');
				}
			}
		}
		resetState.step = stepNumber;
	}

	async function handleResetStep1(event) {
		event.preventDefault();
		clearError('resetError');
		setButtonLoading('step1Btn', true);

		try {
			const username = sanitize(document.getElementById('username').value);

			if (!username || username.length < 3) {
				showError('resetError', 'Please enter a valid username.');
				return;
			}

			resetState.username = username;

			const csrfToken = window.TNToken.get();
			if (!csrfToken) {
				showError('resetError', 'Security token not loaded. Please refresh the page.');
				return;
			}

			const data = await apiCall(API.RESET_GET_QUESTIONS, {
				method: 'POST',
				body: JSON.stringify({
					username: username,
					csrf_token: csrfToken,
				}),
			});

			if (data.success && data.questions) {
				displaySecurityQuestions(data.questions);
				showResetStep(2);
			} else {
				showError('resetError', getUserFriendlyError(data.error));
			}

		} catch (error) {
			console.error('Reset step 1 error:', error);
			showError('resetError', 'Network error. Please check your connection and try again.');
		} finally {
			setButtonLoading('step1Btn', false);
		}
	}

	function displaySecurityQuestions(questions) {
		const container = document.getElementById('questionsContainer');
		if (!container) return;

		container.innerHTML = '';

		questions.forEach((question, index) => {
			const questionDiv = document.createElement('div');
			questionDiv.className = 'auth-question-wrap';

			const label = document.createElement('label');
			label.htmlFor = 'resetAnswer' + index;
			label.className = 'auth-form-label';
			label.textContent = question;

			const input = document.createElement('input');
			input.type = 'text';
			input.id = 'resetAnswer' + index;
			input.name = 'resetAnswer' + index;
			input.required = true;
			input.className = 'auth-form-input';
			input.placeholder = 'Your answer';

			questionDiv.appendChild(label);
			questionDiv.appendChild(input);
			container.appendChild(questionDiv);
		});
	}

	async function handleResetStep2(event) {
		event.preventDefault();
		clearError('resetError');
		setButtonLoading('step2Btn', true);

		try {
			const answerInputs = document.querySelectorAll('[id^="resetAnswer"]');
			const answers = Array.from(answerInputs).map(input => input.value.trim());

			if (answers.some(a => !a)) {
				showError('resetError', 'Please answer all security questions.');
				return;
			}

			const csrfToken = window.TNToken.get();
			if (!csrfToken) {
				showError('resetError', 'Security token not loaded. Please refresh the page.');
				return;
			}

			const data = await apiCall(API.RESET_VERIFY_ANSWERS, {
				method: 'POST',
				body: JSON.stringify({
					username: resetState.username,
					answers: answers,
					csrf_token: csrfToken,
				}),
			});

			if (data.success) {
				resetState.resetToken = data.reset_token;
				showResetStep(4);
			} else {
				showError('resetError', getUserFriendlyError(data.error));
			}

		} catch (error) {
			console.error('Reset step 2 error:', error);
			showError('resetError', 'Network error. Please check your connection and try again.');
		} finally {
			setButtonLoading('step2Btn', false);
		}
	}

	async function handleResetStep3(event) {
		event.preventDefault();
		clearError('resetError');
		setButtonLoading('step3Btn', true);

		try {
			const code = document.getElementById('recoveryCode').value.trim().toLowerCase();

			if (!code || code.length !== 64 || !/^[0-9a-f]{64}$/.test(code)) {
				showError('resetError', 'Please enter a valid 64-character recovery code.');
				return;
			}

			const csrfToken = window.TNToken.get();
			if (!csrfToken) {
				showError('resetError', 'Security token not loaded. Please refresh the page.');
				return;
			}

			const data = await apiCall(API.RESET_VERIFY_CODE, {
				method: 'POST',
				body: JSON.stringify({
					username: resetState.username,
					code: code,
					csrf_token: csrfToken,
				}),
			});

			if (data.success) {
				resetState.resetToken = data.reset_token;
				showResetStep(4);
			} else {
				showError('resetError', getUserFriendlyError(data.error));
			}

		} catch (error) {
			console.error('Reset step 3 error:', error);
			showError('resetError', 'Network error. Please check your connection and try again.');
		} finally {
			setButtonLoading('step3Btn', false);
		}
	}

	async function handleResetStep4(event) {
		event.preventDefault();
		clearError('resetError');
		setButtonLoading('step4Btn', true);

		try {
			const newPassword = document.getElementById('newPassword').value;
			const confirmPassword = document.getElementById('confirmNewPassword').value;

			if (newPassword !== confirmPassword) {
				showError('resetError', 'Passwords do not match.');
				return;
			}

			if (newPassword.length < MIN_PASSWORD_LENGTH) {
				showError('resetError', 'Password must be at least 12 characters.');
				return;
			}

			const csrfToken = window.TNToken.get();
			if (!csrfToken) {
				showError('resetError', 'Security token not loaded. Please refresh the page.');
				return;
			}

			const data = await apiCall(API.RESET_UPDATE_PASSWORD, {
				method: 'POST',
				body: JSON.stringify({
					username: resetState.username,
					new_password: newPassword,
					reset_token: resetState.resetToken,
					csrf_token: csrfToken,
				}),
			});

			if (data.success) {
				showSuccess('resetSuccess', 'Password reset successful! Redirecting to login...');
				setTimeout(() => {
					window.location.href = '/index.html';
				}, 2000);
			} else {
				showError('resetError', getUserFriendlyError(data.error));
			}

		} catch (error) {
			console.error('Reset step 4 error:', error);
			showError('resetError', 'Network error. Please check your connection and try again.');
		} finally {
			setButtonLoading('step4Btn', false);
		}
	}

	// =============================================
	// EVENT LISTENERS
	// =============================================

	document.addEventListener('DOMContentLoaded', function() {

		const loginForm = document.querySelector('form[action="#"]');
		if (loginForm && document.getElementById('username') && document.getElementById('password')) {
			if (!document.getElementById('step1')) {
				loginForm.addEventListener('submit', handleLogin);
			}
		}

		const registerForm = document.getElementById('registerForm');
		if (registerForm) {
			checkRegistrationStatus();
			loadSecurityQuestions();

			const passwordInput = document.getElementById('password');
			if (passwordInput) {
				passwordInput.addEventListener('input', (e) => {
					validatePasswordStrength(e.target.value);
				});
			}

			registerForm.addEventListener('submit', handleRegister);
		}

		const step1Form = document.getElementById('step1Form');
		if (step1Form) {
			step1Form.addEventListener('submit', handleResetStep1);
		}

		const step2Form = document.getElementById('step2Form');
		if (step2Form) {
			step2Form.addEventListener('submit', handleResetStep2);

			const useRecoveryBtn = document.getElementById('useRecoveryCodeBtn');
			if (useRecoveryBtn) {
				useRecoveryBtn.addEventListener('click', () => showResetStep(3));
			}
		}

		const step3Form = document.getElementById('step3Form');
		if (step3Form) {
			step3Form.addEventListener('submit', handleResetStep3);

			const backBtn = document.getElementById('backToQuestionsBtn');
			if (backBtn) {
				backBtn.addEventListener('click', () => showResetStep(2));
			}
		}

		const step4Form = document.getElementById('step4Form');
		if (step4Form) {
			step4Form.addEventListener('submit', handleResetStep4);
		}

	});

	// =============================================
	// PUBLIC API
	// =============================================

	window.TNAuth = {
		login: handleLogin,
		register: handleRegister,
		logout: async function() {
			try {
				await apiCall(API.LOGOUT, {
					method: 'POST'
				});
				window.location.href = '/index.html';
			} catch (error) {
				console.error('Logout error:', error);
			}
		},
	};

	console.log('[Auth] Authentication system loaded v2.0.1');

})();
