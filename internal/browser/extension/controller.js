// Ares Page Agent — Controller Script
// In-page automation: navigation, form filling, click sequences, session management

(function() {
    'use strict';

    const ARES_VERSION = '1.0';
    const ALLOWED_URL_SCHEMES = /^https?:\/\//;
    let messageQueue = [];

    const AresAgentInternal = {
        version: ARES_VERSION,

        navigate: function(url) {
            if (!url || !ALLOWED_URL_SCHEMES.test(url)) {
                return { error: 'Invalid URL - only http/https schemes allowed' };
            }
            try {
                const parsed = new URL(url);
                if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                    return { error: 'Only http/https schemes allowed' };
                }
                window.location.href = url;
                return { navigated: true };
            } catch (e) {
                return { error: 'Invalid URL: ' + e.message };
            }
        },

        click: function(selector) {
            const el = document.querySelector(selector);
            if (el) {
                el.focus();
                el.click();
                return true;
            }
            return false;
        },

        fillForm: function(selector, data) {
            const form = document.querySelector(selector);
            if (!form) return false;
            for (const [name, value] of Object.entries(data)) {
                const input = form.querySelector(`[name="${name}"]`);
                if (input) {
                    input.value = value;
                    input.dispatchEvent(new Event('input', { bubbles: true }));
                    input.dispatchEvent(new Event('change', { bubbles: true }));
                }
            }
            return true;
        },

        submitForm: function(selector) {
            const form = document.querySelector(selector);
            if (form) {
                form.submit();
                return true;
            }
            return false;
        },

        getCookies: function() {
            return document.cookie.split(';').map(c => {
                const eqIdx = c.indexOf('=');
                if (eqIdx > 0) {
                    return { name: c.substring(0, eqIdx).trim(), value: '[REDACTED]' };
                }
                return { name: c.trim(), value: '[REDACTED]' };
            });
        },

        getLocalStorage: function() {
            const keys = [];
            for (let i = 0; i < localStorage.length; i++) {
                keys.push(localStorage.key(i));
            }
            return keys.map(k => ({ key: k, value: '[REDACTED]' }));
        },

        getSessionStorage: function() {
            const keys = [];
            for (let i = 0; i < sessionStorage.length; i++) {
                keys.push(sessionStorage.key(i));
            }
            return keys.map(k => ({ key: k, value: '[REDACTED]' }));
        },

        getAllStorage: function() {
            return {
                cookies: this.getCookies(),
                localStorage: this.getLocalStorage(),
                sessionStorage: this.getSessionStorage(),
            };
        },

        getDOMSnapshot: function() {
            return {
                url: window.location.href,
                title: document.title,
                forms: Array.from(document.forms).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.elements).map(i => ({ name: i.name, type: i.type, id: i.id }))
                })),
                links: Array.from(document.querySelectorAll('a[href]')).map(a => a.href).slice(0, 50),
                scripts: Array.from(document.querySelectorAll('script[src]')).map(s => s.src),
            };
        },

        executeScript: function() {
            return { success: false, error: 'Arbitrary script execution is disabled for security' };
        },

        waitForSelector: function(selector, timeout) {
            return new Promise((resolve, reject) => {
                const el = document.querySelector(selector);
                if (el) { resolve(el); return; }

                const observer = new MutationObserver(() => {
                    const el = document.querySelector(selector);
                    if (el) {
                        observer.disconnect();
                        resolve(el);
                    }
                });

                observer.observe(document.body, { childList: true, subtree: true });

                setTimeout(() => {
                    observer.disconnect();
                    reject(new Error(`Selector ${selector} not found within ${timeout}ms`));
                }, timeout || 10000);
            });
        },

        waitForNetworkIdle: function(timeout) {
            return new Promise(resolve => {
                const done = () => {
                    clearTimeout(t);
                    resolve(true);
                };
                let t = setTimeout(done, timeout || 5000);

                if (document.readyState !== 'complete') {
                    window.addEventListener('load', done);
                }
            });
        },

        takeSnapshot: function() {
            return {
                timestamp: Date.now(),
                url: window.location.href,
                title: document.title,
                bodyText: document.body ? document.body.innerText.substring(0, 5000) : '',
                domSnapshot: this.getDOMSnapshot(),
            };
        },

        pollForChanges: function(interval, callback) {
            let lastHTML = document.body ? document.body.innerHTML : '';
            return setInterval(() => {
                const current = document.body ? document.body.innerHTML : '';
                if (current !== lastHTML) {
                    lastHTML = current;
                    callback({ changed: true, snapshot: this.takeSnapshot() });
                }
            }, interval || 2000);
        },

        handleCommand: function(cmd) {
            switch (cmd.action) {
                case 'navigate': return { action: 'navigate', result: this.navigate(cmd.url) };
                case 'click': return { action: 'click', result: this.click(cmd.selector) };
                case 'fillForm': return { action: 'fillForm', result: this.fillForm(cmd.selector, cmd.data) };
                case 'getStorage': return { action: 'getStorage', result: this.getAllStorage() };
                case 'snapshot': return { action: 'snapshot', result: this.takeSnapshot() };
                case 'execute': return { action: 'execute', result: this.executeScript() };
                case 'dom': return { action: 'dom', result: this.getDOMSnapshot() };
                default: return { action: 'unknown', error: `Unknown action: ${cmd.action}` };
            }
        },
    };

    // Internal agent is not exposed to page context for security
    // External scripts cannot access AresAgentInternal
})();
