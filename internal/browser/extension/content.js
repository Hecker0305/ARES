// Ares Browser Extension — Content Script
// Injected into every page to bridge DOM access to the Ares engine

(function() {
    'use strict';

    let ws = null;
    let engineURL = 'http://localhost:8282';
    let tabId = null;

    const ALLOWED_URL_SCHEMES = /^https?:\/\//;

    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        if (msg.type === 'ARES_INIT') {
            engineURL = msg.engineURL || engineURL;
            initWebSocket();
            sendResponse({ status: 'connected', agent: 'active' });
        }

        if (msg.type === 'ARES_SCRIPT') {
            sendResponse({ error: 'Arbitrary script execution is disabled' });
            return true;
        }

        if (msg.type === 'ARES_SCREENSHOT') {
            captureVisibleArea(result => {
                sendResponse({ result });
            });
            return true;
        }

        if (msg.type === 'ARES_STORAGE') {
            sendResponse(getAllStorage());
        }

        return false;
    });

    function initWebSocket() {
        try {
            ws = new WebSocket('wss://' + engineURL.replace('http://', '').replace('https://', '') + '/events');

            ws.onopen = () => {
                ws.send(JSON.stringify({ type: 'REGISTER', role: 'browser_agent', tab: tabId }));
            };

            ws.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type === 'COMMAND') {
                        handleCommand(msg);
                    }
                } catch (e) { /* ignore parse errors */ }
            };

            ws.onerror = () => { ws = null; };

            ws.onclose = () => {
                setTimeout(initWebSocket, 5000);
            };
        } catch (e) { /* ws unavailable */ }
    }

    function handleCommand(cmd) {
        switch (cmd.action) {
            case 'execute':
                sendResult(cmd.id, { error: 'Arbitrary script execution is disabled' });
                break;
            case 'screenshot':
                captureVisibleArea(r => sendResult(cmd.id, r));
                break;
            case 'navigate':
                if (!cmd.url || !ALLOWED_URL_SCHEMES.test(cmd.url)) {
                    sendResult(cmd.id, { error: 'Invalid URL scheme - only http/https allowed' });
                    return;
                }
                try {
                    const parsed = new URL(cmd.url);
                    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                        sendResult(cmd.id, { error: 'Only http/https schemes allowed' });
                        return;
                    }
                    window.location.href = cmd.url;
                    sendResult(cmd.id, { navigated: true });
                } catch (e) {
                    sendResult(cmd.id, { error: 'Invalid URL: ' + e.message });
                }
                break;
            case 'inject':
                sendResult(cmd.id, { error: 'Direct code injection is disabled for security' });
                break;
        }
    }

    const ALLOWED_DOM_OPS = new Set([
        'querySelector', 'querySelectorAll', 'getElementById',
        'getElementsByClassName', 'getElementsByTagName',
        'getAttribute', 'hasAttribute', 'matches',
        'innerText', 'textContent', 'innerHTML',
    ]);

    function executeInPage(script, callback) {
        callback({ success: false, error: 'Arbitrary script execution is disabled for security' });
    }

    function captureVisibleArea(callback) {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;

            html2canvas(document.body).then(c => {
                canvas.getContext('2d').drawImage(c, 0, 0);
                callback({ success: true, dataURL: canvas.toDataURL('image/png').substring(0, 500000) });
            }).catch(e => {
                callback({ success: false, error: e.message });
            });
        } catch (e) {
            callback({ success: false, error: 'html2canvas not available' });
        }
    }

    function getAllStorage() {
        return {
            cookies: document.cookie.split(';').map(c => {
                const eqIdx = c.indexOf('=');
                if (eqIdx > 0) {
                    const name = c.substring(0, eqIdx).trim();
                    const value = c.substring(eqIdx + 1).trim();
                    return { name, value: '[REDACTED]' };
                }
                return { name: c.trim(), value: '[REDACTED]' };
            }),
            localStorage: Object.keys(localStorage).map(k => ({ key: k, value: '[REDACTED]' })),
            sessionStorage: Object.keys(sessionStorage).map(k => ({ key: k, value: '[REDACTED]' })),
        };
    }

    function sendResult(id, result) {
        if (ws && ws.readyState === 1) {
            ws.send(JSON.stringify({ type: 'RESULT', id, result }));
        }
    }

    chrome.runtime.sendMessage({ type: 'TAB_READY', url: window.location.href });

    window.addEventListener('beforeunload', () => {
        chrome.runtime.sendMessage({ type: 'TAB_CLOSED', url: window.location.href });
    });
})();
