// Ares Browser Extension — Background Service Worker
// Manages tab lifecycle, WS connections, and command routing

const ENGINE_ORIGIN = 'http://localhost:8282';
let ws = null;
const tabs = new Map();
let isAuthenticated = false;
const ALLOWED_COMMANDS = new Set(['EXECUTE_SCRIPT', 'SCREENSHOT', 'GET_ALL_STORAGE']);

chrome.runtime.onInstalled.addListener(() => {
    console.log('[Ares] Extension installed');
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'TAB_READY') {
        chrome.tabs.query({ active: true, currentWindow: true }, foundTabs => {
            if (foundTabs[0]) {
                tabs.set(foundTabs[0].id, { url: msg.url, ready: true });
                broadcastToEngine({ type: 'TAB_REGISTERED', tabId: foundTabs[0].id, url: msg.url });
            }
        });
    }

    if (msg.type === 'TAB_CLOSED') {
        for (const [id, tab] of tabs) {
            if (tab.url === msg.url) {
                tabs.delete(id);
                broadcastToEngine({ type: 'TAB_CLOSED', tabId: id });
                break;
            }
        }
    }

    if (msg.type === 'GET_SESSION') {
        const senderUrl = sender.url || '';
        if (!senderUrl.startsWith(ENGINE_ORIGIN)) {
            console.warn('[Ares] GET_SESSION blocked: unauthorized origin', senderUrl);
            sendResponse({ error: 'unauthorized origin' });
            return true;
        }
        chrome.cookies.getAll({}, cookies => {
            const sessionCookies = cookies.filter(c => c.name.includes('session') || c.name.includes('token') || c.name.includes('auth'));
            sendResponse(sessionCookies.map(c => ({ name: c.name, value: '[REDACTED]', domain: c.domain })));
        });
        return true;
    }

    if (msg.type === 'CONNECT_ENGINE') {
        connectToEngine(msg.engineURL || ENGINE_ORIGIN);
        sendResponse({ connected: true });
    }

    return false;
});

function connectToEngine(url) {
    try {
        const wsURL = 'wss://' + url.replace('http://', '').replace('https://', '') + '/events';
        ws = new WebSocket(wsURL);

        ws.onopen = () => {
            ws.send(JSON.stringify({ type: 'REGISTER', role: 'extension', version: '1.0' }));
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'AUTH_CHALLENGE') {
                    authenticate(msg.challenge);
                    return;
                }
                if (!isAuthenticated) {
                    console.warn('[Ares] Ignoring message: not authenticated');
                    return;
                }
                routeCommand(msg);
            } catch (e) { /* ignore */ }
        };

        ws.onclose = () => {
            isAuthenticated = false;
            setTimeout(() => connectToEngine(url), 5000);
        };

        ws.onerror = () => {
            console.error('[Ares] WebSocket error');
        };
    } catch (e) { /* ws unavailable */ }
}

function authenticate(challenge) {
    chrome.storage.local.get(['aresApiKey'], function(result) {
        const apiKey = result.aresApiKey;
        if (!apiKey) {
            console.error('[Ares] No API key configured - use extension settings to set ARES_API_KEY');
            return;
        }
        const response = {
            type: 'AUTH_RESPONSE',
            challenge: challenge,
            apiKey: apiKey
        };
        if (ws && ws.readyState === 1) {
            ws.send(JSON.stringify(response));
            isAuthenticated = true;
        }
    });
}

function routeCommand(cmd) {
    if (!ALLOWED_COMMANDS.has(cmd.type)) {
        console.warn('[Ares] Blocked disallowed command:', cmd.type);
        if (ws && ws.readyState === 1) {
            ws.send(JSON.stringify({ type: 'ERROR', message: `Command ${cmd.type} not allowed` }));
        }
        return;
    }

    if (cmd.type === 'EXECUTE_SCRIPT') {
        if (!cmd.script || typeof cmd.script !== 'string') {
            console.warn('[Ares] Invalid script parameter');
            return;
        }
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, { type: 'ARES_SCRIPT', script: cmd.script }, resp => {
                    if (ws && ws.readyState === 1) {
                        ws.send(JSON.stringify({ type: 'EXEC_RESULT', tabId: tabs[0].id, result: resp }));
                    }
                });
            }
        });
    }

    if (cmd.type === 'SCREENSHOT') {
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, { type: 'ARES_SCREENSHOT' }, resp => {
                    if (ws && ws.readyState === 1) {
                        ws.send(JSON.stringify({ type: 'SCREENSHOT_RESULT', tabId: tabs[0].id, result: resp }));
                    }
                });
            }
        });
    }

    if (cmd.type === 'GET_ALL_STORAGE') {
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, { type: 'ARES_STORAGE' }, resp => {
                    if (ws && ws.readyState === 1) {
                        ws.send(JSON.stringify({ type: 'STORAGE_RESULT', tabId: tabs[0].id, result: resp }));
                    }
                });
            }
        });
    }
}

function broadcastToEngine(msg) {
    if (ws && ws.readyState === 1) {
        ws.send(JSON.stringify(msg));
    }
}

chrome.runtime.onStartup.addListener(() => {
    connectToEngine(ENGINE_ORIGIN);
});

connectToEngine(ENGINE_ORIGIN);
