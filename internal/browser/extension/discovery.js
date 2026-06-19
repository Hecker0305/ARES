// Ares Page Agent — Discovery Script
// Injected into target pages to discover: APIs, forms, inputs, secrets,interesting DOM nodes

(function() {
    'use strict';

    const findings = [];
    const baseURL = window.location.origin;

    // 1. Auto-discover API endpoints
    function discoverAPIs() {
        const apis = new Set();
        const seen = new Set();

        document.querySelectorAll('a[href], form[action], [data-api], [data-endpoint], [data-url]').forEach(el => {
            let api = el.getAttribute('data-api') || el.getAttribute('data-endpoint') || el.getAttribute('data-url') || el.getAttribute('action') || el.getAttribute('href');
            if (api && !seen.has(api)) {
                seen.add(api);
                if (api.startsWith('/') || api.startsWith('http')) {
                    if (api.startsWith('/')) api = baseURL + api;
                    apis.add(api);
                }
            }
        });

        // JS file analysis for API routes
        document.querySelectorAll('script[src]').forEach(s => {
            findings.push({ type: 'script_src', value: s.src });
        });

        // fetch/axios patterns
        const scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(s => {
            const text = s.textContent;
            const fetchMatches = text.match(/fetch\s*\(['"`]([^'"`]+)['"`]/g);
            const axiosMatches = text.match(/axios\.(get|post|put|delete)\s*\(['"`]([^'"`]+)['"`]/g);
            const xhrMatches = text.match(/new\s+XMLHttpRequest\(\).*\.open\s*\(\s*['"](GET|POST|PUT|DELETE)['"]\s*,\s*['"`]([^'"`]+)['"`]/g);
            if (fetchMatches) fetchMatches.forEach(m => findings.push({ type: 'api_fetch', value: m }));
            if (axiosMatches) axiosMatches.forEach(m => findings.push({ type: 'api_axios', value: m }));
            if (xhrMatches) xhrMatches.forEach(m => findings.push({ type: 'api_xhr', value: m }));
        });

        return Array.from(apis);
    }

    // 2. Form discovery
    function discoverForms() {
        const forms = [];
        document.querySelectorAll('form').forEach(form => {
            const inputs = [];
            form.querySelectorAll('input, select, textarea').forEach(input => {
                inputs.push({
                    name: input.name || input.id || '',
                    type: input.type || 'text',
                    id: input.id || '',
                    autocomplete: input.getAttribute('autocomplete') || '',
                });
            });
            forms.push({
                action: form.action || window.location.href,
                method: form.method || 'GET',
                inputs: inputs,
            });
        });
        return forms;
    }

    // 3. Secret discovery (redacted values only)
    function discoverSecrets() {
        const secrets = [];
        const text = document.documentElement.innerHTML;
        const patterns = {
            'api_key': /api[_-]?key['":\s=]+['"][a-zA-Z0-9_-]{20,}['"]/gi,
            'aws_key': /AKIA[0-9A-Z]{16}/g,
            'bearer': /bearer['":\s]+[a-zA-Z0-9_.-]{20,}/gi,
            'jwt': /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
            'url_creds': /:\/\/[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@/g,
        };
        for (const [type, regex] of Object.entries(patterns)) {
            const matches = text.match(regex);
            if (matches) {
                matches.slice(0, 5).forEach(m => secrets.push({ type, value: '[REDACTED - requires authorization to view]' }));
            }
        }
        return secrets;
    }

    // 4. Interesting DOM nodes
    function discoverInterestingNodes() {
        const nodes = [];
        document.querySelectorAll('[onclick], [onerror], [onload], [data-id], [data-user], [data-token]').forEach(el => {
            const tag = el.tagName.toLowerCase();
            const id = el.id || '';
            const cls = el.className || '';
            const attrs = {};
            for (const attr of el.attributes) {
                if (attr.name.startsWith('data-') || attr.name.startsWith('on')) {
                    attrs[attr.name] = attr.value.substring(0, 50);
                }
            }
            nodes.push({ tag, id, class: cls, attrs });
        });
        return nodes;
    }

    // 5. Sinks for XSS
    function findXSSSinks() {
        const sinks = [];
        const sinkSelectors = [
            'script[src]',
            '[onclick]',
            '[onerror]',
            '[onload]',
            '[onmouseover]',
            '[onfocus]',
            '[onblur]',
            '[onchange]',
            '[onsubmit]',
            '[onkeydown]',
            'a[href^="javascript:"]',
            'img[src^="javascript:"]',
            'iframe[src^="javascript:"]',
            '[innerHTML]',
            '[outerHTML]',
            '[insertAdjacentHTML]',
        ];
        for (const sel of sinkSelectors) {
            document.querySelectorAll(sel).forEach(el => {
                sinks.push({
                    tag: el.tagName.toLowerCase(),
                    selector: sel,
                    hasHandler: sel.startsWith('[on'),
                    url: window.location.href,
                });
            });
        }
        return sinks;
    }

    // 6. GraphQL discovery
    function discoverGraphQL() {
        const gql = [];
        const hasGQLEndpoint = document.querySelector('meta[name="graphql"]') ||
            document.querySelector('input[name="query"]') ||
            document.querySelector('textarea[name="query"]') ||
            window.__APOLLO_STATE__ ||
            window.__GRAPHCQL__ ||
            window.__GQL__;

        if (hasGQLEndpoint) {
            gql.push({ found: true, url: window.location.href });
        }

        document.querySelectorAll('script:not([src])').forEach(s => {
            if (s.textContent.includes('gql`') || s.textContent.includes('graphql`') ||
                s.textContent.includes('query ') && s.textContent.includes('{')) {
                gql.push({ inline_gql: true, url: window.location.href });
            }
        });

        return gql;
    }

    // Main discovery
    function run() {
        const result = {
            url: window.location.href,
            timestamp: new Date().toISOString(),
            apis: discoverAPIs(),
            forms: discoverForms(),
            secrets: discoverSecrets(),
            interestingNodes: discoverInterestingNodes(),
            xssSinks: findXSSSinks(),
            graphql: discoverGraphQL(),
            title: document.title,
            cookies: document.cookie ? document.cookie.split(';').length : 0,
        };

        // Send to engine
        try {
            fetch('http://localhost:8282/page_agent', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(result)
            });
        } catch (e) {
            // Store locally if server unavailable
            window.__ares_discovery = result;
        }

        return result;
    }

    if (document.readyState === 'complete') {
        run();
    } else {
        window.addEventListener('load', run);
    }
})();