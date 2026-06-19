(() => {
  const ARES_MARKER_PREFIX = 'ARES_XSS_';
  const ENGINE_ORIGIN = 'http://localhost:8282';
  const DIALOG_EVENTS = ['alert', 'confirm', 'prompt'];
  const findings = [];
  
  function init() {
    setupDOMObserver();
    setupDialogInterceptors();
    setupConsoleMonitor();
    notifyBackground('content_ready');
  }
  
  function setupDOMObserver() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            checkElement(node);
          }
        });
      });
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }
  
  function checkElement(element) {
    const html = element.innerHTML || '';
    const text = element.textContent || '';
    
    if (html.includes(ARES_MARKER_PREFIX)) {
      processMarker(element);
    }
    
    if (looksSuspicious(html) || looksSuspicious(text)) {
      reportFinding({
        type: 'DOM_TAMPERING',
        element: element.tagName,
        html: sanitize(html.substring(0, 500)),
        url: window.location.href
      });
    }
    
    element.querySelectorAll('*').forEach(child => {
      const attrs = Array.from(child.attributes || []);
      attrs.forEach(attr => {
        if (attr.value.includes(ARES_MARKER_PREFIX)) {
          processMarker(child, attr.name);
        }
      });
    });
  }
  
  function processMarker(element, attrName = null) {
    try {
      const marker = attrName 
        ? element.getAttribute(attrName)
        : element.textContent;
      
      if (marker && marker.startsWith(ARES_MARKER_PREFIX)) {
        const data = JSON.parse(atob(marker.replace(ARES_MARKER_PREFIX, '')));
        reportFinding({
          ...data,
          url: window.location.href,
          timestamp: Date.now()
        });
        
        if (data.action === 'remove') {
          element.remove();
        }
      }
    } catch (err) {
      console.error('Failed to process ARES marker', err);
    }
  }
  
  function setupDialogInterceptors() {
    const originalAlert = window.alert;
    const originalConfirm = window.confirm;
    const originalPrompt = window.prompt;
    
    window.alert = function(msg) {
      reportFinding({
        type: 'JS_ALERT',
        message: String(msg),
        url: window.location.href,
        timestamp: Date.now()
      });
      return originalAlert.apply(this, arguments);
    };
    
    window.confirm = function(msg) {
      reportFinding({
        type: 'JS_CONFIRM',
        message: String(msg),
        url: window.location.href,
        timestamp: Date.now()
      });
      return originalConfirm.apply(this, arguments);
    };
    
    window.prompt = function(msg, defaultValue) {
      reportFinding({
        type: 'JS_PROMPT',
        message: String(msg),
        defaultValue: String(defaultValue),
        url: window.location.href,
        timestamp: Date.now()
      });
      return originalPrompt.apply(this, arguments);
    };
  }
  
    function setupConsoleMonitor() {
        const originalLog = console.log;
        const originalWarn = console.warn;
        const origConsoleError = console.error;
        
        console.log = function(...args) {
            const str = args.map(a => String(a)).join(' ');
            if (str.includes(ARES_MARKER_PREFIX)) {
                checkConsoleOutput(args);
            }
            return originalLog.apply(console, args);
        };
        
        console.warn = function(...args) {
            const str = args.map(a => String(a)).join(' ');
            if (str.includes(ARES_MARKER_PREFIX)) {
                checkConsoleOutput(args);
            }
            return originalWarn.apply(console, args);
        };
        
        console.error = function(...args) {
            const str = args.map(a => String(a)).join(' ');
            if (str.includes(ARES_MARKER_PREFIX)) {
                checkConsoleOutput(args);
            }
            return origConsoleError.apply(console, args);
        };
    }
  
  function checkConsoleOutput(args) {
    const str = args.map(a => String(a)).join(' ');
    
    if (str.includes(ARES_MARKER_PREFIX)) {
      try {
        const data = JSON.parse(atob(str.replace(ARES_MARKER_PREFIX, '')));
        reportFinding({
          ...data,
          url: window.location.href,
          timestamp: Date.now()
        });
      } catch (err) {
        origConsoleError('Failed to parse ARES marker from console', err);
      }
    }
    
    if (str.includes('XSS') || str.includes('injection') || str.includes('vulnerability')) {
      reportFinding({
        type: 'CONSOLE_VULN_INDICATOR',
        message: str.substring(0, 500),
        url: window.location.href,
        timestamp: Date.now()
      });
    }
  }
  
  function looksSuspicious(str) {
    const patterns = [
      /<script[^>]*>[\s\S]*?<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe[^>]*>/gi,
      /<object[^>]*>/gi,
      /<embed[^>]*>/gi,
      /<form[^>]*>/gi,
      /expression\s*\(/gi,
      /url\s*\(/gi,
      /@import/gi
    ];
    
    return patterns.some(pattern => pattern.test(str));
  }
  
  function sanitize(str) {
    return str
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }
  
    function reportFinding(finding) {
        findings.push(finding);
        
        // Get extension ID from manifest or generate one
        const extId = chrome.runtime && chrome.runtime.id ? chrome.runtime.id : 'unknown';
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.sendMessage({
                type: 'XSS_FINDING',
                finding: finding
            });
        }
    
    if (window.parent !== window) {
      window.parent.postMessage({
        type: 'ARES_XSS_FINDING',
        finding: finding
      }, ENGINE_ORIGIN);
    }
    
    dispatchEvent(new CustomEvent('ares-xss-finding', {
      detail: finding
    }));
  }
  
  function notifyBackground(message) {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: message
      });
    }
  }
  
  function getFindings() {
    return findings;
  }
  
  function clearFindings() {
    findings.length = 0;
  }
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  
  window.ARESContentScript = {
    getFindings,
    clearFindings,
    reportFinding
  };
})();
