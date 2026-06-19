const API_BASE = '/api';
let currentUser = null;
let eventSource = null;
let scans = [];
let findings = [];
let settings = {
  rateLimit: 60,
  sessionTimeout: 24,
  corsOrigins: ''
};

document.addEventListener('DOMContentLoaded', () => {
  initAuth();
  initNavigation();
  initDashboard();
  initFindings();
  initReports();
  initSettings();
  initModal();
});

async function initAuth() {
  try {
    const res = await authFetch(`${API_BASE}/auth/validate`);
    if (!res.ok) throw new Error('Invalid session');
    const data = await res.json();
    currentUser = data;
    document.getElementById('user-info').textContent = `${data.username} (${data.role})`;
  } catch (err) {
    document.getElementById('user-info').textContent = 'Not authenticated';
  }
  
  document.getElementById('logout-btn').addEventListener('click', async () => {
    await authFetch(`${API_BASE}/auth/logout`, { method: 'POST' });
    window.location.href = '/login';
  });
}

function initNavigation() {
  const navBtns = document.querySelectorAll('.nav-btn');
  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      navBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      const tabId = btn.dataset.tab + '-tab';
      document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
      });
      document.getElementById(tabId)?.classList.add('active');
      
      if (btn.dataset.tab === 'dashboard') loadScans();
      if (btn.dataset.tab === 'findings') loadFindings();
    });
  });
}

function initDashboard() {
  document.getElementById('new-scan-btn').addEventListener('click', showNewScanModal);
  loadScans();
  connectEventSource();
}

function initFindings() {
  document.getElementById('filter-severity').addEventListener('change', filterFindings);
  document.getElementById('filter-type').addEventListener('change', filterFindings);
}

function initReports() {
  document.getElementById('generate-report-btn').addEventListener('click', generateReport);
}

function initSettings() {
  document.getElementById('save-settings-btn').addEventListener('click', saveSettings);
  document.getElementById('new-user-btn').addEventListener('click', showNewUserModal);
  loadSettings();
  loadUsers();
}

function initModal() {
  const modal = document.getElementById('modal');
  const closeBtn = modal.querySelector('.modal-close');
  closeBtn.addEventListener('click', () => modal.classList.remove('show'));
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.classList.remove('show');
  });
}

async function loadScans() {
  try {
    const res = await authFetch(`${API_BASE}/scans`);
    if (!res.ok) throw new Error('Failed to load scans');
    scans = await res.json();
    renderScans();
    updateStats();
  } catch (err) {
    showToast('Failed to load scans: ' + err.message, 'error');
  }
}

function renderScans() {
  const container = document.getElementById('scans-list');
  
  if (scans.length === 0) {
    container.innerHTML = '<div class="empty-state">No active scans. Start a new scan to begin.</div>';
    return;
  }
  
  const reportSelect = document.getElementById('report-scan-id');
  reportSelect.innerHTML = '<option value="">Select a scan</option>';
  
  container.innerHTML = scans.map(scan => {
    const opt = document.createElement('option');
    opt.value = scan.id;
    opt.textContent = scan.id + ' - ' + scan.target;
    reportSelect.appendChild(opt);
    
    return `
      <div class="scan-item" data-id="${escapeHtml(scan.id)}">
        <div class="scan-info">
          <div class="scan-target">${escapeHtml(scan.target)}</div>
          <div class="scan-meta">
            <span>ID: ${escapeHtml(scan.id)}</span>
            <span>Phase: ${escapeHtml(scan.phase || 'N/A')}</span>
            <span>Started: ${escapeHtml(formatTime(scan.start_time))}</span>
          </div>
          <div class="scan-progress">
            <div class="scan-progress-bar" style="width: ${Math.min(100, Math.max(0, scan.progress || 0))}%"></div>
          </div>
        </div>
        <div class="scan-actions">
          <span class="scan-status ${escapeHtml(scan.status)}">${escapeHtml(scan.status)}</span>
          <button class="btn-icon btn-view-details" data-scan-id="${escapeHtml(scan.id)}" title="View Details">👁</button>
          ${scan.status === 'running' ? `<button class="btn-icon btn-stop-scan" data-scan-id="${escapeHtml(scan.id)}" title="Stop Scan">⏹</button>` : ''}
        </div>
      </div>
    `;
  }).join('');

  container.querySelectorAll('.btn-view-details').forEach(btn => {
    btn.addEventListener('click', () => viewScanDetails(btn.dataset.scanId));
  });
  container.querySelectorAll('.btn-stop-scan').forEach(btn => {
    btn.addEventListener('click', () => stopScan(btn.dataset.scanId));
  });
}

async function loadFindings() {
  findings = [];
  for (const scan of scans) {
    try {
      const res = await authFetch(`${API_BASE}/scans/${scan.id}/findings`);
      if (res.ok) {
        const scanFindings = await res.json();
        findings = [...findings, ...scanFindings.map(f => ({...f, scanId: scan.id}))];
      }
    } catch (err) {
      console.error('Failed to load findings for scan', scan.id, err);
    }
  }
  renderFindings();
}

function renderFindings() {
  const container = document.getElementById('findings-list');
  
  if (findings.length === 0) {
    container.innerHTML = '<div class="empty-state">No findings yet. Run a scan to detect vulnerabilities.</div>';
    return;
  }
  
  container.innerHTML = findings.map(f => `
    <div class="finding-item" data-severity="${f.severity}" data-type="${f.type}">
      <div class="finding-header">
        <span class="finding-title">${escapeHtml(f.title || f.type)}</span>
        <span class="severity-badge ${f.severity}">${f.severity}</span>
      </div>
      <p class="finding-description">${escapeHtml(f.description || 'No description available')}</p>
      <div class="finding-meta">
        <span class="finding-meta-item">Target: ${escapeHtml(f.target || 'N/A')}</span>
        <span class="finding-meta-item">CVSS: ${f.cvss || 'N/A'}</span>
        <span class="finding-meta-item">Confirmed: ${f.confirmed ? 'Yes' : 'No'}</span>
      </div>
      ${f.mitre_tags && f.mitre_tags.length ? `
        <div class="finding-tags">
          ${f.mitre_tags.map(t => `<span class="tag">${t}</span>`).join('')}
        </div>
      ` : ''}
    </div>
  `).join('');
}

function filterFindings() {
  const severity = document.getElementById('filter-severity').value;
  const type = document.getElementById('filter-type').value;
  
  document.querySelectorAll('.finding-item').forEach(item => {
    const matchSeverity = !severity || item.dataset.severity === severity;
    const matchType = !type || item.dataset.type === type;
    item.style.display = matchSeverity && matchType ? 'block' : 'none';
  });
}

async function generateReport() {
  const scanId = document.getElementById('report-scan-id').value;
  const format = document.getElementById('report-format').value;
  
  if (!scanId) {
    showToast('Please select a scan', 'error');
    return;
  }
  
  try {
    const res = await authFetch(`${API_BASE}/scans/${scanId}/report?format=${format}`);
    if (!res.ok) throw new Error('Failed to generate report');
    
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${scanId}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
    
    showToast('Report generated successfully', 'success');
  } catch (err) {
    showToast('Failed to generate report: ' + err.message, 'error');
  }
}

async function loadSettings() {
  try {
    const res = await authFetch(`${API_BASE}/settings`);
    if (res.ok) {
      settings = await res.json();
      document.getElementById('setting-rate-limit').value = settings.rateLimit || 60;
      document.getElementById('setting-session-timeout').value = settings.sessionTimeout || 24;
      document.getElementById('setting-cors').value = settings.corsOrigins || '';
    }
  } catch (err) {
    console.error('Failed to load settings', err);
  }
}

async function saveSettings() {
  settings.rateLimit = parseInt(document.getElementById('setting-rate-limit').value);
  settings.sessionTimeout = parseInt(document.getElementById('setting-session-timeout').value);
  settings.corsOrigins = document.getElementById('setting-cors').value;
  
  try {
    const res = await authFetch(`${API_BASE}/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    if (!res.ok) throw new Error('Failed to save settings');
    showToast('Settings saved successfully', 'success');
  } catch (err) {
    showToast('Failed to save settings: ' + err.message, 'error');
  }
}

async function loadUsers() {
  try {
    const res = await authFetch(`${API_BASE}/admin/users`);
    if (!res.ok) throw new Error('Failed to load users');
    const users = await res.json();
    renderUsers(users);
  } catch (err) {
    document.getElementById('users-list').innerHTML = '<div class="empty-state">Failed to load users</div>';
  }
}

function renderUsers(users) {
  const container = document.getElementById('users-list');
  
  if (users.length === 0) {
    container.innerHTML = '<div class="empty-state">No users found</div>';
    return;
  }
  
  container.innerHTML = users.map(user => `
    <div class="user-item">
      <div class="user-info">
        <div class="user-avatar">${escapeHtml(user.username.charAt(0).toUpperCase())}</div>
        <div class="user-details">
          <h3>${escapeHtml(user.username)}</h3>
          <p>Last login: ${escapeHtml(user.last_login ? formatTime(user.last_login) : 'Never')}</p>
        </div>
      </div>
      <div>
        <span class="role-badge ${escapeHtml(user.role)}">${escapeHtml(user.role)}</span>
        ${user.role !== 'admin' ? `<button class="btn-icon btn-delete-user" data-username="${escapeHtml(user.username)}" title="Delete User">🗑</button>` : ''}
      </div>
    </div>
  `).join('');

  container.querySelectorAll('.btn-delete-user').forEach(btn => {
    btn.addEventListener('click', () => deleteUser(btn.dataset.username));
  });
}

async function deleteUser(username) {
  if (!confirm(`Delete user ${username}?`)) return;
  
  try {
    const res = await authFetch(`${API_BASE}/admin/users/${username}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error('Failed to delete user');
    showToast('User deleted', 'success');
    loadUsers();
  } catch (err) {
    showToast('Failed to delete user: ' + err.message, 'error');
  }
}

function showNewScanModal() {
  const modal = document.getElementById('modal');
  const body = document.getElementById('modal-body');
  
  body.innerHTML = `
    <h2 style="margin-bottom: 20px; color: var(--text-primary);">Start New Scan</h2>
    <form id="new-scan-form">
      <div class="form-row">
        <label>Target URL</label>
        <input type="text" id="scan-target" placeholder="https://example.com" required style="width: 100%; padding: 12px; background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary);">
      </div>
      <button type="submit" class="btn-primary" style="margin-top: 16px; width: 100%;">Start Scan</button>
    </form>
  `;
  
  modal.classList.add('show');
  
  document.getElementById('new-scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = document.getElementById('scan-target').value;
    
    try {
      const res = await authFetch(`${API_BASE}/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
      });
      if (!res.ok) throw new Error('Failed to start scan');
      
      const scan = await res.json();
      scans.unshift(scan);
      renderScans();
      updateStats();
      modal.classList.remove('show');
      showToast('Scan started successfully', 'success');
    } catch (err) {
      showToast('Failed to start scan: ' + err.message, 'error');
    }
  });
}

function showNewUserModal() {
  const modal = document.getElementById('modal');
  const body = document.getElementById('modal-body');
  
  body.innerHTML = `
    <h2 style="margin-bottom: 20px; color: var(--text-primary);">Add New User</h2>
    <form id="new-user-form">
      <div class="form-row">
        <label>Username</label>
        <input type="text" id="user-username" required style="width: 100%; padding: 12px; background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary);">
      </div>
      <div class="form-row">
        <label>Password</label>
        <input type="password" id="user-password" required style="width: 100%; padding: 12px; background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary);">
      </div>
      <div class="form-row">
        <label>Role</label>
        <select id="user-role" style="width: 100%; padding: 12px; background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary);">
          <option value="viewer">Viewer</option>
          <option value="operator">Operator</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <button type="submit" class="btn-primary" style="margin-top: 16px; width: 100%;">Create User</button>
    </form>
  `;
  
  modal.classList.add('show');
  
  document.getElementById('new-user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('user-username').value;
    const password = document.getElementById('user-password').value;
    const role = document.getElementById('user-role').value;
    
    try {
      const res = await authFetch(`${API_BASE}/admin/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, role })
      });
      if (!res.ok) throw new Error('Failed to create user');
      
      modal.classList.remove('show');
      showToast('User created successfully', 'success');
      loadUsers();
    } catch (err) {
      showToast('Failed to create user: ' + err.message, 'error');
    }
  });
}

function viewScanDetails(scanId) {
  const scan = scans.find(s => s.id === scanId);
  if (!scan) return;
  
  const modal = document.getElementById('modal');
  const body = document.getElementById('modal-body');
  
  body.innerHTML = `
    <h2 style="margin-bottom: 20px; color: var(--text-primary);">Scan Details</h2>
    <div style="margin-bottom: 16px;">
      <p><strong>ID:</strong> ${scan.id}</p>
      <p><strong>Target:</strong> ${escapeHtml(scan.target)}</p>
      <p><strong>Status:</strong> <span class="scan-status ${scan.status}">${scan.status}</span></p>
      <p><strong>Phase:</strong> ${scan.phase || 'N/A'}</p>
      <p><strong>Progress:</strong> ${scan.progress || 0}%</p>
      <p><strong>Started:</strong> ${formatTime(scan.start_time)}</p>
    </div>
    <h3 style="margin-bottom: 12px; color: var(--text-primary);">Events</h3>
    <div style="max-height: 300px; overflow-y: auto; font-family: var(--font-mono); font-size: 12px;">
      ${scan.events && scan.events.length ? scan.events.map(ev => `
        <div style="padding: 8px; border-bottom: 1px solid var(--border-color);">
          <span style="color: var(--text-muted);">[${formatTime(ev.timestamp)}]</span>
          <span style="color: var(--accent-blue);">[${ev.type}]</span>
          ${escapeHtml(ev.message)}
        </div>
      `).join('') : '<div class="empty-state">No events</div>'}
    </div>
    <h3 style="margin: 16px 0 12px; color: var(--text-primary);">Findings</h3>
    <div style="max-height: 300px; overflow-y: auto;">
      ${scan.findings && scan.findings.length ? scan.findings.map(f => `
        <div style="padding: 12px; border-bottom: 1px solid var(--border-color);">
          <span class="severity-badge ${f.severity}">${f.severity}</span>
          <strong>${escapeHtml(f.title || f.type)}</strong>
          <p style="color: var(--text-secondary); margin-top: 4px;">${escapeHtml(f.description || '')}</p>
        </div>
      `).join('') : '<div class="empty-state">No findings</div>'}
    </div>
  `;
  
  modal.classList.add('show');
}

async function stopScan(scanId) {
  if (!confirm('Stop this scan?')) return;
  
  try {
    const res = await authFetch(`${API_BASE}/scans/${scanId}/stop`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Failed to stop scan');
    
    const scan = scans.find(s => s.id === scanId);
    if (scan) scan.status = 'stopped';
    renderScans();
    updateStats();
    showToast('Scan stopped', 'success');
  } catch (err) {
    showToast('Failed to stop scan: ' + err.message, 'error');
  }
}

function connectEventSource() {
  if (eventSource) {
    eventSource.close();
  }
  
  eventSource = new EventSource(`${API_BASE}/scans/events`);
  
  eventSource.onmessage = (e) => {
    try {
      const event = JSON.parse(e.data);
      addEventToFeed(event);
      
      if (event.type === 'FINDING_ADD') {
        const statsEl = document.getElementById('stat-findings');
        statsEl.textContent = parseInt(statsEl.textContent) + 1;
      }
    } catch (err) {
      console.error('Failed to parse event', err);
    }
  };
  
  eventSource.onerror = () => {
    eventSource.close();
    setTimeout(connectEventSource, 5000);
  };
}

function addEventToFeed(event) {
  const feed = document.getElementById('event-feed');
  const emptyState = feed.querySelector('.empty-state');
  if (emptyState) emptyState.remove();
  
  const eventEl = document.createElement('div');
  eventEl.className = 'event-item';
  eventEl.innerHTML = `
    <span class="event-time">${formatTime(event.timestamp)}</span>
    <span class="event-type ${event.type}">${event.type}</span>
    <span class="event-message">${escapeHtml(event.message)}</span>
  `;
  
  feed.insertBefore(eventEl, feed.firstChild);
  
  while (feed.children.length > 100) {
    feed.removeChild(feed.lastChild);
  }
}

function updateStats() {
  const activeCount = scans.filter(s => s.status === 'running').length;
  const totalFindings = scans.reduce((sum, s) => sum + (s.findings?.length || 0), 0);
  const criticalCount = scans.reduce((sum, s) => sum + (s.findings?.filter(f => f.severity === 'critical').length || 0), 0);
  const highCount = scans.reduce((sum, s) => sum + (s.findings?.filter(f => f.severity === 'high').length || 0), 0);
  
  document.getElementById('stat-active').textContent = activeCount;
  document.getElementById('stat-findings').textContent = totalFindings;
  document.getElementById('stat-critical').textContent = criticalCount;
  document.getElementById('stat-high').textContent = highCount;
}

function getAuthHeaders() {
  const token = getCookie('ares_session');
  if (token) {
    return { 'Authorization': 'Bearer ' + token };
  }
  return {};
}

function getCookie(name) {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? match[2] : null;
}

function authFetch(url, options = {}) {
  return fetch(url, { ...options, credentials: 'same-origin', headers: { ...options.headers, ...getAuthHeaders() } });
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function formatTime(timestamp) {
  if (!timestamp) return 'N/A';
  const date = new Date(timestamp);
  return date.toLocaleString();
}

function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.className = `toast ${type} show`;
  
  setTimeout(() => {
    toast.classList.remove('show');
  }, 3000);
}

class WebSocketManager {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000;
    this.handlers = new Map();
  }
  
  connect() {
    try {
      this.ws = new WebSocket(this.url);
      
      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.reconnectAttempts = 0;
      };
      
      this.ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          const handler = this.handlers.get(data.type);
          if (handler) handler(data);
        } catch (err) {
          console.error('Failed to parse WebSocket message', err);
        }
      };
      
      this.ws.onerror = (err) => {
        console.error('WebSocket error', err);
      };
      
      this.ws.onclose = () => {
        console.log('WebSocket closed');
        this.reconnect();
      };
    } catch (err) {
      console.error('Failed to connect WebSocket', err);
      this.reconnect();
    }
  }
  
  reconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      setTimeout(() => {
        console.log(`Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        this.connect();
      }, this.reconnectDelay * this.reconnectAttempts);
    }
  }
  
  on(eventType, handler) {
    this.handlers.set(eventType, handler);
  }
  
  send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }
  
  close() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

class ScanManager {
  constructor(apiBase) {
    this.apiBase = apiBase;
    this.scans = new Map();
  }
  
  async start(target, options = {}) {
    try {
      const res = await authFetch(`${this.apiBase}/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, ...options })
      });
      
      if (!res.ok) throw new Error('Failed to start scan');
      
      const scan = await res.json();
      this.scans.set(scan.id, scan);
      return scan;
    } catch (err) {
      throw err;
    }
  }
  
  async stop(scanId) {
    try {
      const res = await authFetch(`${this.apiBase}/scans/${scanId}/stop`, {
        method: 'POST'
      });
      
      if (!res.ok) throw new Error('Failed to stop scan');
      
      const scan = this.scans.get(scanId);
      if (scan) scan.status = 'stopped';
      return true;
    } catch (err) {
      throw err;
    }
  }
  
  async getStatus(scanId) {
    try {
      const res = await authFetch(`${this.apiBase}/scans/${scanId}`);
      if (!res.ok) throw new Error('Scan not found');
      return await res.json();
    } catch (err) {
      throw err;
    }
  }
  
  async getFindings(scanId, filters = {}) {
    try {
      const params = new URLSearchParams(filters);
      const res = await authFetch(`${this.apiBase}/scans/${scanId}/findings?${params}`);
      if (!res.ok) throw new Error('Failed to get findings');
      return await res.json();
    } catch (err) {
      throw err;
    }
  }
  
  async getReport(scanId, format = 'json') {
    try {
      const res = await authFetch(`${this.apiBase}/scans/${scanId}/report?format=${format}`);
      if (!res.ok) throw new Error('Failed to get report');
      return await res.blob();
    } catch (err) {
      throw err;
    }
  }
  
  getAll() {
    return Array.from(this.scans.values());
  }
  
  get(scanId) {
    return this.scans.get(scanId);
  }
}

const scanManager = new ScanManager(API_BASE);

window.addEventListener('beforeunload', () => {
  if (eventSource) {
    eventSource.close();
  }
});
