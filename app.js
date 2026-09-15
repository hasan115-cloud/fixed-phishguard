// PhishGuard Enterprise Security Dashboard Controller

let currentAuthToken = localStorage.getItem('phishguard_admin_token') || '';
let currentUser = null;
let sseSource = null;
let currentUrlPage = 1;

// Global tab switcher
function switchTab(tabId) {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.tab === tabId);
  });

  document.querySelectorAll('.tab-view').forEach(el => {
    el.classList.toggle('active', el.id === `tab-${tabId}`);
  });

  const titles = {
    'overview': 'Enterprise Overview',
    'systems': 'Enrolled Systems Fleet',
    'url-history': 'Central URL Audit Trail',
    'rules': 'Security Rules Policy',
    'alerts': 'Security Alerts',
    'install': 'Install PhishGuard Extension',
    'reports': 'Reports & Analytics'
  };

  const titleEl = document.getElementById('currentTabTitle');
  if (titleEl && titles[tabId]) {
    titleEl.textContent = titles[tabId];
  }

  // Auto-refresh tab content
  if (tabId === 'overview') loadOverviewStats();
  if (tabId === 'systems') loadSystems();
  if (tabId === 'url-history') loadUrlHistory();
  if (tabId === 'rules') loadRules();
  if (tabId === 'alerts') loadAlerts();
  if (tabId === 'reports') loadReports();
  if (tabId === 'install') loadInstallTab();
}

// Toast helper
function showToast(text, icon = 'ℹ️') {
  const toast = document.getElementById('toastMessage');
  const toastText = document.getElementById('toastText');
  const toastIcon = document.getElementById('toastIcon');
  if (!toast) return;

  toastText.textContent = text;
  toastIcon.textContent = icon;
  toast.style.display = 'flex';
  setTimeout(() => {
    toast.style.display = 'none';
  }, 3500);
}

// Global UI Formatting & Badge Helpers (declared top-level for all renderers)
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getClassificationBadge(decision, threatLevel) {
  const d = (decision || '').toUpperCase();
  const t = (threatLevel || '').toUpperCase();
  if (d === 'BLOCK' || t === 'CRITICAL' || t === 'HIGH') {
    return '<span class="badge-pill badge-block">PHISHING</span>';
  }
  if (d === 'WARNING' || t === 'MEDIUM') {
    return '<span class="badge-pill badge-warning">SUSPICIOUS</span>';
  }
  return '<span class="badge-pill badge-allow">SAFE</span>';
}

function getDecisionBadge(decision) {
  const d = (decision || 'ALLOW').toUpperCase();
  if (d === 'BLOCK') return '<span class="badge-pill badge-block">🛑 BLOCK</span>';
  if (d === 'WARNING') return '<span class="badge-pill badge-warning">⚠️ WARNING</span>';
  return '<span class="badge-pill badge-allow">🛡️ ALLOW</span>';
}

function getThreatBadge(level) {
  const l = (level || 'SAFE').toUpperCase();
  if (l === 'CRITICAL') return '<span class="badge-pill badge-critical">CRITICAL</span>';
  if (l === 'HIGH') return '<span class="badge-pill badge-block">HIGH</span>';
  if (l === 'MEDIUM') return '<span class="badge-pill badge-warning">MEDIUM</span>';
  if (l === 'LOW') return '<span class="badge-pill" style="background:#1e293b; color:#94a3b8;">LOW</span>';
  return '<span class="badge-pill badge-allow">SAFE</span>';
}

function getAlertStatusBadge(status) {
  const s = (status || 'NEW').toUpperCase();
  if (s === 'NEW') return '<span class="badge-pill badge-block">NEW</span>';
  if (s === 'ACKNOWLEDGED') return '<span class="badge-pill badge-warning">ACKNOWLEDGED</span>';
  return '<span class="badge-pill badge-allow">RESOLVED</span>';
}

// Auth API call wrapper
async function apiFetch(url, options = {}) {
  const headers = options.headers || {};
  if (currentAuthToken) {
    headers['Authorization'] = `Bearer ${currentAuthToken}`;
  }
  headers['Content-Type'] = headers['Content-Type'] || 'application/json';

  const res = await fetch(url, { ...options, headers });
  if (res.status === 401) {
    // Session expired or invalid - drop it and force the user back to the login screen.
    // We NEVER auto-authenticate with default/hardcoded credentials in production.
    currentAuthToken = '';
    currentUser = null;
    localStorage.removeItem('phishguard_admin_token');
    showLoginGate('Your session has expired. Please sign in again.');
  }
  return res;
}

// Show the login screen and hide the authenticated app shell
function showLoginGate(message) {
  const gate = document.getElementById('loginGate');
  const shell = document.getElementById('appShellRoot');
  if (gate) gate.style.display = 'flex';
  if (shell) shell.style.display = 'none';
  if (sseSource) {
    try { sseSource.close(); } catch {}
    sseSource = null;
  }
  const errEl = document.getElementById('loginError');
  if (errEl) {
    if (message) {
      errEl.textContent = message;
      errEl.style.display = 'block';
    } else {
      errEl.style.display = 'none';
    }
  }
}

// Reveal the authenticated dashboard shell
function showAppShell() {
  const gate = document.getElementById('loginGate');
  const shell = document.getElementById('appShellRoot');
  if (gate) gate.style.display = 'none';
  if (shell) shell.style.display = '';
}

// Verify any stored token is still valid before showing the dashboard.
// Does NOT create sessions on its own - only real /api/auth/login issues tokens.
async function checkExistingSession() {
  if (!currentAuthToken) {
    showLoginGate();
    return;
  }
  try {
    const res = await fetch('/api/auth/me', {
      headers: { Authorization: `Bearer ${currentAuthToken}` }
    });
    if (res.ok) {
      const data = await res.json();
      currentUser = data.user || data;
      updateUserUI();
      showAppShell();
      loadOverviewStats();
      initSse();
    } else {
      currentAuthToken = '';
      localStorage.removeItem('phishguard_admin_token');
      showLoginGate();
    }
  } catch (err) {
    showLoginGate('Unable to reach the server. Please check your connection and try again.');
  }
}

// Real login submission handler (wired up in DOMContentLoaded below)
async function handleLoginSubmit(e) {
  e.preventDefault();
  const usernameEl = document.getElementById('loginUsername');
  const passwordEl = document.getElementById('loginPassword');
  const btn = document.getElementById('loginSubmitBtn');
  const errEl = document.getElementById('loginError');

  const username = usernameEl.value.trim();
  const password = passwordEl.value;
  if (!username || !password) return;

  if (btn) { btn.disabled = true; btn.textContent = 'Signing in...'; }
  if (errEl) errEl.style.display = 'none';

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data.token) {
      currentAuthToken = data.token;
      currentUser = data.user;
      localStorage.setItem('phishguard_admin_token', currentAuthToken);
      updateUserUI();
      showAppShell();
      loadOverviewStats();
      initSse();
    } else {
      if (errEl) {
        errEl.textContent = data.error || 'Invalid username or password.';
        errEl.style.display = 'block';
      }
    }
  } catch (err) {
    if (errEl) {
      errEl.textContent = 'Unable to reach the server. Please try again.';
      errEl.style.display = 'block';
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }
  }
}

function updateUserUI() {
  const nameEl = document.getElementById('sidebarUsername');
  const avatarEl = document.getElementById('avatarLetter');
  if (currentUser && nameEl) {
    nameEl.textContent = currentUser.username;
    if (avatarEl) avatarEl.textContent = currentUser.username.charAt(0).toUpperCase();
  }
}

// -------------------------------------------------------------
// 1. OVERVIEW DASHBOARD
// -------------------------------------------------------------
async function loadOverviewStats() {
  try {
    const res = await fetch('/api/dashboard/stats');
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('cardTotalClients').textContent = data.totalClients || 0;
    document.getElementById('cardOnlineClients').textContent = `${data.onlineClients || 0} online now`;
    document.getElementById('cardTotalUrls').textContent = data.totalUrlsMonitored || 0;
    document.getElementById('cardAllowedUrls').textContent = `${data.allowedUrls || 0} allowed`;
    document.getElementById('cardBlockedUrls').textContent = data.blockedUrls || 0;
    document.getElementById('cardWarningUrls').textContent = `${data.warningUrls || 0} warnings flagged`;
    document.getElementById('cardActiveAlerts').textContent = data.newAlerts || 0;
    document.getElementById('cardCriticalAlerts').textContent = `${data.criticalAlerts || 0} critical`;

    // Telemetry Classification Breakdown (Real Data)
    const classTotalEl = document.getElementById('overviewClassTotal');
    const classSafeEl = document.getElementById('overviewClassSafe');
    const classSuspiciousEl = document.getElementById('overviewClassSuspicious');
    const classPhishingEl = document.getElementById('overviewClassPhishing');
    if (classTotalEl) classTotalEl.textContent = data.totalUrlsMonitored || 0;
    if (classSafeEl) classSafeEl.textContent = data.allowedUrls || 0;
    if (classSuspiciousEl) classSuspiciousEl.textContent = data.warningUrls || 0;
    if (classPhishingEl) classPhishingEl.textContent = data.blockedUrls || 0;

    // Badges in sidebar
    document.getElementById('onlineBadgeCount').textContent = data.onlineClients || 0;
    document.getElementById('alertBadgeCount').textContent = data.newAlerts || 0;

    // Notification bell update
    updateNotifBell(data.newAlerts || 0);

    // Recent events table
    const tbody = document.getElementById('overviewRecentEventsTbody');
    if (data.recentEvents && data.recentEvents.length > 0) {
      tbody.innerHTML = data.recentEvents.map(e => `
        <tr>
          <td style="white-space:nowrap; font-size:0.8rem;">${new Date(e.timestamp).toLocaleTimeString()}</td>
          <td><span style="font-weight:600;">${escapeHtml(e.system_name || e.client_id)}</span></td>
          <td>${getClassificationBadge(e.decision, e.threat_level)}</td>
          <td><span style="color:#38bdf8; font-family:monospace; font-size:0.82rem;">${escapeHtml(e.domain)}</span></td>
          <td>${getDecisionBadge(e.decision)}</td>
        </tr>
      `).join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No events recorded yet.</td></tr>';
    }

    // Top blocked domains
    const topList = document.getElementById('overviewTopBlockedList');
    if (data.topBlockedDomains && data.topBlockedDomains.length > 0) {
      topList.innerHTML = data.topBlockedDomains.map(d => `
        <div style="display:flex; justify-content:space-between; align-items:center; background:var(--bg-input); padding:8px 12px; border-radius:6px; border:1px solid var(--border);">
          <span style="font-family:monospace; color:#f87171;">${escapeHtml(d.domain)}</span>
          <span class="badge-pill badge-block">${d.count} blocked</span>
        </div>
      `).join('');
    } else {
      topList.innerHTML = '<div style="font-size:0.84rem; color:var(--text-muted); text-align:center; padding:16px;">No blocked domains recorded</div>';
    }
  } catch (err) {
    console.error('Failed to load overview stats', err);
  }
}

// Notification Bell Management
function updateNotifBell(alertCount) {
  const notifBadge = document.getElementById('notifBellBadge');
  const notifDropdownBadge = document.getElementById('notifDropdownBadge');
  const count = parseInt(alertCount, 10) || 0;

  if (notifBadge) {
    if (count > 0) {
      notifBadge.style.display = 'inline-block';
      notifBadge.textContent = count > 99 ? '99+' : count;
    } else {
      notifBadge.style.display = 'none';
      notifBadge.textContent = '0';
    }
  }
  if (notifDropdownBadge) {
    notifDropdownBadge.textContent = count;
  }
}

async function loadNotifDropdownList() {
  const listEl = document.getElementById('notifDropdownList');
  if (!listEl) return;
  listEl.innerHTML = '<div style="text-align:center; padding:16px; color:var(--text-muted); font-size:0.82rem;">Loading alerts...</div>';

  try {
    const res = await fetch('/api/alerts?limit=6');
    if (!res.ok) throw new Error('Failed to load alerts');
    const data = await res.json();
    const alerts = data.alerts || [];

    if (alerts.length === 0) {
      listEl.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted); font-size:0.82rem;">No alerts available</div>';
      return;
    }

    listEl.innerHTML = alerts.map(a => `
      <div style="padding:10px 14px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:flex-start; gap:10px; font-size:0.8rem; background: ${a.status === 'NEW' ? 'rgba(239, 68, 68, 0.08)' : 'transparent'};">
        <div style="flex:1; overflow:hidden;">
          <div style="display:flex; align-items:center; gap:6px; margin-bottom:3px;">
            ${getThreatBadge(a.severity)}
            <strong style="color:var(--text-main); font-size:0.82rem;">${escapeHtml(a.domain)}</strong>
          </div>
          <div style="color:var(--text-muted); font-size:0.75rem; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">
            ${escapeHtml(a.reason || a.alert_type)}
          </div>
          <div style="color:var(--text-dim); font-size:0.7rem; margin-top:2px;">
            ${new Date(a.timestamp).toLocaleTimeString()} • ${escapeHtml(a.system_name || a.client_id)}
          </div>
        </div>
        ${a.status === 'NEW' ? `
          <button class="btn-header" style="font-size:0.68rem; padding:2px 6px;" onclick="event.stopPropagation(); updateAlertStatus('${a.id}', 'ACKNOWLEDGED');">Ack</button>
        ` : ''}
      </div>
    `).join('');
  } catch (err) {
    listEl.innerHTML = '<div style="text-align:center; padding:16px; color:#ef4444; font-size:0.82rem;">Failed to load alerts</div>';
  }
}

// -------------------------------------------------------------
// 2. ENROLLED SYSTEMS (FLEET)
// -------------------------------------------------------------
let allLoadedSystems = [];

function renderSystemsTable(systems) {
  const tbody = document.getElementById('systemsTableBody');
  if (!tbody) return;

  const searchInput = document.getElementById('filterSystemSearch');
  const statusFilter = document.getElementById('filterSystemStatus');
  const searchVal = searchInput ? searchInput.value.trim().toLowerCase() : '';
  const statusVal = statusFilter ? statusFilter.value : '';

  let filtered = systems || [];
  if (searchVal) {
    filtered = filtered.filter(c =>
      (c.system_name && c.system_name.toLowerCase().includes(searchVal)) ||
      (c.client_id && c.client_id.toLowerCase().includes(searchVal)) ||
      (c.hostname && c.hostname.toLowerCase().includes(searchVal)) ||
      (c.ip_address && c.ip_address.toLowerCase().includes(searchVal))
    );
  }
  if (statusVal) {
    filtered = filtered.filter(c => c.status === statusVal);
  }

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:var(--text-muted); padding:20px;">No systems found matching filters.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(c => {
    const isOnline = c.status === 'ONLINE';
    const statusBadge = isOnline
      ? '<span class="badge-pill badge-online">● Online</span>'
      : '<span class="badge-pill badge-offline">○ Offline</span>';

    return `
      <tr>
        <td>${statusBadge}</td>
        <td><strong>${escapeHtml(c.system_name)}</strong><br><small style="color:var(--text-muted);">${escapeHtml(c.hostname || 'workstation')}</small></td>
        <td><code style="color:#38bdf8;">${escapeHtml(c.client_id)}</code></td>
        <td>${escapeHtml(c.os || 'Desktop')}<br><small style="color:var(--text-muted);">${escapeHtml(c.browser || 'Chrome')}</small></td>
        <td>${escapeHtml(c.extension_version || '1.4')}</td>
        <td><code>${escapeHtml(c.ip_address || '127.0.0.1')}</code></td>
        <td>${new Date(c.last_seen).toLocaleString()}</td>
        <td>${c.totalEvents || 0} / <span style="color:#ef4444; font-weight:600;">${c.blockedCount || 0}</span></td>
        <td>
          <div style="display:flex; gap:6px;">
            <button class="btn-header" onclick="viewClientDetail('${escapeHtml(c.client_id)}')">Inspect</button>
            <button class="btn-header" style="color:#ef4444;" onclick="deleteClient('${escapeHtml(c.client_id)}')" title="Decommission">✕</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

async function loadSystems() {
  const tbody = document.getElementById('systemsTableBody');
  tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding:20px;">Refreshing fleet systems...</td></tr>';

  try {
    const res = await fetch('/api/clients');
    const data = await res.json();
    const clients = data.clients || [];
    allLoadedSystems = clients;

    // Populate client filter dropdowns
    const clientSelect = document.getElementById('urlHistoryClientSelect');
    if (clientSelect) {
      clientSelect.innerHTML = '<option value="">All Clients</option>' +
        clients.map(c => `<option value="${escapeHtml(c.client_id)}">${escapeHtml(c.system_name)} (${escapeHtml(c.client_id)})</option>`).join('');
    }

    if (clients.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:var(--text-muted); padding:20px;">No systems connected</td></tr>';
      return;
    }

    renderSystemsTable(allLoadedSystems);
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:#ef4444;">Failed to load systems fleet.</td></tr>';
  }
}

async function viewClientDetail(clientId) {
  const modal = document.getElementById('clientDetailModal');
  const body = document.getElementById('clientDetailBody');
  const title = document.getElementById('clientDetailTitle');

  modal.classList.add('open');
  body.innerHTML = '<div style="text-align:center; padding:30px;">Loading system inspection data...</div>';

  try {
    const res = await fetch(`/api/clients/${clientId}`);
    const data = await res.json();
    const c = data.client;
    const stats = data.stats;

    title.textContent = `Inspection: ${c.system_name} (${c.client_id})`;

    body.innerHTML = `
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px; background:var(--bg-input); padding:14px; border-radius:8px;">
        <div><strong>Status:</strong> ${c.status === 'ONLINE' ? '🟢 Online' : '⚪ Offline'}</div>
        <div><strong>IP Address:</strong> <code>${c.ip_address || '127.0.0.1'}</code></div>
        <div><strong>OS / Platform:</strong> ${c.os || 'Desktop'}</div>
        <div><strong>Browser:</strong> ${c.browser || 'Google Chrome'}</div>
        <div><strong>First Enrolled:</strong> ${new Date(c.first_seen).toLocaleString()}</div>
        <div><strong>Last Heartbeat:</strong> ${new Date(c.last_seen).toLocaleString()}</div>
      </div>

      <div class="stats-row" style="margin-bottom:16px;">
        <div class="stat-card" style="padding:10px 14px;">
          <div class="stat-meta"><span class="stat-title">Total URLs</span><span class="stat-number">${stats.totalEvents}</span></div>
        </div>
        <div class="stat-card" style="padding:10px 14px;">
          <div class="stat-meta"><span class="stat-title">Blocked Phishing</span><span class="stat-number" style="color:#ef4444;">${stats.blockedCount}</span></div>
        </div>
        <div class="stat-card" style="padding:10px 14px;">
          <div class="stat-meta"><span class="stat-title">Warnings</span><span class="stat-number" style="color:#f59e0b;">${stats.warningCount}</span></div>
        </div>
      </div>

      <h4 style="font-size:0.9rem; margin-bottom:8px;">Recent Endpoint Navigation Timeline</h4>
      <div class="table-responsive" style="max-height:240px; overflow-y:auto;">
        <table class="data-table">
          <thead>
            <tr><th>Time</th><th>Destination</th><th>Decision</th><th>Reason</th></tr>
          </thead>
          <tbody>
            ${(data.events || []).slice(0, 15).map(ev => `
              <tr>
                <td>${new Date(ev.timestamp).toLocaleTimeString()}</td>
                <td><code style="color:#38bdf8;">${escapeHtml(ev.domain)}</code></td>
                <td>${getDecisionBadge(ev.decision)}</td>
                <td style="font-size:0.75rem;">${escapeHtml(ev.reason || '')}</td>
              </tr>
            `).join('') || '<tr><td colspan="4" style="text-align:center;">No activity recorded for this endpoint yet.</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    body.innerHTML = '<div style="color:#ef4444; padding:20px;">Failed to load client details.</div>';
  }
}

function closeClientDetailModal() {
  document.getElementById('clientDetailModal').classList.remove('open');
}

async function deleteClient(clientId) {
  if (!confirm(`Are you sure you want to decommission client ${clientId}?`)) return;

  try {
    const res = await apiFetch(`/api/clients/${clientId}`, { method: 'DELETE' });
    if (res.ok) {
      showToast('Client decommissioned successfully');
      loadSystems();
      loadOverviewStats();
    } else {
      showToast('Failed to delete client', '⚠️');
    }
  } catch (err) {
    showToast('Network error during deletion', '⚠️');
  }
}

// -------------------------------------------------------------
// 3. URL HISTORY AUDIT TRAIL
// -------------------------------------------------------------
async function loadUrlHistory(page = 1) {
  currentUrlPage = page;
  const tbody = document.getElementById('urlHistoryTableBody');
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px;">Loading navigation events...</td></tr>';

  const search = document.getElementById('urlHistorySearch').value.trim();
  const decision = document.getElementById('urlHistoryDecision').value;
  const threatLevel = document.getElementById('urlHistoryThreatLevel').value;
  const clientId = document.getElementById('urlHistoryClientSelect').value;

  const params = new URLSearchParams({ page, limit: 25 });
  if (search) params.append('search', search);
  if (decision && decision !== 'ALL') params.append('decision', decision);
  if (threatLevel && threatLevel !== 'ALL') params.append('threatLevel', threatLevel);
  if (clientId) params.append('clientId', clientId);

  try {
    const res = await fetch(`/api/url-events?${params.toString()}`);
    const data = await res.json();
    const events = data.events || [];
    const p = data.pagination || { total: 0, totalPages: 1 };

    document.getElementById('urlHistoryPaginationInfo').textContent =
      `Showing page ${page} of ${p.totalPages || 1} (${p.total} total events)`;

    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:20px;">No URL history available</td></tr>';
      return;
    }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td style="white-space:nowrap; font-size:0.8rem;">${new Date(e.timestamp).toLocaleString()}</td>
        <td><strong>${escapeHtml(e.system_name || e.client_id)}</strong><br><small style="color:var(--text-muted); font-family:monospace;">${escapeHtml(e.client_id)}</small></td>
        <td>${getClassificationBadge(e.decision, e.threat_level)}</td>
        <td><span style="color:#38bdf8; font-weight:600;">${escapeHtml(e.domain)}</span></td>
        <td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:monospace; font-size:0.78rem;">
          <a href="${escapeHtml(e.url)}" target="_blank" rel="noopener noreferrer" style="color:#94a3b8; text-decoration:none;">${escapeHtml(e.url)}</a>
        </td>
        <td>${getDecisionBadge(e.decision)}</td>
        <td style="font-size:0.78rem; color:#cbd5e1;">${escapeHtml(e.reason || e.rule_name || 'Heuristic evaluation')}</td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:#ef4444;">Failed to load URL audit records.</td></tr>';
  }
}

// -------------------------------------------------------------
// 4. REAL-TIME ACTIVITY FEED (SSE)
// -------------------------------------------------------------
function initSse() {
  if (sseSource) sseSource.close();

  const dot = document.getElementById('sseDot');
  const label = document.getElementById('sseLabel');

  sseSource = new EventSource('/api/dashboard/events-stream');

  sseSource.onopen = () => {
    if (dot) dot.classList.remove('disconnected');
    if (label) label.textContent = 'Live Sync Active';
  };

  sseSource.onerror = () => {
    if (dot) dot.classList.add('disconnected');
    if (label) label.textContent = 'Sync (Polling active)';
  };

  // Resilient Polling Fallback (Vercel serverless & offline friendly)
  // Automatically refreshes active tab every 15s even if long-lived SSE connection is unavailable
  if (!window._dashboardPollingTimer) {
    window._dashboardPollingTimer = setInterval(() => {
      try {
        if (document.getElementById('tab-overview')?.classList.contains('active')) {
          loadOverviewStats();
        } else if (document.getElementById('tab-systems')?.classList.contains('active')) {
          loadSystems();
        } else if (document.getElementById('tab-alerts')?.classList.contains('active')) {
          loadAlerts();
        }
      } catch (err) {
        console.debug('Dashboard background poll skipped:', err);
      }
    }, 15000);
  }

  // URL Event listener
  sseSource.addEventListener('URL_EVENT', (e) => {
    try {
      // Refresh stats if on overview
      if (document.getElementById('tab-overview')?.classList.contains('active')) {
        loadOverviewStats();
      }
      if (document.getElementById('tab-url-history')?.classList.contains('active')) {
        loadUrlHistory(currentUrlPage);
      }
      if (document.getElementById('tab-reports')?.classList.contains('active')) {
        loadReports();
      }
    } catch {}
  });

  // Client registration listener
  sseSource.addEventListener('CLIENT_REGISTERED', (e) => {
    try {
      const data = JSON.parse(e.data);
      showToast(`New Endpoint Enrolled: ${data.client?.system_name || 'Client'}`);
      loadSystems();
    } catch {}
  });

  // Security Alert listener
  sseSource.addEventListener('SECURITY_ALERT', (e) => {
    try {
      const data = JSON.parse(e.data);
      showToast(`🚨 Security Alert Triggered on ${data.domain}`, '🛑');
      loadOverviewStats();
      loadAlerts();
    } catch {}
  });

  // Security Rules update listener
  sseSource.addEventListener('RULES_UPDATED', () => {
    try {
      if (document.getElementById('tab-rules')?.classList.contains('active')) {
        loadRules();
      }
    } catch {}
  });
}

// -------------------------------------------------------------
// 5. SECURITY RULES POLICY
// -------------------------------------------------------------
// -------------------------------------------------------------
// 5. SECURITY RULES POLICY (SECTION A: WHITELIST & SECTION B: PHISHING)
// -------------------------------------------------------------
async function loadRules() {
  const tbodyAll = document.getElementById('rulesTableBody');
  const tbodyWhitelist = document.getElementById('whitelistTableBody');
  const tbodyPhishing = document.getElementById('phishingTableBody');

  if (tbodyAll) tbodyAll.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:20px;">Loading policy rules...</td></tr>';
  if (tbodyWhitelist) tbodyWhitelist.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:16px;">Loading whitelist rules...</td></tr>';
  if (tbodyPhishing) tbodyPhishing.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:16px;">Loading phishing rules...</td></tr>';

  try {
    const res = await fetch('/api/rules');
    const data = await res.json();
    const rules = data.rules || [];

    // Filter into Section A (Whitelist) and Section B (Phishing)
    const whitelistRules = rules.filter(r => r.type === 'ALLOW');
    const phishingRules = rules.filter(r => r.type === 'BLOCK' || r.type === 'WARNING');

    // 1. Render Section A: Whitelist
    if (tbodyWhitelist) {
      if (whitelistRules.length === 0) {
        tbodyWhitelist.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:16px;">No whitelist rules defined yet. Domains entered above will bypass checks and be marked SAFE.</td></tr>';
      } else {
        tbodyWhitelist.innerHTML = whitelistRules.map(r => `
          <tr>
            <td><span class="badge-pill badge-allow">SAFE / ALLOWED</span></td>
            <td><code style="color:#10b981; font-weight:700; font-size:0.88rem;">${escapeHtml(r.pattern)}</code></td>
            <td style="color:var(--text-muted); font-size:0.82rem;">${escapeHtml(r.description || 'Administrative Whitelist')}</td>
            <td><strong>${r.priority}</strong></td>
            <td>
              <button class="btn-header" style="${r.enabled ? 'color:#10b981; font-weight:600;' : 'color:#94a3b8;'}" onclick="toggleRule('${r.id}')">
                ${r.enabled ? '● Active' : '○ Disabled'}
              </button>
            </td>
            <td>
              <button class="btn-header" style="color:#ef4444; padding:4px 10px;" onclick="deleteRule('${r.id}')">Delete</button>
            </td>
          </tr>
        `).join('');
      }
    }

    // 2. Render Section B: Phishing
    if (tbodyPhishing) {
      if (phishingRules.length === 0) {
        tbodyPhishing.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:16px;">No phishing rules defined yet. Domains entered above will be blocked and sound the threat alarm.</td></tr>';
      } else {
        tbodyPhishing.innerHTML = phishingRules.map(r => `
          <tr>
            <td><span class="badge-pill ${r.type === 'BLOCK' ? 'badge-block' : 'badge-warning'}">${r.type === 'BLOCK' ? 'PHISHING / BLOCK' : 'SUSPICIOUS'}</span></td>
            <td><code style="color:#ef4444; font-weight:700; font-size:0.88rem;">${escapeHtml(r.pattern)}</code></td>
            <td style="color:var(--text-muted); font-size:0.82rem;">${escapeHtml(r.description || 'Threat Blocklist')}</td>
            <td>${getThreatBadge(r.severity)}</td>
            <td><strong>${r.priority}</strong></td>
            <td>
              <button class="btn-header" style="${r.enabled ? 'color:#10b981; font-weight:600;' : 'color:#94a3b8;'}" onclick="toggleRule('${r.id}')">
                ${r.enabled ? '● Active' : '○ Disabled'}
              </button>
            </td>
            <td>
              <button class="btn-header" style="color:#ef4444; padding:4px 10px;" onclick="deleteRule('${r.id}')">Delete</button>
            </td>
          </tr>
        `).join('');
      }
    }

    // 3. Render Master Rules List
    if (tbodyAll) {
      if (rules.length === 0) {
        tbodyAll.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:20px;">No rules defined.</td></tr>';
      } else {
        tbodyAll.innerHTML = rules.map(r => `
          <tr>
            <td>${getDecisionBadge(r.type)}</td>
            <td><code style="color:#38bdf8; font-weight:600;">${escapeHtml(r.pattern)}</code></td>
            <td><span style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted);">${r.target_type}</span></td>
            <td><strong>${r.priority}</strong></td>
            <td>${getThreatBadge(r.severity)}</td>
            <td style="max-width:260px;">${escapeHtml(r.description || '—')}</td>
            <td>
              <button class="btn-header" style="${r.enabled ? 'color:#10b981;' : 'color:#94a3b8;'}" onclick="toggleRule('${r.id}')">
                ${r.enabled ? '● Active' : '○ Disabled'}
              </button>
            </td>
            <td>
              <div style="display:flex; gap:6px;">
                <button class="btn-header" onclick="openEditRuleModal('${r.id}')">Edit</button>
                <button class="btn-header" style="color:#ef4444;" onclick="deleteRule('${r.id}')">Delete</button>
              </div>
            </td>
          </tr>
        `).join('');
      }
    }
  } catch (err) {
    if (tbodyAll) tbodyAll.innerHTML = '<tr><td colspan="8" style="text-align:center; color:#ef4444;">Failed to load rules.</td></tr>';
  }
}

async function addQuickWhitelistRule() {
  const urlInput = document.getElementById('whitelistUrlInput');
  const descInput = document.getElementById('whitelistDescInput');
  const rawVal = (urlInput ? urlInput.value : '').trim();
  const desc = (descInput ? descInput.value : '').trim();

  if (!rawVal) {
    showToast('Please enter a URL or domain to whitelist', '⚠️');
    return;
  }

  try {
    const res = await apiFetch('/api/rules', {
      method: 'POST',
      body: JSON.stringify({
        type: 'ALLOW',
        pattern: rawVal,
        targetType: 'domain',
        severity: 'LOW',
        priority: 100,
        description: desc || `Administrative Whitelist: ${rawVal}`
      })
    });

    if (res.ok) {
      showToast('✅ Whitelist rule saved successfully to persistent database');
      if (urlInput) urlInput.value = '';
      if (descInput) descInput.value = '';
      loadRules();
    } else {
      const err = await res.json();
      showToast(err.error || 'Failed to save whitelist rule', '⚠️');
    }
  } catch (e) {
    showToast('Failed to contact server', '⚠️');
  }
}

async function addQuickPhishingRule() {
  const urlInput = document.getElementById('phishingUrlInput');
  const descInput = document.getElementById('phishingDescInput');
  const rawVal = (urlInput ? urlInput.value : '').trim();
  const desc = (descInput ? descInput.value : '').trim();

  if (!rawVal) {
    showToast('Please enter a URL or domain to classify as Phishing', '⚠️');
    return;
  }

  try {
    const res = await apiFetch('/api/rules', {
      method: 'POST',
      body: JSON.stringify({
        type: 'BLOCK',
        pattern: rawVal,
        targetType: 'domain',
        severity: 'HIGH',
        priority: 100,
        description: desc || `Phishing Threat Blocklist: ${rawVal}`
      })
    });

    if (res.ok) {
      showToast('🚨 Phishing rule saved successfully to persistent database');
      if (urlInput) urlInput.value = '';
      if (descInput) descInput.value = '';
      loadRules();
    } else {
      const err = await res.json();
      showToast(err.error || 'Failed to save phishing rule', '⚠️');
    }
  } catch (e) {
    showToast('Failed to contact server', '⚠️');
  }
}

function openNewRuleModal() {
  document.getElementById('ruleModalTitle').textContent = 'Create Security Policy Rule';
  document.getElementById('ruleEditId').value = '';
  document.getElementById('rulePattern').value = '';
  document.getElementById('ruleDescription').value = '';
  document.getElementById('rulePriority').value = '10';
  document.getElementById('ruleModal').classList.add('open');
}

async function openEditRuleModal(ruleId) {
  try {
    const res = await fetch('/api/rules');
    const data = await res.json();
    const rule = (data.rules || []).find(r => r.id === ruleId);
    if (!rule) return;

    document.getElementById('ruleModalTitle').textContent = 'Edit Security Policy Rule';
    document.getElementById('ruleEditId').value = rule.id;
    document.getElementById('ruleType').value = rule.type;
    document.getElementById('rulePattern').value = rule.pattern;
    document.getElementById('ruleTargetType').value = rule.target_type;
    document.getElementById('ruleSeverity').value = rule.severity;
    document.getElementById('rulePriority').value = rule.priority;
    document.getElementById('ruleDescription').value = rule.description || '';
    document.getElementById('ruleModal').classList.add('open');
  } catch {}
}

function closeRuleModal() {
  document.getElementById('ruleModal').classList.remove('open');
}

async function saveRuleForm(e) {
  e.preventDefault();
  const id = document.getElementById('ruleEditId').value;
  const payload = {
    type: document.getElementById('ruleType').value,
    pattern: document.getElementById('rulePattern').value.trim(),
    targetType: document.getElementById('ruleTargetType').value,
    severity: document.getElementById('ruleSeverity').value,
    priority: parseInt(document.getElementById('rulePriority').value, 10) || 10,
    description: document.getElementById('ruleDescription').value.trim()
  };

  try {
    const url = id ? `/api/rules/${id}` : '/api/rules';
    const method = id ? 'PUT' : 'POST';
    const res = await apiFetch(url, { method, body: JSON.stringify(payload) });

    if (res.ok) {
      showToast(`Rule ${id ? 'updated' : 'created'} successfully`);
      closeRuleModal();
      loadRules();
    } else {
      const err = await res.json();
      showToast(err.error || 'Failed to save rule', '⚠️');
    }
  } catch {
    showToast('Failed to contact server', '⚠️');
  }
}

async function toggleRule(id) {
  try {
    const res = await apiFetch(`/api/rules/${id}/toggle`, { method: 'PATCH' });
    if (res.ok) {
      loadRules();
    }
  } catch {}
}

async function deleteRule(id) {
  if (!confirm('Are you sure you want to delete this policy rule?')) return;
  try {
    const res = await apiFetch(`/api/rules/${id}`, { method: 'DELETE' });
    if (res.ok) {
      showToast('Rule removed');
      loadRules();
    }
  } catch {}
}

// -------------------------------------------------------------
// 6. SECURITY ALERTS
// -------------------------------------------------------------
async function loadAlerts() {
  const tbody = document.getElementById('alertsTableBody');
  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:20px;">Loading alerts...</td></tr>';

  const status = document.getElementById('filterAlertStatus').value;
  const severity = document.getElementById('filterAlertSeverity').value;
  const params = new URLSearchParams();
  if (status && status !== 'ALL') params.append('status', status);
  if (severity && severity !== 'ALL') params.append('severity', severity);

  try {
    const res = await fetch(`/api/alerts?${params.toString()}`);
    const data = await res.json();
    const alerts = data.alerts || [];

    if (alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:20px;">No alerts available</td></tr>';
      return;
    }

    tbody.innerHTML = alerts.map(a => `
      <tr>
        <td>${getAlertStatusBadge(a.status)}</td>
        <td style="white-space:nowrap;">${new Date(a.timestamp).toLocaleString()}</td>
        <td><strong>${escapeHtml(a.system_name || a.client_id)}</strong></td>
        <td><code style="color:#f87171;">${escapeHtml(a.domain)}</code></td>
        <td>${getThreatBadge(a.severity)}</td>
        <td style="font-size:0.75rem;">${escapeHtml(a.alert_type)}</td>
        <td style="font-size:0.78rem;">${escapeHtml(a.reason)}</td>
        <td>
          <div style="display:flex; gap:6px;">
            ${a.status !== 'RESOLVED' ? `<button class="btn-header" onclick="updateAlertStatus('${a.id}', 'RESOLVED')">Resolve</button>` : ''}
            ${a.status === 'NEW' ? `<button class="btn-header" onclick="updateAlertStatus('${a.id}', 'ACKNOWLEDGED')">Ack</button>` : ''}
          </div>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:#ef4444;">Failed to load alerts.</td></tr>';
  }
}

async function updateAlertStatus(id, newStatus) {
  try {
    const res = await apiFetch(`/api/alerts/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ status: newStatus })
    });
    if (res.ok) {
      showToast(`Alert set to ${newStatus}`);
      loadAlerts();
      loadOverviewStats();
    }
  } catch {}
}

// -------------------------------------------------------------
// 7. REPORTS & ANALYTICS
// -------------------------------------------------------------
let currentReportData = null;

async function loadReports() {
  const scopeSingleRadio = document.getElementById('scopeSingleRadio');
  const singlePickerContainer = document.getElementById('singleSystemPickerContainer');
  const singleSelect = document.getElementById('reportSingleSystemSelect');
  const timeSelect = document.getElementById('reportTimeRange');

  const isSingle = scopeSingleRadio && scopeSingleRadio.checked;
  if (singlePickerContainer) {
    singlePickerContainer.style.display = isSingle ? 'block' : 'none';
  }

  // Populate single systems dropdown if empty
  if (singleSelect && singleSelect.options.length <= 1) {
    try {
      const cRes = await fetch('/api/clients');
      const cData = await cRes.json();
      const clients = cData.clients || [];
      clients.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.client_id;
        opt.textContent = `${c.system_name || c.client_id} (${c.client_id}) - ${c.status}`;
        singleSelect.appendChild(opt);
      });
    } catch {}
  }

  let scope = 'ALL';
  if (isSingle) {
    scope = singleSelect && singleSelect.value ? singleSelect.value : '';
    if (!scope && singleSelect && singleSelect.options.length > 1) {
      scope = singleSelect.options[1].value;
      singleSelect.value = scope;
    }
  }

  const timeRange = timeSelect ? timeSelect.value : 'ALL';

  const tbodyEvents = document.getElementById('reportDetailedEventsTbody');
  const tbodyPerSystem = document.getElementById('reportPerSystemTbody');

  if (tbodyEvents) {
    tbodyEvents.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--text-muted);">Fetching real telemetry from database...</td></tr>';
  }

  try {
    const res = await fetch(`/api/reports/detailed?scope=${encodeURIComponent(scope || 'ALL')}&timeRange=${encodeURIComponent(timeRange)}`);
    const data = await res.json();
    currentReportData = data;

    // Header & metadata
    const genTimeEl = document.getElementById('reportGeneratedTime');
    if (genTimeEl) genTimeEl.textContent = new Date(data.generatedAt || Date.now()).toLocaleString();

    const scopeLabel = document.getElementById('reportScopeLabel');
    if (scopeLabel) {
      scopeLabel.textContent = isSingle ? (data.scope?.name || 'Single System') : 'All Systems (Enterprise Fleet)';
    }

    const metaCard = document.getElementById('reportSystemMetaCard');
    if (metaCard) {
      if (data.scope?.type === 'SINGLE') {
        metaCard.style.display = 'block';
        const sn = document.getElementById('repMetaSysName');
        const cid = document.getElementById('repMetaClientId');
        const hn = document.getElementById('repMetaHostname');
        const os = document.getElementById('repMetaOS');
        const ip = document.getElementById('repMetaIP');
        const st = document.getElementById('repMetaStatus');
        if (sn) sn.textContent = data.scope.name || '—';
        if (cid) cid.textContent = data.scope.clientId || '—';
        if (hn) hn.textContent = data.scope.hostname || '—';
        if (os) os.textContent = data.scope.os || '—';
        if (ip) ip.textContent = data.scope.ip || '—';
        if (st) {
          st.textContent = data.scope.status || 'OFFLINE';
          st.className = `badge-pill ${data.scope.status === 'ONLINE' ? 'badge-allow' : 'badge-block'}`;
        }
      } else {
        metaCard.style.display = 'none';
      }
    }

    // Totals
    const t = data.totals || {};
    const totEl = document.getElementById('repTotalEvents');
    const alwEl = document.getElementById('repAllowedEvents');
    const blkEl = document.getElementById('repBlockedEvents');
    const wrnEl = document.getElementById('repWarningEvents');
    if (totEl) totEl.textContent = t.total_events || 0;
    if (alwEl) alwEl.textContent = t.allowed_events || 0;
    if (blkEl) blkEl.textContent = t.blocked_events || 0;
    if (wrnEl) wrnEl.textContent = t.warning_events || 0;

    // 2. Summary Counts Per System Table
    if (tbodyPerSystem) {
      const byClient = data.byClient || [];
      if (byClient.length > 0) {
        tbodyPerSystem.innerHTML = byClient.map(c => `
          <tr>
            <td>
              <strong>${escapeHtml(c.system_name || c.client_id)}</strong>
              <br><span style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">${escapeHtml(c.client_id)}</span>
            </td>
            <td style="color:#10b981; font-weight:700;">${c.safe_count || 0} Safe</td>
            <td style="color:#f59e0b; font-weight:700;">${c.suspicious_count || 0} Suspicious</td>
            <td style="color:#ef4444; font-weight:700;">${c.phishing_count || 0} Phishing</td>
            <td><strong>${c.total || 0}</strong></td>
          </tr>
        `).join('');
      } else if (data.scope?.type === 'SINGLE') {
        tbodyPerSystem.innerHTML = `
          <tr>
            <td><strong>${escapeHtml(data.scope.name || data.scope.clientId)}</strong></td>
            <td style="color:#10b981; font-weight:700;">${t.allowed_events || 0} Safe</td>
            <td style="color:#f59e0b; font-weight:700;">${t.warning_events || 0} Suspicious</td>
            <td style="color:#ef4444; font-weight:700;">${t.blocked_events || 0} Phishing</td>
            <td><strong>${t.total_events || 0}</strong></td>
          </tr>
        `;
      } else {
        tbodyPerSystem.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:16px; color:var(--text-muted);">No endpoint telemetry recorded yet.</td></tr>';
      }
    }

    // 3. Detailed events audit trail table
    if (tbodyEvents) {
      const events = data.events || [];
      if (events.length === 0) {
        tbodyEvents.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-muted);">No navigation or threat records match this filter criteria.</td></tr>';
      } else {
        tbodyEvents.innerHTML = events.map(e => {
          let classificationBadge = '<span class="badge-pill badge-allow">SAFE</span>';
          if (e.decision === 'BLOCK') {
            classificationBadge = '<span class="badge-pill badge-block">PHISHING</span>';
          } else if (e.decision === 'WARNING') {
            classificationBadge = '<span class="badge-pill badge-warning">SUSPICIOUS</span>';
          }

          return `
            <tr>
              <td style="white-space:nowrap; font-size:0.8rem;">${new Date(e.timestamp).toLocaleString()}</td>
              <td><strong>${escapeHtml(e.system_name || e.client_id || 'Client')}</strong></td>
              <td><code style="color:#38bdf8;">${escapeHtml(e.domain)}</code></td>
              <td style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(e.url)}">
                <span style="font-size:0.8rem; color:#cbd5e1;">${escapeHtml(e.url)}</span>
              </td>
              <td>${classificationBadge}</td>
              <td>${getThreatBadge(e.threat_level)}</td>
              <td style="font-size:0.78rem; color:var(--text-muted);">${escapeHtml(e.reason || e.rule_name || 'Standard evaluation')}</td>
            </tr>
          `;
        }).join('');
      }
    }
  } catch (err) {
    console.error('Failed to load detailed report:', err);
    if (tbodyEvents) {
      tbodyEvents.innerHTML = '<tr><td colspan="7" style="text-align:center; color:#ef4444; padding:20px;">Failed to load report from server database.</td></tr>';
    }
  }
}

function downloadReportPdf() {
  if (!currentReportData) {
    showToast('Report data is still loading...', '⚠️');
    return;
  }

  const { jsPDF } = window.jspdf || {};
  if (!jsPDF) {
    window.print();
    return;
  }

  try {
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

    // Header Banner
    doc.setFillColor(15, 23, 42); // slate-900
    doc.rect(0, 0, 210, 32, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.text('PhishGuard Enterprise Threat Assessment Report', 14, 14);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.5);
    doc.setTextColor(148, 163, 184); // slate-400
    doc.text('Endpoint Telemetry, Policy Enforcements & Threat Audit', 14, 22);

    // Metadata Box
    doc.setFontSize(9);
    doc.setTextColor(51, 65, 85);
    const genDate = new Date(currentReportData.generatedAt || Date.now()).toLocaleString();
    const scopeName = currentReportData.scope?.name || 'All Systems';

    doc.text(`Generated: ${genDate}`, 14, 38);
    doc.text(`Report Scope: ${scopeName}`, 14, 44);

    if (currentReportData.scope?.type === 'SINGLE') {
      const s = currentReportData.scope;
      doc.text(`Client ID: ${s.clientId}  |  IP: ${s.ip}  |  OS: ${s.os}  |  Status: ${s.status}`, 14, 50);
    }

    // Summary Metrics Box
    const t = currentReportData.totals || {};
    const startY = currentReportData.scope?.type === 'SINGLE' ? 55 : 49;

    doc.setFillColor(241, 245, 249);
    doc.roundedRect(14, startY, 182, 17, 2, 2, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(15, 23, 42);
    doc.text(`Total Scanned: ${t.total_events || 0}`, 20, startY + 7);
    doc.setTextColor(16, 185, 129);
    doc.text(`Safe / Allowed: ${t.allowed_events || 0}`, 65, startY + 7);
    doc.setTextColor(239, 68, 68);
    doc.text(`Phishing Intercepted: ${t.blocked_events || 0}`, 115, startY + 7);
    doc.setTextColor(245, 158, 11);
    doc.text(`Suspicious Warnings: ${t.warning_events || 0}`, 160, startY + 7);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text('Verified Endpoint Security Audit Telemetry', 20, startY + 13);

    let nextY = startY + 22;

    // Summary Counts Per System Table (if present)
    if (currentReportData.byClient && currentReportData.byClient.length > 0 && doc.autoTable) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text('Summary Counts Per System / Endpoint:', 14, nextY + 3);

      const clientRows = currentReportData.byClient.map(c => [
        c.system_name || c.client_id || 'Endpoint',
        `${c.safe_count || 0} Safe`,
        `${c.suspicious_count || 0} Suspicious`,
        `${c.phishing_count || 0} Phishing`,
        String(c.total || 0)
      ]);

      doc.autoTable({
        startY: nextY + 5,
        head: [['System / Endpoint', 'Safe Count', 'Suspicious Count', 'Phishing Count', 'Total Monitored']],
        body: clientRows,
        theme: 'striped',
        headStyles: {
          fillColor: [51, 65, 85],
          textColor: [255, 255, 255],
          fontSize: 8,
          fontStyle: 'bold'
        },
        styles: {
          fontSize: 7.5,
          cellPadding: 2,
          textColor: [30, 41, 59]
        }
      });

      nextY = doc.lastAutoTable ? doc.lastAutoTable.finalY + 8 : nextY + 30;
    }

    // Monitored URL Events Audit Trail Table
    const tableData = (currentReportData.events || []).map(e => [
      new Date(e.timestamp).toLocaleTimeString(),
      e.system_name || e.client_id || '—',
      e.domain || '—',
      e.decision === 'BLOCK' ? 'PHISHING' : (e.decision === 'WARNING' ? 'SUSPICIOUS' : 'SAFE'),
      e.threat_level || 'SAFE',
      e.reason ? (e.reason.length > 55 ? e.reason.substring(0, 52) + '...' : e.reason) : 'Standard evaluation'
    ]);

    if (doc.autoTable) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text('Monitored Navigation & Classification Audit Trail:', 14, nextY + 3);

      doc.autoTable({
        startY: nextY + 5,
        head: [['Time', 'System', 'Domain', 'Classification', 'Threat', 'Detection / Policy Reason']],
        body: tableData.length > 0 ? tableData : [['—', 'No events', 'No events logged for this filter', '—', '—', '—']],
        theme: 'grid',
        headStyles: {
          fillColor: [30, 41, 59],
          textColor: [255, 255, 255],
          fontSize: 8,
          fontStyle: 'bold'
        },
        styles: {
          fontSize: 7.5,
          cellPadding: 2.2,
          textColor: [30, 41, 59]
        },
        columnStyles: {
          0: { cellWidth: 20 },
          1: { cellWidth: 30 },
          2: { cellWidth: 38 },
          3: { cellWidth: 22 },
          4: { cellWidth: 18 },
          5: { cellWidth: 54 }
        },
        didParseCell: (hookData) => {
          if (hookData.section === 'body' && hookData.column.index === 3) {
            const val = hookData.cell.raw;
            if (val === 'PHISHING') hookData.cell.styles.textColor = [220, 38, 38];
            else if (val === 'SUSPICIOUS') hookData.cell.styles.textColor = [217, 119, 6];
            else if (val === 'SAFE') hookData.cell.styles.textColor = [16, 185, 129];
          }
        }
      });
    }

    const safeScope = (currentReportData.scope?.name || 'All').replace(/[^a-zA-Z0-9_-]/g, '_');
    doc.save(`PhishGuard-Report-${safeScope}-${Date.now()}.pdf`);
    showToast('PDF report downloaded successfully');
  } catch (err) {
    console.error('PDF export error:', err);
    window.print();
  }
}

// -------------------------------------------------------------
// 10. INSTALL & ENROLL EXTENSION
// -------------------------------------------------------------
function loadInstallTab() {
  const targetInput = document.getElementById('targetServerUrlInput');
  if (targetInput && !targetInput.value) {
    targetInput.value = window.location.origin;
  }
  loadEnrollmentTokens();
  loadPackageInfo();
}

function downloadExtensionZip() {
  const targetInput = document.getElementById('targetServerUrlInput');
  const serverUrl = (targetInput && targetInput.value.trim()) ? targetInput.value.trim() : window.location.origin;
  const downloadUrl = `/api/extension/download?serverUrl=${encodeURIComponent(serverUrl)}`;
  showToast('Packaging FortiNex Extension archive...', '📦');
  window.location.href = downloadUrl;
}

async function loadEnrollmentTokens() {
  const tbody = document.getElementById('tokensTableBody');
  if (!tbody) return;
  try {
    const res = await apiFetch('/api/clients/tokens');
    if (!res.ok) throw new Error('Failed to fetch tokens');
    const data = await res.json();
    const tokens = data.tokens || [];

    if (tokens.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:15px; color:var(--text-muted);">No tokens found. Click "+ Generate Token" to create one.</td></tr>';
      return;
    }

    // Set recommended active token in display
    const activeToken = tokens.find(t => t.status === 'ACTIVE');
    if (activeToken) {
      const activeDisplay = document.getElementById('activeTokenDisplay');
      if (activeDisplay) activeDisplay.value = activeToken.token;
    }

    tbody.innerHTML = tokens.map(t => {
      const statusBadge = t.status === 'ACTIVE' 
        ? '<span class="badge-pill badge-allow">ACTIVE</span>'
        : (t.status === 'REVOKED' ? '<span class="badge-pill badge-block">REVOKED</span>' : '<span class="badge-pill badge-warning">' + escapeHtml(t.status) + '</span>');
      
      const expiresFormatted = t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'Never';
      const isRevokable = t.status === 'ACTIVE';

      return `<tr>
        <td style="font-family:monospace; font-weight:700; color:#38bdf8;">
          ${escapeHtml(t.token)}
          <button class="btn-header" style="padding:2px 6px; font-size:0.7rem; margin-left:6px;" onclick="copyToClipboard('${escapeHtml(t.token)}')">📋</button>
        </td>
        <td>${statusBadge}</td>
        <td>${t.uses_count || 0} / ${t.max_uses ? t.max_uses : '∞'}</td>
        <td style="font-size:0.75rem; color:var(--text-muted);">${expiresFormatted}</td>
        <td>
          ${isRevokable ? `<button class="btn-action" style="color:#ef4444;" onclick="revokeToken('${escapeHtml(t.token)}')">Revoke</button>` : '<span style="color:var(--text-dim); font-size:0.75rem;">None</span>'}
        </td>
      </tr>`;
    }).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#ef4444; padding:15px;">Failed to load tokens.</td></tr>';
  }
}

async function loadPackageInfo() {
  try {
    const res = await fetch('/api/extension/info');
    if (res.ok) {
      const data = await res.json();
      const badge = document.getElementById('extVersionBadge');
      if (badge && data.version) badge.textContent = `v${data.version}`;
      
      const fileList = document.getElementById('packageFilesList');
      if (fileList && Array.isArray(data.files)) {
        fileList.innerHTML = data.files.map(f => 
          `<div style="padding:6px 10px; background:var(--bg-input); border-radius:4px; border:1px solid var(--border); display:flex; justify-content:space-between; align-items:center;">
            <span>${escapeHtml(f.name)}</span>
            <span style="color:var(--text-dim); font-size:0.72rem;">${(f.size / 1024).toFixed(1)} KB</span>
          </div>`
        ).join('');
      }
    }
  } catch {}
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(`Copied: ${text}`, '📋');
    }).catch(() => {
      fallbackCopyText(text);
    });
  } else {
    fallbackCopyText(text);
  }
}

function fallbackCopyText(text) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.opacity = '0';
  document.body.appendChild(textArea);
  textArea.select();
  try {
    document.execCommand('copy');
    showToast(`Copied: ${text}`, '📋');
  } catch {
    showToast('Copy not supported by browser', '⚠️');
  }
  document.body.removeChild(textArea);
}

function openTokenModal() {
  document.getElementById('tokenModal').classList.add('open');
}

function closeTokenModal() {
  document.getElementById('tokenModal').classList.remove('open');
  document.getElementById('tokenForm').reset();
}

async function saveTokenForm(e) {
  e.preventDefault();
  const description = document.getElementById('tokenDescription').value.trim();
  const max_uses = parseInt(document.getElementById('tokenMaxUses').value) || 25;
  const expires_days = parseInt(document.getElementById('tokenExpiresDays').value) || 30;

  try {
    const res = await apiFetch('/api/clients/tokens/generate', {
      method: 'POST',
      body: JSON.stringify({ description, max_uses, expires_days })
    });
    if (res.ok) {
      const data = await res.json();
      closeTokenModal();
      showToast(`Token generated: ${data.token.token}`, '🔑');
      loadEnrollmentTokens();
    } else {
      showToast('Failed to generate token', '⚠️');
    }
  } catch {
    showToast('Error connecting to server', '⚠️');
  }
}

async function revokeToken(token) {
  if (!confirm(`Revoke enrollment token "${token}"? No further workstations will be able to enroll using it.`)) return;
  try {
    const res = await apiFetch(`/api/clients/tokens/${encodeURIComponent(token)}/revoke`, {
      method: 'POST'
    });
    if (res.ok) {
      showToast('Token revoked successfully', '🛑');
      loadEnrollmentTokens();
    } else {
      showToast('Failed to revoke token', '⚠️');
    }
  } catch {
    showToast('Error revoking token', '⚠️');
  }
}

// Check URL Modal handlers
function openCheckUrlModal() {
  document.getElementById('checkUrlModal').classList.add('open');
  document.getElementById('manualCheckOutput').style.display = 'none';
  document.getElementById('manualCheckUrlInput').focus();
}

function closeCheckUrlModal() {
  document.getElementById('checkUrlModal').classList.remove('open');
}

async function runManualCheckUrl(e) {
  e.preventDefault();
  const url = document.getElementById('manualCheckUrlInput').value.trim();
  if (!url) return;

  const outBox = document.getElementById('manualCheckOutput');
  const badge = document.getElementById('manualCheckDecisionBadge');
  const reasonEl = document.getElementById('manualCheckReason');
  const detailsEl = document.getElementById('manualCheckDetails');

  outBox.style.display = 'block';
  badge.innerHTML = '<span class="badge-pill badge-warning">Evaluating...</span>';
  reasonEl.textContent = 'Querying central decision engine...';

  try {
    const res = await fetch('/api/security/check-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, clientId: 'ADMIN-CONSOLE', systemName: 'Security Lead Console' })
    });
    const data = await res.json();
    badge.innerHTML = getDecisionBadge(data.decision);
    reasonEl.textContent = `Reason: ${data.reason}`;
    detailsEl.textContent = `Domain: ${data.domain} | Threat Level: ${data.threatLevel} | Matched Rule: ${data.ruleName || 'None'}`;
    loadOverviewStats();
  } catch (err) {
    badge.innerHTML = '<span class="badge-pill badge-block">ERROR</span>';
    reasonEl.textContent = err.message;
  }
}

// -------------------------------------------------------------
// Document Initialization & Event Listeners
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  // Navigation Tabs
  document.querySelectorAll('.nav-item').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      switchTab(link.dataset.tab);
    });
  });

  // Top Bar buttons
  const btnRefreshAll = document.getElementById('btnRefreshAll');
  if (btnRefreshAll) {
    btnRefreshAll.addEventListener('click', () => {
      const activeTab = document.querySelector('.nav-item.active')?.dataset.tab || 'overview';
      switchTab(activeTab);
      showToast('Dashboard refreshed');
    });
  }

  // Top bar Check URL modal button
  const btnTestModal = document.getElementById('btnTestUrlCheckModal');
  if (btnTestModal) {
    btnTestModal.addEventListener('click', openCheckUrlModal);
  }

  // Top bar Notification Bell
  const btnNotifBell = document.getElementById('btnNotificationBell');
  const notifDropdown = document.getElementById('notifBellDropdown');
  if (btnNotifBell && notifDropdown) {
    btnNotifBell.addEventListener('click', (e) => {
      e.stopPropagation();
      const isVisible = notifDropdown.style.display === 'flex';
      notifDropdown.style.display = isVisible ? 'none' : 'flex';
      if (!isVisible) {
        loadNotifDropdownList();
      }
    });

    document.addEventListener('click', (e) => {
      const container = document.getElementById('notifBellContainer');
      if (container && !container.contains(e.target)) {
        notifDropdown.style.display = 'none';
      }
    });
  }

  const btnNotifViewAll = document.getElementById('btnNotifViewAll');
  if (btnNotifViewAll) {
    btnNotifViewAll.addEventListener('click', () => {
      if (notifDropdown) notifDropdown.style.display = 'none';
      switchTab('alerts');
    });
  }

  // Top bar Download Extension button
  const btnDownloadTop = document.getElementById('btnDownloadExtTop');
  if (btnDownloadTop) {
    btnDownloadTop.addEventListener('click', () => {
      switchTab('install');
      downloadExtensionZip();
    });
  }

  // Install Tab buttons
  const btnDownloadMain = document.getElementById('btnDownloadExtMain');
  if (btnDownloadMain) {
    btnDownloadMain.addEventListener('click', downloadExtensionZip);
  }

  const btnCopyServer = document.getElementById('btnCopyServerUrl');
  if (btnCopyServer) {
    btnCopyServer.addEventListener('click', () => {
      const url = document.getElementById('targetServerUrlInput')?.value || window.location.origin;
      copyToClipboard(url);
    });
  }

  const btnCopyToken = document.getElementById('btnCopyActiveToken');
  if (btnCopyToken) {
    btnCopyToken.addEventListener('click', () => {
      const tok = document.getElementById('activeTokenDisplay')?.value || 'ENROLL-FORTINEX-2026';
      copyToClipboard(tok);
    });
  }

  const btnOpenToken = document.getElementById('btnOpenGenerateTokenModal');
  if (btnOpenToken) {
    btnOpenToken.addEventListener('click', openTokenModal);
  }

  const tokenForm = document.getElementById('tokenForm');
  if (tokenForm) {
    tokenForm.addEventListener('submit', saveTokenForm);
  }

  const btnPkgInfo = document.getElementById('btnRefreshPkgInfo');
  if (btnPkgInfo) {
    btnPkgInfo.addEventListener('click', loadPackageInfo);
  }

  const checkUrlForm = document.getElementById('checkUrlForm');
  if (checkUrlForm) {
    checkUrlForm.addEventListener('submit', runManualCheckUrl);
  }

  // Systems
  const btnRefreshSystems = document.getElementById('btnRefreshSystems');
  if (btnRefreshSystems) {
    btnRefreshSystems.addEventListener('click', loadSystems);
  }

  const filterSystemSearch = document.getElementById('filterSystemSearch');
  if (filterSystemSearch) {
    filterSystemSearch.addEventListener('input', () => {
      renderSystemsTable(allLoadedSystems);
    });
  }

  const filterSystemStatus = document.getElementById('filterSystemStatus');
  if (filterSystemStatus) {
    filterSystemStatus.addEventListener('change', () => {
      renderSystemsTable(allLoadedSystems);
    });
  }

  // URL History
  const btnApplyUrlFilters = document.getElementById('btnApplyUrlFilters');
  if (btnApplyUrlFilters) {
    btnApplyUrlFilters.addEventListener('click', () => loadUrlHistory(1));
  }

  const btnRefreshUrlHistory = document.getElementById('btnRefreshUrlHistory');
  if (btnRefreshUrlHistory) {
    btnRefreshUrlHistory.addEventListener('click', () => loadUrlHistory(currentUrlPage));
  }

  const btnUrlHistoryPrev = document.getElementById('btnUrlHistoryPrev');
  if (btnUrlHistoryPrev) {
    btnUrlHistoryPrev.addEventListener('click', () => {
      if (currentUrlPage > 1) loadUrlHistory(currentUrlPage - 1);
    });
  }

  const btnUrlHistoryNext = document.getElementById('btnUrlHistoryNext');
  if (btnUrlHistoryNext) {
    btnUrlHistoryNext.addEventListener('click', () => {
      loadUrlHistory(currentUrlPage + 1);
    });
  }

  const btnExportUrlHistoryCsv = document.getElementById('btnExportUrlHistoryCsv');
  if (btnExportUrlHistoryCsv) {
    btnExportUrlHistoryCsv.addEventListener('click', () => {
      window.location.href = '/api/reports/export-csv?type=url-events';
    });
  }

  // Alerts
  const btnRefreshAlerts = document.getElementById('btnRefreshAlerts');
  if (btnRefreshAlerts) {
    btnRefreshAlerts.addEventListener('click', loadAlerts);
  }

  const filterAlertStatus = document.getElementById('filterAlertStatus');
  if (filterAlertStatus) {
    filterAlertStatus.addEventListener('change', loadAlerts);
  }

  const filterAlertSeverity = document.getElementById('filterAlertSeverity');
  if (filterAlertSeverity) {
    filterAlertSeverity.addEventListener('change', loadAlerts);
  }

  const btnExportAlertsCsv = document.getElementById('btnExportAlertsCsv');
  if (btnExportAlertsCsv) {
    btnExportAlertsCsv.addEventListener('click', () => {
      window.location.href = '/api/reports/export-csv?type=alerts';
    });
  }

  // Reports Scope & Filters
  const scopeAllRadio = document.getElementById('scopeAllRadio');
  const scopeSingleRadio = document.getElementById('scopeSingleRadio');
  const reportSingleSystemSelect = document.getElementById('reportSingleSystemSelect');
  const reportTimeRange = document.getElementById('reportTimeRange');

  if (scopeAllRadio) {
    scopeAllRadio.addEventListener('change', loadReports);
  }
  if (scopeSingleRadio) {
    scopeSingleRadio.addEventListener('change', loadReports);
  }
  if (reportSingleSystemSelect) {
    reportSingleSystemSelect.addEventListener('change', loadReports);
  }
  if (reportTimeRange) {
    reportTimeRange.addEventListener('change', loadReports);
  }

  const btnRefreshReport = document.getElementById('btnRefreshReport');
  if (btnRefreshReport) {
    btnRefreshReport.addEventListener('click', loadReports);
  }

  const btnPrintReport = document.getElementById('btnPrintReport');
  if (btnPrintReport) {
    btnPrintReport.addEventListener('click', () => window.print());
  }

  const btnDownloadReportPdf = document.getElementById('btnDownloadReportPdf');
  if (btnDownloadReportPdf) {
    btnDownloadReportPdf.addEventListener('click', downloadReportPdf);
  }

  const btnDownloadReportCsv = document.getElementById('btnDownloadReportCsv');
  if (btnDownloadReportCsv) {
    btnDownloadReportCsv.addEventListener('click', () => {
      const isSingle = document.getElementById('scopeSingleRadio')?.checked;
      const scope = isSingle ? (document.getElementById('reportSingleSystemSelect')?.value || 'ALL') : 'ALL';
      const timeRange = document.getElementById('reportTimeRange')?.value || 'ALL';
      window.location.href = `/api/reports/export-csv?type=url-events&scope=${encodeURIComponent(scope)}&timeRange=${encodeURIComponent(timeRange)}`;
    });
  }

  // Rules: Quick Add Whitelist and Phishing
  const btnAddWhitelistBtn = document.getElementById('btnAddWhitelistBtn');
  if (btnAddWhitelistBtn) {
    btnAddWhitelistBtn.addEventListener('click', addQuickWhitelistRule);
  }
  const whitelistUrlInput = document.getElementById('whitelistUrlInput');
  if (whitelistUrlInput) {
    whitelistUrlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        addQuickWhitelistRule();
      }
    });
  }

  const btnAddPhishingBtn = document.getElementById('btnAddPhishingBtn');
  if (btnAddPhishingBtn) {
    btnAddPhishingBtn.addEventListener('click', addQuickPhishingRule);
  }
  const phishingUrlInput = document.getElementById('phishingUrlInput');
  if (phishingUrlInput) {
    phishingUrlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        addQuickPhishingRule();
      }
    });
  }

  const btnOpenNewRuleModal = document.getElementById('btnOpenNewRuleModal');
  if (btnOpenNewRuleModal) {
    btnOpenNewRuleModal.addEventListener('click', openNewRuleModal);
  }

  const ruleForm = document.getElementById('ruleForm');
  if (ruleForm) {
    ruleForm.addEventListener('submit', saveRuleForm);
  }

  // Admin Logout
  const btnAdminLogout = document.getElementById('btnAdminLogout');
  if (btnAdminLogout) {
    btnAdminLogout.addEventListener('click', async () => {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${currentAuthToken}` }
        });
      } catch {}
      localStorage.removeItem('phishguard_admin_token');
      currentAuthToken = '';
      currentUser = null;
      showToast('Logged out.');
      showLoginGate();
    });
  }

  // Login form
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', handleLoginSubmit);
  }

  // Initial Load - verifies any existing token, otherwise shows the login screen.
  // No credentials are ever auto-submitted.
  checkExistingSession();
});
