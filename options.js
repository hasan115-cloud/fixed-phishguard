// PhishGuard Extension - Options & Remote Connectivity Controller

document.addEventListener('DOMContentLoaded', async () => {
  const serverUrlInput = document.getElementById('serverUrlInput');
  const systemNameInput = document.getElementById('systemNameInput');
  const enrollmentTokenInput = document.getElementById('enrollmentTokenInput');
  const btnSave = document.getElementById('btnSave');
  const btnTest = document.getElementById('btnTest');
  const btnSyncRules = document.getElementById('btnSyncRules');
  const statusContainer = document.getElementById('statusContainer');

  const displayClientId = document.getElementById('displayClientId');
  const displayRulesCount = document.getElementById('displayRulesCount');
  const displayQueueCount = document.getElementById('displayQueueCount');
  const displayLastHeartbeat = document.getElementById('displayLastHeartbeat');

  // Load current values
  const data = await chrome.storage.local.get([
    'serverUrl',
    'clientId',
    'systemName',
    'enrollmentToken',
    'cachedRules',
    'offlineQueue',
    'lastHeartbeat'
  ]);

  const defaultUrl = (typeof PHISHGUARD_CONFIG !== 'undefined' && PHISHGUARD_CONFIG.DEFAULT_SERVER_URL)
    ? PHISHGUARD_CONFIG.DEFAULT_SERVER_URL
    : 'http://localhost:3000';

  serverUrlInput.value = data.serverUrl || defaultUrl;
  systemNameInput.value = data.systemName || '';
  enrollmentTokenInput.value = data.enrollmentToken || '';

  displayClientId.textContent = data.clientId || 'Not registered';
  displayRulesCount.textContent = (data.cachedRules && data.cachedRules.length) ? `${data.cachedRules.length} rules active` : '0 rules';
  displayQueueCount.textContent = `${(data.offlineQueue && data.offlineQueue.length) || 0} queued events`;
  displayLastHeartbeat.textContent = data.lastHeartbeat ? new Date(data.lastHeartbeat).toLocaleTimeString() : 'Pending';

  // Test Connection
  btnTest.addEventListener('click', async () => {
    let target = serverUrlInput.value.trim().replace(/\/+$/, '');
    if (!target) {
      statusContainer.innerHTML = '<div class="status-badge error">❌ Please enter a valid Server URL</div>';
      return;
    }
    if (!/^https?:\/\//i.test(target)) {
      target = 'http://' + target;
      serverUrlInput.value = target;
    }

    statusContainer.innerHTML = '<div class="status-badge testing">⏳ Testing reachability...</div>';
    const startTime = performance.now();

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(`${target}/api/health`, { signal: controller.signal });
      clearTimeout(timeoutId);
      const elapsed = Math.round(performance.now() - startTime);

      if (res.ok) {
        const json = await res.json();
        statusContainer.innerHTML = `<div class="status-badge connected">✅ Connected (${elapsed}ms) — Server Healthy (${json.service || 'PhishGuard Hub'})</div>`;
      } else {
        statusContainer.innerHTML = `<div class="status-badge error">⚠️ Server responded with HTTP status ${res.status}</div>`;
      }
    } catch (err) {
      statusContainer.innerHTML = `<div class="status-badge error">❌ Unreachable: ${err.message}. Check firewall or server address.</div>`;
    }
  });

  // Save Settings
  btnSave.addEventListener('click', async () => {
    let target = serverUrlInput.value.trim().replace(/\/+$/, '');
    if (!target) target = 'http://localhost:3000';
    if (!/^https?:\/\//i.test(target)) target = 'http://' + target;
    serverUrlInput.value = target;

    const sysName = systemNameInput.value.trim() || undefined;
    const token = enrollmentTokenInput.value.trim() || undefined;

    await chrome.storage.local.set({
      serverUrl: target,
      systemName: sysName,
      enrollmentToken: token
    });

    // Notify background worker
    try {
      chrome.runtime.sendMessage({
        action: 'UPDATE_CONFIG',
        serverUrl: target,
        systemName: sysName,
        enrollmentToken: token
      });
    } catch {}

    statusContainer.innerHTML = '<div class="status-badge connected">💾 Settings saved & applied to background worker!</div>';
    setTimeout(() => {
      // Auto-trigger test to refresh status
      btnTest.click();
    }, 500);
  });

  // Sync Rules Now
  btnSyncRules.addEventListener('click', async () => {
    const target = serverUrlInput.value.trim().replace(/\/+$/, '');
    statusContainer.innerHTML = '<div class="status-badge testing">⏳ Fetching security rules...</div>';

    try {
      const res = await fetch(`${target}/api/rules`);
      if (res.ok) {
        const data = await res.json();
        const rules = data.rules || [];
        await chrome.storage.local.set({ cachedRules: rules });
        displayRulesCount.textContent = `${rules.length} rules active`;
        statusContainer.innerHTML = `<div class="status-badge connected">✅ Synced ${rules.length} security rules from server!</div>`;
      } else {
        statusContainer.innerHTML = `<div class="status-badge error">Failed to fetch rules (HTTP ${res.status})</div>`;
      }
    } catch (err) {
      statusContainer.innerHTML = `<div class="status-badge error">Sync failed: ${err.message}</div>`;
    }
  });
});
