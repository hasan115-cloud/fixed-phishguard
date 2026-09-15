// PhishGuard Enterprise Background Service Worker (Manifest V3)
// Real URL monitoring, Multi-Mode Central Server enrollment, Heartbeat, and Interceptive Blocking

try {
  importScripts('config.js');
} catch {
  // Standalone or config.js already loaded
}

const DEFAULT_SERVER_URL = (typeof PHISHGUARD_CONFIG !== 'undefined' && PHISHGUARD_CONFIG.DEFAULT_SERVER_URL)
  ? PHISHGUARD_CONFIG.DEFAULT_SERVER_URL
  : 'http://localhost:3000';

const DEFAULT_TRUSTED = [
  'google.com', 'accounts.google.com', 'microsoft.com', 'apple.com',
  'amazon.com', 'github.com', 'paypal.com', 'chase.com'
];

let cachedServerUrl = DEFAULT_SERVER_URL;
let cachedServerMode = 'AUTO';
let cachedClientId = null;
let cachedSystemName = null;
let cachedEnrollmentToken = (typeof PHISHGUARD_CONFIG !== 'undefined' && PHISHGUARD_CONFIG.DEFAULT_ENROLLMENT_TOKEN) || 'ENROLL-FORTINEX-2026';
let isServerConnected = false;
let offlineEventQueue = [];
let localRulesCache = [];
const recentNavChecks = new Map(); // deduplication map: tabId:url -> { timestamp, decisionResult }

// Helper: Generate persistent Unique Client ID
function generateClientId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let rand = '';
  for (let i = 0; i < 6; i++) {
    rand += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `CLIENT-${rand}`;
}

// Helper: Fast Server Ping to test reachability and latency
async function pingServer(url, timeoutMs = 2500) {
  if (!url) return { ok: false, error: 'No URL provided' };
  const cleanUrl = url.replace(/\/+$/, '');
  const startTime = Date.now();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(`${cleanUrl}/api/security/ping`, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'X-Extension-Version': '1.4'
      }
    });
    clearTimeout(timeoutId);
    const latency = Date.now() - startTime;
    if (res.ok) {
      const data = await res.json().catch(() => ({ status: 'ok' }));
      return { ok: true, latency, data, url: cleanUrl };
    }
    return { ok: false, status: res.status, latency, url: cleanUrl };
  } catch (err) {
    return { ok: false, error: err.message, latency: Date.now() - startTime, url: cleanUrl };
  }
}

// Auto-discovery of reachable server URL across Localhost, LAN, and Remote modes
async function resolveWorkingServerUrl() {
  // 1. Try current cached URL first
  const currentPing = await pingServer(cachedServerUrl, 2000);
  if (currentPing.ok) {
    isServerConnected = true;
    return cachedServerUrl;
  }

  // If fixed custom mode (not AUTO), don't override
  if (cachedServerMode !== 'AUTO') {
    isServerConnected = false;
    return cachedServerUrl;
  }

  // 2. Try candidate endpoints from PHISHGUARD_CONFIG
  const candidates = [];
  if (typeof PHISHGUARD_CONFIG !== 'undefined') {
    if (PHISHGUARD_CONFIG.MODES) {
      if (PHISHGUARD_CONFIG.MODES.REMOTE) candidates.push(PHISHGUARD_CONFIG.MODES.REMOTE);
      if (PHISHGUARD_CONFIG.MODES.LAN) candidates.push(PHISHGUARD_CONFIG.MODES.LAN);
      if (PHISHGUARD_CONFIG.MODES.LOCALHOST) candidates.push(PHISHGUARD_CONFIG.MODES.LOCALHOST);
    }
    if (PHISHGUARD_CONFIG.DEFAULT_SERVER_URL && !candidates.includes(PHISHGUARD_CONFIG.DEFAULT_SERVER_URL)) {
      candidates.push(PHISHGUARD_CONFIG.DEFAULT_SERVER_URL);
    }
  }
  if (!candidates.includes('http://localhost:3000')) candidates.push('http://localhost:3000');

  for (const cand of candidates) {
    if (cand === cachedServerUrl) continue;
    const test = await pingServer(cand, 2000);
    if (test.ok) {
      console.log(`[PhishGuard] Auto-discovered reachable server: ${cand} (${test.latency}ms)`);
      cachedServerUrl = cand;
      isServerConnected = true;
      chrome.storage.local.set({ serverUrl: cand, serverConnected: true });
      return cand;
    }
  }

  isServerConnected = false;
  chrome.storage.local.set({ serverConnected: false });
  return cachedServerUrl;
}

// Initialize Client Configuration and Enrollment
async function initializeClient() {
  chrome.storage.local.get(
    ['clientId', 'systemName', 'serverUrl', 'serverMode', 'enrollmentToken', 'trustedDomains', 'soundEnabled', 'offlineQueue', 'cachedRules'],
    async (data) => {
      // 1. Client ID
      if (!data.clientId) {
        cachedClientId = generateClientId();
        chrome.storage.local.set({ clientId: cachedClientId });
      } else {
        cachedClientId = data.clientId;
      }

      // 2. Server URL & Mode
      cachedServerUrl = data.serverUrl || DEFAULT_SERVER_URL;
      cachedServerMode = data.serverMode || 'AUTO';

      // 3. System Name & Token
      cachedSystemName = data.systemName || cachedClientId;
      if (data.enrollmentToken) cachedEnrollmentToken = data.enrollmentToken;

      // 4. Default Trusted & Sound
      if (!data.trustedDomains) {
        chrome.storage.local.set({ trustedDomains: DEFAULT_TRUSTED });
      }
      if (data.soundEnabled === undefined) {
        chrome.storage.local.set({ soundEnabled: true });
      }
      if (data.offlineQueue) {
        offlineEventQueue = data.offlineQueue;
      }
      if (data.cachedRules) {
        localRulesCache = data.cachedRules;
      }

      console.log(`[PhishGuard] Initialized ${cachedClientId} -> Target Server: ${cachedServerUrl}`);

      // Probe & resolve server connection
      await resolveWorkingServerUrl();

      // Perform Central Server Enrollment
      await registerWithServer();

      // Sync latest rules
      await syncRulesFromServer();

      // Flush any queued offline events
      flushOfflineQueue();
    }
  );
}

// Sync Rules from Server
async function syncRulesFromServer() {
  try {
    const res = await fetch(`${cachedServerUrl}/api/rules`, {
      headers: {
        'X-Client-ID': cachedClientId || '',
        'X-System-Name': cachedSystemName || '',
        'X-Extension-Version': '1.4'
      }
    });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.rules)) {
        localRulesCache = data.rules;
        chrome.storage.local.set({ cachedRules: data.rules });
      }
    }
  } catch (err) {
    console.debug('[PhishGuard] Rules sync note:', err.message);
  }
}

// Enroll / Register with Central Server
async function registerWithServer() {
  if (!cachedClientId) return;
  try {
    let osName = 'Desktop';
    if (chrome.runtime.getPlatformInfo) {
      const info = await new Promise((resolve) => chrome.runtime.getPlatformInfo(resolve));
      osName = `${info.os} (${info.arch})`;
    }

    const storageData = await new Promise((resolve) =>
      chrome.storage.local.get(['serverUrl', 'enrollmentToken', 'systemName'], resolve)
    );
    if (storageData.serverUrl) cachedServerUrl = storageData.serverUrl;
    if (storageData.systemName) cachedSystemName = storageData.systemName;
    const token = storageData.enrollmentToken || cachedEnrollmentToken;

    const manifest = chrome.runtime.getManifest();
    const payload = {
      clientId: cachedClientId,
      systemName: cachedSystemName || cachedClientId,
      hostname: `${osName.toLowerCase().replace(/[^a-z0-9]/g, '-')}-workstation`,
      os: osName,
      browser: `Chrome ${navigator.userAgent.match(/Chrome\/([0-9.]+)/)?.[1] || 'V3'}`,
      extensionVersion: manifest.version || '1.4',
      enrollmentToken: token || undefined,
      metadata: {
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        installedAt: new Date().toISOString()
      }
    };

    const res = await fetch(`${cachedServerUrl}/api/clients/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-ID': cachedClientId,
        'X-System-Name': cachedSystemName || cachedClientId,
        'X-Enrollment-Token': token || '',
        'X-Extension-Version': manifest.version || '1.4'
      },
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      const data = await res.json();
      console.log('[PhishGuard] Successfully registered with Central Server:', data);
      isServerConnected = true;
      chrome.storage.local.set({ serverConnected: true, lastRegisterTime: Date.now() });
    } else {
      console.warn('[PhishGuard] Server registration returned HTTP:', res.status);
    }
  } catch (err) {
    console.warn('[PhishGuard] Central server registration deferred (offline or unreachable):', err.message);
    isServerConnected = false;
    chrome.storage.local.set({ serverConnected: false });
  }
}

// Listen for dynamic storage updates (e.g. user changes Server URL or Token in popup)
if (chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
      let shouldReRegister = false;
      if (changes.serverUrl) {
        cachedServerUrl = changes.serverUrl.newValue || DEFAULT_SERVER_URL;
        shouldReRegister = true;
      }
      if (changes.serverMode) {
        cachedServerMode = changes.serverMode.newValue || 'AUTO';
      }
      if (changes.systemName) {
        cachedSystemName = changes.systemName.newValue;
        shouldReRegister = true;
      }
      if (changes.enrollmentToken) {
        cachedEnrollmentToken = changes.enrollmentToken.newValue;
        shouldReRegister = true;
      }
      if (shouldReRegister) {
        registerWithServer();
      }
    }
  });
}

// Periodic Heartbeat to Central Server
async function sendHeartbeat() {
  if (!cachedClientId) return;

  try {
    const res = await fetch(`${cachedServerUrl}/api/clients/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-ID': cachedClientId,
        'X-System-Name': cachedSystemName || cachedClientId,
        'X-Extension-Version': '1.4'
      },
      body: JSON.stringify({
        clientId: cachedClientId,
        systemName: cachedSystemName || cachedClientId
      })
    });

    if (res.ok) {
      isServerConnected = true;
      chrome.storage.local.set({ serverConnected: true, lastHeartbeatTime: Date.now() });
    } else {
      isServerConnected = false;
      chrome.storage.local.set({ serverConnected: false });
    }
  } catch (err) {
    isServerConnected = false;
    chrome.storage.local.set({ serverConnected: false });
    console.debug('[PhishGuard] Heartbeat failed, server unreachable.');
  }
}

// Flush Offline Queued Events
async function flushOfflineQueue() {
  if (offlineEventQueue.length === 0) return;

  const queueCopy = [...offlineEventQueue];
  offlineEventQueue = [];
  chrome.storage.local.set({ offlineQueue: [] });

  for (const item of queueCopy) {
    try {
      await fetch(`${cachedServerUrl}/api/url-events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Client-ID': cachedClientId || '',
          'X-System-Name': cachedSystemName || ''
        },
        body: JSON.stringify(item)
      });
    } catch {
      // Re-queue if still failed
      offlineEventQueue.push(item);
    }
  }

  if (offlineEventQueue.length > 0) {
    chrome.storage.local.set({ offlineQueue: offlineEventQueue });
  }
}

// Fallback Heuristic Phishing Evaluator with Local Rules Cache
function evaluateUrlLocal(rawUrl, trustedList = []) {
  try {
    const u = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
    const host = u.hostname.toLowerCase();
    const pathname = u.pathname.toLowerCase();
    const search = u.search.toLowerCase();

    // Check cached rules first (allows offline enforcement of Whitelist/Phishing rules)
    if (localRulesCache && localRulesCache.length > 0) {
      for (const r of localRulesCache) {
        if (!r.enabled) continue;
        const rawPat = (r.pattern || '').toLowerCase().trim();
        const cleanPat = rawPat.replace(/^[a-z]+:\/\//i, '').replace(/\/+$/, '').split('/')[0].split(':')[0];
        let match = false;
        if (host === rawPat || host === cleanPat || host.endsWith('.' + cleanPat) || rawUrl.toLowerCase().includes(rawPat) || rawUrl.toLowerCase().includes(cleanPat)) {
          match = true;
        } else if (rawPat.includes('*')) {
          const escaped = rawPat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
          try {
            match = new RegExp(`^${escaped}$`, 'i').test(rawUrl) || new RegExp(`^${escaped}$`, 'i').test(host);
          } catch {}
        } else if (r.target_type === 'regex') {
          try {
            match = new RegExp(rawPat, 'i').test(rawUrl);
          } catch {}
        }

        if (match) {
          if (r.type === 'ALLOW') {
            return {
              url: rawUrl,
              domain: host,
              verdict: 'safe',
              score: 0,
              reasons: [`Whitelisted by administrative policy: ${r.pattern}`],
              ruleName: r.description || r.pattern
            };
          } else if (r.type === 'BLOCK') {
            return {
              url: rawUrl,
              domain: host,
              verdict: 'phishing',
              score: 99,
              reasons: [`Blocked by administrative policy: ${r.pattern}`],
              ruleName: r.description || r.pattern
            };
          } else if (r.type === 'WARNING') {
            return {
              url: rawUrl,
              domain: host,
              verdict: 'suspicious',
              score: 65,
              reasons: [`Flagged by administrative warning rule: ${r.pattern}`],
              ruleName: r.description || r.pattern
            };
          }
        }
      }
    }

    if (trustedList.some(d => host === d || host.endsWith('.' + d))) {
      return { url: rawUrl, domain: host, verdict: 'safe', score: 0, reasons: ['Whitelisted domain'] };
    }

    let score = 5;
    const reasons = [];

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      score += 50;
      reasons.push('Numerical IP address used as hostname');
    }

    if (rawUrl.includes('@')) {
      score += 40;
      reasons.push('URL contains deceptive "@" redirection');
    }

    const tld = host.split('.').pop();
    const highRiskTlds = ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'club', 'work'];
    if (highRiskTlds.includes(tld)) {
      score += 30;
      reasons.push(`High-risk top-level domain (.${tld})`);
    }

    const brands = ['paypal', 'apple', 'microsoft', 'google', 'netflix', 'amazon', 'chase', 'binance'];
    for (const b of brands) {
      if (host.includes(b) && !host.endsWith(`.${b}.com`) && host !== `${b}.com`) {
        score += 45;
        reasons.push(`Brand impersonation of ${b}`);
        break;
      }
    }

    const keywords = ['login', 'signin', 'verify', 'account', 'security', 'banking', 'wallet'];
    const matched = keywords.filter(k => host.includes(k) || pathname.includes(k) || search.includes(k));
    if (matched.length > 0) {
      score += matched.length * 12;
      reasons.push(`Sensitive authentication keywords detected (${matched.join(', ')})`);
    }

    const subCount = host.split('.').length - 2;
    if (subCount >= 3) {
      score += 20;
      reasons.push(`Excessive subdomain hierarchy (${subCount} levels)`);
    }

    score = Math.min(score, 99);
    const verdict = score >= 70 ? 'phishing' : score >= 35 ? 'suspicious' : 'safe';
    if (reasons.length === 0) reasons.push('Legitimate domain structure verified');

    return { url: rawUrl, domain: host, verdict, score, reasons };
  } catch {
    return { url: rawUrl, domain: 'unknown', verdict: 'safe', score: 0, reasons: ['Invalid or non-web URL'] };
  }
}

// -------------------------------------------------------------
// REAL URL MONITORING & INTERCEPTIVE BLOCKING
// Manifest V3 Navigation Interception via chrome.webNavigation
// -------------------------------------------------------------
async function handleUrlNavigation(tabId, rawUrl) {
  if (!rawUrl || !rawUrl.startsWith('http')) return;

  // Ignore internal/extension traffic
  if (rawUrl.includes('warning.html') || rawUrl.includes(cachedServerUrl)) return;

  // Deduplicate identical navigation checks within 3.5 seconds
  const dedupeKey = `${tabId}:${rawUrl}`;
  const now = Date.now();
  if (recentNavChecks.has(dedupeKey)) {
    const prev = recentNavChecks.get(dedupeKey);
    if (now - prev.timestamp < 3500) {
      if (prev.decisionResult && prev.decisionResult.decision === 'BLOCK') {
        const warningUrl = chrome.runtime.getURL(
          `warning.html?url=${encodeURIComponent(rawUrl)}&domain=${encodeURIComponent(prev.decisionResult.domain || '')}&verdict=phishing&score=${prev.decisionResult.heuristicScore || 95}&reason=${encodeURIComponent(prev.decisionResult.reason || '')}&rule=${encodeURIComponent(prev.decisionResult.ruleName || '')}&clientId=${encodeURIComponent(cachedClientId || '')}&allowBypass=0&sound=1`
        );
        chrome.tabs.update(tabId, { url: warningUrl });
      }
      return;
    }
  }

  // Prune cache if over 100 entries
  if (recentNavChecks.size > 100) {
    const expiredCutoff = now - 10000;
    for (const [k, v] of recentNavChecks.entries()) {
      if (v.timestamp < expiredCutoff) recentNavChecks.delete(k);
    }
  }

  try {
    // 1. Query Central Security Decision Engine
    let decisionResult = null;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2500); // 2.5s fast timeout

      const res = await fetch(`${cachedServerUrl}/api/security/check-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Client-ID': cachedClientId || '',
          'X-System-Name': cachedSystemName || '',
          'X-Extension-Version': '1.4'
        },
        body: JSON.stringify({
          url: rawUrl,
          clientId: cachedClientId,
          systemName: cachedSystemName,
          tabId
        }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        decisionResult = await res.json();
      }
    } catch (netErr) {
      console.debug('[PhishGuard] Central server check timed out or offline, evaluating locally:', netErr.message);
    }

    // 2. Fallback to local heuristic if server was unreachable
    if (!decisionResult) {
      const local = evaluateUrlLocal(rawUrl, DEFAULT_TRUSTED);
      decisionResult = {
        decision: local.verdict === 'phishing' ? 'BLOCK' : (local.verdict === 'suspicious' ? 'WARNING' : 'ALLOW'),
        threatLevel: local.verdict === 'phishing' ? 'HIGH' : (local.verdict === 'suspicious' ? 'MEDIUM' : 'SAFE'),
        reason: local.reasons.join('; '),
        ruleName: 'Local Heuristic Fallback',
        heuristicScore: local.score,
        url: rawUrl,
        domain: local.domain
      };

      // Queue event to report when server reconnects
      offlineEventQueue.push({
        url: rawUrl,
        clientId: cachedClientId,
        systemName: cachedSystemName,
        decision: decisionResult.decision,
        threatLevel: decisionResult.threatLevel,
        reason: decisionResult.reason
      });
      chrome.storage.local.set({ offlineQueue: offlineEventQueue });
    }

    // Cache this decision for deduplication
    recentNavChecks.set(dedupeKey, { timestamp: now, decisionResult });

    // 3. ACTUALLY BLOCK AND INTERRUPT NAVIGATION IF DECISION IS BLOCK
    if (decisionResult.decision === 'BLOCK') {
      console.warn(`[PhishGuard] 🛑 BLOCKING NAVIGATION: ${rawUrl} (Reason: ${decisionResult.reason})`);

      // Trigger 100% reliable alert sound via offscreen service
      triggerExtensionAlertSound('phishing');

      // Trigger system desktop notification
      try {
        if (chrome.notifications && chrome.notifications.create) {
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon.png',
            title: '🚨 PhishGuard: Phishing Attack Intercepted',
            message: `Threat: ${decisionResult.reason || 'Deceptive URL intercepted'}\nDestination: ${decisionResult.domain || rawUrl}`,
            priority: 2
          });
        }
      } catch {}

      const warningUrl = chrome.runtime.getURL(
        `warning.html?url=${encodeURIComponent(rawUrl)}&domain=${encodeURIComponent(decisionResult.domain || '')}&verdict=phishing&score=${decisionResult.heuristicScore || 95}&reason=${encodeURIComponent(decisionResult.reason || '')}&rule=${encodeURIComponent(decisionResult.ruleName || '')}&clientId=${encodeURIComponent(cachedClientId || '')}&allowBypass=0&sound=1`
      );

      chrome.tabs.update(tabId, { url: warningUrl });

      // Update badge
      if (chrome.action && chrome.action.setBadgeText) {
        chrome.action.setBadgeText({ text: '!', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#dc3545', tabId });
      }
    } else if (decisionResult.decision === 'WARNING') {
      // Trigger warning chime via offscreen service
      triggerExtensionAlertSound('suspicious');

      try {
        if (chrome.notifications && chrome.notifications.create) {
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon.png',
            title: '⚠️ PhishGuard: Suspicious Navigation Flagged',
            message: `Warning: ${decisionResult.reason || 'Suspicious risk profile detected'} on ${decisionResult.domain || rawUrl}`,
            priority: 1
          });
        }
      } catch {}

      if (chrome.action && chrome.action.setBadgeText) {
        chrome.action.setBadgeText({ text: '?', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId });
      }
    } else {
      if (chrome.action && chrome.action.setBadgeText) {
        chrome.action.setBadgeText({ text: '', tabId });
      }
    }
  } catch (err) {
    console.error('[PhishGuard] Navigation handler error:', err);
  }
}

// Listen to webNavigation (primary Manifest V3 navigation interceptor)
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Only intercept top-level frame navigation
    if (details.frameId === 0) {
      handleUrlNavigation(details.tabId, details.url);
    }
  });
}

// Fallback tab update listener
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('http')) {
    // Already handled by webNavigation if supported, or backup here
    if (!chrome.webNavigation) {
      handleUrlNavigation(tabId, tab.url);
    }
  }
});

// Alarms for periodic heartbeat, rules sync, and queue flushing
chrome.alarms.create('phishguard-heartbeat', { periodInMinutes: 0.5 }); // every 30 seconds
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'phishguard-heartbeat') {
    sendHeartbeat();
    syncRulesFromServer();
    flushOfflineQueue();
  }
});

// Fallback interval in case alarms are delayed
setInterval(() => {
  sendHeartbeat();
  syncRulesFromServer();
}, 30000);

// Setup on extension install and browser startup
chrome.runtime.onInstalled.addListener(() => {
  initializeClient();
});

chrome.runtime.onStartup.addListener(() => {
  initializeClient();
});

// Initialize right away
initializeClient();

// Tab statistics map
const tabStatsMap = new Map();

// Message dispatching for popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'CHECK_URL') {
    // First try Central Server API, fallback to local heuristic
    fetch(`${cachedServerUrl}/api/security/check-url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-ID': cachedClientId || '',
        'X-System-Name': cachedSystemName || '',
        'X-Extension-Version': '1.4'
      },
      body: JSON.stringify({
        url: request.url,
        clientId: cachedClientId,
        systemName: cachedSystemName
      })
    })
      .then(r => r.json())
      .then(data => sendResponse(data))
      .catch(() => {
        chrome.storage.local.get(['trustedDomains'], (st) => {
          const res = evaluateUrlLocal(request.url, st.trustedDomains || DEFAULT_TRUSTED);
          sendResponse(res);
        });
      });
    return true;
  }

  if (request.action === 'GET_CLIENT_INFO') {
    sendResponse({
      clientId: cachedClientId,
      systemName: cachedSystemName,
      serverUrl: cachedServerUrl,
      serverMode: cachedServerMode,
      isConnected: isServerConnected,
      enrollmentToken: cachedEnrollmentToken
    });
    return true;
  }

  if (request.action === 'TEST_CONNECTION') {
    const targetUrl = (request.serverUrl || cachedServerUrl).replace(/\/+$/, '');
    pingServer(targetUrl, 3000).then(result => {
      sendResponse(result);
    });
    return true;
  }

  if (request.action === 'SET_SERVER_URL' || request.action === 'UPDATE_CONFIG') {
    if (request.serverUrl) {
      cachedServerUrl = request.serverUrl.replace(/\/+$/, '');
    }
    if (request.serverMode) {
      cachedServerMode = request.serverMode;
    }
    if (request.systemName) {
      cachedSystemName = request.systemName;
    }
    if (request.enrollmentToken) {
      cachedEnrollmentToken = request.enrollmentToken;
    }

    chrome.storage.local.set({
      serverUrl: cachedServerUrl,
      serverMode: cachedServerMode,
      systemName: cachedSystemName,
      enrollmentToken: cachedEnrollmentToken
    }, async () => {
      const ping = await pingServer(cachedServerUrl, 3000);
      isServerConnected = ping.ok;
      if (ping.ok) {
        await registerWithServer();
        await syncRulesFromServer();
      }
      sendResponse({
        success: true,
        connected: isServerConnected,
        serverUrl: cachedServerUrl,
        serverMode: cachedServerMode,
        systemName: cachedSystemName,
        latency: ping.latency
      });
    });
    return true;
  }

  if (request.action === 'SYNC_RULES') {
    syncRulesFromServer().then(() => {
      sendResponse({ success: true, rulesCount: localRulesCache.length });
    });
    return true;
  }

  if (request.action === 'UPDATE_TAB_STATS') {
    if (sender.tab && sender.tab.id) {
      tabStatsMap.set(sender.tab.id, request.stats);
    }
    sendResponse({ ok: true });
    return true;
  }

  if (request.action === 'GET_TAB_STATS') {
    const stats = tabStatsMap.get(request.tabId) || { total: 0, phishing: 0, suspicious: 0, safe: 0 };
    sendResponse(stats);
    return true;
  }
});
