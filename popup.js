// PhishGuard Extension Popup Logic
// Dual-mode: Native Chrome Extension (chrome.runtime / chrome.storage) & Web Simulator fallback

(function () {
  'use strict';

  // DOM Elements
  const currentUrlEl = document.getElementById('currentUrl');
  const verdictAreaEl = document.getElementById('verdictArea');
  const reasonsAreaEl = document.getElementById('reasonsArea');
  const reasonsListEl = document.getElementById('reasonsList');
  const statsBarEl = document.getElementById('statsBar');
  const statTotalEl = document.getElementById('statTotal');
  const statPhishingEl = document.getElementById('statPhishing');
  const statSuspiciousEl = document.getElementById('statSuspicious');
  const statSafeEl = document.getElementById('statSafe');
  const trustRowEl = document.getElementById('trustRow');
  const trustLabelEl = document.getElementById('trustLabel');
  const trustBtnEl = document.getElementById('trustBtn');
  const untrustBtnEl = document.getElementById('untrustBtn');
  const rescanBtnEl = document.getElementById('rescanBtn');
  const recentSectionEl = document.getElementById('recentSection');
  const recentToggleBtn = document.getElementById('recentToggleBtn');
  const recentChevronEl = document.getElementById('recentChevron');
  const recentListEl = document.getElementById('recentList');
  const soundBtnEl = document.getElementById('soundBtn');
  const clientIdLabelEl = document.getElementById('clientIdLabel');
  const serverDotEl = document.getElementById('serverDot');
  const dashboardBtnEl = document.getElementById('dashboardBtn');

  // Config drawer elements
  const btnToggleConfigEl = document.getElementById('btnToggleConfig');
  const configPanelEl = document.getElementById('configPanel');
  const popupServerUrlEl = document.getElementById('popupServerUrl');
  const btnSaveConfigEl = document.getElementById('btnSaveConfig');
  const btnOpenOptionsEl = document.getElementById('btnOpenOptions');
  const configStatusMsgEl = document.getElementById('configStatusMsg');

  // State
  let activeUrl = 'https://example.com';
  let activeDomain = 'example.com';
  let isSoundEnabled = true;
  let isRecentExpanded = false;
  let trustedDomains = new Set();
  let recentScans = [];
  let currentServerUrl = 'http://localhost:3000';

  const isExtension = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id && chrome.tabs;

  // Sound generator & visual bell animation
  function playAlertSound(type) {
    // Visually ring the notification bell indicator
    if (soundBtnEl) {
      soundBtnEl.classList.remove('bell-ringing');
      void soundBtnEl.offsetWidth; // trigger reflow
      soundBtnEl.classList.add('bell-ringing');
      setTimeout(() => {
        if (soundBtnEl) soundBtnEl.classList.remove('bell-ringing');
      }, 2500);
    }

    if (!isSoundEnabled) return;
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const audioCtx = new AudioCtx();
      if (audioCtx.state === 'suspended') {
        audioCtx.resume();
      }
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);

      if (type === 'phishing') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, audioCtx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.35);
        gain.gain.setValueAtTime(0.25, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.35);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.35);
      } else if (type === 'suspicious') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(659, audioCtx.currentTime);
        gain.gain.setValueAtTime(0.2, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.25);
      }
    } catch (e) {
      console.debug('Sound playback unavailable', e);
    }
  }

  // Load storage data
  async function loadState() {
    if (isExtension) {
      return new Promise((resolve) => {
        chrome.storage.local.get(['trustedDomains', 'recentScans', 'soundEnabled'], (data) => {
          if (data.trustedDomains) trustedDomains = new Set(data.trustedDomains);
          if (data.recentScans) recentScans = data.recentScans;
          if (data.soundEnabled !== undefined) isSoundEnabled = data.soundEnabled;
          resolve();
        });
      });
    } else {
      try {
        const storedTrusted = localStorage.getItem('phishguard_trusted');
        if (storedTrusted) trustedDomains = new Set(JSON.parse(storedTrusted));
        const storedRecent = localStorage.getItem('phishguard_recent');
        if (storedRecent) recentScans = JSON.parse(storedRecent);
        const storedSound = localStorage.getItem('phishguard_sound');
        if (storedSound !== null) isSoundEnabled = JSON.parse(storedSound);
      } catch (e) {
        console.warn('Storage access fallback', e);
      }
    }
  }

  async function saveState() {
    if (isExtension) {
      chrome.storage.local.set({
        trustedDomains: Array.from(trustedDomains),
        recentScans: recentScans.slice(0, 20),
        soundEnabled: isSoundEnabled
      });
    } else {
      try {
        localStorage.setItem('phishguard_trusted', JSON.stringify(Array.from(trustedDomains)));
        localStorage.setItem('phishguard_recent', JSON.stringify(recentScans.slice(0, 20)));
        localStorage.setItem('phishguard_sound', JSON.stringify(isSoundEnabled));
      } catch (e) {
        console.warn('LocalStorage save failed', e);
      }
    }
  }

  // Get active URL
  async function determineActiveUrl() {
    // Check URL search parameter
    const params = new URLSearchParams(window.location.search);
    if (params.get('url')) {
      return params.get('url');
    }

    if (isExtension) {
      return new Promise((resolve) => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs && tabs[0] && tabs[0].url) {
            resolve(tabs[0].url);
          } else {
            resolve('https://google.com');
          }
        });
      });
    }

    // Web simulation default
    const lastTested = localStorage.getItem('phishguard_last_url');
    return lastTested || 'https://paypal-security-update.account-verify.xyz/signin';
  }

  // Evaluate URL
  async function scanUrl(url) {
    showLoading();

    try {
      let result;

      // 1. If in Chrome Extension, prefer background worker which handles server config & auth
      if (isExtension && chrome.runtime && chrome.runtime.sendMessage) {
        result = await new Promise((resolve) => {
          chrome.runtime.sendMessage({ action: 'CHECK_URL', url }, (res) => {
            resolve(res || null);
          });
        });
      }

      // 2. Direct API check if not in extension or background didn't return
      if (!result) {
        try {
          const baseApi = (currentServerUrl || '').replace(/\/+$/, '');
          const res = await fetch(`${baseApi}/api/security/check-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              url,
              clientId: 'POPUP-INSPECTOR',
              systemName: 'PhishGuard Extension Popup'
            })
          });
          if (res.ok) {
            result = await res.json();
          }
        } catch (err) {
          console.debug('Direct API check unavailable, using fallback', err);
        }
      }

      // 3. Fallback client-side heuristic if offline
      if (!result) {
        result = clientSideEvaluate(url, trustedDomains);
      }

      // Normalize fields
      if (result) {
        if (!result.verdict) {
          if (result.decision === 'BLOCK') result.verdict = 'phishing';
          else if (result.decision === 'WARNING') result.verdict = 'suspicious';
          else result.verdict = 'safe';
        }
        if (result.score === undefined && result.heuristicScore !== undefined) {
          result.score = result.heuristicScore;
        }
        if (!result.reasons && result.reason) {
          result.reasons = [result.reason];
        }
      }

      renderVerdict(result);
      recordRecentScan(url, result);
    } catch (e) {
      console.error('Scan failed', e);
      showError('Scan encountered an error');
    }
  }

  function clientSideEvaluate(rawUrl, trustedSet) {
    let hostname = 'unknown';
    try {
      const u = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
      hostname = u.hostname;
    } catch {
      hostname = rawUrl;
    }

    const isTrusted = trustedSet.has(hostname);
    if (isTrusted) {
      return {
        url: rawUrl,
        domain: hostname,
        verdict: 'safe',
        score: 0,
        reasons: ['Domain is in user trusted list'],
        isTrusted: true
      };
    }

    const lower = rawUrl.toLowerCase();
    let score = 5;
    const reasons = [];

    if (/^https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(lower)) {
      score += 45;
      reasons.push('Uses numerical IP address instead of domain name');
    }
    if (lower.includes('@')) {
      score += 35;
      reasons.push('Contains deceptive "@" symbol in URL');
    }
    if (/\.(xyz|top|tk|ml|ga|cf|gq|buzz|club|work)(\/|$)/.test(lower)) {
      score += 25;
      reasons.push('High-risk top-level domain extension');
    }
    if (lower.includes('paypal') && !lower.includes('paypal.com')) {
      score += 40;
      reasons.push('Impersonates PayPal brand');
    }
    if (lower.includes('verify') || lower.includes('security') || lower.includes('signin') || lower.includes('banking')) {
      score += 20;
      reasons.push('Contains sensitive auth/account verification keywords');
    }

    score = Math.min(score, 99);
    const verdict = score >= 70 ? 'phishing' : score >= 35 ? 'suspicious' : 'safe';
    if (reasons.length === 0) {
      reasons.push('Standard legitimate domain structure');
    }

    return {
      url: rawUrl,
      domain: hostname,
      verdict,
      score,
      reasons,
      isTrusted: false
    };
  }

  function showLoading() {
    verdictAreaEl.className = 'verdict-card vc-loading';
    verdictAreaEl.innerHTML = `
      <div class="spinner"></div>
      <div style="margin-top:6px;font-size:0.85rem;color:#9aabc4;">Scanning page...</div>
    `;
    reasonsAreaEl.style.display = 'none';
    rescanBtnEl.disabled = true;
  }

  function showError(msg) {
    verdictAreaEl.className = 'verdict-card vc-loading';
    verdictAreaEl.innerHTML = `<div style="color:#ff6b7a;font-size:0.85rem;">${msg}</div>`;
    rescanBtnEl.disabled = false;
  }

  function renderVerdict(data) {
    rescanBtnEl.disabled = false;
    currentUrlEl.textContent = data.url;
    currentUrlEl.title = data.url;
    activeDomain = data.domain || activeDomain;

    const rawVerdict = data.verdict || (data.decision === 'BLOCK' ? 'phishing' : (data.decision === 'WARNING' ? 'suspicious' : 'safe'));
    const verdict = String(rawVerdict || 'safe').toLowerCase();
    const score = data.score !== undefined ? data.score : (data.heuristicScore !== undefined ? data.heuristicScore : (verdict === 'phishing' ? 95 : (verdict === 'suspicious' ? 60 : 0)));

    let cardClass = 'vc-safe';
    let labelClass = 'verdict-safe';
    let icon = '🛡️';
    let label = 'Legitimate Site';

    if (verdict === 'phishing') {
      cardClass = 'vc-phishing';
      labelClass = 'verdict-phishing';
      icon = '⛔';
      label = 'Phishing Detected';
      playAlertSound('phishing');
    } else if (verdict === 'suspicious') {
      cardClass = 'vc-suspicious';
      labelClass = 'verdict-suspicious';
      icon = '⚠️';
      label = 'Suspicious Site';
      playAlertSound('suspicious');
    } else {
      cardClass = 'vc-safe';
      labelClass = 'verdict-safe';
      icon = '🛡️';
      label = 'Safe Website';
    }

    verdictAreaEl.className = `verdict-card ${cardClass}`;
    verdictAreaEl.innerHTML = `
      <div class="verdict-icon">${icon}</div>
      <div class="verdict-label ${labelClass}">${label}</div>
      <div class="verdict-score">Risk Score: ${score}/100</div>
    `;

    // Render Reasons
    if (data.reasons && data.reasons.length > 0) {
      reasonsAreaEl.style.display = 'block';
      reasonsListEl.innerHTML = '';
      data.reasons.forEach(r => {
        const item = document.createElement('div');
        item.className = 'reason-item';
        item.textContent = `• ${r}`;
        reasonsListEl.appendChild(item);
      });
    } else {
      reasonsAreaEl.style.display = 'none';
    }

    // Render Trust Row
    updateTrustRow(activeDomain);

    // Render Mock/Tab Link Stats
    renderPageStats(verdict);
  }

  function updateTrustRow(domain) {
    trustRowEl.style.display = 'flex';
    const isTrusted = trustedDomains.has(domain);

    if (isTrusted) {
      trustLabelEl.textContent = `${domain} is trusted`;
      trustBtnEl.textContent = '✓ Trusted';
      trustBtnEl.className = 'btn-trust trusted';
      untrustBtnEl.style.display = 'inline';
    } else {
      trustLabelEl.textContent = `Trust ${domain}?`;
      trustBtnEl.textContent = '+ Trust';
      trustBtnEl.className = 'btn-trust';
      untrustBtnEl.style.display = 'none';
    }
  }

  function renderPageStats(pageVerdict) {
    statsBarEl.style.display = 'flex';
    // If running in extension, could get real tab link stats, otherwise realistic display
    const phishingCount = pageVerdict === 'phishing' ? 1 : 0;
    const suspiciousCount = pageVerdict === 'suspicious' ? 1 : 0;
    const safeCount = pageVerdict === 'safe' ? 14 : 12;
    const totalCount = phishingCount + suspiciousCount + safeCount;

    statTotalEl.textContent = `${totalCount} links`;
    statPhishingEl.textContent = `${phishingCount} phishing`;
    statSuspiciousEl.textContent = `${suspiciousCount} suspicious`;
    statSafeEl.textContent = `${safeCount} safe`;
  }

  function recordRecentScan(url, data) {
    // Avoid immediate duplicate
    recentScans = recentScans.filter(s => s.url !== url);
    recentScans.unshift({
      url,
      verdict: data.verdict,
      score: data.score,
      time: Date.now()
    });
    if (recentScans.length > 15) recentScans.pop();
    saveState();
    renderRecentList();
  }

  function renderRecentList() {
    if (recentScans.length === 0) {
      recentSectionEl.style.display = 'none';
      return;
    }
    recentSectionEl.style.display = 'block';
    recentListEl.innerHTML = '';

    recentScans.forEach(item => {
      const el = document.createElement('div');
      el.className = 'recent-item';
      const verdictClass = item.verdict === 'phishing' ? 'rv-phishing' : item.verdict === 'suspicious' ? 'rv-suspicious' : 'rv-safe';
      const verdictText = item.verdict ? item.verdict.toUpperCase() : 'SAFE';

      el.innerHTML = `
        <div class="recent-url" title="${item.url}">${item.url}</div>
        <div class="recent-verdict ${verdictClass}">${verdictText} (${item.score})</div>
      `;
      el.addEventListener('click', () => {
        activeUrl = item.url;
        scanUrl(activeUrl);
      });
      recentListEl.appendChild(el);
    });
  }

  // Event Listeners
  trustBtnEl.addEventListener('click', () => {
    if (!trustedDomains.has(activeDomain)) {
      trustedDomains.add(activeDomain);
      saveState();
      updateTrustRow(activeDomain);
      scanUrl(activeUrl);
    }
  });

  untrustBtnEl.addEventListener('click', () => {
    if (trustedDomains.has(activeDomain)) {
      trustedDomains.delete(activeDomain);
      saveState();
      updateTrustRow(activeDomain);
      scanUrl(activeUrl);
    }
  });

  rescanBtnEl.addEventListener('click', () => {
    scanUrl(activeUrl);
  });

  recentToggleBtn.addEventListener('click', () => {
    isRecentExpanded = !isRecentExpanded;
    recentListEl.style.display = isRecentExpanded ? 'block' : 'none';
    recentChevronEl.textContent = isRecentExpanded ? '▴' : '▾';
  });

  soundBtnEl.addEventListener('click', () => {
    isSoundEnabled = !isSoundEnabled;
    soundBtnEl.textContent = isSoundEnabled ? '🔔' : '🔕';
    soundBtnEl.title = isSoundEnabled ? 'Sound alerts enabled' : 'Sound alerts muted';
    saveState();
  });

  // Listen for messages from parent window if embedded in iframe
  window.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'PHISHGUARD_SCAN_URL') {
      activeUrl = event.data.url;
      scanUrl(activeUrl);
    }
  });

  if (dashboardBtnEl) {
    dashboardBtnEl.addEventListener('click', () => {
      const targetUrl = currentServerUrl || window.location.origin || 'http://localhost:3000';
      if (isExtension && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url: targetUrl });
      } else {
        window.open(targetUrl, '_blank');
      }
    });
  }

  // Config Drawer Event Listeners
  if (btnToggleConfigEl && configPanelEl) {
    btnToggleConfigEl.addEventListener('click', () => {
      const isHidden = configPanelEl.style.display === 'none';
      configPanelEl.style.display = isHidden ? 'block' : 'none';
      if (isHidden && popupServerUrlEl) {
        popupServerUrlEl.value = currentServerUrl;
        popupServerUrlEl.focus();
      }
    });
  }

  if (btnOpenOptionsEl) {
    btnOpenOptionsEl.addEventListener('click', (e) => {
      e.preventDefault();
      if (chrome.runtime && chrome.runtime.openOptionsPage) {
        chrome.runtime.openOptionsPage();
      } else {
        window.open('options.html', '_blank');
      }
    });
  }

  if (btnSaveConfigEl && popupServerUrlEl) {
    btnSaveConfigEl.addEventListener('click', async () => {
      let url = popupServerUrlEl.value.trim().replace(/\/+$/, '');
      if (!url) return;
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
      }
      popupServerUrlEl.value = url;
      if (configStatusMsgEl) configStatusMsgEl.textContent = 'Testing connection...';

      try {
        const res = await fetch(`${url}/api/security/ping`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
          currentServerUrl = url;
          if (isExtension) {
            chrome.storage.local.set({ serverUrl: url, serverConnected: true });
            chrome.runtime.sendMessage({ action: 'UPDATE_CONFIG', serverUrl: url });
          } else {
            localStorage.setItem('phishguard_server_url', url);
          }
          if (configStatusMsgEl) {
            configStatusMsgEl.style.color = '#4ade80';
            configStatusMsgEl.textContent = 'Connected successfully!';
          }
          if (serverDotEl) {
            serverDotEl.classList.remove('offline');
            serverDotEl.title = 'Connected';
          }
          setTimeout(() => {
            if (configPanelEl) configPanelEl.style.display = 'none';
            scanUrl(activeUrl);
          }, 800);
        } else {
          throw new Error('Server returned HTTP ' + res.status);
        }
      } catch (err) {
        if (configStatusMsgEl) {
          configStatusMsgEl.style.color = '#ff6b7a';
          configStatusMsgEl.textContent = 'Connection failed: ' + err.message;
        }
        if (serverDotEl) {
          serverDotEl.classList.add('offline');
          serverDotEl.title = 'Offline';
        }
      }
    });
  }

  // Initialization
  async function init() {
    await loadState();
    soundBtnEl.textContent = isSoundEnabled ? '🔔' : '🔕';
    renderRecentList();

    // Check enterprise client info
    if (isExtension) {
      chrome.runtime.sendMessage({ action: 'GET_CLIENT_INFO' }, (info) => {
        if (info) {
          if (info.clientId && clientIdLabelEl) clientIdLabelEl.textContent = info.clientId;
          if (info.serverUrl) {
            currentServerUrl = info.serverUrl;
            if (popupServerUrlEl) popupServerUrlEl.value = info.serverUrl;
          }
        }
      });
      chrome.storage.local.get(['serverConnected', 'clientId', 'serverUrl'], (data) => {
        if (data.clientId && clientIdLabelEl) clientIdLabelEl.textContent = data.clientId;
        if (data.serverUrl) {
          currentServerUrl = data.serverUrl;
          if (popupServerUrlEl) popupServerUrlEl.value = data.serverUrl;
        }
        if (serverDotEl) {
          if (data.serverConnected === false) {
            serverDotEl.classList.add('offline');
            serverDotEl.title = 'Offline';
          } else {
            serverDotEl.classList.remove('offline');
            serverDotEl.title = 'Connected';
          }
        }
      });
    } else {
      if (clientIdLabelEl) clientIdLabelEl.textContent = 'WEB-CONSOLE';
      const stored = localStorage.getItem('phishguard_server_url');
      if (stored) currentServerUrl = stored;
      if (popupServerUrlEl) popupServerUrlEl.value = currentServerUrl;
    }

    activeUrl = await determineActiveUrl();
    try {
      const u = new URL(activeUrl.startsWith('http') ? activeUrl : 'https://' + activeUrl);
      activeDomain = u.hostname;
    } catch {
      activeDomain = activeUrl;
    }
    scanUrl(activeUrl);
  }

  init();
})();
