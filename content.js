// PhishGuard Content Script — In-Page Link Protection & Visual Indicators

(function () {
  'use strict';

  // Ensure toast container exists
  let toastContainer = document.querySelector('[data-phishguard="toasts"]');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.setAttribute('data-phishguard', 'toasts');
    document.body.appendChild(toastContainer);
  }

  function showToast(message, type = 'phishing') {
    const toast = document.createElement('div');
    toast.style.cssText = `
      background: ${type === 'phishing' ? '#dc3545' : '#f59e0b'};
      color: #fff;
      padding: 10px 14px;
      border-radius: 6px;
      font-size: 13px;
      font-family: 'Segoe UI', sans-serif;
      box-shadow: 0 4px 12px rgba(0,0,0,0.35);
      pointer-events: auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      animation: pg-badge-in 0.25s ease;
    `;
    toast.innerHTML = `
      <div><strong>PhishGuard:</strong> ${message}</div>
      <button style="background:none;border:none;color:#fff;font-weight:bold;cursor:pointer;font-size:14px;">✕</button>
    `;
    toast.querySelector('button').onclick = () => toast.remove();
    toastContainer.appendChild(toast);
    setTimeout(() => {
      if (toast.parentNode) toast.remove();
    }, 5000);
  }

  // Rapid lexical evaluation for in-page links
  function evaluateLink(href) {
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return null;

    try {
      const u = new URL(href, window.location.origin);
      const host = u.hostname.toLowerCase();
      const lower = href.toLowerCase();

      // Check for raw IP
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
        return { verdict: 'phishing', score: 92, reason: 'Raw numerical IP address' };
      }

      // Check for @ symbol
      if (href.includes('@')) {
        return { verdict: 'phishing', score: 85, reason: 'Obfuscated @ redirect' };
      }

      // Check for high risk TLD
      if (/\.(xyz|top|tk|ml|ga|cf|gq|buzz|club|work|bid|trade)(\/|$)/.test(lower)) {
        if (lower.includes('login') || lower.includes('verify') || lower.includes('bank') || lower.includes('security')) {
          return { verdict: 'phishing', score: 88, reason: 'Suspicious TLD with auth keywords' };
        }
        return { verdict: 'suspicious', score: 55, reason: 'High-risk TLD' };
      }

      // Brand impersonation
      if ((lower.includes('paypal') || lower.includes('appleid') || lower.includes('netflix') || lower.includes('wellsfargo')) &&
          !host.endsWith('.paypal.com') && !host.endsWith('.apple.com') && !host.endsWith('.netflix.com') && !host.endsWith('.wellsfargo.com')) {
        return { verdict: 'phishing', score: 90, reason: 'Brand impersonation in domain' };
      }

      // Sensitive keywords on HTTP
      if (u.protocol === 'http:' && (lower.includes('login') || lower.includes('verify') || lower.includes('password'))) {
        return { verdict: 'suspicious', score: 60, reason: 'Insecure login form over HTTP' };
      }

      return { verdict: 'safe', score: 10 };
    } catch {
      return null;
    }
  }

  // Scan all links in DOM
  function scanPageLinks() {
    const links = document.querySelectorAll('a[href]');
    let stats = { total: links.length, phishing: 0, suspicious: 0, safe: 0 };

    links.forEach(link => {
      if (link.dataset.phishguardChecked) return;
      link.dataset.phishguardChecked = 'true';

      const href = link.getAttribute('href');
      const evalResult = evaluateLink(href);
      if (!evalResult) return;

      if (evalResult.verdict === 'phishing') {
        stats.phishing++;
        link.classList.add('phishguard-phishing');
        link.setAttribute('title', `Blocked by PhishGuard: Phishing threat detected (${evalResult.reason})`);

        link.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();

          // Add inline blocked badge
          let badge = link.nextElementSibling;
          if (!badge || !badge.hasAttribute('data-phishguard-badge')) {
            badge = document.createElement('span');
            badge.setAttribute('data-phishguard-badge', '');
            badge.textContent = '⛔ Blocked by PhishGuard';
            link.parentNode.insertBefore(badge, link.nextSibling);
          }

          showToast(`Navigation blocked! Dangerous destination: ${evalResult.reason}`, 'phishing');
        });
      } else if (evalResult.verdict === 'suspicious') {
        stats.suspicious++;
        link.classList.add('phishguard-suspicious');
        link.setAttribute('title', `PhishGuard Warning: Suspicious link (${evalResult.reason})`);

        link.addEventListener('click', (e) => {
          showToast(`Caution: Navigating to suspicious link: ${link.href}`, 'suspicious');
        });
      } else {
        stats.safe++;
      }
    });

    // Notify background script if running in extension
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
      chrome.runtime.sendMessage({
        action: 'UPDATE_TAB_STATS',
        stats
      });
    }
  }

  // Run on load and observe dynamic DOM changes
  scanPageLinks();
  const observer = new MutationObserver(() => scanPageLinks());
  observer.observe(document.body, { childList: true, subtree: true });

  // Expose global test trigger for simulator
  window.PhishGuardScanLinks = scanPageLinks;
})();
