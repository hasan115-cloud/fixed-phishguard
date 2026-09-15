// PhishGuard Email Protection Script (Gmail & Outlook)
// Detects deceptive links and display-text spoofing in webmail interfaces

(function () {
  'use strict';

  function inspectEmailLinks() {
    // Select common email body containers in Gmail (.a3s, .ii.gt) and Outlook (.rps_, [data-body="true"])
    const emailContainers = document.querySelectorAll(
      '.a3s, .ii.gt, .rps_, [data-body="true"], [role="main"] .expanded-message, .email-content-wrapper'
    );

    emailContainers.forEach(container => {
      const links = container.querySelectorAll('a[href]:not([data-phishguard-email-checked])');

      links.forEach(link => {
        link.setAttribute('data-phishguard-email-checked', 'true');
        const href = link.href.trim();
        const text = link.innerText.trim();

        // Check for text spoofing: text looks like a trusted domain or URL, but href is different
        const looksLikeUrl = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}/i.test(text);

        if (looksLikeUrl) {
          try {
            let displayedHost = text.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
            const actualHost = new URL(href).hostname.toLowerCase();

            if (displayedHost.startsWith('www.')) displayedHost = displayedHost.slice(4);
            const cleanActual = actualHost.startsWith('www.') ? actualHost.slice(4) : actualHost;

            if (displayedHost !== cleanActual && !cleanActual.endsWith('.' + displayedHost)) {
              // Deceptive spoofing detected!
              link.classList.add('phishguard-phishing');
              link.style.outline = '2px dashed #ef4444';
              link.setAttribute(
                'title',
                `⚠️ PhishGuard Alert: Link text shows "${displayedHost}" but actually navigates to "${cleanActual}"!`
              );

              // Add warning pill
              const warnTag = document.createElement('span');
              warnTag.style.cssText = `
                background: #dc3545;
                color: #fff;
                font-size: 10px;
                padding: 1px 5px;
                border-radius: 3px;
                margin-left: 4px;
                font-weight: bold;
              `;
              warnTag.textContent = `⚠️ Spoofed: points to ${cleanActual}`;
              link.parentNode.insertBefore(warnTag, link.nextSibling);
            }
          } catch {
            // Invalid URL in href
          }
        }
      });
    });
  }

  // Scan immediately and on DOM changes
  inspectEmailLinks();
  const observer = new MutationObserver(() => inspectEmailLinks());
  observer.observe(document.body, { childList: true, subtree: true });

  window.PhishGuardScanEmail = inspectEmailLinks;
})();
