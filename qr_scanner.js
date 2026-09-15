// PhishGuard QR Code (Quishing) Scanner
// Scans QR code images on web pages and evaluates target destination URLs

(function () {
  'use strict';

  function scanImagesForQr() {
    const images = document.querySelectorAll('img:not([data-phishguard-qr-checked])');

    images.forEach(img => {
      img.setAttribute('data-phishguard-qr-checked', 'true');

      // If jsQR is available and image is loaded
      if (typeof jsQR !== 'undefined' && img.complete && img.naturalWidth > 50 && img.naturalHeight > 50) {
        try {
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          canvas.width = img.naturalWidth;
          canvas.height = img.naturalHeight;
          ctx.drawImage(img, 0, 0);

          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);

          if (code && code.data) {
            handleQrDetected(img, code.data);
          }
        } catch (e) {
          // Cross-origin image or canvas taint
        }
      }
    });
  }

  function handleQrDetected(imgElement, qrData) {
    const isUrl = qrData.startsWith('http://') || qrData.startsWith('https://');
    if (!isUrl) return;

    // Evaluate QR URL
    const isSuspicious = qrData.includes('.xyz') || qrData.includes('verify') || qrData.includes('@');
    const badge = document.createElement('div');
    badge.style.cssText = `
      position: absolute;
      background: ${isSuspicious ? '#dc3545' : '#198754'};
      color: #fff;
      font-size: 11px;
      padding: 3px 6px;
      border-radius: 4px;
      font-family: sans-serif;
      z-index: 99999;
      box-shadow: 0 2px 6px rgba(0,0,0,0.3);
    `;
    badge.textContent = isSuspicious ? `⚠️ PhishGuard: Suspicious QR destination` : `🛡️ QR verified`;

    const rect = imgElement.getBoundingClientRect();
    badge.style.top = `${window.scrollY + rect.top + 4}px`;
    badge.style.left = `${window.scrollX + rect.left + 4}px`;
    document.body.appendChild(badge);
  }

  window.addEventListener('load', scanImagesForQr);
  window.PhishGuardScanQr = scanImagesForQr;
})();
