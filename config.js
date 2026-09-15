// PhishGuard Extension - Central Configuration
// This file is auto-configured when downloading the extension ZIP from the central dashboard,
// and can also be adjusted dynamically via the Extension Options or Popup Settings UI.

// NOTE: This is the SOURCE template used only when loading the extension unpacked
// straight from this repo folder, or as a fallback for `npm run build` before
// PRODUCTION_API_URL/URL is known. The RECOMMENDED way to install the extension is
// to click "Download Extension" on the deployed dashboard's Install tab - that
// endpoint (/api/extension/download) generates a config.js pre-filled with your
// actual deployed server URL automatically, so every install works out of the box.
const PHISHGUARD_CONFIG = {
  // Configurable Server URL (Dynamic / Auto-adaptive)
  // Supports Localhost (Dev), LAN (Internal Testing), and Remote (Cloud / Production)
  DEFAULT_SERVER_URL: 'http://localhost:3000',
  SERVER_MODE: 'AUTO', // 'AUTO' | 'LOCALHOST' | 'LAN' | 'REMOTE' | 'CUSTOM'

  // Pre-configured connection endpoints. REMOTE is auto-filled at build time from the
  // Netlify deploy URL (see build.js) - if you see localhost here, either run the
  // Netlify build, download the extension from the dashboard, or set your server URL
  // manually from the extension's Options page.
  MODES: {
    LOCALHOST: 'http://localhost:3000',
    LAN: 'http://localhost:3000',
    REMOTE: 'http://localhost:3000'
  },

  // Fleet enrollment token
  DEFAULT_ENROLLMENT_TOKEN: 'ENROLL-FORTINEX-2026',

  // Extension metadata
  EXTENSION_NAME: 'FortiNex PhishGuard Extension',
  VERSION: '1.4'
};

if (typeof globalThis !== 'undefined') {
  globalThis.PHISHGUARD_CONFIG = PHISHGUARD_CONFIG;
}

