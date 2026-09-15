import express from 'express';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { db } from '../db.js';

const require = createRequire(import.meta.url);
const archiver = require('archiver');

const router = express.Router();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.join(__dirname, '..', '..');

// Required files comprising the full Chrome Extension
const EXTENSION_FILES = [
  'manifest.json',
  'config.js',
  'options.html',
  'options.js',
  'background.js',
  'content.js',
  'engine.js',
  'popup.html',
  'popup.js',
  'warning.html',
  'warning.js',
  'offscreen.html',
  'offscreen.js',
  'gmail_content.js',
  'qr_scanner.js',
  'jsqr.min.js',
  'styles.css',
  'icon.png'
];

// 1. Get Extension Package Info & Files List
router.get('/info', (req, res) => {
  try {
    const manifestPath = path.join(ROOT_DIR, 'manifest.json');
    let manifestData = { version: '1.4', name: 'FortiNex PhishGuard Extension' };
    if (fs.existsSync(manifestPath)) {
      manifestData = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    }

    const filesInfo = EXTENSION_FILES.map((filename) => {
      const fullPath = path.join(ROOT_DIR, filename);
      const exists = fs.existsSync(fullPath);
      const size = exists ? fs.statSync(fullPath).size : 0;
      return { filename, exists, size };
    });

    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000';
    const detectedServerUrl = `${protocol}://${host}`;

    res.json({
      name: manifestData.name || 'FortiNex PhishGuard Extension',
      version: manifestData.version || '1.4',
      manifestVersion: manifestData.manifest_version || 3,
      files: filesInfo,
      detectedServerUrl,
      downloadUrl: '/api/extension/download'
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to inspect extension package: ' + err.message });
  }
});

// 2. Download Real Extension ZIP Package
router.get('/download', async (req, res) => {
  try {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000';
    const isRemote = host && !host.includes('localhost') && !host.includes('127.0.0.1');

    const detectedRemoteUrl = process.env.PRODUCTION_API_URL ||
      (isRemote ? `${protocol}://${host}` : `${protocol}://${host}`);

    // Find LAN IP
    let lanIp = '127.0.0.1';
    try {
      const interfaces = os.networkInterfaces();
      for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
          if (iface.family === 'IPv4' && !iface.internal && !iface.address.startsWith('169.254')) {
            lanIp = iface.address;
            break;
          }
        }
      }
    } catch {}

    const port = process.env.SERVER_PORT || 3000;
    const lanUrl = lanIp !== '127.0.0.1' ? `http://${lanIp}:${port}` : `http://localhost:${port}`;
    const localhostUrl = `http://localhost:${port}`;

    // Determine target server URL for the extension
    const customServerUrl = req.query.serverUrl;
    let targetServerUrl = customServerUrl;

    if (!targetServerUrl) {
      targetServerUrl = isRemote ? detectedRemoteUrl : localhostUrl;
    }

    // Determine mode
    let mode = req.query.mode;
    if (!mode) {
      if (targetServerUrl.startsWith('https://')) mode = 'REMOTE';
      else if (targetServerUrl.includes('localhost') || targetServerUrl.includes('127.0.0.1')) mode = 'LOCALHOST';
      else mode = 'LAN';
    }

    // Active enrollment token
    let activeToken = 'ENROLL-FORTINEX-2026';
    try {
      const activeTokenRow = await db.prepare("SELECT token FROM enrollment_tokens WHERE status = 'ACTIVE' ORDER BY created_at DESC LIMIT 1").get();
      if (activeTokenRow?.token) {
        activeToken = activeTokenRow.token;
      }
    } catch (e) {
      console.warn('[Extension Download] Token lookup note:', e.message);
    }

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="FortiNex-Extension.zip"');

    const archive = new archiver.ZipArchive({ zlib: { level: 9 } });

    archive.on('error', (err) => {
      console.error('[Extension ZIP] Archiver error:', err);
      if (!res.headersSent) {
        res.status(500).send({ error: 'Archiving error: ' + err.message });
      }
    });

    archive.pipe(res);

    for (const filename of EXTENSION_FILES) {
      const fullPath = path.join(ROOT_DIR, filename);
      if (!fs.existsSync(fullPath)) {
        console.warn(`[Extension ZIP] Missing file skipped: ${filename}`);
        continue;
      }

      // If background.js, ensure DEFAULT_SERVER_URL points to targetServerUrl
      if (filename === 'background.js') {
        let content = fs.readFileSync(fullPath, 'utf8');
        content = content.replace(
          /const DEFAULT_SERVER_URL\s*=\s*[^;]+;/,
          `const DEFAULT_SERVER_URL = '${targetServerUrl}';`
        );
        archive.append(content, { name: path.join('FortiNex-Extension', filename) });
      } else if (filename === 'config.js') {
        const configContent = `// FortiNex PhishGuard Extension - Dynamic Central Configuration
// Auto-generated package pre-configured for: ${targetServerUrl}
const PHISHGUARD_CONFIG = {
  DEFAULT_SERVER_URL: '${targetServerUrl}',
  SERVER_MODE: '${mode}',
  MODES: {
    LOCALHOST: '${localhostUrl}',
    LAN: '${lanUrl}',
    REMOTE: '${detectedRemoteUrl}'
  },
  DEFAULT_ENROLLMENT_TOKEN: '${activeToken}',
  VERSION: '1.4',
  NAME: 'FortiNex PhishGuard Extension'
};

if (typeof globalThis !== 'undefined') {
  globalThis.PHISHGUARD_CONFIG = PHISHGUARD_CONFIG;
}
`;
        archive.append(configContent, { name: path.join('FortiNex-Extension', filename) });
      } else if (filename === 'manifest.json') {
        let manifestContent = fs.readFileSync(fullPath, 'utf8');
        try {
          const parsed = JSON.parse(manifestContent);
          parsed.name = 'FortiNex PhishGuard Enterprise Extension';
          parsed.description = 'FortiNex PhishGuard — Real-time browser endpoint phishing defense, URL interception, and security rules enforcement.';
          parsed.host_permissions = ['*://*/*', '<all_urls>'];
          manifestContent = JSON.stringify(parsed, null, 2);
        } catch {
          // Keep as is
        }
        archive.append(manifestContent, { name: path.join('FortiNex-Extension', filename) });
      } else {
        archive.file(fullPath, { name: path.join('FortiNex-Extension', filename) });
      }
    }

    archive.finalize();
  } catch (err) {
    console.error('[Extension ZIP] Download failure:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Download failed: ' + err.message });
    }
  }
});

export default router;
