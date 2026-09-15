import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const archiver = require('archiver');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DIST_DIR = path.join(__dirname, 'dist');

console.log('==============================================');
console.log('🚀 Building FortiNex Security Platform & Extension');
console.log('==============================================');

// 1. Clean & ensure dist directory
if (fs.existsSync(DIST_DIR)) {
  fs.rmSync(DIST_DIR, { recursive: true, force: true });
}
fs.mkdirSync(DIST_DIR, { recursive: true });

// 2. Frontend web application files
const WEB_FILES = [
  'index.html',
  'app.js',
  'styles.css',
  'icon.png'
];

for (const file of WEB_FILES) {
  const src = path.join(__dirname, file);
  const dest = path.join(DIST_DIR, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
    console.log(`  ✓ Web asset copied: ${file} (${fs.statSync(dest).size} bytes)`);
  } else {
    console.warn(`  ⚠️ Web asset missing: ${file}`);
  }
}

// 3. Vendor scripts (jsPDF & jsPDF-AutoTable for client-side report generation)
const VENDOR_FILES = [
  {
    src: path.join(__dirname, 'node_modules/jspdf/dist/jspdf.umd.min.js'),
    dest: path.join(DIST_DIR, 'vendor/jspdf/dist/jspdf.umd.min.js')
  },
  {
    src: path.join(__dirname, 'node_modules/jspdf-autotable/dist/jspdf.plugin.autotable.min.js'),
    dest: path.join(DIST_DIR, 'vendor/jspdf-autotable/dist/jspdf.plugin.autotable.min.js')
  }
];

for (const v of VENDOR_FILES) {
  if (fs.existsSync(v.src)) {
    fs.mkdirSync(path.dirname(v.dest), { recursive: true });
    fs.copyFileSync(v.src, v.dest);
    console.log(`  ✓ Vendor asset copied: ${path.relative(DIST_DIR, v.dest)}`);
  } else {
    console.warn(`  ⚠️ Vendor asset source not found: ${v.src}`);
  }
}

// 3b. Determine the production server URL for this deploy.
// Netlify automatically sets `URL` to the live site's primary URL during builds.
// PRODUCTION_API_URL can be set explicitly (e.g. for a custom domain) and always wins.
const PRODUCTION_URL = (process.env.PRODUCTION_API_URL || process.env.URL || process.env.DEPLOY_PRIME_URL || '').replace(/\/+$/, '');

if (PRODUCTION_URL) {
  console.log(`  ✓ Detected production server URL: ${PRODUCTION_URL}`);
} else {
  console.warn('  ⚠️ No PRODUCTION_API_URL/URL env var found at build time - extension will default to manual/auto-detect configuration.');
}

// 4. Chrome Extension package files
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

for (const file of EXTENSION_FILES) {
  const src = path.join(__dirname, file);
  const dest = path.join(DIST_DIR, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
    console.log(`  ✓ Extension component bundled: ${file}`);
  }
}

// 4b. If we know the production URL at build time, bake it into dist/config.js so the
// statically-built extension package (and its ZIP below) work immediately out of the
// box on any computer, with no manual configuration required.
if (PRODUCTION_URL) {
  const configDest = path.join(DIST_DIR, 'config.js');
  const generatedConfig = `// FortiNex PhishGuard Extension - Central Configuration
// Auto-generated at build time for production deploy: ${PRODUCTION_URL}
const PHISHGUARD_CONFIG = {
  DEFAULT_SERVER_URL: '${PRODUCTION_URL}',
  SERVER_MODE: 'REMOTE',
  MODES: {
    LOCALHOST: 'http://localhost:3000',
    LAN: 'http://localhost:3000',
    REMOTE: '${PRODUCTION_URL}'
  },
  DEFAULT_ENROLLMENT_TOKEN: 'ENROLL-FORTINEX-2026',
  EXTENSION_NAME: 'FortiNex PhishGuard Extension',
  VERSION: '1.4'
};

if (typeof globalThis !== 'undefined') {
  globalThis.PHISHGUARD_CONFIG = PHISHGUARD_CONFIG;
}
`;
  fs.writeFileSync(configDest, generatedConfig, 'utf8');

  // Also bake the URL into background.js's compile-time default so an unpacked load
  // of dist/ works even if config.js somehow fails to load first.
  const bgDest = path.join(DIST_DIR, 'background.js');
  if (fs.existsSync(bgDest)) {
    let bgContent = fs.readFileSync(bgDest, 'utf8');
    bgContent = bgContent.replace(
      /: 'http:\/\/localhost:3000';/,
      `: '${PRODUCTION_URL}';`
    );
    fs.writeFileSync(bgDest, bgContent, 'utf8');
  }
  console.log(`  ✓ Injected production server URL into dist/config.js and dist/background.js`);
}

// 5. Netlify _redirects configuration for SPA and Serverless API
const REDIRECTS_CONTENT = `# Netlify redirects for FortiNex API and Web Hub
/api/*  /.netlify/functions/api/:splat  200
/vendor/*  /vendor/:splat  200
/*  /index.html  200
`;
fs.writeFileSync(path.join(DIST_DIR, '_redirects'), REDIRECTS_CONTENT, 'utf8');
console.log('  ✓ Generated Netlify _redirects');

// 6. Pre-build FortiNex-Extension.zip for one-click static download
const zipPath = path.join(DIST_DIR, 'FortiNex-Extension.zip');
const output = fs.createWriteStream(zipPath);
const archive = new archiver.ZipArchive({ zlib: { level: 9 } });

const zipPromise = new Promise((resolve, reject) => {
  output.on('close', () => {
    console.log(`  ✓ Extension ZIP archive created: FortiNex-Extension.zip (${archive.pointer()} bytes)`);
    // Also copy as PhishGuard-Extension.zip for backward compatibility
    fs.copyFileSync(zipPath, path.join(DIST_DIR, 'PhishGuard-Extension.zip'));
    resolve();
  });
  archive.on('error', (err) => reject(err));
  archive.pipe(output);

  for (const file of EXTENSION_FILES) {
    // Prefer the dist copy (which has the production URL injected above) over source.
    const distFilePath = path.join(DIST_DIR, file);
    const srcFilePath = path.join(__dirname, file);
    const filePath = fs.existsSync(distFilePath) ? distFilePath : srcFilePath;
    if (fs.existsSync(filePath)) {
      archive.file(filePath, { name: path.join('FortiNex-Extension', file) });
    }
  }

  archive.finalize();
});

await zipPromise;

// 7. Verification check
const distFiles = fs.readdirSync(DIST_DIR);
console.log('==============================================');
console.log(`✅ Production build successful! ${distFiles.length} top-level entries in ${DIST_DIR}`);
console.log('==============================================');
