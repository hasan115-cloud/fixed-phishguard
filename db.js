import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import pg from 'pg';

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Are we running inside a serverless platform (Netlify Functions, Vercel, AWS Lambda)?
// This is computed early because it changes how (and whether) we're allowed to fall
// back to a local SQLite file.
const IS_SERVERLESS = Boolean(
  process.env.NETLIFY || process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.LAMBDA_TASK_ROOT
);

function resolveDatabasePath() {
  const isServerless = process.env.VERCEL || process.env.NETLIFY || process.env.AWS_LAMBDA_FUNCTION_NAME;
  if (isServerless && !process.env.DATABASE_URL) {
    return '/tmp/phishguard.db';
  }
  const raw = process.env.DATABASE_URL;
  if (!raw) {
    return path.join(__dirname, '..', 'phishguard.db');
  }
  if (raw.startsWith('file:')) {
    const clean = raw.replace(/^file:\/\//, '').replace(/^file:/, '');
    return path.resolve(process.cwd(), clean);
  }
  if (raw.startsWith('/') || raw.startsWith('./') || raw.startsWith('../') || raw.endsWith('.db')) {
    return path.resolve(process.cwd(), raw);
  }
  return path.join(__dirname, '..', 'phishguard.db');
}

const DB_PATH = resolveDatabasePath();

let isPostgres = false;
let pgPool = null;
let sqliteDb = null;
let dbInitialized = false;
// When true, no usable database is configured and every query should fail loudly
// with a clear, actionable message rather than crashing the whole process/function.
let dbUnavailableReason = null;

// Convert SQL parameters from '?' to '$1, $2, $3...' for PostgreSQL
function toPgSql(sql) {
  let paramIndex = 1;
  return sql.replace(/\?/g, () => `$${paramIndex++}`);
}

function flattenParams(params) {
  if (!params || params.length === 0) return [];
  return params.flat();
}

// SQLite is ONLY for local/standalone development. It is never used on Netlify or
// any other serverless platform because their filesystems are ephemeral/per-invocation,
// which silently loses data - exactly what MUST_FIX #3 forbids. `node:sqlite` is also a
// fairly recent Node built-in (Node 22.5+), so it's imported lazily/dynamically here so
// that simply loading this module never crashes a Node 18/20 serverless runtime that
// doesn't have it - the import is only ever attempted on the local dev path below.
async function initSqliteInstance() {
  if (sqliteDb) return sqliteDb;
  const { DatabaseSync } = await import('node:sqlite');
  try {
    sqliteDb = new DatabaseSync(DB_PATH);
  } catch (err) {
    console.warn(`[DB] Failed to open SQLite at ${DB_PATH} (${err.message}), using in-memory`);
    sqliteDb = new DatabaseSync(':memory:');
  }

  try {
    sqliteDb.exec('PRAGMA journal_mode = WAL;');
    sqliteDb.exec('PRAGMA foreign_keys = ON;');
  } catch (e) {
    // WAL pragma not supported in-memory or already set
  }
  return sqliteDb;
}

// Initial connection detection (PostgreSQL vs SQLite)
const rawDatabaseUrl = process.env.DATABASE_URL || '';
const isRemotePgUrl = /^(postgres|postgresql):\/\//i.test(rawDatabaseUrl);
const isDummyPgPlaceholder = rawDatabaseUrl.includes('username:password') || rawDatabaseUrl.includes('host/database');

async function setupDatabaseConnection() {
  if (isRemotePgUrl && !isDummyPgPlaceholder) {
    try {
      console.log('[DB] Connecting to PostgreSQL database at:', rawDatabaseUrl.replace(/:[^:@]+@/, ':****@'));
      pgPool = new Pool({
        connectionString: rawDatabaseUrl,
        ssl: (rawDatabaseUrl.includes('localhost') || rawDatabaseUrl.includes('127.0.0.1')) ? false : { rejectUnauthorized: false },
        connectionTimeoutMillis: 4000,
        idleTimeoutMillis: 10000,
        max: IS_SERVERLESS ? 3 : 10
      });
      // Attempt rapid test query
      await pgPool.query('SELECT 1 as connected');
      isPostgres = true;
      console.log('[DB] Successfully connected to persistent PostgreSQL database!');
      return;
    } catch (err) {
      pgPool = null;
      isPostgres = false;
      if (IS_SERVERLESS) {
        dbUnavailableReason = `Could not connect to the PostgreSQL database at DATABASE_URL (${err.message}). On Netlify, a real Postgres connection is required - check that DATABASE_URL is correct and reachable.`;
        console.error('[DB] ' + dbUnavailableReason);
        return;
      }
      console.warn(`[DB] PostgreSQL connection attempt failed (${err.message}). Falling back to local SQLite at ${DB_PATH} (development only).`);
    }
  }

  if (IS_SERVERLESS) {
    // Never silently fall back to SQLite in a serverless environment: its filesystem
    // is ephemeral, so "persisted" data would vanish between invocations/cold starts.
    dbUnavailableReason = 'DATABASE_URL is not set (or is a placeholder) in this deployment. ' +
      'A persistent PostgreSQL database is required on Netlify - e.g. Netlify DB (Neon), Neon, or Supabase. ' +
      'Set DATABASE_URL in Site settings -> Environment variables and redeploy.';
    console.error('[DB] ' + dbUnavailableReason);
    return;
  }

  // Local/standalone development fallback only.
  await initSqliteInstance();
}

await setupDatabaseConnection();

function assertDbAvailable() {
  if (dbUnavailableReason) {
    const err = new Error(dbUnavailableReason);
    err.code = 'DB_UNAVAILABLE';
    throw err;
  }
}

// Unified Database Interface supporting both SQLite and PostgreSQL
export const db = {
  prepare(sql) {
    assertDbAvailable();
    if (isPostgres && pgPool) {
      const pgSql = toPgSql(sql);
      return {
        all: async (...params) => {
          const res = await pgPool.query(pgSql, flattenParams(params));
          return res.rows;
        },
        get: async (...params) => {
          const res = await pgPool.query(pgSql, flattenParams(params));
          return res.rows[0] || undefined;
        },
        run: async (...params) => {
          const res = await pgPool.query(pgSql, flattenParams(params));
          return { changes: res.rowCount, lastInsertRowid: null };
        }
      };
    } else {
      if (!sqliteDb) {
        throw new Error('[DB] Local SQLite instance is not ready yet. This should only happen in local development.');
      }
      const stmt = sqliteDb.prepare(sql);
      return {
        all: (...params) => stmt.all(...flattenParams(params)),
        get: (...params) => stmt.get(...flattenParams(params)),
        run: (...params) => stmt.run(...flattenParams(params))
      };
    }
  },
  exec(sql) {
    assertDbAvailable();
    if (isPostgres && pgPool) {
      return pgPool.query(sql);
    } else {
      if (!sqliteDb) {
        throw new Error('[DB] Local SQLite instance is not ready yet. This should only happen in local development.');
      }
      return sqliteDb.exec(sql);
    }
  }
};

export function isDatabaseAvailable() {
  return !dbUnavailableReason;
}

export function getDatabaseUnavailableReason() {
  return dbUnavailableReason;
}

export function getDatabase() {
  return db;
}

export function isUsingPostgres() {
  return isPostgres;
}

export function getDatabaseType() {
  if (dbUnavailableReason) return 'UNAVAILABLE';
  return isPostgres ? 'PostgreSQL' : 'SQLite';
}

export function getDatabasePath() {
  if (dbUnavailableReason) return 'not configured';
  return isPostgres ? (rawDatabaseUrl.replace(/:[^:@]+@/, ':****@')) : DB_PATH;
}

// Database schema initialization and baseline seeding
export async function initDatabase() {
  if (dbInitialized) return;
  assertDbAvailable();

  const schemaStatements = [
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'admin',
      created_at TEXT NOT NULL,
      last_login TEXT
    );`,
    `CREATE TABLE IF NOT EXISTS clients (
      client_id TEXT PRIMARY KEY,
      system_name TEXT NOT NULL,
      hostname TEXT,
      os TEXT,
      browser TEXT,
      extension_version TEXT,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ONLINE',
      ip_address TEXT,
      client_metadata TEXT
    );`,
    `CREATE TABLE IF NOT EXISTS url_events (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      system_name TEXT,
      url TEXT NOT NULL,
      domain TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      decision TEXT NOT NULL,
      threat_level TEXT NOT NULL,
      rule_id TEXT,
      rule_name TEXT,
      reason TEXT,
      browser_info TEXT
    );`,
    `CREATE TABLE IF NOT EXISTS rules (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      pattern TEXT NOT NULL,
      target_type TEXT NOT NULL DEFAULT 'domain',
      description TEXT,
      severity TEXT NOT NULL DEFAULT 'MEDIUM',
      enabled INTEGER NOT NULL DEFAULT 1,
      priority INTEGER NOT NULL DEFAULT 10,
      created_by TEXT NOT NULL DEFAULT 'admin',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );`,
    `CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      system_name TEXT,
      url TEXT NOT NULL,
      domain TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      severity TEXT NOT NULL,
      alert_type TEXT NOT NULL,
      reason TEXT NOT NULL,
      rule_id TEXT,
      status TEXT NOT NULL DEFAULT 'NEW',
      resolved_at TEXT,
      resolved_by TEXT
    );`,
    `CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      client_id TEXT NOT NULL,
      system_name TEXT,
      start_time TEXT NOT NULL,
      last_activity TEXT NOT NULL,
      related_alert_count INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'OPEN',
      notes TEXT
    );`,
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      admin_user TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT,
      result TEXT NOT NULL DEFAULT 'SUCCESS',
      ip_address TEXT,
      details TEXT
    );`,
    `CREATE TABLE IF NOT EXISTS enrollment_tokens (
      token TEXT PRIMARY KEY,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      max_uses INTEGER NOT NULL DEFAULT 25,
      uses_count INTEGER NOT NULL DEFAULT 0,
      description TEXT
    );`,
    `CREATE TABLE IF NOT EXISTS system_config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );`
  ];

  const indexStatements = [
    'CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_status ON enrollment_tokens(status);',
    'CREATE INDEX IF NOT EXISTS idx_url_events_client ON url_events(client_id);',
    'CREATE INDEX IF NOT EXISTS idx_url_events_timestamp ON url_events(timestamp DESC);',
    'CREATE INDEX IF NOT EXISTS idx_url_events_domain ON url_events(domain);',
    'CREATE INDEX IF NOT EXISTS idx_url_events_decision ON url_events(decision);',
    'CREATE INDEX IF NOT EXISTS idx_alerts_client ON alerts(client_id);',
    'CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);',
    'CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);',
    'CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled, priority DESC);',
    'CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);'
  ];

  if (isPostgres && pgPool) {
    for (const stmt of schemaStatements) {
      await pgPool.query(stmt);
    }
    for (const idx of indexStatements) {
      try {
        await pgPool.query(idx);
      } catch (e) {
        // index might already exist
      }
    }
  } else {
    const dbInstance = sqliteDb || initSqliteInstance();
    dbInstance.exec(schemaStatements.join('\n') + '\n' + indexStatements.join('\n'));
  }

  // Seed default admin users
  const usersToSeed = [
    { username: 'admin', password: 'PhishGuardAdmin2026!' },
    { username: process.env.ADMIN_USERNAME || 'hasan', password: process.env.ADMIN_PASSWORD || '@2026#Admin!92' }
  ];

  for (const u of usersToSeed) {
    if (!u.username) continue;
    const existing = await db.prepare('SELECT id FROM users WHERE username = ?').get(u.username);
    if (!existing) {
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(u.password, salt);
      const userId = 'usr-' + Date.now().toString(36) + '-' + Math.random().toString(36).substring(2, 6);
      const now = new Date().toISOString();
      await db.prepare('INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(userId, u.username, hash, 'admin', now);
      console.log(`[DB] Administrator created: ${u.username}`);
    }
  }

  // Seed baseline policy rules if empty
  const ruleCountRow = await db.prepare('SELECT COUNT(*) as count FROM rules').get();
  const ruleCount = parseInt(ruleCountRow?.count || 0, 10);
  if (ruleCount === 0) {
    const now = new Date().toISOString();
    const defaultRules = [
      {
        id: 'rule-blk-01',
        type: 'BLOCK',
        pattern: '*.account-verify.xyz',
        target_type: 'wildcard',
        description: 'Block credential-phishing subdomains on .xyz TLD',
        severity: 'HIGH',
        priority: 100
      },
      {
        id: 'rule-blk-02',
        type: 'BLOCK',
        pattern: 'paypal-security-update.account-verify.xyz',
        target_type: 'domain',
        description: 'Block verified PayPal impersonation phishing domain',
        severity: 'CRITICAL',
        priority: 110
      },
      {
        id: 'rule-blk-03',
        type: 'BLOCK',
        pattern: 'apple-id-support-cloud.live-auth.top',
        target_type: 'domain',
        description: 'Block Apple ID typosquatting credential harvester',
        severity: 'CRITICAL',
        priority: 110
      },
      {
        id: 'rule-blk-04',
        type: 'BLOCK',
        pattern: '192.168.1.105',
        target_type: 'domain',
        description: 'Block raw numerical IP address banking masquerade',
        severity: 'HIGH',
        priority: 90
      },
      {
        id: 'rule-warn-01',
        type: 'WARNING',
        pattern: '*.club',
        target_type: 'wildcard',
        description: 'Warn users navigating to high-abuse .club domain registries',
        severity: 'MEDIUM',
        priority: 50
      },
      {
        id: 'rule-warn-02',
        type: 'WARNING',
        pattern: 'free-crypto-giveaway-airdrop.club',
        target_type: 'domain',
        description: 'Warn users on cryptocurrency giveaway landing pages',
        severity: 'MEDIUM',
        priority: 60
      },
      {
        id: 'rule-alw-01',
        type: 'ALLOW',
        pattern: 'github.com',
        target_type: 'domain',
        description: 'Enterprise trusted software development portal',
        severity: 'LOW',
        priority: 200
      },
      {
        id: 'rule-alw-02',
        type: 'ALLOW',
        pattern: '*.google.com',
        target_type: 'wildcard',
        description: 'Corporate Google Workspace services',
        severity: 'LOW',
        priority: 200
      },
      {
        id: 'rule-alw-03',
        type: 'ALLOW',
        pattern: '*.microsoft.com',
        target_type: 'wildcard',
        description: 'Microsoft 365 and Azure enterprise portals',
        severity: 'LOW',
        priority: 200
      }
    ];

    for (const r of defaultRules) {
      await db.prepare(`
        INSERT INTO rules (id, type, pattern, target_type, description, severity, enabled, priority, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, 'system-init', ?, ?)
      `).run(r.id, r.type, r.pattern, r.target_type, r.description, r.severity, r.priority, now, now);
    }
    console.log(`[DB] Installed baseline security policy (${defaultRules.length} rules)`);
  }

  // System configuration
  const initConfig = async (key, value) => {
    const existing = await db.prepare('SELECT key FROM system_config WHERE key = ?').get(key);
    if (!existing) {
      await db.prepare('INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, ?)')
        .run(key, value, new Date().toISOString());
    }
  };

  await initConfig('HEARTBEAT_TIMEOUT_SECONDS', '90');
  await initConfig('ALLOW_USER_BYPASS', 'false');
  await initConfig('AUTO_CREATE_INCIDENTS', 'true');
  await initConfig('ENROLLMENT_TOKEN', 'ENROLL-FORTINEX-2026');

  // Default fleet enrollment token
  const existingToken = await db.prepare('SELECT token FROM enrollment_tokens WHERE token = ?').get('ENROLL-FORTINEX-2026');
  if (!existingToken) {
    const now = new Date();
    const expires = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
    await db.prepare(`
      INSERT INTO enrollment_tokens (token, created_by, created_at, expires_at, status, max_uses, uses_count, description)
      VALUES (?, 'system-init', ?, ?, 'ACTIVE', 100, 0, 'Default FortiNex Enterprise fleet enrollment token')
    `).run('ENROLL-FORTINEX-2026', now.toISOString(), expires.toISOString());
  }

  dbInitialized = true;
  console.log(`[DB] ${isPostgres ? 'PostgreSQL database ready' : 'Persistent SQLite database ready at ' + DB_PATH}`);
}
