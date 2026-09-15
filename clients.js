import express from 'express';
import { db } from '../db.js';
import { broadcast } from '../sse.js';
import { requireAuth, logAudit } from '../auth.js';

const router = express.Router();

async function getHeartbeatTimeoutSeconds() {
  try {
    const row = await db.prepare("SELECT value FROM system_config WHERE key = 'HEARTBEAT_TIMEOUT_SECONDS'").get();
    return row ? parseInt(row.value, 10) || 90 : 90;
  } catch {
    return 90;
  }
}

// Helper: Validate enrollment token
async function validateEnrollmentToken(token) {
  if (!token) return { valid: true };
  try {
    const row = await db.prepare('SELECT * FROM enrollment_tokens WHERE token = ?').get(token.trim());
    if (!row) {
      return { valid: false, error: 'Invalid enrollment token' };
    }
    if (row.status !== 'ACTIVE') {
      return { valid: false, error: `Enrollment token is ${row.status.toLowerCase()}` };
    }
    if (new Date(row.expires_at).getTime() < Date.now()) {
      return { valid: false, error: 'Enrollment token has expired' };
    }
    if (row.uses_count >= row.max_uses) {
      return { valid: false, error: 'Enrollment token maximum usage limit reached' };
    }
    return { valid: true, tokenRow: row };
  } catch (err) {
    return { valid: false, error: 'Token validation error: ' + err.message };
  }
}

// 1. Client Registration / Enrollment (Called by Chrome Extension on install/startup)
const handleEnrollment = async (req, res) => {
  try {
    const {
      clientId,
      systemName,
      hostname,
      os,
      browser,
      extensionVersion,
      metadata,
      enrollmentToken
    } = req.body;

    const ipAddress = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || req.connection?.remoteAddress || '127.0.0.1';
    const now = new Date().toISOString();

    if (!clientId) {
      return res.status(400).json({ error: 'clientId is required' });
    }

    // Token validation if token provided
    if (enrollmentToken) {
      const tokenCheck = await validateEnrollmentToken(enrollmentToken);
      if (!tokenCheck.valid) {
        return res.status(401).json({ error: tokenCheck.error });
      }
      await db.prepare('UPDATE enrollment_tokens SET uses_count = uses_count + 1 WHERE token = ?').run(enrollmentToken.trim());
    }

    const assignedSystemName = systemName || hostname || `CLIENT-${clientId.substring(0, 6).toUpperCase()}`;

    // Check if client exists
    const existing = await db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);

    if (existing) {
      await db.prepare(`
        UPDATE clients
        SET system_name = ?,
            hostname = COALESCE(?, hostname),
            os = COALESCE(?, os),
            browser = COALESCE(?, browser),
            extension_version = COALESCE(?, extension_version),
            last_seen = ?,
            status = 'ONLINE',
            ip_address = ?,
            client_metadata = COALESCE(?, client_metadata)
        WHERE client_id = ?
      `).run(
        assignedSystemName,
        hostname || null,
        os || null,
        browser || null,
        extensionVersion || null,
        now,
        ipAddress,
        typeof metadata === 'object' ? JSON.stringify(metadata) : metadata || null,
        clientId
      );
    } else {
      await db.prepare(`
        INSERT INTO clients (
          client_id, system_name, hostname, os, browser,
          extension_version, first_seen, last_seen, status, ip_address, client_metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ONLINE', ?, ?)
      `).run(
        clientId,
        assignedSystemName,
        hostname || 'unknown-host',
        os || 'Chrome OS/Linux/Windows',
        browser || 'Google Chrome',
        extensionVersion || '1.4',
        now,
        now,
        ipAddress,
        typeof metadata === 'object' ? JSON.stringify(metadata) : metadata || '{}'
      );
    }

    const clientRecord = await db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);

    broadcast('CLIENT_REGISTERED', { client: clientRecord });

    res.json({
      success: true,
      clientId,
      systemName: assignedSystemName,
      status: 'ONLINE',
      registeredAt: now,
      message: 'Extension enrolled successfully'
    });
  } catch (err) {
    res.status(500).json({ error: 'Enrollment failed: ' + err.message });
  }
};

router.post('/register', handleEnrollment);
router.post('/enroll', handleEnrollment);

// Token Management Endpoints
router.get('/tokens', async (req, res) => {
  try {
    const tokens = await db.prepare('SELECT * FROM enrollment_tokens ORDER BY created_at DESC').all();
    res.json({ tokens: tokens || [] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch tokens: ' + err.message });
  }
});

router.post('/tokens/generate', requireAuth, async (req, res) => {
  try {
    const { description, maxUses = 25, expiresInDays = 30 } = req.body;
    const randChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let rand = '';
    for (let i = 0; i < 12; i++) {
      rand += randChars[Math.floor(Math.random() * randChars.length)];
    }
    const token = `ENROLL-${rand.substring(0, 4)}-${rand.substring(4, 8)}-${rand.substring(8)}`;

    const now = new Date();
    const expires = new Date(now.getTime() + (parseInt(expiresInDays, 10) || 30) * 24 * 60 * 60 * 1000);

    await db.prepare(`
      INSERT INTO enrollment_tokens (token, created_by, created_at, expires_at, status, max_uses, uses_count, description)
      VALUES (?, ?, ?, ?, 'ACTIVE', ?, 0, ?)
    `).run(token, req.user?.username || 'admin', now.toISOString(), expires.toISOString(), parseInt(maxUses, 10) || 25, description || 'Dynamic enrollment token');

    res.status(201).json({ success: true, token, expiresAt: expires.toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate token: ' + err.message });
  }
});

router.post('/tokens/:token/revoke', requireAuth, async (req, res) => {
  try {
    const { token } = req.params;
    await db.prepare("UPDATE enrollment_tokens SET status = 'REVOKED' WHERE token = ?").run(token);
    res.json({ success: true, message: `Token ${token} revoked` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke token: ' + err.message });
  }
});

// 2. Client Heartbeat (Called periodically by Chrome Extension)
router.post('/heartbeat', async (req, res) => {
  try {
    const { clientId } = req.body;
    const ipAddress = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || req.connection?.remoteAddress || '127.0.0.1';
    const now = new Date().toISOString();

    if (!clientId) {
      return res.status(400).json({ error: 'clientId is required' });
    }

    const existing = await db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);
    if (!existing) {
      const systemName = `CLIENT-${clientId.substring(0, 6).toUpperCase()}`;
      await db.prepare(`
        INSERT INTO clients (
          client_id, system_name, hostname, os, browser,
          extension_version, first_seen, last_seen, status, ip_address, client_metadata
        ) VALUES (?, ?, 'enrolled-host', 'Auto-detected', 'Google Chrome', '1.4', ?, ?, 'ONLINE', ?, '{}')
      `).run(clientId, systemName, now, now, ipAddress);
    } else {
      await db.prepare(`
        UPDATE clients
        SET last_seen = ?, status = 'ONLINE', ip_address = ?
        WHERE client_id = ?
      `).run(now, ipAddress, clientId);
    }

    broadcast('CLIENT_HEARTBEAT', {
      clientId,
      lastSeen: now,
      status: 'ONLINE',
      ipAddress
    });

    res.json({
      success: true,
      status: 'ONLINE',
      serverTime: now,
      heartbeatIntervalSeconds: 30
    });
  } catch (err) {
    res.status(500).json({ error: 'Heartbeat error: ' + err.message });
  }
});

// 3. List all registered systems (Dashboard)
router.get('/', async (req, res) => {
  try {
    const timeoutSec = await getHeartbeatTimeoutSeconds();
    const nowMs = Date.now();

    const clients = (await db.prepare('SELECT * FROM clients ORDER BY first_seen DESC').all()) || [];

    const statsRows = (await db.prepare(`
      SELECT
        client_id,
        COUNT(*) as total_events,
        SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked_count,
        SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as warning_count,
        SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed_count
      FROM url_events
      GROUP BY client_id
    `).all()) || [];

    const statsMap = new Map();
    for (const row of statsRows) {
      statsMap.set(row.client_id, row);
    }

    const result = clients.map(c => {
      const lastSeenMs = new Date(c.last_seen).getTime();
      const isOnline = (nowMs - lastSeenMs) <= (timeoutSec * 1000);
      const computedStatus = isOnline ? 'ONLINE' : 'OFFLINE';

      const st = statsMap.get(c.client_id) || {
        total_events: 0,
        blocked_count: 0,
        warning_count: 0,
        allowed_count: 0
      };

      return {
        ...c,
        status: computedStatus,
        totalEvents: parseInt(st.total_events || 0, 10),
        blockedCount: parseInt(st.blocked_count || 0, 10),
        warningCount: parseInt(st.warning_count || 0, 10),
        allowedCount: parseInt(st.allowed_count || 0, 10)
      };
    });

    res.json({ clients: result, timeoutSeconds: timeoutSec });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve clients: ' + err.message });
  }
});

// 4. Get specific client detail with recent events
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const timeoutSec = await getHeartbeatTimeoutSeconds();
    const nowMs = Date.now();

    const client = await db.prepare('SELECT * FROM clients WHERE client_id = ?').get(id);
    if (!client) {
      return res.status(404).json({ error: 'Client not found' });
    }

    const lastSeenMs = new Date(client.last_seen).getTime();
    const isOnline = (nowMs - lastSeenMs) <= (timeoutSec * 1000);
    client.status = isOnline ? 'ONLINE' : 'OFFLINE';

    const events = (await db.prepare(`
      SELECT * FROM url_events
      WHERE client_id = ?
      ORDER BY timestamp DESC
      LIMIT 100
    `).all(id)) || [];

    const alerts = (await db.prepare(`
      SELECT * FROM alerts
      WHERE client_id = ?
      ORDER BY timestamp DESC
      LIMIT 50
    `).all(id)) || [];

    const stats = await db.prepare(`
      SELECT
        COUNT(*) as total_events,
        SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked_count,
        SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as warning_count,
        SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed_count
      FROM url_events
      WHERE client_id = ?
    `).get(id);

    res.json({
      client,
      stats: {
        totalEvents: parseInt(stats?.total_events || 0, 10),
        blockedCount: parseInt(stats?.blocked_count || 0, 10),
        warningCount: parseInt(stats?.warning_count || 0, 10),
        allowedCount: parseInt(stats?.allowed_count || 0, 10)
      },
      events,
      alerts
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve client: ' + err.message });
  }
});

// 5. Delete / Decommission a client
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const client = await db.prepare('SELECT * FROM clients WHERE client_id = ?').get(id);
    if (!client) {
      return res.status(404).json({ error: 'Client not found' });
    }

    await db.prepare('DELETE FROM clients WHERE client_id = ?').run(id);

    logAudit({
      adminUser: req.user?.username || 'admin',
      action: 'DECOMMISSION_CLIENT',
      target: id,
      result: 'SUCCESS',
      ipAddress: req.ip,
      details: `Removed client ${client.system_name} (${id})`
    });

    broadcast('CLIENT_DELETED', { clientId: id });

    res.json({ success: true, message: 'Client deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete client: ' + err.message });
  }
});

export default router;
