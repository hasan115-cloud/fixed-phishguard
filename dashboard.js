import express from 'express';
import { db } from '../db.js';
import { sseHandler } from '../sse.js';

const router = express.Router();

// Real-Time Server-Sent Events Stream
router.get('/events-stream', sseHandler);

// Aggregated Real Security Statistics
router.get('/stats', async (req, res) => {
  try {
    const timeoutRow = await db.prepare("SELECT value FROM system_config WHERE key = 'HEARTBEAT_TIMEOUT_SECONDS'").get();
    const timeoutSec = timeoutRow ? parseInt(timeoutRow.value, 10) || 90 : 90;
    const nowMs = Date.now();

    // All clients & calculate actual online/offline based on last_seen
    const allClients = (await db.prepare('SELECT client_id, last_seen, status FROM clients').all()) || [];
    let onlineClients = 0;
    let offlineClients = 0;

    for (const c of allClients) {
      const lastSeenMs = new Date(c.last_seen).getTime();
      if (nowMs - lastSeenMs <= timeoutSec * 1000) {
        onlineClients++;
      } else {
        offlineClients++;
      }
    }

    // URL events counts
    const urlStats = (await db.prepare(`
      SELECT
        COUNT(*) as total_urls,
        SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed_urls,
        SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as warning_urls,
        SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked_urls
      FROM url_events
    `).get()) || { total_urls: 0, allowed_urls: 0, warning_urls: 0, blocked_urls: 0 };

    // Alert counts
    const alertStats = (await db.prepare(`
      SELECT
        COUNT(*) as total_alerts,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_alerts,
        SUM(CASE WHEN status = 'NEW' THEN 1 ELSE 0 END) as new_alerts
      FROM alerts
    `).get()) || { total_alerts: 0, critical_alerts: 0, new_alerts: 0 };

    // Rule counts
    const ruleStats = (await db.prepare(`
      SELECT
        COUNT(*) as total_rules,
        SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled_rules
      FROM rules
    `).get()) || { total_rules: 0, enabled_rules: 0 };

    // Top blocked threat domains
    const topBlockedDomains = (await db.prepare(`
      SELECT domain, COUNT(*) as count
      FROM url_events
      WHERE decision = 'BLOCK'
      GROUP BY domain
      ORDER BY count DESC
      LIMIT 5
    `).all()) || [];

    // Recent 10 events
    const recentEvents = (await db.prepare(`
      SELECT * FROM url_events
      ORDER BY timestamp DESC
      LIMIT 10
    `).all()) || [];

    res.json({
      totalClients: allClients.length,
      onlineClients,
      offlineClients,
      totalUrlsMonitored: parseInt(urlStats.total_urls || 0, 10),
      allowedUrls: parseInt(urlStats.allowed_urls || 0, 10),
      warningUrls: parseInt(urlStats.warning_urls || 0, 10),
      blockedUrls: parseInt(urlStats.blocked_urls || 0, 10),
      totalAlerts: parseInt(alertStats.total_alerts || 0, 10),
      criticalAlerts: parseInt(alertStats.critical_alerts || 0, 10),
      newAlerts: parseInt(alertStats.new_alerts || 0, 10),
      totalRules: parseInt(ruleStats.total_rules || 0, 10),
      enabledRules: parseInt(ruleStats.enabled_rules || 0, 10),
      topBlockedDomains,
      recentEvents
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate dashboard statistics: ' + err.message });
  }
});

export default router;
