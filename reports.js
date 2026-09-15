import express from 'express';
import { db } from '../db.js';

const router = express.Router();

// Aggregated report statistics
router.get('/summary', async (req, res) => {
  try {
    const { startDate, endDate, clientId } = req.query;

    const where = [];
    const params = [];

    if (startDate) {
      where.push('timestamp >= ?');
      params.push(startDate);
    }
    if (endDate) {
      where.push('timestamp <= ?');
      params.push(endDate);
    }
    if (clientId) {
      where.push('client_id = ?');
      params.push(clientId);
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    const totals = (await db.prepare(`
      SELECT
        COUNT(*) as total_events,
        SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed_events,
        SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as warning_events,
        SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked_events
      FROM url_events
      ${whereSql}
    `).get(...params)) || { total_events: 0, allowed_events: 0, warning_events: 0, blocked_events: 0 };

    const byThreatLevel = (await db.prepare(`
      SELECT threat_level, COUNT(*) as count
      FROM url_events
      ${whereSql}
      GROUP BY threat_level
      ORDER BY count DESC
    `).all(...params)) || [];

    const topBlockedWhere = where.length > 0 ? whereSql + " AND decision = 'BLOCK'" : "WHERE decision = 'BLOCK'";
    const topBlocked = (await db.prepare(`
      SELECT domain, COUNT(*) as count
      FROM url_events
      ${topBlockedWhere}
      GROUP BY domain
      ORDER BY count DESC
      LIMIT 10
    `).all(...params)) || [];

    const byClient = (await db.prepare(`
      SELECT client_id, system_name, COUNT(*) as count,
             SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked
      FROM url_events
      ${whereSql}
      GROUP BY client_id, system_name
      ORDER BY count DESC
      LIMIT 10
    `).all(...params)) || [];

    res.json({
      totals: {
        total_events: parseInt(totals.total_events || 0, 10),
        allowed_events: parseInt(totals.allowed_events || 0, 10),
        warning_events: parseInt(totals.warning_events || 0, 10),
        blocked_events: parseInt(totals.blocked_events || 0, 10)
      },
      byThreatLevel,
      topBlocked,
      byClient
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate report summary: ' + err.message });
  }
});

// Comprehensive real-data report endpoint for PDF generation and printable dashboard
router.get('/detailed', async (req, res) => {
  try {
    const { scope = 'ALL', timeRange = 'ALL', startDate, endDate } = req.query;

    const where = [];
    const params = [];

    // 1. Time range filter
    const now = new Date();
    let computedStartDate = null;
    let computedEndDate = null;

    if (timeRange === '24h') {
      computedStartDate = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
    } else if (timeRange === '7d') {
      computedStartDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
    } else if (timeRange === '30d') {
      computedStartDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
    } else if (timeRange === 'custom') {
      if (startDate) computedStartDate = new Date(startDate).toISOString();
      if (endDate) {
        const e = new Date(endDate);
        e.setHours(23, 59, 59, 999);
        computedEndDate = e.toISOString();
      }
    }

    if (computedStartDate) {
      where.push('timestamp >= ?');
      params.push(computedStartDate);
    }
    if (computedEndDate) {
      where.push('timestamp <= ?');
      params.push(computedEndDate);
    }

    // 2. Client scope filter
    let targetClient = null;
    if (scope && scope !== 'ALL') {
      where.push('client_id = ?');
      params.push(scope);
      targetClient = await db.prepare('SELECT * FROM clients WHERE client_id = ?').get(scope);
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    // 3. Totals
    const totals = (await db.prepare(`
      SELECT
        COUNT(*) as total_events,
        SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed_events,
        SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as warning_events,
        SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked_events
      FROM url_events
      ${whereSql}
    `).get(...params)) || { total_events: 0, allowed_events: 0, warning_events: 0, blocked_events: 0 };

    // 4. By Threat Level
    const byThreatLevel = (await db.prepare(`
      SELECT threat_level, COUNT(*) as count
      FROM url_events
      ${whereSql}
      GROUP BY threat_level
      ORDER BY count DESC
    `).all(...params)) || [];

    // 5. Top Blocked Domains
    const topBlockedWhere = where.length > 0 ? `${whereSql} AND decision = 'BLOCK'` : "WHERE decision = 'BLOCK'";
    const topBlocked = (await db.prepare(`
      SELECT domain, COUNT(*) as count
      FROM url_events
      ${topBlockedWhere}
      GROUP BY domain
      ORDER BY count DESC
      LIMIT 10
    `).all(...params)) || [];

    // 6. Recent Detailed Events (up to 100)
    const events = (await db.prepare(`
      SELECT id, client_id, system_name, url, domain, timestamp, decision, threat_level, rule_name, reason
      FROM url_events
      ${whereSql}
      ORDER BY timestamp DESC
      LIMIT 100
    `).all(...params)) || [];

    // 6b. Per-System Breakdown
    const byClient = (await db.prepare(`
      SELECT
        client_id,
        system_name,
        COUNT(*) as total,
        SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as safe_count,
        SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as suspicious_count,
        SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as phishing_count
      FROM url_events
      ${whereSql}
      GROUP BY client_id, system_name
      ORDER BY total DESC
    `).all(...params)) || [];

    // 7. Alerts count matching scope & time
    const alertWhere = [];
    const alertParams = [];
    if (computedStartDate) {
      alertWhere.push('timestamp >= ?');
      alertParams.push(computedStartDate);
    }
    if (computedEndDate) {
      alertWhere.push('timestamp <= ?');
      alertParams.push(computedEndDate);
    }
    if (scope && scope !== 'ALL') {
      alertWhere.push('client_id = ?');
      alertParams.push(scope);
    }
    const alertWhereSql = alertWhere.length > 0 ? `WHERE ${alertWhere.join(' AND ')}` : '';

    const alertsCount = (await db.prepare(`
      SELECT
        COUNT(*) as total_alerts,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_alerts,
        SUM(CASE WHEN alert_type = 'PHISHING_BLOCKED' THEN 1 ELSE 0 END) as phishing_alerts,
        SUM(CASE WHEN alert_type = 'SUSPICIOUS_WARNING' THEN 1 ELSE 0 END) as warning_alerts
      FROM alerts
      ${alertWhereSql}
    `).get(...alertParams)) || { total_alerts: 0, critical_alerts: 0, phishing_alerts: 0, warning_alerts: 0 };

    res.json({
      generatedAt: new Date().toISOString(),
      scope: scope === 'ALL' ? { type: 'ALL', name: 'All Enrolled Systems (Aggregated Enterprise Fleet)' } : {
        type: 'SINGLE',
        clientId: scope,
        name: targetClient?.system_name || scope,
        hostname: targetClient?.hostname || 'Unknown Host',
        os: targetClient?.os || 'Unknown OS',
        browser: targetClient?.browser || 'Chrome',
        ip: targetClient?.ip_address || '—',
        status: targetClient?.status || 'OFFLINE'
      },
      timeRange: {
        key: timeRange,
        startDate: computedStartDate,
        endDate: computedEndDate || new Date().toISOString()
      },
      totals: {
        total_events: parseInt(totals.total_events || 0, 10),
        allowed_events: parseInt(totals.allowed_events || 0, 10),
        warning_events: parseInt(totals.warning_events || 0, 10),
        blocked_events: parseInt(totals.blocked_events || 0, 10)
      },
      threatLevels: byThreatLevel,
      topBlocked,
      events,
      byClient,
      alerts: alertsCount
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate detailed report: ' + err.message });
  }
});

// CSV Export
router.get('/export-csv', async (req, res) => {
  try {
    const { type = 'url-events', clientId, startDate, endDate } = req.query;

    const where = [];
    const params = [];

    if (startDate) {
      where.push('timestamp >= ?');
      params.push(startDate);
    }
    if (endDate) {
      where.push('timestamp <= ?');
      params.push(endDate);
    }
    if (clientId) {
      where.push('client_id = ?');
      params.push(clientId);
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    if (type === 'alerts') {
      const alerts = (await db.prepare(`
        SELECT id, client_id, system_name, url, domain, timestamp, severity, alert_type, reason, status
        FROM alerts
        ${whereSql}
        ORDER BY timestamp DESC
        LIMIT 1000
      `).all(...params)) || [];

      const headers = ['Alert ID', 'Client ID', 'System Name', 'URL', 'Domain', 'Timestamp', 'Severity', 'Alert Type', 'Reason', 'Status'];
      const rows = alerts.map(a => [
        a.id, a.client_id, a.system_name, `"${(a.url || '').replace(/"/g, '""')}"`, a.domain, a.timestamp, a.severity, a.alert_type, `"${(a.reason || '').replace(/"/g, '""')}"`, a.status
      ]);

      const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="fortinex_alerts_${Date.now()}.csv"`);
      return res.send(csvContent);
    }

    // Default: URL events
    const events = (await db.prepare(`
      SELECT id, client_id, system_name, url, domain, timestamp, decision, threat_level, rule_name, reason
      FROM url_events
      ${whereSql}
      ORDER BY timestamp DESC
      LIMIT 2000
    `).all(...params)) || [];

    const headers = ['Event ID', 'Client ID', 'System Name', 'URL', 'Domain', 'Timestamp', 'Decision', 'Threat Level', 'Rule Name', 'Reason'];
    const rows = events.map(e => [
      e.id, e.client_id, e.system_name, `"${(e.url || '').replace(/"/g, '""')}"`, e.domain, e.timestamp, e.decision, e.threat_level, `"${(e.rule_name || '').replace(/"/g, '""')}"`, `"${(e.reason || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="fortinex_url_events_${Date.now()}.csv"`);
    res.send(csvContent);
  } catch (err) {
    res.status(500).json({ error: 'Failed to export CSV: ' + err.message });
  }
});

export default router;
