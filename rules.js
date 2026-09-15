import express from 'express';
import { db } from '../db.js';
import { broadcast } from '../sse.js';
import { requireAuth, logAudit } from '../auth.js';
import { refreshRulesCache } from '../decisionEngine.js';

const router = express.Router();

// List all rules
router.get('/', async (req, res) => {
  try {
    const rules = await db.prepare('SELECT * FROM rules ORDER BY priority DESC, created_at DESC').all();
    res.json({ rules });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch rules: ' + err.message });
  }
});

// Create new rule
router.post('/', requireAuth, async (req, res) => {
  try {
    const {
      type,
      pattern,
      targetType = 'domain',
      description,
      severity = 'MEDIUM',
      priority = 10,
      enabled = 1
    } = req.body;

    if (!type || !pattern) {
      return res.status(400).json({ error: 'Rule type (ALLOW, WARNING, BLOCK) and pattern are required' });
    }

    const validTypes = ['ALLOW', 'WARNING', 'BLOCK'];
    if (!validTypes.includes(type.toUpperCase())) {
      return res.status(400).json({ error: 'Type must be ALLOW, WARNING, or BLOCK' });
    }

    const id = 'rule-' + type.toLowerCase().substring(0, 3) + '-' + Date.now().toString(36);
    const now = new Date().toISOString();
    const createdBy = req.user?.username || 'admin';

    await db.prepare(`
      INSERT INTO rules (
        id, type, pattern, target_type, description,
        severity, enabled, priority, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      type.toUpperCase(),
      pattern.trim(),
      targetType,
      description || '',
      severity.toUpperCase(),
      enabled ? 1 : 0,
      parseInt(priority, 10) || 10,
      createdBy,
      now,
      now
    );

    const rule = await db.prepare('SELECT * FROM rules WHERE id = ?').get(id);

    logAudit({
      adminUser: createdBy,
      action: 'CREATE_RULE',
      target: id,
      result: 'SUCCESS',
      ipAddress: req.ip,
      details: `Created ${type.toUpperCase()} rule for ${pattern}`
    });

    await refreshRulesCache();
    broadcast('RULES_UPDATED', { action: 'CREATE', rule });

    res.status(201).json({ success: true, rule });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create rule: ' + err.message });
  }
});

// Update rule
router.put('/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      type,
      pattern,
      targetType,
      description,
      severity,
      priority,
      enabled
    } = req.body;

    const existing = await db.prepare('SELECT * FROM rules WHERE id = ?').get(id);
    if (!existing) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    const now = new Date().toISOString();

    await db.prepare(`
      UPDATE rules
      SET type = COALESCE(?, type),
          pattern = COALESCE(?, pattern),
          target_type = COALESCE(?, target_type),
          description = COALESCE(?, description),
          severity = COALESCE(?, severity),
          priority = COALESCE(?, priority),
          enabled = COALESCE(?, enabled),
          updated_at = ?
      WHERE id = ?
    `).run(
      type ? type.toUpperCase() : null,
      pattern ? pattern.trim() : null,
      targetType || null,
      description !== undefined ? description : null,
      severity ? severity.toUpperCase() : null,
      priority !== undefined ? parseInt(priority, 10) : null,
      enabled !== undefined ? (enabled ? 1 : 0) : null,
      now,
      id
    );

    const updated = await db.prepare('SELECT * FROM rules WHERE id = ?').get(id);

    logAudit({
      adminUser: req.user?.username || 'admin',
      action: 'UPDATE_RULE',
      target: id,
      result: 'SUCCESS',
      ipAddress: req.ip,
      details: `Updated rule ${id} (${updated?.pattern || ''})`
    });

    await refreshRulesCache();
    broadcast('RULES_UPDATED', { action: 'UPDATE', rule: updated });

    res.json({ success: true, rule: updated });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update rule: ' + err.message });
  }
});

// Toggle rule enabled/disabled
router.patch('/:id/toggle', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await db.prepare('SELECT * FROM rules WHERE id = ?').get(id);
    if (!existing) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    const newStatus = existing.enabled ? 0 : 1;
    const now = new Date().toISOString();

    await db.prepare('UPDATE rules SET enabled = ?, updated_at = ? WHERE id = ?').run(newStatus, now, id);

    logAudit({
      adminUser: req.user?.username || 'admin',
      action: newStatus ? 'ENABLE_RULE' : 'DISABLE_RULE',
      target: id,
      result: 'SUCCESS',
      ipAddress: req.ip,
      details: `${newStatus ? 'Enabled' : 'Disabled'} rule ${existing.pattern}`
    });

    await refreshRulesCache();
    broadcast('RULES_UPDATED', { action: 'TOGGLE', id, enabled: newStatus });

    res.json({ success: true, id, enabled: newStatus });
  } catch (err) {
    res.status(500).json({ error: 'Failed to toggle rule: ' + err.message });
  }
});

// Delete rule
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await db.prepare('SELECT * FROM rules WHERE id = ?').get(id);
    if (!existing) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    await db.prepare('DELETE FROM rules WHERE id = ?').run(id);

    logAudit({
      adminUser: req.user?.username || 'admin',
      action: 'DELETE_RULE',
      target: id,
      result: 'SUCCESS',
      ipAddress: req.ip,
      details: `Deleted rule ${existing.pattern}`
    });

    await refreshRulesCache();
    broadcast('RULES_UPDATED', { action: 'DELETE', id });

    res.json({ success: true, message: 'Rule deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete rule: ' + err.message });
  }
});

export default router;
