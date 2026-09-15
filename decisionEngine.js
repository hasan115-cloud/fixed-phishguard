import { db } from './db.js';
import { evaluatePhishing, extractUrlFeatures } from '../engine.js';

let cachedRules = null;
let lastCacheTime = 0;

export async function refreshRulesCache() {
  try {
    const rules = await db.prepare(`
      SELECT * FROM rules
      WHERE enabled = 1
      ORDER BY priority DESC, created_at ASC
    `).all();
    cachedRules = Array.isArray(rules) ? rules : [];
    lastCacheTime = Date.now();
    return cachedRules;
  } catch (err) {
    console.error('[DecisionEngine] Failed to refresh rules cache:', err);
    return cachedRules || [];
  }
}

export function getCachedRules() {
  if (cachedRules !== null && Date.now() - lastCacheTime < 30000) {
    return cachedRules;
  }
  try {
    const res = db.prepare(`
      SELECT * FROM rules
      WHERE enabled = 1
      ORDER BY priority DESC, created_at ASC
    `).all();
    if (Array.isArray(res)) {
      cachedRules = res;
      lastCacheTime = Date.now();
      return cachedRules;
    }
  } catch {}
  refreshRulesCache();
  return cachedRules || [];
}

/**
 * Match a pattern against a target string.
 * Supports:
 * - exact matches
 * - wildcard prefixes (*.example.com)
 * - wildcard infixes (*phish*)
 * - path wildcards (http://badsite.com/*)
 */
function matchesPattern(pattern, target, isDomainOnly = false) {
  if (!pattern || !target) return false;

  const p = pattern.trim().toLowerCase();
  const t = target.trim().toLowerCase();

  const cleanP = p.replace(/^[a-z]+:\/\//i, '').replace(/\/+$/, '').split('/')[0].split(':')[0];
  const cleanT = t.replace(/^[a-z]+:\/\//i, '').replace(/\/+$/, '').split('/')[0].split(':')[0];

  // Exact match on raw or normalized domain
  if (p === t || cleanP === cleanT || cleanP === t || p === cleanT) return true;

  // Domain specific sub-domain match (e.g. pattern = example.com matches sub.example.com)
  if (isDomainOnly) {
    if (cleanT.endsWith('.' + cleanP) || t.endsWith('.' + cleanP)) return true;
  }

  // Wildcard pattern (e.g. *.example.com or *badsite*)
  if (p.includes('*')) {
    const escaped = p
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*');
    try {
      const regex = new RegExp(`^${escaped}$`, 'i');
      if (regex.test(t) || regex.test(cleanT)) return true;
    } catch {
      // invalid regex fallback
    }
  }

  // Also check if raw URL target contains clean domain pattern
  if (!isDomainOnly && t.includes(cleanP)) {
    return true;
  }

  return false;
}

/**
 * Evaluate URL security decision.
 * Returns:
 * {
 *   decision: 'ALLOW' | 'WARNING' | 'BLOCK',
 *   threatLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
 *   reason: string,
 *   ruleId: string | null,
 *   ruleName: string | null,
 *   features: object,
 *   heuristicScore: number
 * }
 */
export function evaluateUrlDecision(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      decision: 'ALLOW',
      threatLevel: 'SAFE',
      reason: 'Empty or invalid URL provided',
      ruleId: null,
      ruleName: null,
      features: {},
      heuristicScore: 0
    };
  }

  let parsedUrl;
  let domain = rawUrl;
  try {
    parsedUrl = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
    domain = parsedUrl.hostname.toLowerCase();
  } catch {
    domain = rawUrl.toLowerCase();
  }

  // 1. Fetch active administrative rules (cached for ultra-fast deterministic evaluation)
  const rules = getCachedRules();

  // 2. Check rules in order of priority and specificity
  for (const rule of rules) {
    let matched = false;

    if (rule.target_type === 'domain') {
      matched = matchesPattern(rule.pattern, domain, true) || matchesPattern(rule.pattern, rawUrl, false);
    } else if (rule.target_type === 'url') {
      matched = matchesPattern(rule.pattern, rawUrl, false) || matchesPattern(rule.pattern, domain, true);
    } else if (rule.target_type === 'wildcard') {
      matched = matchesPattern(rule.pattern, domain, true) || matchesPattern(rule.pattern, rawUrl, false);
    } else {
      matched = matchesPattern(rule.pattern, domain, true) || matchesPattern(rule.pattern, rawUrl, false);
    }

    if (matched) {
      let threatLevel = rule.severity || 'MEDIUM';
      if (rule.type === 'BLOCK' && (!threatLevel || threatLevel === 'LOW')) {
        threatLevel = 'HIGH';
      } else if (rule.type === 'ALLOW') {
        threatLevel = 'SAFE';
      }

      return {
        decision: rule.type, // 'ALLOW', 'WARNING', 'BLOCK'
        threatLevel,
        reason: rule.description || `Matched administrative ${rule.type} security rule (${rule.pattern})`,
        ruleId: rule.id,
        ruleName: rule.pattern,
        features: extractUrlFeatures(rawUrl),
        heuristicScore: rule.type === 'BLOCK' ? 100 : (rule.type === 'WARNING' ? 50 : 0)
      };
    }
  }

  // 3. If no administrative rule matched, run ML heuristic engine
  const heuristicResult = evaluatePhishing(rawUrl, []);
  let decision = 'ALLOW';
  let threatLevel = 'SAFE';

  if (heuristicResult.verdict === 'phishing') {
    decision = 'BLOCK';
    threatLevel = heuristicResult.score >= 85 ? 'CRITICAL' : 'HIGH';
  } else if (heuristicResult.verdict === 'suspicious') {
    decision = 'WARNING';
    threatLevel = 'MEDIUM';
  } else {
    decision = 'ALLOW';
    threatLevel = heuristicResult.score > 20 ? 'LOW' : 'SAFE';
  }

  const primaryReason = (heuristicResult.reasons && heuristicResult.reasons.length > 0)
    ? heuristicResult.reasons.join('; ')
    : 'No malicious indicators detected';

  return {
    decision,
    threatLevel,
    reason: primaryReason,
    ruleId: null,
    ruleName: heuristicResult.verdict === 'safe' ? 'ML Heuristic: Legitimate Domain' : 'ML Threat Detection Engine',
    features: heuristicResult.features || extractUrlFeatures(rawUrl),
    heuristicScore: heuristicResult.score || 0
  };
}
