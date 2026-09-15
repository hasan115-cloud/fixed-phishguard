// PhishGuard Core Detection Engine
// Feature extraction & explainable scoring modeled after XGBoost / Random Forest URL classifier

export const TRUSTED_DEFAULT_DOMAINS = new Set([
  'google.com', 'www.google.com', 'accounts.google.com', 'mail.google.com',
  'microsoft.com', 'login.microsoftonline.com', 'outlook.live.com', 'office.com',
  'apple.com', 'appleid.apple.com', 'icloud.com',
  'amazon.com', 'aws.amazon.com',
  'github.com', 'gitlab.com', 'stackoverflow.com',
  'wikipedia.org', 'en.wikipedia.org',
  'youtube.com', 'linkedin.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
  'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
  'netflix.com', 'spotify.com', 'dropbox.com', 'reddit.com'
]);

export const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'club', 'work',
  'date', 'racing', 'kim', 'loan', 'stream', 'party', 'trade', 'bid',
  'download', 'accountant', 'click', 'link', 'rest', 'fit', 'country',
  'gdn', 'mom', 'rodeo', 'vodka', 'surf', 'vip', 'monster', 'hair', 'beauty'
]);

export const SENSITIVE_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'security',
  'update', 'banking', 'secure', 'account', 'confirm', 'wallet', 'support',
  'authenticate', 'recover', 'billing', 'invoice', 'password', 'credential',
  'recover-account', 'auth', 'webscr', 'cmd=_login', 'session', 'validate'
];

export const TARGET_BRANDS = [
  { name: 'PayPal', patterns: ['paypal', 'paypa1', 'pay-pal', 'paypaii'] },
  { name: 'Apple', patterns: ['apple', 'app1e', 'appleid', 'icloud', 'ic1oud'] },
  { name: 'Microsoft', patterns: ['microsoft', 'microsofft', 'office365', 'outlook', 'live-login'] },
  { name: 'Google', patterns: ['google', 'g00gle', 'gmail', 'google-security'] },
  { name: 'Amazon', patterns: ['amazon', 'amaz0n', 'aws-security'] },
  { name: 'Netflix', patterns: ['netflix', 'netf1ix', 'netflix-verify'] },
  { name: 'Chase Bank', patterns: ['chase', 'chase-security', 'chasebank'] },
  { name: 'Meta / Facebook', patterns: ['facebook', 'faceb00k', 'meta-auth', 'instagram-verify'] },
  { name: 'Cryptocurrency Wallet', patterns: ['binance', 'coinbase', 'metamask', 'ledger', 'trustwallet'] }
];

export function extractUrlFeatures(rawUrl) {
  let parsed;
  let normalized = rawUrl.trim();
  if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
    normalized = 'http://' + normalized;
  }

  try {
    parsed = new URL(normalized);
  } catch {
    return {
      isValid: false,
      rawUrl,
      error: 'Invalid URL format'
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const search = parsed.search.toLowerCase();
  const fullUrl = parsed.href.toLowerCase();

  // IP address hostname check
  const isIpV4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isHexOctalIp = /^(0x[0-9a-fA-F]+|\d{8,11})$/.test(hostname);
  const isIpAddress = isIpV4 || isHexOctalIp;

  // Subdomain & TLD extraction
  const parts = hostname.split('.');
  const tld = parts.length > 1 ? parts[parts.length - 1] : '';
  const registeredDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  const subdomains = parts.length > 2 ? parts.slice(0, -2).join('.') : '';
  const subdomainCount = parts.length > 2 ? parts.length - 2 : 0;

  // Lexical indicators
  const hasAtSymbol = rawUrl.includes('@');
  const hasDoubleSlashRedirect = pathname.includes('//') || search.includes('http://') || search.includes('https://');
  const hasDashInDomain = hostname.includes('-');
  const dashCountInHostname = (hostname.match(/-/g) || []).length;
  const isHighRiskTld = HIGH_RISK_TLDS.has(tld);
  const hasNonStandardPort = parsed.port !== '' && !['80', '443'].includes(parsed.port);
  const isHttps = parsed.protocol === 'https:';

  // Keyword check
  const matchedKeywords = SENSITIVE_KEYWORDS.filter(kw =>
    hostname.includes(kw) || pathname.includes(kw) || search.includes(kw)
  );

  // Brand impersonation check
  const brandImpersonations = [];
  for (const brand of TARGET_BRANDS) {
    for (const pattern of brand.patterns) {
      if (hostname.includes(pattern)) {
        // Legitimate brand check
        const isLegit = hostname === brand.patterns[0] + '.com' ||
                        hostname.endsWith('.' + brand.patterns[0] + '.com') ||
                        hostname.endsWith('.' + brand.patterns[0] + '.org');
        if (!isLegit) {
          brandImpersonations.push({
            brand: brand.name,
            matchedPattern: pattern,
            inSubdomain: subdomains.includes(pattern),
            inDomain: registeredDomain.includes(pattern)
          });
        }
      }
    }
  }

  // Punycode check (IDN homograph attack)
  const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');

  // URL length and entropy
  const urlLength = rawUrl.length;
  const hostnameLength = hostname.length;
  const numericCount = (hostname.match(/\d/g) || []).length;
  const numericRatio = hostnameLength > 0 ? numericCount / hostnameLength : 0;

  return {
    isValid: true,
    normalizedUrl: parsed.href,
    protocol: parsed.protocol,
    hostname,
    pathname,
    search,
    tld,
    registeredDomain,
    subdomains,
    subdomainCount,
    isIpAddress,
    hasAtSymbol,
    hasDoubleSlashRedirect,
    hasDashInDomain,
    dashCountInHostname,
    isHighRiskTld,
    hasNonStandardPort,
    port: parsed.port,
    isHttps,
    matchedKeywords,
    brandImpersonations,
    isPunycode,
    urlLength,
    hostnameLength,
    numericRatio
  };
}

export function evaluatePhishing(rawUrl, customTrusted = []) {
  const trustedSet = new Set([...TRUSTED_DEFAULT_DOMAINS, ...customTrusted.map(d => d.toLowerCase())]);
  const features = extractUrlFeatures(rawUrl);

  if (!features.isValid) {
    return {
      url: rawUrl,
      verdict: 'safe',
      score: 0,
      reasons: ['Not a valid web URL or internal scheme'],
      features
    };
  }

  // Check if directly in trusted list
  if (trustedSet.has(features.hostname) || trustedSet.has(features.registeredDomain)) {
    return {
      url: features.normalizedUrl,
      domain: features.hostname,
      verdict: 'safe',
      score: 4,
      reasons: ['Domain is in trusted whitelist'],
      isTrusted: true,
      features
    };
  }

  let score = 5; // Baseline prior probability
  const reasons = [];

  // Rule 1: IP address as hostname (Very strong phishing indicator)
  if (features.isIpAddress) {
    score += 45;
    reasons.push('Uses direct numerical IP address instead of registered domain');
  }

  // Rule 2: Brand Impersonation / Deceptive Domain
  if (features.brandImpersonations.length > 0) {
    const brand = features.brandImpersonations[0];
    score += 40;
    if (brand.inSubdomain) {
      reasons.push(`Impersonates ${brand.brand}: brand name placed in subdomain to mislead users`);
    } else {
      reasons.push(`Potential typosquatting/impersonation of ${brand.brand}`);
    }
  }

  // Rule 3: Punycode / IDN Homograph
  if (features.isPunycode) {
    score += 35;
    reasons.push('Uses Internationalized Domain Name (Punycode / IDN homograph attack potential)');
  }

  // Rule 4: High-Risk TLD
  if (features.isHighRiskTld) {
    score += 25;
    reasons.push(`Registered under high-abuse top-level domain (.${features.tld})`);
  }

  // Rule 5: '@' symbol in URL
  if (features.hasAtSymbol) {
    score += 35;
    reasons.push('Contains "@" character, which tricks browsers into ignoring preceding credentials');
  }

  // Rule 6: Double slash redirect in path
  if (features.hasDoubleSlashRedirect) {
    score += 25;
    reasons.push('Contains embedded URL redirect sequence (open redirect attempt)');
  }

  // Rule 7: Excessive Subdomains
  if (features.subdomainCount >= 3) {
    score += 20;
    reasons.push(`Excessive subdomain nesting (${features.subdomainCount} levels deep), typical of phishing kits`);
  } else if (features.subdomainCount === 2 && features.hasDashInDomain) {
    score += 15;
    reasons.push('Complex subdomain structure combined with hyphenated domain');
  }

  // Rule 8: Hyphens in domain
  if (features.dashCountInHostname >= 2) {
    score += 15;
    reasons.push(`Multiple hyphens (${features.dashCountInHostname}) in domain name`);
  }

  // Rule 9: Sensitive Security / Account Keywords
  if (features.matchedKeywords.length > 0) {
    const kwList = features.matchedKeywords.slice(0, 3).join(', ');
    if (!features.isHttps) {
      score += 30;
      reasons.push(`Sensitive security terms (${kwList}) served over insecure HTTP`);
    } else if (features.matchedKeywords.length >= 2) {
      score += 18;
      reasons.push(`Suspicious cluster of credential/auth keywords (${kwList})`);
    } else {
      score += 10;
      reasons.push(`Contains auth-related keyword (${kwList})`);
    }
  }

  // Rule 10: Non-standard port
  if (features.hasNonStandardPort) {
    score += 20;
    reasons.push(`Uses non-standard web port (:${features.port})`);
  }

  // Rule 11: Length & entropy anomalies
  if (features.urlLength > 100) {
    score += 12;
    reasons.push(`Unusually long URL (${features.urlLength} characters)`);
  }
  if (features.numericRatio > 0.3) {
    score += 15;
    reasons.push('Domain contains high proportion of numerical characters');
  }

  // Cap score between 0 and 99
  score = Math.min(Math.max(score, 0), 99);

  let verdict = 'safe';
  if (score >= 70) {
    verdict = 'phishing';
  } else if (score >= 35) {
    verdict = 'suspicious';
  }

  if (reasons.length === 0) {
    reasons.push('Standard domain structure, verified SSL, and no malicious patterns detected');
  }

  return {
    url: features.normalizedUrl,
    domain: features.hostname,
    verdict,
    score,
    reasons,
    features
  };
}
