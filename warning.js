// PhishGuard Enterprise Warning Screen Handler

(function () {
  'use strict';

  const params = new URLSearchParams(window.location.search);
  const rawUrl = params.get('url') || 'http://paypal-security-update.account-verify.xyz/signin';
  const score = params.get('score') || '95';
  const verdict = params.get('verdict') || 'phishing';
  const matchedRule = params.get('rule');
  const clientId = params.get('clientId');
  const allowBypass = params.get('allowBypass') === '1';

  let reasons = [];
  const singleReason = params.get('reason');
  const rawReasons = params.get('reasons');

  if (singleReason) {
    reasons = singleReason.split(';').map(s => s.trim()).filter(Boolean);
  } else if (rawReasons) {
    try {
      reasons = JSON.parse(rawReasons);
    } catch {
      reasons = rawReasons.split('|').filter(Boolean);
    }
  }

  if (reasons.length === 0) {
    if (verdict === 'suspicious') {
      reasons = [
        'Contains sensitive authentication keywords in URL path',
        'Uncommon domain pattern with elevated risk profile'
      ];
    } else {
      reasons = [
        'Matched administrative security block policy or malicious reputation list',
        'Credential harvesting pattern identified in navigation destination',
        'Deceptive domain structure detected'
      ];
    }
  }

  const blockedUrlEl = document.getElementById('blockedUrl');
  const scorePillEl = document.getElementById('scorePill');
  const rulePillEl = document.getElementById('rulePill');
  const clientPillEl = document.getElementById('clientPill');
  const timePillEl = document.getElementById('timePill');
  const reasonsBlockEl = document.getElementById('reasonsBlock');
  const reasonsListEl = document.getElementById('reasonsList');
  const btnBackEl = document.getElementById('btnBack');
  const btnProceedEl = document.getElementById('btnProceed');
  const policyLockEl = document.getElementById('policyLock');

  if (blockedUrlEl) blockedUrlEl.textContent = rawUrl;

  const scoreNum = parseInt(score, 10) || 90;
  let threatLevelText = 'Threat Level: HIGH';
  if (scoreNum >= 90) threatLevelText = 'Threat Level: CRITICAL';
  else if (scoreNum >= 40) threatLevelText = 'Threat Level: MEDIUM';
  else threatLevelText = 'Threat Level: LOW';

  if (scorePillEl) scorePillEl.textContent = `${threatLevelText} (${scoreNum}/100)`;

  if (rulePillEl && matchedRule) {
    rulePillEl.textContent = `Rule: ${matchedRule}`;
    rulePillEl.style.display = 'inline-block';
  }

  if (clientPillEl && clientId) {
    clientPillEl.textContent = `System: ${clientId}`;
    clientPillEl.style.display = 'inline-block';
  }

  if (timePillEl) {
    timePillEl.textContent = `Blocked: ${new Date().toLocaleTimeString()}`;
  }

  if (verdict === 'suspicious') {
    document.body.classList.add('suspicious');
    document.title = 'PhishGuard — Suspicious Site Warning';
    const h1 = document.getElementById('warningHeading');
    if (h1) h1.textContent = 'Suspicious Site Flagged';
    const icon = document.getElementById('warningIcon');
    if (icon) icon.textContent = '⚠️';
    const subtitle = document.getElementById('warningSubtitle');
    if (subtitle) {
      subtitle.textContent = 'PhishGuard has flagged this website as potentially suspicious. Proceed with extreme caution.';
    }
  }

  if (reasonsListEl && reasons.length > 0) {
    reasonsBlockEl.style.display = 'block';
    reasonsListEl.innerHTML = '';
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      reasonsListEl.appendChild(li);
    });
  }

  // Bypass policy enforcement
  if (allowBypass && btnProceedEl) {
    btnProceedEl.style.display = 'inline-block';
    btnProceedEl.addEventListener('click', () => {
      const confirmed = window.confirm(
        'SECURITY WARNING: You are proceeding to a high-risk website. Do not enter passwords or credentials.\n\nProceed anyway?'
      );
      if (confirmed) {
        window.location.href = rawUrl;
      }
    });
  } else {
    if (btnProceedEl) btnProceedEl.style.display = 'none';
    if (policyLockEl) policyLockEl.style.display = 'block';
  }

  if (btnBackEl) {
    btnBackEl.addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'about:blank';
      }
    });
  }

  // --- Real Audible Alarm & Notification Bell Behavior ---
  const alertBellBarEl = document.getElementById('alertBellBar');
  const bellIconEl = document.getElementById('bellIcon');
  const bellTextEl = document.getElementById('bellText');
  const btnSoundControlEl = document.getElementById('btnSoundControl');

  let audioCtx = null;
  let isSoundMuted = false;
  let hasUserInteracted = false;

  function initAudioContext() {
    if (!audioCtx) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (AudioContextClass) {
        audioCtx = new AudioContextClass();
      }
    }
    if (audioCtx && audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
    return audioCtx;
  }

  function playSecurityAlarm() {
    if (isSoundMuted) return;

    try {
      const ctx = initAudioContext();
      if (!ctx) return;

      if (ctx.state === 'suspended') {
        // Autoplay policy prevented immediate playback until user interaction
        if (btnSoundControlEl) {
          btnSoundControlEl.textContent = '🔇 Click to Sound Alarm';
          btnSoundControlEl.style.background = '#f59e0b';
        }
        if (bellTextEl) {
          bellTextEl.textContent = 'SECURITY ALERT: Click anywhere to play audio alarm';
        }
        return;
      }

      // Autoplay succeeded or user interacted
      if (btnSoundControlEl) {
        btnSoundControlEl.textContent = '🔊 Alarm Active';
        btnSoundControlEl.style.background = verdict === 'suspicious' ? '#d97706' : '#dc3545';
      }
      if (bellTextEl) {
        bellTextEl.textContent = verdict === 'suspicious'
          ? 'SUSPICIOUS THREAT ALARM TRIGGERED'
          : 'AUDIBLE SECURITY THREAT ALARM TRIGGERED';
      }
      if (bellIconEl) {
        bellIconEl.classList.add('bell-ringing');
      }

      // Play unmistakable multi-tone security siren
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      if (verdict === 'phishing') {
        osc.type = 'sawtooth';
        // Alternating European-style security emergency siren (880Hz -> 659Hz -> 880Hz -> 659Hz)
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.setValueAtTime(659, now + 0.2);
        osc.frequency.setValueAtTime(880, now + 0.4);
        osc.frequency.setValueAtTime(659, now + 0.6);
        osc.frequency.setValueAtTime(880, now + 0.8);

        gain.gain.setValueAtTime(0.28, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 1.1);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now);
        osc.stop(now + 1.1);
      } else {
        // Suspicious warning chime
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(520, now);
        osc.frequency.setValueAtTime(680, now + 0.2);
        osc.frequency.setValueAtTime(520, now + 0.4);

        gain.gain.setValueAtTime(0.25, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 0.8);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now);
        osc.stop(now + 0.8);
      }
    } catch (e) {
      console.warn('[PhishGuard] Audio alert notice:', e);
    }
  }

  // Sound control toggle button
  if (btnSoundControlEl) {
    btnSoundControlEl.addEventListener('click', (e) => {
      e.stopPropagation();
      initAudioContext();
      isSoundMuted = !isSoundMuted;
      if (isSoundMuted) {
        btnSoundControlEl.textContent = '🔇 Sound Muted';
        btnSoundControlEl.style.background = '#4b5563';
        if (bellIconEl) bellIconEl.classList.remove('bell-ringing');
      } else {
        btnSoundControlEl.textContent = '🔊 Alarm Active';
        btnSoundControlEl.style.background = verdict === 'suspicious' ? '#d97706' : '#dc3545';
        if (bellIconEl) bellIconEl.classList.add('bell-ringing');
        playSecurityAlarm();
      }
    });
  }

  // Attempt to play immediately
  try {
    playSecurityAlarm();
  } catch {}

  // Fallback to guarantee audio triggers on any first user gesture if restricted by browser autoplay policy
  const onUserGesture = () => {
    if (hasUserInteracted) return;
    hasUserInteracted = true;
    const ctx = initAudioContext();
    if (ctx) {
      playSecurityAlarm();
    }
  };

  window.addEventListener('click', onUserGesture, { once: true });
  window.addEventListener('keydown', onUserGesture, { once: true });
  window.addEventListener('pointerdown', onUserGesture, { once: true });
})();
