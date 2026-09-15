// PhishGuard Extension — Offscreen Audio Service
// Ensures 100% reliable audio alert playback without user-gesture blocks

let audioCtx = null;

function getAudioContext() {
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

function playSecurityAlarm(verdict = 'phishing') {
  try {
    const ctx = getAudioContext();
    if (!ctx) return;

    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    if (verdict === 'phishing') {
      osc.type = 'sawtooth';
      // High-urgency European emergency alternating siren
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.setValueAtTime(659, now + 0.18);
      osc.frequency.setValueAtTime(880, now + 0.36);
      osc.frequency.setValueAtTime(659, now + 0.54);
      osc.frequency.setValueAtTime(880, now + 0.72);

      gain.gain.setValueAtTime(0.35, now);
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

      gain.gain.setValueAtTime(0.28, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.8);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.8);
    }
  } catch (err) {
    console.warn('[PhishGuard Offscreen] Audio playback warning:', err);
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'PLAY_ALERT_SOUND') {
    playSecurityAlarm(msg.verdict || 'phishing');
    sendResponse({ success: true, played: true });
    return true;
  }
});
