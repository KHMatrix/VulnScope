const KHAudio = (function () {
  let ctx = null;
  let enabled = false;

  function ensureCtx() {
    if (!ctx) {
      const AC = window.AudioContext || window.webkitAudioContext;
      ctx = new AC();
    }
    if (ctx.state === "suspended") ctx.resume();
    return ctx;
  }

  function tone(freq, duration, type = "sine", gainPeak = 0.08, delay = 0) {
    if (!enabled) return;
    const c = ensureCtx();
    const osc = c.createOscillator();
    const gain = c.createGain();
    osc.type = type;
    osc.frequency.value = freq;
    gain.gain.setValueAtTime(0, c.currentTime + delay);
    gain.gain.linearRampToValueAtTime(gainPeak, c.currentTime + delay + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, c.currentTime + delay + duration);
    osc.connect(gain).connect(c.destination);
    osc.start(c.currentTime + delay);
    osc.stop(c.currentTime + delay + duration + 0.02);
  }

  return {
    setEnabled(v) { enabled = v; if (v) ensureCtx(); },
    isEnabled() { return enabled; },
    click() { tone(720, 0.06, "square", 0.05); },
    scanStart() { tone(300, 0.12, "sawtooth"); tone(600, 0.12, "sawtooth", 0.06, 0.08); },
    scanComplete() { tone(500, 0.1, "sine"); tone(750, 0.12, "sine", 0.07, 0.09); tone(1000, 0.16, "sine", 0.06, 0.18); },
    warning() { tone(220, 0.18, "square", 0.07); tone(180, 0.22, "square", 0.07, 0.2); },
  };
})();
