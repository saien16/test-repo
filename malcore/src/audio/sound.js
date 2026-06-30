/* audio/sound.js — マルこれ おとエンジン（Web Audio 合成のみ）
   公開API:
     Sound.unlock()                初回タッチで AudioContext 生成/再開
     Sound.setMuted(bool)/isMuted()
     Sound.play(name)              'select'|'strike'|'crit'|'cutin'|'win'|'lose'|'warn'
   ・外部音源ファイル禁止。合成のみ。muted時/未対応時は no-op（ヘッドレス安全）。
   ・トップレベルで AudioContext を即生成しない。 */
const Sound = (() => {
  let ac = null, master = null, bgmGain = null, muted = false, unsupported = false;
  let bgmTimer = null, bstep = 0, btime = 0;

  function ctx() {
    if (ac) return ac;
    if (unsupported) return null;
    try {
      const AC = (typeof window !== 'undefined') && (window.AudioContext || window.webkitAudioContext);
      if (!AC) { unsupported = true; return null; }
      ac = new AC();
      const comp = ac.createDynamicsCompressor();
      comp.threshold.value = -12; comp.knee.value = 16; comp.ratio.value = 14;
      comp.attack.value = 0.003; comp.release.value = 0.25; comp.connect(ac.destination);
      master = ac.createGain(); master.gain.value = 0.55; master.connect(comp);
      bgmGain = ac.createGain(); bgmGain.gain.value = muted ? 0 : 0.42; bgmGain.connect(master);
    } catch (e) { unsupported = true; ac = null; return null; }
    return ac;
  }

  function resume(a) { try { if (a && a.state === 'suspended' && a.resume) a.resume(); } catch (e) {} }

  function unlock() {
    const a = ctx(); if (!a) return; resume(a);
    try {
      const b = a.createBuffer(1, 1, 22050); const s = a.createBufferSource();
      s.buffer = b; s.connect(a.destination); (s.start ? s.start(0) : s.noteOn && s.noteOn(0));
    } catch (e) {}
    resume(a);
  }

  /* ---- 1音（発振器→ゲインのエンベロープ）---- */
  function tone(opt) {
    const a = ctx(); if (!a || muted) return;
    resume(a);
    const t0 = a.currentTime + (opt.delay || 0);
    const o = a.createOscillator(), g = a.createGain();
    o.type = opt.type || 'square';
    o.frequency.setValueAtTime(opt.f0, t0);
    if (opt.f1 != null) o.frequency.exponentialRampToValueAtTime(Math.max(1, opt.f1), t0 + opt.dur);
    const peak = opt.gain != null ? opt.gain : 0.5;
    g.gain.setValueAtTime(0.0001, t0);
    g.gain.exponentialRampToValueAtTime(peak, t0 + 0.008);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + opt.dur);
    o.connect(g); g.connect(master);
    o.start(t0); o.stop(t0 + opt.dur + 0.02);
  }

  /* ---- 短いノイズ（破裂・撃破の芯）---- */
  function noise(dur, gain, delay) {
    const a = ctx(); if (!a || muted) return;
    resume(a);
    const t0 = a.currentTime + (delay || 0);
    const n = Math.floor(a.sampleRate * dur);
    const buf = a.createBuffer(1, n, a.sampleRate);
    const d = buf.getChannelData(0);
    // 疑似乱数（Math.random不使用環境でも動くよう簡易LCG）
    let s = 1234567;
    for (let i = 0; i < n; i++) { s = (s * 1103515245 + 12345) & 0x7fffffff; d[i] = (s / 0x3fffffff - 1) * (1 - i / n); }
    const src = a.createBufferSource(); src.buffer = buf;
    const g = a.createGain(); g.gain.value = gain != null ? gain : 0.4;
    src.connect(g); g.connect(master); src.start(t0);
  }

  /* ============ BGM（テクノ系・128BPM・16小節＝ちょうど30秒でループ）============ */
  const BPM = 128, STEP = 60 / BPM / 4, STEPS = 16 * 16; // 16th音符 / 16小節
  const roots = [45, 41, 48, 43];                         // コード根音 Am F C G（4小節ごと）
  const chords = [[57, 60, 64], [53, 57, 60], [48, 52, 55], [55, 59, 62]];
  function mtof(m) { return 440 * Math.pow(2, (m - 69) / 12); }

  function bvoice(type, freq, t, dur, gain) {
    const o = ac.createOscillator(), g = ac.createGain();
    o.type = type; o.frequency.value = freq;
    g.gain.setValueAtTime(0.0001, t);
    g.gain.exponentialRampToValueAtTime(gain, t + 0.005);
    g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
    o.connect(g); g.connect(bgmGain); o.start(t); o.stop(t + dur + 0.02);
  }
  function bkick(t) {
    const o = ac.createOscillator(), g = ac.createGain();
    o.type = 'sine'; o.frequency.setValueAtTime(150, t); o.frequency.exponentialRampToValueAtTime(45, t + 0.12);
    g.gain.setValueAtTime(0.9, t); g.gain.exponentialRampToValueAtTime(0.0001, t + 0.18);
    o.connect(g); g.connect(bgmGain); o.start(t); o.stop(t + 0.2);
  }
  function bhat(t, gain) {
    const n = Math.floor(ac.sampleRate * 0.03), buf = ac.createBuffer(1, n, ac.sampleRate), d = buf.getChannelData(0);
    let s = 98765; for (let i = 0; i < n; i++) { s = (s * 1103515245 + 12345) & 0x7fffffff; d[i] = (s / 0x3fffffff - 1) * (1 - i / n); }
    const src = ac.createBufferSource(); src.buffer = buf;
    const hp = ac.createBiquadFilter(); hp.type = 'highpass'; hp.frequency.value = 7000;
    const g = ac.createGain(); g.gain.value = gain;
    src.connect(hp); hp.connect(g); g.connect(bgmGain); src.start(t);
  }
  function bgmSchedule() {
    if (!ac) return;
    const ahead = ac.currentTime + 0.12;
    while (btime < ahead) {
      if (!muted) {
        const s = bstep % STEPS, bar = (s / 16) | 0, inBar = s % 16, ci = ((bar / 4) | 0) % 4;
        if (inBar % 4 === 0) bkick(btime);                                   // 四つ打ちキック
        if (inBar % 2 === 1) bhat(btime, inBar % 8 === 7 ? 0.18 : 0.10);     // オフビートのハット
        if (inBar % 2 === 0) bvoice('sawtooth', mtof(roots[ci] + (inBar % 8 === 0 ? 0 : 12)), btime, STEP * 1.4, 0.30); // ベース
        if (bar % 8 >= 4) bvoice('square', mtof(chords[ci][inBar % 3] + 12), btime, STEP * 0.8, 0.12); // 後半でアルペジオ
        if (inBar === 0) chords[ci].forEach(m => bvoice('triangle', mtof(m), btime, STEP * 14, 0.045)); // 小節頭のパッド
      }
      btime += STEP; bstep++;
    }
  }

  const SFX = {
    select() { tone({ type: 'square', f0: 520, f1: 700, dur: 0.07, gain: 0.25 }); },
    hit() { noise(0.10, 0.4); tone({ type: 'sine', f0: 120, f1: 48, dur: 0.16, gain: 0.4 }); }, // 被弾
    shield() { // 敵防御の提示（重く低い二音）
      tone({ type: 'square', f0: 330, dur: 0.10, gain: 0.22 });
      tone({ type: 'square', f0: 247, dur: 0.18, gain: 0.26, delay: 0.09 });
    },
    strike() { // 必殺技ヒット: 下降ズァッ＋ノイズの芯
      noise(0.12, 0.35);
      tone({ type: 'sawtooth', f0: 320, f1: 80, dur: 0.18, gain: 0.45 });
    },
    crit() { // 会心: ヒット＋上昇キラッ
      SFX.strike();
      tone({ type: 'square', f0: 880, f1: 1760, dur: 0.16, gain: 0.32, delay: 0.05 });
      tone({ type: 'triangle', f0: 1320, f1: 2200, dur: 0.14, gain: 0.22, delay: 0.10 });
    },
    cutin() { // カットイン発動: 上昇スイープ
      tone({ type: 'sawtooth', f0: 200, f1: 1200, dur: 0.22, gain: 0.3 });
    },
    warn() { tone({ type: 'square', f0: 300, f1: 160, dur: 0.18, gain: 0.3 }); },
    win() { // 勝利: 上昇アルペジオ
      [523, 659, 784, 1047].forEach((f, i) => tone({ type: 'triangle', f0: f, dur: 0.22, gain: 0.3, delay: i * 0.12 }));
    },
    lose() { // 敗北: 下降
      [392, 311, 247].forEach((f, i) => tone({ type: 'sawtooth', f0: f, f1: f * 0.7, dur: 0.3, gain: 0.3, delay: i * 0.16 }));
    },
  };

  function play(name) { try { (SFX[name] || (() => {}))(); } catch (e) {} }

  function bgm() {
    const a = ctx(); if (!a) return; resume(a);
    if (bgmTimer) return;                 // 多重再生しない
    bstep = 0; btime = a.currentTime + 0.1;
    try { bgmSchedule(); bgmTimer = setInterval(bgmSchedule, 25); } catch (e) {}
  }
  function stopBgm() { if (bgmTimer) { clearInterval(bgmTimer); bgmTimer = null; } }

  return {
    unlock,
    setMuted(b) { muted = !!b; if (bgmGain) bgmGain.gain.value = muted ? 0 : 0.42; },
    isMuted() { return muted; },
    play, bgm, stopBgm,
  };
})();

if (typeof globalThis !== 'undefined') globalThis.Sound = Sound;
