/* ============================================================
   むしとりバトル — sound.js（おとエンジン / Web Audio 合成のみ）
   公開API（CONTRACT厳守）:
     Sound.unlock()            初回タッチで AudioContext 生成/再開
     Sound.setMuted(bool) / Sound.isMuted()
     Sound.bgm(name)           'title'|'field'|'vs'|'result'（多重再生しない）
     Sound.stop()              BGM停止
     Sound.sfx = { select,step,catch,miss,flee,big,win,lose,warn }
   ・外部音源ファイル禁止。合成のみ。
   ・muted時は鳴らさない。未対応/未生成でも例外を投げず no-op。
   ・トップレベルで AudioContext を即生成しない（ヘッドレス安全）。
   ============================================================ */
const Sound = (() => {
  let ac = null;            // AudioContext（unlock まで遅延生成）
  let master = null;        // マスター gain（→ リミッター → 出力）
  let musicGain = null;     // BGM 用 gain
  let sfxGain = null;       // 効果音 用 gain
  let muted = false;
  let started = false;      // ctx 生成済みか
  let unsupported = false;  // AudioContext 非対応
  let musicTimer = null;    // BGM スケジューラの timeout ハンドル
  let curBgm = null;        // いま鳴っている BGM 名（多重再生ふせぎ）

  /* ---- AudioContext を必要になってから1度だけ作る ---- */
  function ctx() {
    if (ac) return ac;
    if (unsupported) return null;
    try {
      const AC = (typeof window !== 'undefined') &&
        (window.AudioContext || window.webkitAudioContext);
      if (!AC) { unsupported = true; return null; }
      ac = new AC();
      // リミッター（音が重なっても割れないように強めに圧縮）
      const comp = ac.createDynamicsCompressor();
      comp.threshold.value = -12;
      comp.knee.value = 16;
      comp.ratio.value = 14;
      comp.attack.value = 0.003;
      comp.release.value = 0.25;
      comp.connect(ac.destination);
      master = ac.createGain(); master.gain.value = 0.62; master.connect(comp);
      musicGain = ac.createGain(); musicGain.gain.value = 0.24; musicGain.connect(master);
      sfxGain = ac.createGain(); sfxGain.gain.value = 0.5; sfxGain.connect(master);
      started = true;
    } catch (e) { unsupported = true; ac = null; return null; }
    return ac;
  }

  function resumeIfNeeded(a) {
    try { if (a && a.state === 'suspended' && a.resume) a.resume(); } catch (e) {}
  }

  /* ============================================================
     unlock：初回ユーザー操作で呼ぶ。iOS の無音アンロックも行う。
     ============================================================ */
  function unlock() {
    try {
      const a = ctx();
      if (!a) return;
      resumeIfNeeded(a);
      // iOS Safari/Chrome: 同期的に無音バッファを1回再生して解放
      try {
        const b = a.createBuffer(1, 1, 22050);
        const src = a.createBufferSource();
        src.buffer = b; src.connect(a.destination);
        if (src.start) src.start(0); else if (src.noteOn) src.noteOn(0);
      } catch (e) {}
      resumeIfNeeded(a);
    } catch (e) { /* no-op */ }
  }

  function setMuted(b) {
    muted = !!b;
    if (muted) stopBgmLoop();
    else if (curBgm) { const m = curBgm; curBgm = null; startBgm(m); } // 再開
  }
  function isMuted() { return muted; }

  /* ============================================================
     かんたんなオシレータ音（効果音の部品）
     ============================================================ */
  function tone(freq, t0, dur, type, gain, glideTo) {
    const a = ctx(); if (!a) return;
    try {
      const o = a.createOscillator(), g = a.createGain();
      o.type = type || 'sine';
      o.frequency.setValueAtTime(freq, t0);
      if (glideTo) o.frequency.exponentialRampToValueAtTime(Math.max(1, glideTo), t0 + dur);
      g.gain.setValueAtTime(0.0001, t0);
      g.gain.exponentialRampToValueAtTime(Math.max(0.0002, gain), t0 + 0.012);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
      o.connect(g); g.connect(sfxGain);
      o.start(t0); o.stop(t0 + dur + 0.03);
    } catch (e) {}
  }
  function noise(t0, dur, gain, hp) {
    const a = ctx(); if (!a) return;
    try {
      const n = Math.max(1, Math.floor(a.sampleRate * dur));
      const buf = a.createBuffer(1, n, a.sampleRate);
      const d = buf.getChannelData ? buf.getChannelData(0) : null;
      if (d) for (let i = 0; i < n; i++) d[i] = (Math.random() * 2 - 1) * (1 - i / n);
      const src = a.createBufferSource(); src.buffer = buf;
      const g = a.createGain(); g.gain.value = gain;
      const f = a.createBiquadFilter(); f.type = 'highpass'; f.frequency.value = hp || 800;
      src.connect(f); f.connect(g); g.connect(sfxGain);
      src.start(t0);
    } catch (e) {}
  }

  /* 効果音は呼ばれるたび「今」から鳴らす */
  function now() { const a = ctx(); return a ? a.currentTime : 0; }
  function guard(fn) {
    return function () {
      if (muted) return;
      const a = ctx(); if (!a) return;
      resumeIfNeeded(a);
      try { fn(); } catch (e) { /* no-op */ }
    };
  }

  const sfx = {
    // メニュー選択（ピッ）
    select: guard(() => { const t = now(); tone(660, t, 0.08, 'triangle', 0.18); }),
    // 1マス歩く（控えめ・短い）
    step:   guard(() => { const t = now(); tone(150, t, 0.045, 'square', 0.05, 120); }),
    // 捕獲成功（上昇アルペジオ）
    catch:  guard(() => { const t = now(); [523, 659, 784, 1047].forEach((f, i) => tone(f, t + i * 0.09, 0.2, 'triangle', 0.22)); }),
    // あみ はずれ（コツン下降）
    miss:   guard(() => { const t = now(); tone(300, t, 0.14, 'square', 0.14, 130); noise(t, 0.1, 0.06, 600); }),
    // 逃走（さーっと下降）
    flee:   guard(() => { const t = now(); tone(520, t, 0.42, 'sawtooth', 0.16, 110); noise(t, 0.25, 0.06, 500); }),
    // でかい！（きらきら）
    big:    guard(() => { const t = now(); [392, 523, 659, 880, 1175].forEach((f, i) => tone(f, t + i * 0.07, 0.28, 'triangle', 0.24)); noise(t, 0.3, 0.07, 3000); }),
    // 勝ち（ファンファーレ）
    win:    guard(() => { const t = now(); [523, 659, 784, 1047, 784, 1047, 1319].forEach((f, i) => tone(f, t + i * 0.11, 0.26, 'triangle', 0.24)); }),
    // 負け（しょんぼり下降）
    lose:   guard(() => { const t = now(); [392, 330, 262].forEach((f, i) => tone(f, t + i * 0.17, 0.3, 'sine', 0.2)); }),
    // 警戒予告（ピピッ）
    warn:   guard(() => { const t = now(); tone(740, t, 0.1, 'square', 0.16); tone(740, t + 0.16, 0.1, 'square', 0.16); }),
  };

  /* ============================================================
     BGM：絶対時刻スケジューラ（音割れしない四つ打ち系）
     曲ごとに テンポ・コード・リード を変える。
     ============================================================ */
  function semis(n) { return 440 * Math.pow(2, n / 12); }

  // メロディ譜 [半音オフセット(整数) or 'r'休符, 長さ(拍)]
  const MEL_TITLE = [ // わくわく長調・はずむフック
    [7, .5], [7, .5], [12, .5], [7, .5], [9, .5], [7, .5], [4, 1],
    [5, .5], [5, .5], [9, .5], [5, .5], [7, .5], [5, .5], [0, 1],
    [7, .5], [12, .5], [14, .5], [16, .5], [14, .5], [12, .5], [9, 1],
    [11, .5], [9, .5], [7, .5], [9, .5], [7, .5], [4, .5], [0, 1],
  ];
  const MEL_FIELD = [ // 明るい昼・のびやか
    [12, .5], [14, .5], [12, .5], [9, .5], [7, .5], [9, .5], [12, 1],
    [11, .5], [9, .5], [7, .5], [5, .5], [4, .5], [5, .5], [7, 1],
    [9, .5], [12, .5], [9, .5], [7, .5], [5, .5], [7, .5], [9, 1],
    [7, .5], [5, .5], [4, .5], [2, .5], [4, .5], [7, .5], [12, 1],
  ];
  const MEL_VS = [ // 緊張感・短調マイナーフック
    [0, .5], [12, .5], [0, .5], [7, .5], [3, .5], [10, .5], [3, .5], [7, .5],
    [5, .5], [12, .5], [5, .5], [10, .5], [3, .5], [7, .5], [0, 1],
    [12, .5], [11, .5], [10, .5], [7, .5], [5, .5], [7, .5], [10, .5], [11, .5],
    [12, .5], [7, .5], [3, .5], [0, .5], [0, 1], [12, 1],
  ];
  const MEL_RESULT = [ // ファンファーレ風
    [0, 1], [4, .5], [7, .5], [12, 2],
    [7, .5], [12, .5], [16, 1], [12, 1],
    [9, 1], [11, .5], [12, .5], [16, 2],
  ];

  // トラック定義（root=基準周波数, chords=4拍ごと進行）
  const TRACKS = {
    title:  { bpm: 126, root: 294, mel: MEL_TITLE,  drums: true,  chords: [[0, 4, 7], [5, 9, 12], [-3, 0, 4], [2, 5, 9]] },
    field:  { bpm: 132, root: 330, mel: MEL_FIELD,  drums: true,  chords: [[0, 4, 7], [7, 11, 14], [5, 9, 12], [2, 5, 9]] },
    vs:     { bpm: 142, root: 277, mel: MEL_VS,     drums: true,  chords: [[0, 3, 7], [-2, 1, 5], [5, 8, 12], [-1, 3, 7]] },
    result: { bpm: 120, root: 294, mel: MEL_RESULT, drums: false, chords: [[0, 4, 7], [0, 4, 7], [5, 9, 12], [7, 11, 14]] },
  };

  // シンセリード（矩形＋ノコギリ・フィルタで張りのある音）
  function synthLead(a, freq, t, dur, vol) {
    try {
      const o1 = a.createOscillator(), o2 = a.createOscillator();
      const g = a.createGain(), f = a.createBiquadFilter();
      o1.type = 'square'; o2.type = 'sawtooth';
      o1.frequency.setValueAtTime(freq, t);
      o2.frequency.setValueAtTime(freq * 1.006, t);
      f.type = 'lowpass'; f.Q.value = 6;
      f.frequency.setValueAtTime(3000, t);
      f.frequency.exponentialRampToValueAtTime(900, t + dur * 0.9);
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(vol, t + 0.01);
      g.gain.setValueAtTime(vol, t + dur * 0.6);
      g.gain.exponentialRampToValueAtTime(0.0001, t + dur * 0.96);
      o1.connect(f); o2.connect(f); f.connect(g); g.connect(musicGain);
      o1.start(t); o2.start(t); o1.stop(t + dur); o2.stop(t + dur);
    } catch (e) {}
  }
  // サブベース（丸い低音）
  function subBass(a, freq, t, dur, vol) {
    try {
      const o = a.createOscillator(), o2 = a.createOscillator(), g = a.createGain();
      o.type = 'sine'; o2.type = 'triangle';
      o.frequency.setValueAtTime(freq, t); o2.frequency.setValueAtTime(freq, t);
      const g2 = a.createGain(); g2.gain.value = 0.25;
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(vol, t + 0.02);
      g.gain.setValueAtTime(vol, t + dur * 0.7);
      g.gain.exponentialRampToValueAtTime(0.0001, t + dur * 0.95);
      o.connect(g); o2.connect(g2); g2.connect(g); g.connect(musicGain);
      o.start(t); o2.start(t); o.stop(t + dur); o2.stop(t + dur);
    } catch (e) {}
  }
  // キック（四つ打ち）
  function kick(a, t) {
    try {
      const o = a.createOscillator(), g = a.createGain();
      o.type = 'sine';
      o.frequency.setValueAtTime(165, t);
      o.frequency.exponentialRampToValueAtTime(48, t + 0.1);
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.55, t + 0.006);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.2);
      o.connect(g); g.connect(musicGain);
      o.start(t); o.stop(t + 0.22);
    } catch (e) {}
  }
  // ハイハット
  function hat(a, t, open) {
    try {
      const dur = open ? 0.1 : 0.04;
      const n = Math.max(1, Math.floor(a.sampleRate * dur));
      const buf = a.createBuffer(1, n, a.sampleRate);
      const d = buf.getChannelData ? buf.getChannelData(0) : null;
      if (d) for (let i = 0; i < n; i++) d[i] = (Math.random() * 2 - 1) * (1 - i / n);
      const src = a.createBufferSource(); src.buffer = buf;
      const f = a.createBiquadFilter(); f.type = 'highpass'; f.frequency.value = open ? 7000 : 5000;
      const g = a.createGain(); g.gain.value = open ? 0.05 : 0.06;
      src.connect(f); f.connect(g); g.connect(musicGain); src.start(t);
    } catch (e) {}
  }

  function startBgm(name) {
    const a = ctx(); if (!a) { curBgm = name; return; }
    if (curBgm === name && musicTimer) return; // すでに同じ曲が鳴っている
    curBgm = name;
    stopBgmLoop();                              // 前を必ず止める（多重再生ふせぎ）
    if (muted || !name) return;
    const tr = TRACKS[name]; if (!tr) return;
    resumeIfNeeded(a);

    const beat = 60 / tr.bpm;
    const rootSemi = 12 * Math.log2(tr.root / 440);
    let mi = 0;        // メロディ index
    let beatPos = 0;   // 何拍目か
    let nextTime = a.currentTime + 0.12;

    const tick = () => {
      // 鳴らす条件が崩れていたら止める
      if (muted || curBgm !== name) return;
      resumeIfNeeded(a);
      try {
        const nowT = a.currentTime;
        // タブ復帰などで大きく遅れていたら追いつかせる（音の重なり防止）
        if (nextTime < nowT + 0.02) nextTime = nowT + 0.06;
        const t = nextTime;
        const note = tr.mel[mi % tr.mel.length];
        const dur = note[1] * beat;
        const chord = tr.chords[Math.floor(beatPos / 4) % tr.chords.length];

        // 主旋律＋1オクターブ下を薄く
        if (note[0] !== 'r') {
          synthLead(a, semis(rootSemi + note[0]), t, dur * 0.95, 0.24);
          synthLead(a, semis(rootSemi + note[0] - 12), t, dur * 0.9, 0.07);
        }
        // 8分アルペジオ（コードを刻む＝テクノの推進力）
        const eighth = beat / 2;
        const steps = Math.max(1, Math.round(note[1] / 0.5));
        for (let k = 0; k < steps; k++) {
          const an = chord[(beatPos * 2 + k) % chord.length];
          synthLead(a, semis(rootSemi + an + 12), t + k * eighth, eighth * 0.7, 0.06);
        }
        // ベース＋ドラム（拍ごと）
        const beats = Math.max(1, Math.round(note[1]));
        for (let b = 0; b < beats; b++) {
          const bt = t + b * beat;
          const rootNote = chord[0];
          subBass(a, semis(rootSemi + rootNote - 24), bt, beat * 0.48, 0.24);
          if (tr.drums) {
            kick(a, bt);                 // 四つ打ち
            hat(a, bt, false);
            hat(a, bt + beat * 0.5, true); // ウラはオープン
          }
          beatPos++;
        }
        mi++;
        nextTime += dur;
      } catch (e) { /* このティックは捨てる */ }
      // 実時刻に合わせて次を予約
      let waitMs = 60;
      try { waitMs = Math.max(10, (nextTime - a.currentTime - 0.05) * 1000); } catch (e) {}
      if (!isFinite(waitMs)) waitMs = 60;
      musicTimer = setTimeout(tick, waitMs);
    };
    tick();
  }

  function stopBgmLoop() {
    if (musicTimer) { try { clearTimeout(musicTimer); } catch (e) {} musicTimer = null; }
  }
  function bgm(name) {
    try { startBgm(name); } catch (e) { /* no-op */ }
  }
  function stop() {
    curBgm = null;
    stopBgmLoop();
  }

  return {
    unlock,
    setMuted, isMuted,
    bgm, stop,
    sfx,
  };
})();
