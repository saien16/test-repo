/* ============================================================
   むしとりバトル — core.js（ゲームのせなか骨）
   状態・設定・共通関数・画面フロー・統合点をここに集約する。
   ほかのモジュールはここで定義した G / CONFIG / U と
   関数（genMap など）を「グローバル共有」で呼び合う。
   ※ ESモジュール化しない（import/export禁止）。
   ============================================================ */

/* ---- チューニング値（数値の正） ---- */
const CONFIG = {
  // フィールド（カメラ追従の広いマップ）
  MAP_W: 30,            // タイル横
  MAP_H: 34,            // タイル縦
  VIEW_TILE: 40,        // 描画時の1タイルpx（カメラのズーム感）
  STEP_MS: 150,         // プレイヤーが1マス進む時間
  SIGN_TARGET: 9,       // 場に出す「けはい」の目安数
  SIGN_RESPAWN_MS: 1400,// けはい再出現の待ち
  // ラウンド
  ROUND_SEC: 90,        // 1ラウンドの秒数
  // 捕獲シーン
  START_DIST: 8,        // 開始きょり(m)
  NET_HIT: { 2: 0.60, 1: 0.80, 0: 0.30 }, // きょり別あみ命中
  ALERT_FLEE: 100,      // これ以上でにげる
  ALERT_WARN: 70,       // これ以上で「けいかい！」予告
  WARN_FLEE_P: 0.45,    // 予告後の毎手にげ確率（まつ除く）
  // CPU（対戦）
  CPU_STEP_MS: { 1: 760, 2: 700, 3: 640, 4: 580, 5: 520 },
  CPU_CATCH_P: { 1: 0.35, 2: 0.45, 3: 0.55, 4: 0.65, 5: 0.75 },
  CPU_CHASE_R: 9,       // この範囲内のけはいへ追跡
  WIN_BONUS: 50,        // 対戦勝利ボーナス
};

/* ---- ゲーム全体の状態 ---- */
const G = {
  screen: 'title',
  mode: 'solo',     // 'solo' | 'vs'
  cpuLv: 1,         // 1..5（vs時）
  night: false,     // 夜フィールドか
  // ラウンド進行
  running: false,
  timeLeft: 0,
  score: 0,
  cpuScore: 0,
  caught: [],       // [{key,name,pts,mm,big}]
  cpuCaught: [],
  // フィールド
  map: null,        // {w,h,tiles:Int8Array} tiles:0草 1水 2岩 3木 4道 5砂利
  signs: [],        // [{tx,ty,key,id}]
  signSeq: 0,
  player: { tx: 0, ty: 0, x: 0, y: 0, dir: 'down', moving: false, mvT: 0, fx: 0, fy: 0, busy: false },
  cpu: { tx: 0, ty: 0, x: 0, y: 0, dir: 'down', moving: false, mvT: 0, fx: 0, fy: 0, stopUntil: 0, path: null, targetId: null },
  input: { dx: 0, dy: 0 }, // 押されている方向
  // 捕獲シーン
  cs: null,
  // 保存
  best: { solo: 0 },
  vsUnlocked: 1,    // 解放済みCPUレベル
  sfxOn: true,
};

/* ---- 共通ユーティリティ U ---- */
const U = {
  rnd: () => Math.random(),
  rint: (a, b) => Math.floor(a + Math.random() * (b - a + 1)),
  pick: (arr) => arr[Math.floor(Math.random() * arr.length)],
  chance: (p) => Math.random() < p,
  clamp: (v, a, b) => v < a ? a : (v > b ? b : v),
  // タイルが歩けるか
  walkable: (tx, ty) => {
    const m = G.map; if (!m) return false;
    if (tx < 0 || ty < 0 || tx >= m.w || ty >= m.h) return false;
    const t = m.tiles[ty * m.w + tx];
    return t === 0 || t === 4 || t === 5; // 草・道・砂利
  },
  tile: (tx, ty) => {
    const m = G.map; if (!m) return 2;
    if (tx < 0 || ty < 0 || tx >= m.w || ty >= m.h) return 2;
    return m.tiles[ty * m.w + tx];
  },
};

/* ---- DOM参照（init で埋める） ---- */
const D = {};

/* ---- 画面きりかえ ---- */
function showScreen(id) {
  G.screen = id;
  document.querySelectorAll('.screen').forEach(el => {
    el.classList.toggle('active', el.id === id);
  });
}

/* ---- 永続化（window.storage 優先・localStorage フォールバック） ---- */
function loadSave() {
  try {
    const raw = (window.storage && window.storage.getItem)
      ? window.storage.getItem('mushiBattle')
      : localStorage.getItem('mushiBattle');
    if (raw) {
      const s = JSON.parse(raw);
      if (s.best) G.best = Object.assign(G.best, s.best);
      if (s.vsUnlocked) G.vsUnlocked = s.vsUnlocked;
      if (typeof s.sfxOn === 'boolean') G.sfxOn = s.sfxOn;
    }
  } catch (e) { /* むし */ }
}
function persistSave() {
  const s = { best: G.best, vsUnlocked: G.vsUnlocked, sfxOn: G.sfxOn };
  try {
    const raw = JSON.stringify(s);
    if (window.storage && window.storage.setItem) window.storage.setItem('mushiBattle', raw);
    else localStorage.setItem('mushiBattle', raw);
  } catch (e) { /* むし */ }
}

/* ============================================================
   画面フロー
   ============================================================ */

/* タイトル → モード選択 */
function gotoModeSelect() {
  Sound.unlock();
  Sound.bgm('title');
  refreshModeSelect();
  showScreen('mode-screen');
}

function refreshModeSelect() {
  // 対戦レベルボタンの解放状態
  document.querySelectorAll('[data-cpulv]').forEach(btn => {
    const lv = +btn.dataset.cpulv;
    const locked = lv > G.vsUnlocked;
    btn.disabled = locked;
    btn.classList.toggle('locked', locked);
  });
  if (D.bestLabel) D.bestLabel.textContent = 'ソロ さいこう: ' + (G.best.solo || 0) + ' pt';
}

/* ラウンド開始（mode/cpuLv/night は呼び出し側で設定済み） */
function startRun() {
  G.running = true;
  G.score = 0; G.cpuScore = 0;
  G.caught = []; G.cpuCaught = [];
  G.timeLeft = CONFIG.ROUND_SEC;
  G.signs = []; G.signSeq = 0;
  G.input.dx = 0; G.input.dy = 0;
  G.player.busy = false;

  genMap();                 // field-cpu.js: G.map / G.signs / プレイヤー初期位置
  if (G.mode === 'vs') setupCpu(); // field-cpu.js

  updateHud();
  showScreen('field-screen');
  Sound.bgm(G.mode === 'vs' ? 'vs' : 'field');
  startField();             // field-cpu.js: rAF ループ開始

  startTimer();
}

/* 1秒タイマー */
let _timerH = null;
function startTimer() {
  stopTimer();
  _timerH = setInterval(() => {
    if (!G.running || G.player.busy) return; // 捕獲中はとめる
    G.timeLeft--;
    updateHud();
    if (G.timeLeft <= 0) endRun();
  }, 1000);
}
function stopTimer() { if (_timerH) { clearInterval(_timerH); _timerH = null; } }

/* HUD更新 */
function updateHud() {
  if (D.hudTime) D.hudTime.textContent = '⏱ ' + Math.max(0, G.timeLeft);
  if (D.hudScore) D.hudScore.textContent = '🐛 ' + G.score;
  if (D.hudCpu) {
    D.hudCpu.style.display = G.mode === 'vs' ? '' : 'none';
    D.hudCpu.textContent = '🤖 ' + G.cpuScore;
  }
}

/* 捕獲シーンから もどる。result = {caught:bool, key, name, pts, mm, big} | null */
function returnToField(result) {
  if (result && result.caught) {
    G.caught.push(result);
    G.score += result.pts;
  }
  G.player.busy = false;
  G.cs = null;
  updateHud();
  if (!G.running) return;
  showScreen('field-screen');
  Sound.bgm(G.mode === 'vs' ? 'vs' : 'field');
  startField(); // ループ再開
}

/* ラウンド終了 → リザルト */
function endRun() {
  if (!G.running) return;
  G.running = false;
  stopTimer();
  stopField();
  G.player.busy = false;

  // ソロ ベスト更新
  let win = null;
  if (G.mode === 'solo') {
    if (G.score > (G.best.solo || 0)) { G.best.solo = G.score; }
  } else {
    win = G.score >= G.cpuScore;
    if (win) {
      G.score += CONFIG.WIN_BONUS;
      // つぎのレベルを解放
      if (G.cpuLv >= G.vsUnlocked && G.vsUnlocked < 5) G.vsUnlocked++;
    }
  }
  persistSave();
  showResult(win);
  Sound.bgm('result');
}

function showResult(win) {
  const big = G.caught.filter(c => c.big).length;
  const maxMm = G.caught.reduce((m, c) => Math.max(m, c.mm || 0), 0);
  let html = '';
  if (G.mode === 'vs') {
    html += `<div class="res-banner ${win ? 'win' : 'lose'}">${win ? '🏆 かち！' : '🥲 まけ…'}</div>`;
    html += `<div class="res-vs"><span>あなた<br><b>${G.score}</b></span><span class="vsmid">VS</span><span>CPU Lv${G.cpuLv}<br><b>${G.cpuScore}</b></span></div>`;
    if (win) Sound.sfx.win(); else Sound.sfx.lose();
  } else {
    html += `<div class="res-banner win">⏱ タイムアップ！</div>`;
    html += `<div class="res-score">スコア <b>${G.score}</b> pt</div>`;
    html += `<div class="res-best">ソロ さいこう: ${G.best.solo} pt</div>`;
    Sound.sfx.win();
  }
  html += `<div class="res-stat">つかまえた: ${G.caught.length}ひき ／ でかい!! ×${big} ／ さいだい ${maxMm}mm</div>`;
  // つかまえた虫の一覧
  html += '<div class="res-list">';
  G.caught.forEach(c => {
    html += `<div class="res-bug">${bugSprite(c.key, 42)}<span>${c.name}<br>${c.mm}mm ${c.big ? '★' : ''}</span></div>`;
  });
  if (!G.caught.length) html += '<div class="res-empty">1ぴきも つかまえられなかった…</div>';
  html += '</div>';
  if (D.resultBody) D.resultBody.innerHTML = html;
  showScreen('result-screen');
}

/* ============================================================
   入力（dパッド＋キーボード）→ G.input にためる
   フィールド側がこれを読んで移動する
   ============================================================ */
function bindInput() {
  const set = (dx, dy) => { G.input.dx = dx; G.input.dy = dy; };
  const dirs = { up: [0, -1], down: [0, 1], left: [-1, 0], right: [1, 0] };
  document.querySelectorAll('[data-dir]').forEach(btn => {
    const [dx, dy] = dirs[btn.dataset.dir];
    const on = (e) => { e.preventDefault(); set(dx, dy); };
    const off = (e) => { e.preventDefault(); if (G.input.dx === dx && G.input.dy === dy) set(0, 0); };
    btn.addEventListener('touchstart', on, { passive: false });
    btn.addEventListener('touchend', off, { passive: false });
    btn.addEventListener('mousedown', on);
    btn.addEventListener('mouseup', off);
    btn.addEventListener('mouseleave', off);
  });
  // キーボード
  const keymap = { ArrowUp: 'up', ArrowDown: 'down', ArrowLeft: 'left', ArrowRight: 'right', w: 'up', s: 'down', a: 'left', d: 'right' };
  const held = new Set();
  window.addEventListener('keydown', (e) => {
    const dir = keymap[e.key]; if (!dir) return;
    held.add(dir); const [dx, dy] = dirs[dir]; set(dx, dy);
  });
  window.addEventListener('keyup', (e) => {
    const dir = keymap[e.key]; if (!dir) return;
    held.delete(dir);
    if (held.size === 0) set(0, 0);
    else { const last = [...held].pop(); const [dx, dy] = dirs[last]; set(dx, dy); }
  });
}

/* ============================================================
   初期化
   ============================================================ */
function initGame() {
  // DOM参照
  D.canvas = document.getElementById('field-canvas');
  D.hudTime = document.getElementById('hud-time');
  D.hudScore = document.getElementById('hud-score');
  D.hudCpu = document.getElementById('hud-cpu');
  D.bestLabel = document.getElementById('best-label');
  D.resultBody = document.getElementById('result-body');

  loadSave();

  // タイトル
  const startBtn = document.getElementById('btn-start');
  if (startBtn) startBtn.addEventListener('click', gotoModeSelect);

  // モード選択
  const soloBtn = document.getElementById('btn-solo');
  if (soloBtn) soloBtn.addEventListener('click', () => {
    G.mode = 'solo'; G.night = false; startRun();
  });
  document.querySelectorAll('[data-cpulv]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      G.mode = 'vs'; G.cpuLv = +btn.dataset.cpulv; G.night = (G.cpuLv >= 4);
      startRun();
    });
  });

  // リザルト → もどる
  const againBtn = document.getElementById('btn-again');
  if (againBtn) againBtn.addEventListener('click', () => { gotoModeSelect(); });

  // フィールドの「あきらめる」
  const giveBtn = document.getElementById('btn-giveup');
  if (giveBtn) giveBtn.addEventListener('click', () => { if (G.running) endRun(); });

  // サウンドトグル
  const muteBtn = document.getElementById('btn-mute');
  if (muteBtn) {
    const sync = () => { muteBtn.textContent = G.sfxOn ? '🔊' : '🔇'; };
    sync();
    muteBtn.addEventListener('click', () => {
      G.sfxOn = !G.sfxOn; Sound.setMuted(!G.sfxOn); persistSave(); sync();
    });
  }

  bindInput();
  Sound.setMuted(!G.sfxOn);
  showScreen('title-screen');
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initGame);
  else initGame();
}
