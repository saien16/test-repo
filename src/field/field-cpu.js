/* ============================================================
   むしとりバトル — field-cpu.js（フィールド＆CPU対戦）
   マップせいせい・たんさく・カメラ追従の立体えがき・CPUライバルを ぜんぶ ここで。
   core.js の G / CONFIG / U / D / enterCatch / updateHud と、
   bugs.js の BUGS / pickSpecies、render/tiles.js の Tiles を つかう。
   ※ import/export しない。関数宣言で genMap/startField/stopField/setupCpu/cpuTick をだす。
   tiles.js（Tiles）が さきに 連結されている まえてい。Tiles参照は ループ内（実行時）だけ。
   ============================================================ */

/* タイルのいみ（tiles）: 0草 / 1水 / 2崖(壁) / 3森(壁) / 4道 / 5砂利 — 歩けるのは 0/4/5
   かざり（deco・歩けるタイルの上だけ）: 0なし / 1花 / 2せいたか草 / 3小石 / 4丸太 / 5きのこ */

/* タイルの ピクセルサイズ＝カメラのズーム感。VIEW_TILE を そのまま タイルpx にする */
function _ts() { return CONFIG.VIEW_TILE; }              // = 40px
function _mapPixW() { return _ts() * CONFIG.MAP_W; }
function _mapPixH() { return _ts() * CONFIG.MAP_H; }

/* タイル中心の「ワールド」ピクセル座標（カメラまえ） */
function _tileCx(tx) { return tx * _ts() + _ts() / 2; }
function _tileCy(ty) { return ty * _ts() + _ts() / 2; }

/* canvas の ろんり（CSS）サイズ */
const VIEW_W = 420, VIEW_H = 600;

/* ============================================================
   マップせいせい（30×34・しぜんな ちけい）
   ============================================================ */
function genMap() {
  const W = CONFIG.MAP_W, H = CONFIG.MAP_H;
  const tiles = new Int8Array(W * H);
  const deco = new Int8Array(W * H);
  const at = (x, y) => y * W + x;
  const inBounds = (x, y) => x >= 0 && y >= 0 && x < W && y < H;

  // ぜんめん 草 でうめる
  tiles.fill(0);

  // そとわくは 森（3）で かこむ
  for (let x = 0; x < W; x++) { tiles[at(x, 0)] = 3; tiles[at(x, H - 1)] = 3; }
  for (let y = 0; y < H; y++) { tiles[at(0, y)] = 3; tiles[at(W - 1, y)] = 3; }

  // ---- うねる 川（1）を よこに わたす。とちゅう 1〜2か所「はし＝道(4)」で つうろを のこす ----
  const riverRows = [];
  {
    const cands = [];
    for (let y = 5; y < H - 5; y++) cands.push(y);
    const want = U.rint(2, 3);
    for (let i = 0; i < want && cands.length; i++) {
      const idx = U.rint(0, cands.length - 1);
      const ry = cands[idx];
      for (let k = cands.length - 1; k >= 0; k--) if (Math.abs(cands[k] - ry) < 4) cands.splice(k, 1);
      riverRows.push(ry);
    }
  }
  for (const ry of riverRows) {
    // うねうね する: 行を サインで すこし 上下させ、はばも 1〜2 で ゆらす
    let phase = U.rnd() * 6.28;
    for (let x = 1; x < W - 1; x++) {
      const wob = Math.round(Math.sin(phase + x * 0.5) * 1.4);
      const cy = U.clamp(ry + wob, 1, H - 2);
      const half = U.rnd() < 0.4 ? 1 : 0; // ところどころ はばひろ
      for (let dy = -half; dy <= half; dy++) {
        const yy = U.clamp(cy + dy, 1, H - 2);
        if (tiles[at(x, yy)] !== 3) tiles[at(x, yy)] = 1;
      }
    }
    // はし（道）を 1〜2か所
    const gaps = U.rint(1, 2);
    for (let g = 0; g < gaps; g++) {
      const gx = U.rint(3, W - 4);
      for (let y = 1; y < H - 1; y++) if (tiles[at(gx, y)] === 1) tiles[at(gx, y)] = 4;
    }
  }

  // ---- 湖／池（1）を 1〜2こ おく（だ円っぽい かたまり） ----
  {
    const ponds = U.rint(1, 2);
    for (let i = 0; i < ponds; i++) {
      const cx = U.rint(4, W - 5), cy = U.rint(6, H - 7);
      const rx = U.rint(2, 4), ry = U.rint(2, 3);
      for (let y = cy - ry; y <= cy + ry; y++) for (let x = cx - rx; x <= cx + rx; x++) {
        if (!inBounds(x, y) || x === 0 || y === 0 || x === W - 1 || y === H - 1) continue;
        const nx = (x - cx) / (rx + 0.5), ny = (y - cy) / (ry + 0.5);
        if (nx * nx + ny * ny <= 1 && tiles[at(x, y)] !== 3) tiles[at(x, y)] = 1;
      }
    }
  }

  // ---- 崖の 尾根（2）で 高低差。たてに 1〜2ほん。すきまを 砂利(5) で あける ----
  {
    const want = U.rint(1, 2);
    for (let i = 0; i < want; i++) {
      const rx = U.rint(4, W - 5);
      let phase = U.rnd() * 6.28;
      for (let y = 1; y < H - 1; y++) {
        const wob = Math.round(Math.sin(phase + y * 0.45) * 1.2);
        const xx = U.clamp(rx + wob, 1, W - 2);
        if (tiles[at(xx, y)] === 1 || tiles[at(xx, y)] === 4) continue; // 川/はし は のこす
        if (tiles[at(xx, y)] !== 3) tiles[at(xx, y)] = 2;
      }
      // すきまを 1〜2か所 砂利で あける
      const gaps = U.rint(1, 2);
      for (let g = 0; g < gaps; g++) {
        const gy = U.rint(2, H - 3);
        for (let y = gy; y < H - 1; y++) { // たてに ちかい 崖を いくつか けずる
          let cleared = false;
          for (let x = 1; x < W - 1; x++) if (tiles[at(x, y)] === 2) { tiles[at(x, y)] = 5; cleared = true; break; }
          if (cleared) break;
        }
      }
    }
  }

  // ---- 森の かたまり（3）を 2〜4こ ちらす（まるい くさむら状） ----
  {
    const blobs = U.rint(2, 4);
    for (let i = 0; i < blobs; i++) {
      const cx = U.rint(3, W - 4), cy = U.rint(3, H - 4);
      const r = U.rint(1, 3);
      for (let y = cy - r; y <= cy + r; y++) for (let x = cx - r; x <= cx + r; x++) {
        if (!inBounds(x, y) || x === 0 || y === 0 || x === W - 1 || y === H - 1) continue;
        const dd = (x - cx) * (x - cx) + (y - cy) * (y - cy);
        if (dd <= r * r && tiles[at(x, y)] === 0 && U.rnd() < 0.8) tiles[at(x, y)] = 3;
      }
    }
  }

  // ---- 道(4)／砂利(5) の こみち を ちらす（歩けるところを へらしすぎない） ----
  for (let n = 0; n < Math.floor(W * H * 0.05); n++) {
    const x = U.rint(1, W - 2), y = U.rint(1, H - 2);
    if (tiles[at(x, y)] !== 0) continue;
    tiles[at(x, y)] = U.pick([4, 5]); // 道 or 砂利（どちらも歩ける）
  }

  G.map = { w: W, h: H, tiles, deco };

  // ---- れんけつせいを ほしょう（壁配置の あとで BFS、孤立は 砂利の こみちで つなぐ）----
  const isWalk = (x, y) => {
    if (!inBounds(x, y)) return false;
    const t = tiles[at(x, y)];
    return t === 0 || t === 4 || t === 5;
  };
  const DD = [[1, 0], [-1, 0], [0, 1], [0, -1]];

  // コンポーネントを みつける
  const comp = new Int16Array(W * H).fill(-1);
  const comps = [];
  for (let y = 1; y < H - 1; y++) for (let x = 1; x < W - 1; x++) {
    if (!isWalk(x, y) || comp[at(x, y)] !== -1) continue;
    const id = comps.length;
    const cells = [];
    const q = [[x, y]]; let head = 0;
    comp[at(x, y)] = id;
    while (head < q.length) {
      const [cx, cy] = q[head++];
      cells.push([cx, cy]);
      for (const [dx, dy] of DD) {
        const nx = cx + dx, ny = cy + dy;
        if (isWalk(nx, ny) && comp[at(nx, ny)] === -1) { comp[at(nx, ny)] = id; q.push([nx, ny]); }
      }
    }
    comps.push(cells);
  }

  // ほんたい＝いちばん 大きい かたまり
  let mainId = 0;
  for (let i = 1; i < comps.length; i++) if (comps[i].length > comps[mainId].length) mainId = i;

  // ほかの かたまりを 本体へ 砂利の こみちで つなぐ
  for (let i = 0; i < comps.length; i++) {
    if (i === mainId || comps.length === 0) continue;
    let bestA = null, bestB = null, bd = 1e9;
    const sample = comps[i], mainCells = comps[mainId];
    const stepA = Math.max(1, (sample.length / 24) | 0);
    const stepB = Math.max(1, (mainCells.length / 40) | 0);
    for (let a = 0; a < sample.length; a += stepA) {
      const [ax, ay] = sample[a];
      for (let b = 0; b < mainCells.length; b += stepB) {
        const [bx, by] = mainCells[b];
        const d = Math.abs(ax - bx) + Math.abs(ay - by);
        if (d < bd) { bd = d; bestA = [ax, ay]; bestB = [bx, by]; }
      }
    }
    if (!bestA) continue;
    let [cx, cy] = bestA;
    const [tx2, ty2] = bestB;
    const carve = (x, y) => {
      if (x <= 0 || y <= 0 || x >= W - 1 || y >= H - 1) return; // そとわくは のこす
      if (!isWalk(x, y)) tiles[at(x, y)] = 5; // 砂利の こみち
    };
    while (cx !== tx2) { cx += cx < tx2 ? 1 : -1; carve(cx, cy); }
    while (cy !== ty2) { cy += cy < ty2 ? 1 : -1; carve(cx, cy); }
  }

  // しゅっぱつち: 本体の 中から、なるべく 中央したよりの 歩けるマス
  let start = null;
  if (comps.length) {
    const cy0 = H - 4, cx0 = (W >> 1);
    let bd2 = 1e9;
    for (const [x, y] of comps[mainId]) {
      const d = Math.abs(x - cx0) + Math.abs(y - cy0);
      if (d < bd2) { bd2 = d; start = { x, y }; }
    }
  }
  if (!start) { tiles[at(1, 1)] = 0; start = { x: 1, y: 1 }; }

  // さいしゅう連結チェック: start から BFS、とどかない 歩けるタイルは 崖(2)で うめて 孤立=0 に
  const seen = new Uint8Array(W * H);
  {
    const q = [start]; let head = 0;
    seen[at(start.x, start.y)] = 1;
    while (head < q.length) {
      const c = q[head++];
      for (const [dx, dy] of DD) {
        const nx = c.x + dx, ny = c.y + dy;
        if (isWalk(nx, ny) && !seen[at(nx, ny)]) { seen[at(nx, ny)] = 1; q.push({ x: nx, y: ny }); }
      }
    }
  }
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    if (isWalk(x, y) && !seen[at(x, y)]) tiles[at(x, y)] = 2;
  }

  // ---- かざり deco を ちらす（歩けるタイルの 上だけ・start は あけておく）----
  for (let y = 1; y < H - 1; y++) for (let x = 1; x < W - 1; x++) {
    if (!isWalk(x, y)) { deco[at(x, y)] = 0; continue; }
    if (x === start.x && y === start.y) continue;
    const t = tiles[at(x, y)];
    if (t !== 0) continue; // 道/砂利の 上には あまり おかない（草の上に）
    const r = U.rnd();
    if (r < 0.10) deco[at(x, y)] = 1;       // 花
    else if (r < 0.16) deco[at(x, y)] = 2;  // せいたか草
    else if (r < 0.185) deco[at(x, y)] = 3; // 小石
    else if (r < 0.20) deco[at(x, y)] = 4;  // 丸太
    else if (r < 0.215) deco[at(x, y)] = 5; // きのこ
  }
  // 花畑: 花を かたまりで すこし こく
  {
    const fields = U.rint(2, 4);
    for (let i = 0; i < fields; i++) {
      const cx = U.rint(3, W - 4), cy = U.rint(3, H - 4), r = U.rint(1, 2);
      for (let y = cy - r; y <= cy + r; y++) for (let x = cx - r; x <= cx + r; x++) {
        if (isWalk(x, y) && tiles[at(x, y)] === 0 && deco[at(x, y)] === 0 && U.rnd() < 0.7) deco[at(x, y)] = 1;
      }
    }
  }

  // プレイヤーを しゅっぱつちへ
  const p = G.player;
  p.tx = start.x; p.ty = start.y;
  p.x = _tileCx(p.tx); p.y = _tileCy(p.ty);
  p.fx = p.x; p.fy = p.y;
  p.dir = 'down'; p.moving = false; p.mvT = 0; p.busy = false;

  // カメラを プレイヤーに あわせて しょきか
  _camInit();

  // けはいを SIGN_TARGET こ ばらまく
  G.signs = [];
  for (let i = 0; i < CONFIG.SIGN_TARGET; i++) spawnSign();
}

/* 歩けて だれとも かぶらない タイルへ けはいを ついか */
function spawnSign() {
  const W = CONFIG.MAP_W, H = CONFIG.MAP_H;
  const occupied = (tx, ty) => {
    if (G.player && G.player.tx === tx && G.player.ty === ty) return true;
    if (G.mode === 'vs' && G.cpu && G.cpu.tx === tx && G.cpu.ty === ty) return true;
    return G.signs.some(s => s.tx === tx && s.ty === ty);
  };
  for (let tries = 0; tries < 400; tries++) {
    const tx = U.rint(1, W - 2), ty = U.rint(1, H - 2);
    if (!U.walkable(tx, ty)) continue;
    if (G.player && Math.abs(tx - G.player.tx) + Math.abs(ty - G.player.ty) < 2) continue;
    if (occupied(tx, ty)) continue;
    G.signs.push({ tx, ty, key: pickSpecies(G.night), id: ++G.signSeq });
    return;
  }
}

/* ============================================================
   CPU（たいせん）
   ============================================================ */
function setupCpu() {
  const W = CONFIG.MAP_W, H = CONFIG.MAP_H;
  let best = null, bd = -1;
  for (let t = 0; t < 500; t++) {
    const x = U.rint(1, W - 2), y = U.rint(1, H - 2);
    if (!U.walkable(x, y)) continue;
    const d = Math.abs(x - G.player.tx) + Math.abs(y - G.player.ty);
    if (d > bd) { bd = d; best = { x, y }; }
    if (bd >= W + H - 6) break;
  }
  if (!best) best = { x: G.player.tx, y: G.player.ty };
  const c = G.cpu;
  c.tx = best.x; c.ty = best.y;
  c.x = _tileCx(c.tx); c.y = _tileCy(c.ty);
  c.fx = c.x; c.fy = c.y;
  c.dir = 'down'; c.moving = false; c.mvT = 0;
  c.stopUntil = 0; c.path = null; c.targetId = null;
  c._acc = 0;
  c._wdir = 'down';
}

/* CPU→もくひょうへの BFS。さいしょの 1マスの [dx,dy] をかえす（なければ null） */
function cpuPathStep(fromTx, fromTy, toTx, toTy) {
  if (fromTx === toTx && fromTy === toTy) return null;
  const W = CONFIG.MAP_W;
  const key = (x, y) => y * W + x;
  const prev = new Map();
  const q = [[fromTx, fromTy]]; let head = 0;
  prev.set(key(fromTx, fromTy), -1);
  let found = false;
  const DD = [[1, 0], [-1, 0], [0, 1], [0, -1]];
  while (head < q.length && !found) {
    const [x, y] = q[head++];
    for (const [dx, dy] of DD) {
      const nx = x + dx, ny = y + dy;
      if (!U.walkable(nx, ny) || prev.has(key(nx, ny))) continue;
      prev.set(key(nx, ny), key(x, y));
      if (nx === toTx && ny === toTy) { found = true; break; }
      q.push([nx, ny]);
    }
  }
  if (!found) return null;
  let cur = key(toTx, toTy);
  const startK = key(fromTx, fromTy);
  while (prev.get(cur) !== startK) cur = prev.get(cur);
  return [cur % W - fromTx, Math.floor(cur / W) - fromTy];
}

/* CPU を 1マス うごかす（歩ける場合のみ）。ほかんを はじめる */
function _cpuStartMove(dx, dy) {
  const c = G.cpu;
  const nx = c.tx + dx, ny = c.ty + dy;
  if (!U.walkable(nx, ny)) return false;
  c.fx = c.x; c.fy = c.y;
  c.tx = nx; c.ty = ny;
  c.moving = true; c.mvT = 0;
  c.dir = dx > 0 ? 'right' : dx < 0 ? 'left' : dy > 0 ? 'down' : 'up';
  return true;
}

function cpuTick(dtMs) {
  const c = G.cpu;
  const now = performance.now();

  if (c.moving) {
    c.mvT += dtMs;
    const stepMs = CONFIG.CPU_STEP_MS[G.cpuLv] || 640;
    const p = Math.min(1, c.mvT / stepMs);
    c.x = c.fx + (_tileCx(c.tx) - c.fx) * p;
    c.y = c.fy + (_tileCy(c.ty) - c.fy) * p;
    if (p >= 1) {
      c.moving = false;
      c.x = _tileCx(c.tx); c.y = _tileCy(c.ty);
      _cpuTryCatch();
    }
    return;
  }

  if (now < c.stopUntil) return;

  c._acc += dtMs;
  const stepMs = CONFIG.CPU_STEP_MS[G.cpuLv] || 640;
  if (c._acc < stepMs) return;
  c._acc = 0;

  let target = null, bd = 1e9;
  for (const s of G.signs) {
    const d = Math.abs(s.tx - c.tx) + Math.abs(s.ty - c.ty);
    if (d < bd) { bd = d; target = s; }
  }
  let moved = false;
  if (target && bd <= CONFIG.CPU_CHASE_R) {
    const step = cpuPathStep(c.tx, c.ty, target.tx, target.ty);
    if (step) moved = _cpuStartMove(step[0], step[1]);
  }
  if (!moved) {
    const DMAP = { up: [0, -1], down: [0, 1], left: [-1, 0], right: [1, 0] };
    const ks = Object.keys(DMAP).sort(() => Math.random() - 0.5);
    const order = [c._wdir, ...ks];
    for (const k of order) {
      const [dx, dy] = DMAP[k];
      if (_cpuStartMove(dx, dy)) { c._wdir = k; break; }
    }
  }
}

/* CPU が けはいタイルへ とうちゃく → 捕獲はんてい */
function _cpuTryCatch() {
  const c = G.cpu;
  const idx = G.signs.findIndex(s => s.tx === c.tx && s.ty === c.ty);
  if (idx < 0) return;
  const sign = G.signs[idx];
  G.signs.splice(idx, 1);
  c.targetId = null;

  const p = CONFIG.CPU_CATCH_P[G.cpuLv] || 0.5;
  if (U.chance(p)) {
    const b = BUGS[sign.key];
    const pts = (b && b.pts) || 0;
    G.cpuScore += pts;
    G.cpuCaught.push({ key: sign.key, name: b ? b.name : '？', pts });
    c.stopUntil = performance.now() + 600;
  } else {
    c.stopUntil = performance.now() + Math.max(1200, (8 - G.cpuLv) * 700);
  }
  updateHud();
  setTimeout(() => { if (G.running) spawnSign(); }, CONFIG.SIGN_RESPAWN_MS);
}

/* ============================================================
   カメラ（プレイヤー追従・端でクランプ・やや遅れて滑らかに）
   ============================================================ */
const _cam = { x: 0, y: 0 };  // 画面左上が さす ワールド座標（px）

function _camClampTarget(wx, wy) {
  // プレイヤー中心が 画面まんなかに くるよう、左上ワールド座標を もとめてクランプ
  const maxX = Math.max(0, _mapPixW() - VIEW_W);
  const maxY = Math.max(0, _mapPixH() - VIEW_H);
  let cx = wx - VIEW_W / 2;
  let cy = wy - VIEW_H / 2;
  cx = U.clamp(cx, 0, maxX);
  cy = U.clamp(cy, 0, maxY);
  return { x: cx, y: cy };
}

function _camInit() {
  const t = _camClampTarget(G.player.x, G.player.y);
  _cam.x = t.x; _cam.y = t.y;
}

function _camUpdate(dtMs) {
  const t = _camClampTarget(G.player.x, G.player.y);
  // フレームレート ふいの なめらかおいかけ（指数おいかけ）
  const k = 1 - Math.pow(0.0025, dtMs / 1000); // やく 0..1（dt おおきいほど 1に ちかい）
  _cam.x += (t.x - _cam.x) * k;
  _cam.y += (t.y - _cam.y) * k;
}

/* ============================================================
   rAF ループ
   ============================================================ */
let _rafId = 0;
let _lastT = 0;
let _stepSfxT = 0;
let _animTime = 0; // 水/草アニメ用の じかん（ms）

function startField() {
  if (_rafId) return;
  _ensureCanvasSize();
  _lastT = performance.now();
  const loop = (now) => {
    _rafId = requestAnimationFrame(loop);
    const dt = Math.min(60, now - _lastT);
    _lastT = now;
    if (!G.player.busy) _update(dt, now);
    _camUpdate(dt);
    _drawField(now);
    _animTime += dt; // 水・草・けはいの アニメ じかんを すすめる
  };
  _rafId = requestAnimationFrame(loop);
}

function stopField() {
  if (_rafId) { cancelAnimationFrame(_rafId); _rafId = 0; }
}

function _update(dtMs, now) {
  const p = G.player;

  if (p.moving) {
    p.mvT += dtMs;
    const t = Math.min(1, p.mvT / CONFIG.STEP_MS);
    p.x = p.fx + (_tileCx(p.tx) - p.fx) * t;
    p.y = p.fy + (_tileCy(p.ty) - p.fy) * t;
    if (t >= 1) {
      p.moving = false;
      p.x = _tileCx(p.tx); p.y = _tileCy(p.ty);
      _checkReachSign();
    }
  } else {
    const { dx, dy } = G.input;
    if (dx !== 0 || dy !== 0) {
      p.dir = dx > 0 ? 'right' : dx < 0 ? 'left' : dy > 0 ? 'down' : 'up';
      const nx = p.tx + dx, ny = p.ty + dy;
      if (U.walkable(nx, ny)) {
        p.fx = p.x; p.fy = p.y;
        p.tx = nx; p.ty = ny;
        p.moving = true; p.mvT = 0;
        if (now - _stepSfxT > 200) { _stepSfxT = now; if (typeof Sound !== 'undefined' && Sound && Sound.sfx) Sound.sfx.step(); }
      }
    }
  }

  if (G.mode === 'vs') cpuTick(dtMs);

  // テンポ: 場の けはいが ふえなさすぎ／枯れすぎ ないよう、たまに 目安数まで そっと おぎなう。
  // （やり過ぎない: たりない ぶんを ゆっくり 1こずつ。既存の respawn と けんかしない軽い保険）
  _topUpSigns(dtMs);
}

/* けはいの 目安数を ほそく たもつ（こまめに 1こだけ おぎなう）。れいがいで おちない */
let _signTopAcc = 0;
function _topUpSigns(dtMs) {
  try {
    if (!G.running || !G.signs) return;
    _signTopAcc += dtMs || 0;
    if (_signTopAcc < 900) return; // やく0.9秒ごとに しらべる（軽く）
    _signTopAcc = 0;
    const target = (typeof CONFIG !== 'undefined' && CONFIG.SIGN_TARGET) ? CONFIG.SIGN_TARGET : 9;
    // 既存の respawn タイマも うごくので、ここでは「いちじるしく たりない」ときだけ 1こ
    if (G.signs.length < target - 1) spawnSign();
  } catch (e) { /* むし */ }
}

/* プレイヤーが けはいタイルへ → 捕獲シーンへ */
function _checkReachSign() {
  const p = G.player;
  const idx = G.signs.findIndex(s => s.tx === p.tx && s.ty === p.ty);
  if (idx < 0) return;
  const sign = G.signs[idx];
  G.signs.splice(idx, 1);
  setTimeout(() => { if (G.running) spawnSign(); }, CONFIG.SIGN_RESPAWN_MS);
  enterCatch(sign);
}

/* ============================================================
   canvas サイズ（devicePixelRatio 対応・リサイズにも安全に）
   ============================================================ */
function _ensureCanvasSize() {
  const cv = D.canvas; if (!cv) return null;
  const ctx = cv.getContext('2d');
  const dpr = (typeof window !== 'undefined' && window.devicePixelRatio) ? window.devicePixelRatio : 1;
  const needW = Math.round(VIEW_W * dpr), needH = Math.round(VIEW_H * dpr);
  if (cv.width !== needW || cv.height !== needH) {
    cv.width = needW; cv.height = needH;
    // CSS の みためサイズは ろんりサイズに（スタイルが あれば そちら ゆうせん）
    if (!cv.style.width) cv.style.width = VIEW_W + 'px';
    if (!cv.style.height) cv.style.height = VIEW_H + 'px';
  }
  // まいフレーム リセット: ろんり座標で えがけるよう DPR スケール
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return ctx;
}

/* ============================================================
   えがく（カメラ変換ご・可視はんいだけ・足元ワールドYで奥行きソート）
   ============================================================ */
function _drawField(now) {
  const ctx = _ensureCanvasSize();
  if (!ctx) return;
  const m = G.map; if (!m) return;
  const TS = _ts();
  const W = m.w, H = m.h;
  const time = _animTime;
  const night = !!G.night;
  const at = (x, y) => y * W + x;

  // ワールド→スクリーン
  const sX = (wx) => wx - _cam.x;
  const sY = (wy) => wy - _cam.y;

  // せなか（くろ）でクリア
  ctx.clearRect(0, 0, VIEW_W, VIEW_H);
  ctx.fillStyle = night ? '#0b1226' : '#1c2b18';
  ctx.fillRect(0, 0, VIEW_W, VIEW_H);

  // ---- 可視タイルはんい（カリング）----
  const x0 = Math.max(0, Math.floor(_cam.x / TS) - 1);
  const y0 = Math.max(0, Math.floor(_cam.y / TS) - 1);
  const x1 = Math.min(W - 1, Math.ceil((_cam.x + VIEW_W) / TS) + 1);
  const y1 = Math.min(H - 1, Math.ceil((_cam.y + VIEW_H) / TS) + 1);

  const tileAt = (x, y) => (x < 0 || y < 0 || x >= W || y >= H) ? 3 : m.tiles[at(x, y)];
  const groundKind = (t) => t === 1 ? 'water' : t === 4 ? 'path' : t === 5 ? 'gravel' : 'grass';
  // 崖(2)/森(3) の 足元は 草の地面に する（立ち上がる物として 上に かさねる）
  const baseKind = (t) => (t === 2 || t === 3) ? 'grass' : groundKind(t);

  const T = (typeof Tiles !== 'undefined') ? Tiles : null;

  // ---- ① 地面レイヤ ----
  for (let y = y0; y <= y1; y++) {
    for (let x = x0; x <= x1; x++) {
      const t = m.tiles[at(x, y)];
      const px = sX(x * TS), py = sY(y * TS);
      const seed = (x * 73856093) ^ (y * 19349663);
      const kind = baseKind(t);
      if (T && T.ground) T.ground(ctx, px, py, TS, kind, seed, time, night);
      else { ctx.fillStyle = kind === 'water' ? '#3a8fd0' : kind === 'path' ? '#c9b079' : kind === 'gravel' ? '#b8b2a0' : '#5ba84e'; ctx.fillRect(px, py, TS + 1, TS + 1); }
    }
  }

  // ---- ② 地面の さかいめ なじみ（水辺・道）----
  if (T && T.transition) {
    for (let y = y0; y <= y1; y++) {
      for (let x = x0; x <= x1; x++) {
        const t = m.tiles[at(x, y)];
        if (t !== 1 && t !== 4) continue; // 水・道 の ふちだけ
        const px = sX(x * TS), py = sY(y * TS);
        const diff = (nx, ny) => {
          const nt = tileAt(nx, ny);
          if (t === 1) return nt !== 1; // 水: りく/べつ地形 が となり
          return nt !== 4;              // 道: みち いがい が となり
        };
        const mask = {
          n: diff(x, y - 1), e: diff(x + 1, y), s: diff(x, y + 1), w: diff(x - 1, y),
          ne: diff(x + 1, y - 1), nw: diff(x - 1, y - 1), se: diff(x + 1, y + 1), sw: diff(x - 1, y + 1),
        };
        const base = t === 1 ? 'water' : 'path';
        T.transition(ctx, px, py, TS, base, mask, time);
      }
    }
  }

  // ---- ③ 平らな deco（花・小石）は 地面の すぐあと ----
  for (let y = y0; y <= y1; y++) {
    for (let x = x0; x <= x1; x++) {
      const d = m.deco[at(x, y)];
      if (d !== 1 && d !== 3) continue; // 花 / 小石
      const cx = sX(_tileCx(x)), cy = sY(_tileCy(y));
      const seed = (x * 73856093) ^ (y * 19349663);
      if (T && T.deco) T.deco(ctx, cx, cy, TS, d === 1 ? 'flower' : 'rock', seed, time);
    }
  }

  // ---- ④ 立ち上がる物を あつめて 足元ワールドYで ソート（後→前）----
  const draws = [];
  for (let y = y0; y <= y1; y++) {
    for (let x = x0; x <= x1; x++) {
      const idx = at(x, y);
      const t = m.tiles[idx];
      const d = m.deco[idx];
      const footY = (y + 1) * TS; // 足元（タイル下辺）ワールドY
      const seed = (x * 73856093) ^ (y * 19349663);
      if (t === 2) draws.push({ y: footY, kind: 'cliff', x, ty: y, seed });
      else if (t === 3) draws.push({ y: footY, kind: 'tree', x, ty: y, seed });
      if (d === 2 || d === 4 || d === 5) draws.push({ y: footY, kind: 'deco', x, ty: y, deco: d, seed });
    }
  }
  // けはい
  for (const s of G.signs) {
    if (s.tx < x0 - 1 || s.tx > x1 + 1 || s.ty < y0 - 1 || s.ty > y1 + 1) continue;
    draws.push({ y: (s.ty + 1) * TS, kind: 'sign', sign: s });
  }
  // CPU・プレイヤー（足元＝x,y はピクセル中心なので 下ばしまで すこし たす）
  if (G.mode === 'vs' && G.cpu) draws.push({ y: G.cpu.y + TS * 0.5, kind: 'cpu' });
  draws.push({ y: G.player.y + TS * 0.5, kind: 'player' });

  draws.sort((a, b) => a.y - b.y);

  for (const it of draws) {
    if (it.kind === 'cliff') {
      const px = sX(it.x * TS), py = sY(it.ty * TS);
      // 下の となりが 崖でなければ 崖面を 下に だす
      const below = tileAt(it.x, it.ty + 1);
      const faceH = (below === 2) ? 0.15 : 0.9;
      const capTop = (tileAt(it.x, it.ty - 1) !== 2); // 上が 崖でなければ 天端
      if (T && T.cliff) T.cliff(ctx, px, py, TS, { faceH, capTop, shadow: faceH > 0.3, seed: it.seed, night });
      else { ctx.fillStyle = '#8a8a82'; ctx.fillRect(px, py, TS, TS); }
    } else if (it.kind === 'tree') {
      const cx = sX(_tileCx(it.x)), cy = sY(_tileCy(it.ty));
      const variant = ((it.seed >>> 3) & 3);
      if (T && T.tree) T.tree(ctx, cx, cy, TS, variant, time, night);
      else { ctx.fillStyle = '#2f6b3a'; ctx.beginPath(); ctx.arc(cx, cy, TS * 0.4, 0, 7); ctx.fill(); }
    } else if (it.kind === 'deco') {
      const cx = sX(_tileCx(it.x)), cy = sY(_tileCy(it.ty));
      const kind = it.deco === 2 ? 'tallgrass' : it.deco === 4 ? 'log' : 'mushroom';
      if (T && T.deco) T.deco(ctx, cx, cy, TS, kind, it.seed, time);
    } else if (it.kind === 'sign') {
      const s = it.sign;
      const cx = sX(_tileCx(s.tx)), cy = sY(_tileCy(s.ty));
      // レアヒント: w で みための おおきさ＆きらめきを かえる（tiles.js は さわらない）
      const rare = _signRare(s);           // 1=レア / 2=中堅 / 3=ふつう
      _drawSignAura(ctx, cx, cy, TS, rare, s, time); // けはいの まえに オーラ／ひかり
      const scale = rare === 1 ? 1.32 : rare === 2 ? 1.14 : 1.0; // レアほど 大きめ
      if (T && T.sign) {
        if (scale !== 1) {
          ctx.save();
          ctx.translate(cx, cy);
          ctx.scale(scale, scale);
          T.sign(ctx, 0, 0, TS, time);
          ctx.restore();
        } else {
          T.sign(ctx, cx, cy, TS, time);
        }
      } else { ctx.fillStyle = '#3e7e36'; ctx.beginPath(); ctx.arc(cx, cy, TS * 0.25 * scale, 0, 7); ctx.fill(); }
      if (rare === 1) _drawSignSparkle(ctx, cx, cy, TS, s, time); // レアは 星の きらめきを うえに
    } else if (it.kind === 'cpu') {
      const c = G.cpu;
      const cx = sX(c.x), cy = sY(c.y);
      const ph = _walkPhase(c, now);
      if (T && T.chibi) T.chibi(ctx, cx, cy + TS * 0.4, TS, c.dir, ph, 'cpu', night);
      else _fallbackChibi(ctx, cx, cy, true);
    } else if (it.kind === 'player') {
      const p = G.player;
      const cx = sX(p.x), cy = sY(p.y);
      const ph = _walkPhase(p, now);
      if (T && T.chibi) T.chibi(ctx, cx, cy + TS * 0.4, TS, p.dir, ph, 'player', night);
      else _fallbackChibi(ctx, cx, cy, false);
    }
  }

  // ---- ⑤ 夜の あんまく（プレイヤー画面座標 中心のライト）----
  if (night && T && T.nightOverlay) {
    const lx = sX(G.player.x), ly = sY(G.player.y);
    T.nightOverlay(ctx, VIEW_W, VIEW_H, lx, ly, TS * 4);
  } else if (night) {
    // フォールバックの あんまく
    const lx = sX(G.player.x), ly = sY(G.player.y), r = TS * 4;
    const grad = ctx.createRadialGradient(lx, ly, TS, lx, ly, r);
    grad.addColorStop(0, 'rgba(8,12,30,0)');
    grad.addColorStop(1, 'rgba(8,12,30,.75)');
    ctx.fillStyle = grad; ctx.fillRect(0, 0, VIEW_W, VIEW_H);
  }
}

/* けはいの レア度を かえす（1=レア / 2=中堅 / 3=ふつう）。BUGS未定義でも おちない */
function _signRare(s) {
  try {
    const b = (typeof BUGS !== 'undefined' && s && s.key) ? BUGS[s.key] : null;
    const w = (b && typeof b.w === 'number') ? b.w : 3;
    if (w <= 1) return 1;
    if (w === 2) return 2;
    return 3;
  } catch (e) { return 3; }
}

/* けはいの 種いろ（淡いオーラ用）。なければ きいろ系で フォールバック */
function _signColor(s) {
  try {
    const b = (typeof BUGS !== 'undefined' && s && s.key) ? BUGS[s.key] : null;
    const c = b && b.color;
    if (typeof c === 'string' && c[0] === '#' && (c.length === 7 || c.length === 4)) return c;
  } catch (e) { /* むし */ }
  return '#ffe478';
}

/* '#rrggbb' / '#rgb' を rgba もじれつへ（パースできなければ きいろ） */
function _toRgba(hex, a) {
  try {
    let h = hex;
    if (h.length === 4) h = '#' + h[1] + h[1] + h[2] + h[2] + h[3] + h[3];
    const r = parseInt(h.slice(1, 3), 16);
    const g = parseInt(h.slice(3, 5), 16);
    const b = parseInt(h.slice(5, 7), 16);
    if (isNaN(r) || isNaN(g) || isNaN(b)) return 'rgba(255,228,120,' + a + ')';
    return 'rgba(' + r + ',' + g + ',' + b + ',' + a + ')';
  } catch (e) { return 'rgba(255,228,120,' + a + ')'; }
}

/* けはいの あしもとに 淡い ひかりの オーラ（レアほど 大きく あかるく 明滅）。
   Tiles.sign の まえに よぶ（うしろがわの ひかり）。れいがいで おちない。 */
function _drawSignAura(ctx, cx, cy, ts, rare, s, time) {
  try {
    if (rare === 3) return; // ふつう は いままで どおり（そうしょく なし）
    const t = (time || 0) * 0.001;
    const col = _signColor(s);
    // 明滅（0..1）。レアは つよめ、中堅は ひかえめ
    const puls = 0.5 + 0.5 * Math.sin(t * (rare === 1 ? 3.2 : 2.2) + (s && s.id ? s.id : 0));
    const baseR = rare === 1 ? ts * 0.62 : ts * 0.42;
    const r = baseR * (1 + 0.10 * puls);
    const aMax = rare === 1 ? 0.34 : 0.18;
    const a = aMax * (0.6 + 0.4 * puls);
    ctx.save();
    let g = null;
    try { g = ctx.createRadialGradient(cx, cy - ts * 0.12, r * 0.15, cx, cy - ts * 0.12, r); }
    catch (e) { g = null; }
    if (g) {
      g.addColorStop(0, _toRgba(col, a));
      g.addColorStop(0.6, _toRgba(col, a * 0.5));
      g.addColorStop(1, _toRgba(col, 0));
      ctx.fillStyle = g;
    } else {
      ctx.fillStyle = _toRgba(col, a * 0.5);
    }
    ctx.beginPath();
    ctx.ellipse(cx, cy - ts * 0.12, r, r * 0.78, 0, 0, Math.PI * 2);
    ctx.fill();
    // レアは ひかりの リングも ひとつ（まわる ような 明滅）
    if (rare === 1) {
      ctx.lineWidth = Math.max(1, ts * 0.03);
      ctx.strokeStyle = _toRgba(col, 0.30 * (0.5 + 0.5 * puls));
      ctx.beginPath();
      ctx.ellipse(cx, cy - ts * 0.05, r * 0.78, r * 0.5, 0, 0, Math.PI * 2);
      ctx.stroke();
    }
    ctx.restore();
  } catch (e) { /* むし */ }
}

/* レアの けはいに 星の きらめき（Tiles.sign の うえに かさねる）。れいがいで おちない */
function _drawSignSparkle(ctx, cx, cy, ts, s, time) {
  try {
    const t = (time || 0) * 0.001;
    const seedId = (s && s.id) ? s.id : 1;
    const stars = 3;
    ctx.save();
    for (let i = 0; i < stars; i++) {
      // それぞれ ちがう いちで まわりながら ちかちか
      const ang = t * 1.1 + i * (Math.PI * 2 / stars) + seedId * 0.7;
      const orbit = ts * (0.34 + 0.06 * Math.sin(t * 2 + i));
      const sxp = cx + Math.cos(ang) * orbit;
      const syp = cy - ts * 0.55 + Math.sin(ang) * orbit * 0.5;
      const tw = 0.5 + 0.5 * Math.sin(t * 5 + i * 1.9 + seedId);
      const a = 0.45 + 0.5 * tw;
      const sr = ts * (0.05 + 0.04 * tw);
      _drawStar(ctx, sxp, syp, sr, a);
    }
    ctx.restore();
  } catch (e) { /* むし */ }
}

/* ちいさな 4ほうの きらきら星（十字のひかり） */
function _drawStar(ctx, x, y, r, a) {
  try {
    ctx.save();
    ctx.fillStyle = 'rgba(255,255,255,' + a + ')';
    ctx.beginPath();
    ctx.moveTo(x, y - r);
    ctx.lineTo(x + r * 0.28, y - r * 0.28);
    ctx.lineTo(x + r, y);
    ctx.lineTo(x + r * 0.28, y + r * 0.28);
    ctx.lineTo(x, y + r);
    ctx.lineTo(x - r * 0.28, y + r * 0.28);
    ctx.lineTo(x - r, y);
    ctx.lineTo(x - r * 0.28, y - r * 0.28);
    ctx.closePath();
    ctx.fill();
    // ちゅうしんの ほんのり きいろ
    ctx.fillStyle = 'rgba(255,240,170,' + (a * 0.8) + ')';
    ctx.beginPath();
    ctx.arc(x, y, r * 0.3, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();
  } catch (e) { /* むし */ }
}

/* 歩きフェーズ（0..1）。moving中は じかんで ぐるぐる、とまっていれば ゆっくり ゆれ */
function _walkPhase(ent, now) {
  if (ent.moving) return ((now / 140) % 1);
  return 0;
}

/* Tiles が まだ ない ときの ほけん用 チビ（ふだんは つかわない） */
function _fallbackChibi(ctx, x, y, rival) {
  ctx.save();
  ctx.fillStyle = 'rgba(15,30,8,.25)';
  ctx.beginPath(); ctx.ellipse(x, y + 12, 10, 3.5, 0, 0, 7); ctx.fill();
  ctx.fillStyle = rival ? '#4a7ac9' : '#e8543d';
  ctx.beginPath(); ctx.arc(x, y, 10, 0, 7); ctx.fill();
  ctx.restore();
}
