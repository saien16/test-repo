/* ============================================================
   むしとりバトル — field-cpu.js（フィールド＆CPU対戦）
   マップせいせい・たんさく・えがく・CPUライバルを ぜんぶ ここで。
   core.js の G / CONFIG / U と、bugs.js の BUGS / pickSpecies / drawBugMini を つかう。
   ※ import/export しない。関数宣言で genMap/startField/stopField/setupCpu/cpuTick をだす。
   ============================================================ */

/* タイルのいろ（0草 1水 2岩 3木 4道 5砂利） */
const FIELD_COLORS = {
  grass:  '#5ba84e', grass2: '#52a045',  // 草（チェッカーで2しょく）
  water:  '#3a8fd0', water2: '#338ac9',  // 水
  rock:   '#8a8a82', rockHi: '#a2a29a',  // 岩
  tree:   '#2f6b3a', treeHi: '#3c7d46',  // 木（こい みどり）
  path:   '#c9b079', path2:  '#c1a86f',  // 道
  gravel: '#b8b2a0', gravel2:'#aea899',  // 砂利
};

/* タイルのサイズ（Canvas 420 / MAP_W）と たて中央よせのオフセット */
function _tileSize() { return 420 / CONFIG.MAP_W; }      // = 30px (14マス)
function _mapPixH()  { return _tileSize() * CONFIG.MAP_H; }
function _offY()     { return (600 - _mapPixH()) / 2; }   // たて中央よせ

/* タイル中心の ピクセル座標 */
function _tileCx(tx) { return tx * _tileSize() + _tileSize() / 2; }
function _tileCy(ty) { return _offY() + ty * _tileSize() + _tileSize() / 2; }

/* ============================================================
   マップせいせい
   ============================================================ */
function genMap() {
  const W = CONFIG.MAP_W, H = CONFIG.MAP_H;
  const tiles = new Int8Array(W * H);
  const at = (x, y) => y * W + x;

  // ぜんめん 草 でうめる
  tiles.fill(0);

  // そとわくは 木（3）
  for (let x = 0; x < W; x++) { tiles[at(x, 0)] = 3; tiles[at(x, H - 1)] = 3; }
  for (let y = 0; y < H; y++) { tiles[at(0, y)] = 3; tiles[at(W - 1, y)] = 3; }

  // よこに よこぎる 川（1）を 2〜3ほん。1マスぶん「はし＝道(4)」をあけて つうろをしぼる
  const riverRows = [];
  {
    const cands = [];
    for (let y = 4; y < H - 4; y++) cands.push(y);
    // ばらけて 2〜3ほん えらぶ
    const want = U.rint(2, 3);
    for (let i = 0; i < want && cands.length; i++) {
      const idx = U.rint(0, cands.length - 1);
      const ry = cands[idx];
      // ちかすぎる行は のぞく
      for (let k = cands.length - 1; k >= 0; k--) if (Math.abs(cands[k] - ry) < 3) cands.splice(k, 1);
      riverRows.push(ry);
    }
  }
  for (const ry of riverRows) {
    for (let x = 1; x < W - 1; x++) tiles[at(x, ry)] = 1;
    // はし（道）を 1〜2か所あけて わたれるように
    const gaps = U.rint(1, 2);
    for (let g = 0; g < gaps; g++) {
      const gx = U.rint(2, W - 3);
      tiles[at(gx, ry)] = 4; // はし
    }
  }

  // たてに 岩山（2）の つい立てを 1〜2ほん。すきまに 砂利(5)の つうろ
  {
    const want = U.rint(1, 2);
    for (let i = 0; i < want; i++) {
      const rx = U.rint(3, W - 4);
      for (let y = 1; y < H - 1; y++) {
        if (tiles[at(rx, y)] === 1 || tiles[at(rx, y)] === 4) continue; // 川/はし は のこす
        tiles[at(rx, y)] = 2;
      }
      // すきまを 1〜2か所 砂利で あける
      const gaps = U.rint(1, 2);
      for (let g = 0; g < gaps; g++) {
        const gy = U.rint(2, H - 3);
        if (tiles[at(rx, gy)] === 2) tiles[at(rx, gy)] = 5;
      }
    }
  }

  // ちょっとした かざり: ところどころ 岩・道・砂利を ちらす（歩けるところを へらしすぎない）
  for (let n = 0; n < Math.floor(W * H * 0.04); n++) {
    const x = U.rint(1, W - 2), y = U.rint(1, H - 2);
    if (tiles[at(x, y)] !== 0) continue;
    tiles[at(x, y)] = U.pick([4, 5]); // 道 or 砂利（どちらも歩ける）
  }

  G.map = { w: W, h: H, tiles };

  // ---- れんけつせいを ほしょう ----
  // 歩けるタイルを れんけつせいぶん（コンポーネント）に わける。
  // いちばん 大きいかたまりを「本体」とし、ほかの かたまりは
  // つうろを ほって 本体に つなぐ（つぶさず のこす）。
  // それでも つなげない 小さな 孤島だけ 砂利で きえいさせず…→ 実際は すべて つなぐので 孤立は 0。
  const isWalk = (x, y) => {
    if (x < 0 || y < 0 || x >= W || y >= H) return false;
    const t = tiles[at(x, y)];
    return t === 0 || t === 4 || t === 5;
  };
  const DD = [[1, 0], [-1, 0], [0, 1], [0, -1]];

  // ラベルづけ（コンポーネントを みつける）
  const comp = new Int16Array(W * H).fill(-1);
  const comps = []; // 各コンポーネントの セルはいれつ
  for (let y = 1; y < H - 1; y++) for (let x = 1; x < W - 1; x++) {
    if (!isWalk(x, y) || comp[at(x, y)] !== -1) continue;
    const id = comps.length;
    const cells = [];
    const q = [[x, y]];
    comp[at(x, y)] = id;
    while (q.length) {
      const [cx, cy] = q.shift();
      cells.push([cx, cy]);
      for (const [dx, dy] of DD) {
        const nx = cx + dx, ny = cy + dy;
        if (isWalk(nx, ny) && comp[at(nx, ny)] === -1) { comp[at(nx, ny)] = id; q.push([nx, ny]); }
      }
    }
    comps.push(cells);
  }

  // ほんたい = いちばん 大きい かたまり
  let mainId = 0;
  for (let i = 1; i < comps.length; i++) if (comps[i].length > comps[mainId].length) mainId = i;

  // ほかの かたまりを 本体へ つなぐ: かたまりから 本体への さいたん（マンハッタン）を ほる
  for (let i = 0; i < comps.length; i++) {
    if (i === mainId) continue;
    // この かたまりの どこか1点 と 本体の さいよりの1点 を むすぶ
    let bestA = null, bestB = null, bd = 1e9;
    const sample = comps[i];
    const mainCells = comps[mainId];
    // サンプルを へらして けいさんりょうを おさえる
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
    // L字に ほる（とちゅうの 木/岩/川 を 砂利の つうろに）
    let [cx, cy] = bestA;
    const [tx2, ty2] = bestB;
    const carve = (x, y) => {
      if (x <= 0 || y <= 0 || x >= W - 1 || y >= H - 1) return; // そとわくは のこす
      if (!isWalk(x, y)) tiles[at(x, y)] = 5; // 砂利の こみち
    };
    while (cx !== tx2) { cx += cx < tx2 ? 1 : -1; carve(cx, cy); }
    while (cy !== ty2) { cy += cy < ty2 ? 1 : -1; carve(cx, cy); }
    // ほった あとは ふたつが つながる。本体ラベルを ぬりなおさず、つぎの ループでも
    // 本体は mainId のまま（あらたに つながったセルは あとの 連結チェックで OK）
  }

  // しゅっぱつち: 本体の 中から、なるべく 中央したよりの 歩けるマス
  let start = null;
  {
    const cy0 = H - 3, cx0 = (W >> 1);
    let bd2 = 1e9;
    for (const [x, y] of comps[mainId]) {
      const d = Math.abs(x - cx0) + Math.abs(y - cy0);
      if (d < bd2) { bd2 = d; start = { x, y }; }
    }
  }
  if (!start) { tiles[at(1, 1)] = 0; start = { x: 1, y: 1 }; }

  // さいしゅう連結チェック: start から BFS して、到達できない 歩けるタイルが
  // のこっていれば（まれ）岩でうめる。これで 孤立=0 を ほしょう。
  const seen = new Uint8Array(W * H);
  const q2 = [start];
  seen[at(start.x, start.y)] = 1;
  while (q2.length) {
    const c = q2.shift();
    for (const [dx, dy] of DD) {
      const nx = c.x + dx, ny = c.y + dy;
      if (isWalk(nx, ny) && !seen[at(nx, ny)]) { seen[at(nx, ny)] = 1; q2.push({ x: nx, y: ny }); }
    }
  }
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    if (isWalk(x, y) && !seen[at(x, y)]) tiles[at(x, y)] = 2;
  }

  // プレイヤーを しゅっぱつちへ
  const p = G.player;
  p.tx = start.x; p.ty = start.y;
  p.x = _tileCx(p.tx); p.y = _tileCy(p.ty);
  p.fx = p.x; p.fy = p.y;
  p.dir = 'down'; p.moving = false; p.mvT = 0; p.busy = false;

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
    // プレイヤーの まうえは さける（いきなり捕獲にならないよう すこし はなす）
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
  // プレイヤーから いちばん とおい 歩けるマスを さがす
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
  c._acc = 0;        // 歩きの ためこみ
  c._wdir = 'down';  // さまよう ときの くせ
}

/* CPU→もくひょうへの BFS。さいしょの 1マスの [dx,dy] をかえす（なければ null） */
function cpuPathStep(fromTx, fromTy, toTx, toTy) {
  if (fromTx === toTx && fromTy === toTy) return null;
  const W = CONFIG.MAP_W, H = CONFIG.MAP_H;
  const key = (x, y) => y * W + x;
  const prev = new Map();
  const q = [[fromTx, fromTy]];
  prev.set(key(fromTx, fromTy), -1);
  let found = false;
  const DD = [[1, 0], [-1, 0], [0, 1], [0, -1]];
  while (q.length && !found) {
    const [x, y] = q.shift();
    for (const [dx, dy] of DD) {
      const nx = x + dx, ny = y + dy;
      if (!U.walkable(nx, ny) || prev.has(key(nx, ny))) continue;
      prev.set(key(nx, ny), key(x, y));
      if (nx === toTx && ny === toTy) { found = true; break; }
      q.push([nx, ny]);
    }
  }
  if (!found) return null;
  // ゴールから さかのぼって さいしょの一歩
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

  // ほかん中なら すすめる
  if (c.moving) {
    c.mvT += dtMs;
    const stepMs = CONFIG.CPU_STEP_MS[G.cpuLv] || 640;
    const p = Math.min(1, c.mvT / stepMs);
    c.x = c.fx + (_tileCx(c.tx) - c.fx) * p;
    c.y = c.fy + (_tileCy(c.ty) - c.fy) * p;
    if (p >= 1) {
      c.moving = false;
      c.x = _tileCx(c.tx); c.y = _tileCy(c.ty);
      // とうちゃくした タイルに けはいが あれば 捕獲はんてい
      _cpuTryCatch();
    }
    return;
  }

  // りゅうちゅう（捕獲ちゅう・くやしくて とまる など）
  if (now < c.stopUntil) return;

  // ステップ かんかく
  c._acc += dtMs;
  const stepMs = CONFIG.CPU_STEP_MS[G.cpuLv] || 640;
  if (c._acc < stepMs) return;
  c._acc = 0;

  // CPU_CHASE_R いないの さいよりの けはいを ねらう
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
    // さまよう: いまの くせを ゆうせん、だめなら ほかへ
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
    // せいこう: てんすう ついか
    const b = BUGS[sign.key];
    const pts = (b && b.pts) || 0;
    G.cpuScore += pts;
    G.cpuCaught.push({ key: sign.key, name: b ? b.name : '？', pts });
    c.stopUntil = performance.now() + 600; // ちょっと まんぞく
  } else {
    // しっぱい: でも けはいは しょうひ。くやしくて すこし とまる
    c.stopUntil = performance.now() + Math.max(1200, (8 - G.cpuLv) * 700);
  }
  updateHud();
  // ばの けはい かずを たもつ
  setTimeout(() => { if (G.running) spawnSign(); }, CONFIG.SIGN_RESPAWN_MS);
}

/* ============================================================
   rAF ループ
   ============================================================ */
let _rafId = 0;
let _lastT = 0;
let _stepSfxT = 0;

function startField() {
  // 多重きどう ぼうし
  if (_rafId) return;
  _lastT = performance.now();
  const loop = (now) => {
    _rafId = requestAnimationFrame(loop);
    const dt = Math.min(60, now - _lastT); // フレームスキップ ほご
    _lastT = now;
    if (!G.player.busy) _update(dt, now);
    _drawField(now);
  };
  _rafId = requestAnimationFrame(loop);
}

function stopField() {
  if (_rafId) { cancelAnimationFrame(_rafId); _rafId = 0; }
}

function _update(dtMs, now) {
  const p = G.player;

  // 1) プレイヤーの いどう
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
        // あしおとは ひかえめに（200msに1回まで）
        if (now - _stepSfxT > 200) { _stepSfxT = now; if (Sound && Sound.sfx) Sound.sfx.step(); }
      }
    }
  }

  // 3) vs モード: CPU
  if (G.mode === 'vs') cpuTick(dtMs);
}

/* プレイヤーが けはいタイルへ → 捕獲シーンへ */
function _checkReachSign() {
  const p = G.player;
  const idx = G.signs.findIndex(s => s.tx === p.tx && s.ty === p.ty);
  if (idx < 0) return;
  const sign = G.signs[idx];
  G.signs.splice(idx, 1);
  // ばの かずを たもつ
  setTimeout(() => { if (G.running) spawnSign(); }, CONFIG.SIGN_RESPAWN_MS);
  enterCatch(sign);
}

/* ============================================================
   えがく
   ============================================================ */
function _drawField(now) {
  const cv = D.canvas; if (!cv) return;
  const ctx = cv.getContext('2d');
  const TS = _tileSize();
  const offY = _offY();
  const W = CONFIG.MAP_W, H = CONFIG.MAP_H;
  const m = G.map; if (!m) return;

  // せなか（くろ）でクリア
  ctx.clearRect(0, 0, 420, 600);
  ctx.fillStyle = '#1c2b18';
  ctx.fillRect(0, 0, 420, 600);

  // タイル
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      const t = m.tiles[y * W + x];
      const px = x * TS, py = offY + y * TS;
      const even = (x + y) % 2 === 0;
      let col;
      if (t === 1) col = even ? FIELD_COLORS.water : FIELD_COLORS.water2;
      else if (t === 2) col = even ? FIELD_COLORS.rock : FIELD_COLORS.rockHi;
      else if (t === 3) col = even ? FIELD_COLORS.tree : FIELD_COLORS.treeHi;
      else if (t === 4) col = even ? FIELD_COLORS.path : FIELD_COLORS.path2;
      else if (t === 5) col = even ? FIELD_COLORS.gravel : FIELD_COLORS.gravel2;
      else col = even ? FIELD_COLORS.grass : FIELD_COLORS.grass2;
      ctx.fillStyle = col;
      ctx.fillRect(px, py, TS + 1, TS + 1);

      // 水は さざなみ
      if (t === 1) {
        ctx.strokeStyle = 'rgba(255,255,255,.35)';
        ctx.lineWidth = 1.4;
        const w = Math.sin(now / 480 + x * 1.6 + y) * 2.4;
        ctx.beginPath();
        ctx.moveTo(px + 5, py + TS * 0.55 + w);
        ctx.quadraticCurveTo(px + TS / 2, py + TS * 0.5 - 3 + w, px + TS - 5, py + TS * 0.55 + w);
        ctx.stroke();
      }
      // 木は こんもり
      else if (t === 3) {
        ctx.fillStyle = 'rgba(20,45,20,.5)';
        ctx.beginPath(); ctx.arc(px + TS / 2, py + TS * 0.55, TS * 0.38, 0, 7); ctx.fill();
        ctx.fillStyle = FIELD_COLORS.treeHi;
        ctx.beginPath(); ctx.arc(px + TS * 0.4, py + TS * 0.42, TS * 0.18, 0, 7); ctx.fill();
      }
      // 岩は ごつごつ
      else if (t === 2) {
        ctx.fillStyle = 'rgba(0,0,0,.18)';
        ctx.beginPath();
        ctx.moveTo(px + 4, py + TS - 4);
        ctx.lineTo(px + TS * 0.4, py + 5);
        ctx.lineTo(px + TS - 4, py + TS - 6);
        ctx.closePath(); ctx.fill();
      }
    }
  }

  // けはい（ゆれる草 or「！」）
  for (const s of G.signs) {
    const cx = _tileCx(s.tx), cy = _tileCy(s.ty);
    const near = Math.abs(s.tx - G.player.tx) + Math.abs(s.ty - G.player.ty) <= 1;
    // ときどき ガサガサ ゆれる（スポットごとに いそうずれ）
    const gust = (((now / 1000) + s.tx * 0.71 + s.ty * 1.37) % 2.4) < 0.8;
    const shake = near || gust;
    const sw = shake ? Math.sin(now / 90 + s.tx) * 3 : Math.sin(now / 900 + s.tx) * 1;
    // ゆれる草むら
    ctx.save();
    ctx.translate(cx + sw, cy + TS * 0.18);
    ctx.fillStyle = '#3e7e36';
    ctx.beginPath();
    ctx.arc(-TS * 0.18, 0, TS * 0.2, 0, 7);
    ctx.arc(TS * 0.18, 0, TS * 0.2, 0, 7);
    ctx.arc(0, -TS * 0.12, TS * 0.22, 0, 7);
    ctx.fill();
    ctx.fillStyle = '#5aa84e';
    ctx.beginPath(); ctx.arc(-TS * 0.05, -TS * 0.14, TS * 0.1, 0, 7); ctx.fill();
    ctx.restore();
    // となりなら「！」ふきだし
    if (near) {
      ctx.save();
      ctx.translate(cx, cy - TS * 0.45 + Math.sin(now / 180) * 2);
      ctx.font = 'bold ' + Math.round(TS * 0.7) + 'px sans-serif';
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.lineWidth = 4; ctx.strokeStyle = '#27431f'; ctx.fillStyle = '#fff';
      ctx.strokeText('！', 0, 0); ctx.fillText('！', 0, 0);
      ctx.restore();
    }
  }

  // CPU
  if (G.mode === 'vs' && G.cpu) {
    const c = G.cpu;
    const walking = c.moving;
    _drawChibi(ctx, c.x, c.y, c.dir, walking, now, true);
  }

  // プレイヤー
  _drawChibi(ctx, G.player.x, G.player.y, G.player.dir, G.player.moving, now, false);

  // よる: あんまく＋プレイヤーの まわりだけ あかるく
  if (G.night) {
    const ppx = G.player.x, ppy = G.player.y;
    const r = TS * 3.5; // 径3〜4マス
    const grad = ctx.createRadialGradient(ppx, ppy, TS * 1.0, ppx, ppy, r);
    grad.addColorStop(0, 'rgba(8,12,30,0)');
    grad.addColorStop(0.7, 'rgba(8,12,30,.30)');
    grad.addColorStop(1, 'rgba(8,12,30,.72)');
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, 420, 600);
    // すみは しっかり くらく
    ctx.fillStyle = 'rgba(8,12,30,.45)';
    ctx.save();
    ctx.beginPath();
    ctx.rect(0, 0, 420, 600);
    ctx.arc(ppx, ppy, r, 0, 7, true); // まんなかは くりぬき
    ctx.fill('evenodd');
    ctx.restore();
  }
}

/* チビキャラ（プレイヤー＝あか / CPU＝あお＋🤖かん） */
function _drawChibi(ctx, x, y, dir, walking, now, rival) {
  const TS = _tileSize();
  const sc = TS / 30; // 30pxタイル を きじゅんに スケール
  const bodyCol = rival ? '#4a7ac9' : '#e8543d';
  const bodyHi = rival ? '#6a96e0' : '#f2785f';
  const capCol = rival ? '#dce6ef' : '#ffd34d';
  const t = now / 85;
  const swing = walking ? Math.sin(t) : 0;
  const bob = walking ? Math.abs(Math.sin(t)) * -2 : Math.sin(now / 680) * 0.8;

  ctx.save();
  ctx.translate(x, y + bob * sc);
  ctx.scale(sc, sc);
  const flip = dir === 'left' ? -1 : 1;
  ctx.scale(flip, 1);
  ctx.lineJoin = 'round'; ctx.lineCap = 'round';

  // かげ
  ctx.fillStyle = 'rgba(15,30,8,.25)';
  ctx.beginPath(); ctx.ellipse(0, 13, 10, 3.5, 0, 0, 7); ctx.fill();

  ctx.lineWidth = 2; ctx.strokeStyle = '#26321c';
  // あし
  const legSwing = swing * 4;
  ctx.fillStyle = rival ? '#2e5aa8' : '#27437a';
  _rr(ctx, -7, 3 + legSwing * 0.4, 6, 9, 2.5); ctx.fill(); ctx.stroke();
  _rr(ctx, 1, 3 - legSwing * 0.4, 6, 9, 2.5); ctx.fill(); ctx.stroke();

  // からだ
  ctx.fillStyle = bodyCol;
  _rr(ctx, -8, -6, 16, 11, 4); ctx.fill(); ctx.stroke();
  ctx.fillStyle = bodyHi;
  _rr(ctx, -8, -6, 6, 11, 4); ctx.fill();

  // あたま
  ctx.fillStyle = '#ffd9b3';
  ctx.beginPath(); ctx.arc(0, -13, 9, 0, 7); ctx.fill(); ctx.stroke();

  // ぼうし
  ctx.fillStyle = capCol;
  ctx.beginPath(); ctx.arc(0, -15, 9, Math.PI, 0); ctx.closePath(); ctx.fill(); ctx.stroke();
  // つば
  ctx.beginPath();
  ctx.moveTo(5, -16);
  ctx.quadraticCurveTo(14, -16, 15, -13);
  ctx.quadraticCurveTo(9, -12, 4, -13);
  ctx.closePath(); ctx.fill(); ctx.stroke();

  // かお（うしろむき いがい）
  if (dir !== 'up') {
    if (dir === 'down') {
      ctx.fillStyle = '#26241f';
      ctx.beginPath(); ctx.arc(-3, -13, 1.4, 0, 7); ctx.arc(3, -13, 1.4, 0, 7); ctx.fill();
    } else {
      ctx.fillStyle = '#26241f';
      ctx.beginPath(); ctx.arc(3, -13, 1.4, 0, 7); ctx.arc(7, -13, 1.3, 0, 7); ctx.fill();
    }
  }

  // CPU は ロボっぽい アンテナ
  if (rival) {
    ctx.strokeStyle = '#9fc0e8'; ctx.lineWidth = 1.6;
    ctx.beginPath(); ctx.moveTo(0, -23); ctx.lineTo(0, -27); ctx.stroke();
    ctx.fillStyle = '#ff5a5a';
    ctx.beginPath(); ctx.arc(0, -28, 1.8, 0, 7); ctx.fill();
  }

  ctx.restore();
}

/* かどまる rect */
function _rr(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}
