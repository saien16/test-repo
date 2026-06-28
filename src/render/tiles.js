/* ============================================================
   むしとりバトル — render/tiles.js
   SNES風（ドラクエ6／クロノ・トリガー級）の立体的タイル描画プリミティブ。
   ここは「じゅんすいな えがく かんすう」だけ。ゲームの じょうたいには さわらない。

   ★ つかいかた（だいじ）
     - すべて スクリーンざひょう（カメラてきようは よびだしがわ field-cpu）で うけとる。
     - ctx=2D / ts=タイルpx / seed=せいすう（おなじ みためを かためる）/ time=ms（みず・くさの うごき）。
     - れいがいを なげない（はんいがいでも あんぜん）。document を トップレベルで さわらない。

   ★ transition の base しよう（ここに めいき）
     - base は「りくがわ（みず・どうろ・すなの たかい／ちがう がわ）」の タイルに かさねる。
       つまり mask.n=true は「きたの となりが ちがう／ひくい ちめん（みず など）」をしめす。
       みずべの しろい なみ・すなの きしは、base=land がわの ふちに そって えがく。
     - import/export きんし。Tiles は ひとつの グローバル const。
   ============================================================ */

const Tiles = (function () {
  'use strict';

  /* ---- かるい seed らんすう（document も Math.random も つかわず かためる） ---- */
  // 32bit せいすうから 0..1 を かえす。seed と salt で ばらす。
  function rnd1(seed, salt) {
    let x = (seed | 0) ^ ((salt | 0) * 0x9e3779b9);
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    x = x >>> 0;
    return x / 4294967296;
  }
  // a..b の せいすう（seed・salt で かためる）
  function rndRange(seed, salt, a, b) {
    return a + Math.floor(rnd1(seed, salt) * (b - a + 1));
  }
  // クランプ
  function clamp(v, a, b) { return v < a ? a : (v > b ? b : v); }

  /* ---- いろの ヘルパ（rgb / rgba もじれつ） ---- */
  function rgb(r, g, b) { return 'rgb(' + (r | 0) + ',' + (g | 0) + ',' + (b | 0) + ')'; }
  function rgba(r, g, b, a) { return 'rgba(' + (r | 0) + ',' + (g | 0) + ',' + (b | 0) + ',' + a + ')'; }

  /* ============================================================
     じめん ground
     ============================================================ */
  function ground(ctx, sx, sy, ts, kind, seed, time, night) {
    try {
      seed = seed | 0;
      time = time || 0;
      if (kind === 'water') { drawWater(ctx, sx, sy, ts, seed, time); }
      else if (kind === 'path') { drawSoil(ctx, sx, sy, ts, seed, false); }
      else if (kind === 'gravel') { drawSoil(ctx, sx, sy, ts, seed, true); }
      else { drawGrass(ctx, sx, sy, ts, seed); }
      // よる は うっすら あおく しずめる（ぜんたいの nightOverlay とは べつに、てもとを しめる）
      if (night) {
        ctx.fillStyle = rgba(20, 30, 70, 0.18);
        ctx.fillRect(sx, sy, ts, ts);
      }
    } catch (e) { /* むし */ }
  }

  // くさ：2〜3しょくの しぜんな のうたん＋まばらな くさの てんびょう
  function drawGrass(ctx, sx, sy, ts, seed) {
    // ベースいろ（タイルごとに ほんの すこし ゆらす→チェッカーに ならない）
    const v = rnd1(seed, 11);
    const base = 118 + Math.floor(v * 16); // 118..134
    ctx.fillStyle = rgb(74, base, 56);
    ctx.fillRect(sx, sy, ts, ts);

    // のうたんの まだら（やわらかい パッチを 2〜3こ）
    const patches = 2 + (seed & 1);
    for (let i = 0; i < patches; i++) {
      const px = sx + rnd1(seed, 20 + i) * ts;
      const py = sy + rnd1(seed, 30 + i) * ts;
      const pr = ts * (0.20 + rnd1(seed, 40 + i) * 0.22);
      const lighter = rnd1(seed, 50 + i) > 0.5;
      ctx.fillStyle = lighter ? rgba(150, 196, 96, 0.30) : rgba(52, 104, 44, 0.28);
      ctx.beginPath();
      ctx.ellipse(px, py, pr, pr * 0.7, 0, 0, Math.PI * 2);
      ctx.fill();
    }

    // くさの てんびょう（ちいさな たての ひっかき。seed で いちを かためる）
    const blades = 5 + (seed % 4);
    ctx.lineWidth = Math.max(1, ts * 0.03);
    for (let i = 0; i < blades; i++) {
      const bx = sx + rnd1(seed, 100 + i) * ts;
      const by = sy + (0.35 + rnd1(seed, 110 + i) * 0.6) * ts;
      const h = ts * (0.12 + rnd1(seed, 120 + i) * 0.10);
      const tone = rnd1(seed, 130 + i);
      ctx.strokeStyle = tone > 0.5 ? rgba(60, 120, 50, 0.55) : rgba(170, 210, 110, 0.55);
      ctx.beginPath();
      ctx.moveTo(bx, by);
      ctx.lineTo(bx + (tone - 0.5) * ts * 0.12, by - h);
      ctx.stroke();
    }
  }

  // つち（path）／じゃり（gravel）：つぶ感
  function drawSoil(ctx, sx, sy, ts, seed, gravel) {
    // ベース：つちは あたたかい ちゃ、じゃりは あかるい グレーちゃ
    if (gravel) ctx.fillStyle = rgb(176, 166, 146);
    else ctx.fillStyle = rgb(170, 132, 86);
    ctx.fillRect(sx, sy, ts, ts);

    // すこし のうたんを ふって のっぺり させない
    ctx.fillStyle = gravel ? rgba(120, 112, 96, 0.22) : rgba(120, 86, 50, 0.22);
    const blob = 2 + (seed & 1);
    for (let i = 0; i < blob; i++) {
      const px = sx + rnd1(seed, 200 + i) * ts;
      const py = sy + rnd1(seed, 210 + i) * ts;
      const pr = ts * (0.18 + rnd1(seed, 220 + i) * 0.2);
      ctx.beginPath();
      ctx.ellipse(px, py, pr, pr * 0.6, 0, 0, Math.PI * 2);
      ctx.fill();
    }

    // つぶ（じゃりは おおめ＆こいし、つちは ちいさな てん）
    const grains = gravel ? 9 + (seed % 5) : 6 + (seed % 4);
    for (let i = 0; i < grains; i++) {
      const gx = sx + rnd1(seed, 300 + i) * ts;
      const gy = sy + rnd1(seed, 310 + i) * ts;
      const gr = gravel
        ? ts * (0.05 + rnd1(seed, 320 + i) * 0.07)
        : ts * (0.02 + rnd1(seed, 320 + i) * 0.03);
      const light = rnd1(seed, 330 + i) > 0.5;
      if (gravel) {
        // こいし：あかるい面＋した影で すこし たちあがって みえる
        ctx.fillStyle = rgba(0, 0, 0, 0.18);
        ctx.beginPath();
        ctx.ellipse(gx, gy + gr * 0.5, gr, gr * 0.6, 0, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = light ? rgb(208, 200, 184) : rgb(150, 142, 126);
        ctx.beginPath();
        ctx.ellipse(gx, gy, gr, gr * 0.8, 0, 0, Math.PI * 2);
        ctx.fill();
      } else {
        ctx.fillStyle = light ? rgba(200, 160, 110, 0.5) : rgba(110, 78, 44, 0.5);
        ctx.beginPath();
        ctx.arc(gx, gy, gr, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  // みず：time で よこに ながれる さざなみ／はんしゃ
  function drawWater(ctx, sx, sy, ts, seed, time) {
    // ふかい あお → あさい あお の たてグラデで おくゆき
    let g;
    try { g = ctx.createLinearGradient(sx, sy, sx, sy + ts); }
    catch (e) { g = null; }
    if (g) {
      g.addColorStop(0, rgb(46, 110, 176));
      g.addColorStop(1, rgb(30, 84, 150));
      ctx.fillStyle = g;
    } else {
      ctx.fillStyle = rgb(40, 100, 168);
    }
    ctx.fillRect(sx, sy, ts, ts);

    // さざなみ：time で よこに ながす しろい よこせん（2〜3ぽん）
    const t = time * 0.001;
    ctx.lineWidth = Math.max(1, ts * 0.04);
    for (let i = 0; i < 3; i++) {
      const baseY = sy + ts * (0.25 + i * 0.27);
      const phase = t * (0.6 + i * 0.18) + rnd1(seed, 400 + i) * 6.28;
      const amp = ts * 0.05;
      const off = Math.sin(phase) * amp;
      ctx.strokeStyle = rgba(220, 240, 255, 0.16 + 0.06 * i);
      ctx.beginPath();
      for (let k = 0; k <= 4; k++) {
        const x = sx + (k / 4) * ts;
        const y = baseY + Math.sin(phase + k * 1.1) * amp + off * 0.2;
        if (k === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.stroke();
    }

    // きらめき：うごく ちいさな ハイライト てん
    const spark = 2;
    for (let i = 0; i < spark; i++) {
      const sxp = sx + ((rnd1(seed, 500 + i) + t * 0.08) % 1) * ts;
      const syp = sy + rnd1(seed, 510 + i) * ts;
      const a = 0.25 + 0.25 * (0.5 + 0.5 * Math.sin(t * 2 + i));
      ctx.fillStyle = rgba(255, 255, 255, a * 0.6);
      ctx.beginPath();
      ctx.arc(sxp, syp, ts * 0.04, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  /* ============================================================
     さかいめ transition（base=land がわの ふちに かさねる）
     ============================================================ */
  function transition(ctx, sx, sy, ts, base, mask, time) {
    try {
      mask = mask || {};
      time = time || 0;
      const isWater = (base === 'water'); // base=water のときは みずがわの ふち（あわ）
      // しろい なみ／すなの きしの いろ
      const edge = isWater ? rgba(220, 240, 255, 0.55) : rgba(236, 222, 178, 0.85);
      const edge2 = isWater ? rgba(180, 220, 250, 0.40) : rgba(208, 188, 140, 0.6);
      const w = Math.max(2, ts * 0.16); // ふちの はば
      const t = time * 0.001;

      // たて・よこの へり（なみ うち。time で ほんのり うねる）
      // きた
      if (mask.n) edgeStrip(ctx, sx, sy, ts, w, 'n', edge, edge2, t, isWater);
      if (mask.s) edgeStrip(ctx, sx, sy, ts, w, 's', edge, edge2, t, isWater);
      if (mask.w) edgeStrip(ctx, sx, sy, ts, w, 'w', edge, edge2, t, isWater);
      if (mask.e) edgeStrip(ctx, sx, sy, ts, w, 'e', edge, edge2, t, isWater);

      // かど（そとがわの かどを まるめる）。となりが りょうほう ちがう ときだけ。
      cornerArc(ctx, sx, sy, ts, w, 'nw', mask, edge);
      cornerArc(ctx, sx, sy, ts, w, 'ne', mask, edge);
      cornerArc(ctx, sx, sy, ts, w, 'sw', mask, edge);
      cornerArc(ctx, sx, sy, ts, w, 'se', mask, edge);
    } catch (e) { /* むし */ }
  }

  function edgeStrip(ctx, sx, sy, ts, w, side, edge, edge2, t, wavy) {
    ctx.fillStyle = edge;
    // よこ（n/s）か たて（w/e）か
    if (side === 'n' || side === 's') {
      const y0 = side === 'n' ? sy : sy + ts - w;
      // なみ うち：うえべりは すこし でこぼこ
      ctx.beginPath();
      ctx.moveTo(sx, y0);
      const seg = 4;
      for (let k = 0; k <= seg; k++) {
        const x = sx + (k / seg) * ts;
        const wob = wavy ? Math.sin(t * 1.4 + k * 1.3 + (side === 'n' ? 0 : 3)) * w * 0.35 : 0;
        const yy = side === 'n' ? y0 + w + wob : y0 - wob;
        ctx.lineTo(x, yy);
      }
      ctx.lineTo(sx + ts, y0);
      ctx.closePath();
      ctx.fill();
      // うちがわの うすい おび
      ctx.fillStyle = edge2;
      const yb = side === 'n' ? sy + w : sy + ts - w * 1.6;
      ctx.fillRect(sx, yb, ts, w * 0.6);
    } else {
      const x0 = side === 'w' ? sx : sx + ts - w;
      ctx.beginPath();
      ctx.moveTo(x0, sy);
      const seg = 4;
      for (let k = 0; k <= seg; k++) {
        const y = sy + (k / seg) * ts;
        const wob = wavy ? Math.sin(t * 1.4 + k * 1.3 + (side === 'w' ? 1 : 4)) * w * 0.35 : 0;
        const xx = side === 'w' ? x0 + w + wob : x0 - wob;
        ctx.lineTo(xx, y);
      }
      ctx.lineTo(x0, sy + ts);
      ctx.closePath();
      ctx.fill();
      ctx.fillStyle = edge2;
      const xb = side === 'w' ? sx + w : sx + ts - w * 1.6;
      ctx.fillRect(xb, sy, w * 0.6, ts);
    }
  }

  function cornerArc(ctx, sx, sy, ts, w, corner, mask, edge) {
    // そとがわの かどに ちいさな しかくっぽい あわ／すなを おく
    let ax, ay, need;
    if (corner === 'nw') { ax = sx; ay = sy; need = mask.nw || (mask.n && mask.w); }
    else if (corner === 'ne') { ax = sx + ts; ay = sy; need = mask.ne || (mask.n && mask.e); }
    else if (corner === 'sw') { ax = sx; ay = sy + ts; need = mask.sw || (mask.s && mask.w); }
    else { ax = sx + ts; ay = sy + ts; need = mask.se || (mask.s && mask.e); }
    if (!need) return;
    ctx.fillStyle = edge;
    ctx.beginPath();
    ctx.arc(ax, ay, w * 0.9, 0, Math.PI * 2);
    ctx.fill();
  }

  /* ============================================================
     がけ cliff（みなみむきの すいちょくな めん＋ねもとの 影）
     ============================================================ */
  function cliff(ctx, sx, sy, ts, opts) {
    try {
      opts = opts || {};
      const faceH = Math.max(0, (typeof opts.faceH === 'number' ? opts.faceH : 0.6)) * ts;
      const capTop = opts.capTop !== false;
      const showShadow = opts.shadow !== false;
      const seed = opts.seed | 0;
      const night = !!opts.night;

      // ねもとの おち影（がけの したに よこながの 影→たかさを かんじる）
      if (showShadow && faceH > 0) {
        ctx.fillStyle = rgba(0, 0, 0, 0.28);
        ctx.beginPath();
        ctx.ellipse(sx + ts * 0.5, sy + ts + faceH, ts * 0.6, ts * 0.16, 0, 0, Math.PI * 2);
        ctx.fill();
      }

      // みなみむきの すいちょく めん（いわはだ。たてグラデで まるみ）
      if (faceH > 0) {
        let g;
        try { g = ctx.createLinearGradient(sx, sy + ts, sx, sy + ts + faceH); }
        catch (e) { g = null; }
        if (g) {
          g.addColorStop(0, rgb(150, 130, 104));
          g.addColorStop(1, rgb(96, 80, 62));
          ctx.fillStyle = g;
        } else {
          ctx.fillStyle = rgb(120, 102, 80);
        }
        ctx.fillRect(sx, sy + ts, ts, faceH);

        // ごつごつ：たての ひびと よこの だんさ（seed で かためる）
        ctx.strokeStyle = rgba(60, 48, 36, 0.5);
        ctx.lineWidth = Math.max(1, ts * 0.035);
        const cracks = 2 + (seed & 1);
        for (let i = 0; i < cracks; i++) {
          const cx = sx + rnd1(seed, 600 + i) * ts;
          ctx.beginPath();
          ctx.moveTo(cx, sy + ts);
          ctx.lineTo(cx + (rnd1(seed, 610 + i) - 0.5) * ts * 0.2, sy + ts + faceH);
          ctx.stroke();
        }
        // ひだりに ハイライト・みぎに 影で たちたいかんを だす
        ctx.fillStyle = rgba(255, 240, 210, 0.12);
        ctx.fillRect(sx, sy + ts, ts * 0.12, faceH);
        ctx.fillStyle = rgba(0, 0, 0, 0.18);
        ctx.fillRect(sx + ts * 0.86, sy + ts, ts * 0.14, faceH);
      }

      // うわめん（てんば）：いわ天端＋ふちの くさ
      if (capTop) {
        // いわの 天端
        ctx.fillStyle = rgb(176, 158, 130);
        ctx.fillRect(sx, sy, ts, ts);
        // でこぼこの まだら
        ctx.fillStyle = rgba(130, 112, 88, 0.4);
        for (let i = 0; i < 3; i++) {
          const px = sx + rnd1(seed, 700 + i) * ts;
          const py = sy + rnd1(seed, 710 + i) * ts;
          ctx.beginPath();
          ctx.ellipse(px, py, ts * 0.16, ts * 0.1, 0, 0, Math.PI * 2);
          ctx.fill();
        }
        // うわべりの くさ（みどりの でっぱり→たかさの きわだち）
        ctx.fillStyle = rgb(86, 140, 64);
        ctx.beginPath();
        ctx.moveTo(sx, sy + ts);
        const seg = 6;
        for (let k = 0; k <= seg; k++) {
          const x = sx + (k / seg) * ts;
          const wob = (rnd1(seed, 720 + k) - 0.5) * ts * 0.12;
          ctx.lineTo(x, sy + ts - ts * 0.12 + wob);
        }
        ctx.lineTo(sx + ts, sy + ts);
        ctx.closePath();
        ctx.fill();
      }

      if (night) {
        ctx.fillStyle = rgba(20, 30, 70, 0.22);
        ctx.fillRect(sx, sy, ts, ts + faceH);
      }
    } catch (e) { /* むし */ }
  }

  /* ============================================================
     き tree（じゅかんが タイルより うえに たちあがる）
     ============================================================ */
  function tree(ctx, sx, sy, ts, variant, time, night) {
    try {
      variant = variant | 0;
      time = time || 0;
      const cx = sx + ts * 0.5;
      const groundY = sy + ts * 0.92; // ねもと（せっち点）
      const sway = Math.sin(time * 0.0012 + variant) * ts * 0.04; // ゆれ

      // ねもとの だ円の おち影
      shadow(ctx, cx, groundY, ts * 0.42, ts * 0.16);

      const kind = variant % 3; // 0=ひろば(広葉) 1=しんよう(針葉) 2=まるい おおき
      const scale = 0.9 + (variant % 2) * 0.25;

      // みき
      const trunkW = ts * 0.16 * scale;
      const trunkH = ts * 0.55 * scale;
      ctx.fillStyle = rgb(110, 78, 48);
      ctx.fillRect(cx - trunkW / 2, groundY - trunkH, trunkW, trunkH);
      // みきの ハイライト
      ctx.fillStyle = rgba(150, 110, 70, 0.6);
      ctx.fillRect(cx - trunkW / 2, groundY - trunkH, trunkW * 0.35, trunkH);

      const crownBaseY = groundY - trunkH;
      if (kind === 1) {
        // しんようじゅ：さんかくの だん（3だん）
        const top = crownBaseY - ts * 1.05 * scale;
        const colD = rgb(34, 92, 52), colL = rgb(60, 130, 74);
        for (let i = 0; i < 3; i++) {
          const ly = crownBaseY - i * ts * 0.42 * scale;
          const lw = ts * (0.62 - i * 0.13) * scale;
          ctx.fillStyle = i % 2 ? colL : colD;
          ctx.beginPath();
          ctx.moveTo(cx + sway * (i + 1) * 0.4, ly - ts * 0.55 * scale);
          ctx.lineTo(cx - lw, ly);
          ctx.lineTo(cx + lw, ly);
          ctx.closePath();
          ctx.fill();
        }
        // てっぺん
        void top;
      } else {
        // ひろようじゅ／まるき：まるい じゅかん（かさねた だ円で もこもこ）
        const big = kind === 2;
        const cyC = crownBaseY - ts * (big ? 0.62 : 0.5) * scale;
        const rw = ts * (big ? 0.62 : 0.5) * scale;
        const rh = ts * (big ? 0.62 : 0.52) * scale;
        const colD = rgb(40, 104, 54), colM = rgb(58, 134, 70), colL = rgb(96, 170, 96);
        // した影がわ
        ctx.fillStyle = colD;
        ctx.beginPath();
        ctx.ellipse(cx + sway, cyC + rh * 0.2, rw, rh, 0, 0, Math.PI * 2);
        ctx.fill();
        // もこもこ（3つの かたまり）
        const blobs = [[-0.4, 0.05, 0.62], [0.4, 0.05, 0.62], [0, -0.35, 0.7]];
        for (let i = 0; i < blobs.length; i++) {
          const b = blobs[i];
          ctx.fillStyle = colM;
          ctx.beginPath();
          ctx.ellipse(cx + sway + b[0] * rw, cyC + b[1] * rh, rw * b[2], rh * b[2], 0, 0, Math.PI * 2);
          ctx.fill();
        }
        // ひかりの あたる うえの ハイライト
        ctx.fillStyle = colL;
        ctx.beginPath();
        ctx.ellipse(cx + sway - rw * 0.25, cyC - rh * 0.4, rw * 0.4, rh * 0.32, 0, 0, Math.PI * 2);
        ctx.fill();
      }

      if (night) {
        ctx.fillStyle = rgba(20, 30, 70, 0.22);
        ctx.beginPath();
        ctx.ellipse(cx, crownBaseY - ts * 0.4, ts * 0.7, ts * 0.9, 0, 0, Math.PI * 2);
        ctx.fill();
      }
    } catch (e) { /* むし */ }
  }

  /* ============================================================
     そうしょく deco
     ============================================================ */
  function deco(ctx, sx, sy, ts, kind, seed, time) {
    try {
      seed = seed | 0;
      time = time || 0;
      const cx = sx + ts * 0.5;
      const baseY = sy + ts * 0.82;
      if (kind === 'flower') drawFlower(ctx, sx, sy, ts, seed);
      else if (kind === 'tallgrass') drawTallgrass(ctx, cx, baseY, ts, seed, time);
      else if (kind === 'rock') drawRock(ctx, cx, baseY, ts, seed);
      else if (kind === 'log') drawLog(ctx, cx, baseY, ts, seed);
      else if (kind === 'mushroom') drawMushroom(ctx, cx, baseY, ts, seed);
    } catch (e) { /* むし */ }
  }

  // はな：すうしょく。ひらたい そうしょく（地面の すぐあと）
  function drawFlower(ctx, sx, sy, ts, seed) {
    const cols = [
      [255, 120, 150], [255, 210, 90], [180, 140, 240], [255, 255, 255], [120, 190, 255],
    ];
    const n = 3 + (seed % 3);
    for (let i = 0; i < n; i++) {
      const fx = sx + (0.2 + rnd1(seed, 800 + i) * 0.6) * ts;
      const fy = sy + (0.35 + rnd1(seed, 810 + i) * 0.5) * ts;
      const c = cols[rndRange(seed, 820 + i, 0, cols.length - 1)];
      const r = ts * 0.07;
      // くき
      ctx.strokeStyle = rgba(60, 130, 50, 0.8);
      ctx.lineWidth = Math.max(1, ts * 0.025);
      ctx.beginPath();
      ctx.moveTo(fx, fy + r * 1.4);
      ctx.lineTo(fx, fy + r * 3);
      ctx.stroke();
      // はなびら（4まい）
      ctx.fillStyle = rgb(c[0], c[1], c[2]);
      for (let p = 0; p < 4; p++) {
        const a = p * Math.PI / 2;
        ctx.beginPath();
        ctx.ellipse(fx + Math.cos(a) * r, fy + Math.sin(a) * r, r * 0.7, r * 0.7, 0, 0, Math.PI * 2);
        ctx.fill();
      }
      // ちゅうしん
      ctx.fillStyle = rgb(255, 235, 120);
      ctx.beginPath();
      ctx.arc(fx, fy, r * 0.55, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  // せいたか草：time で そよぐ。すこし たちあがる（影つき）
  function drawTallgrass(ctx, cx, baseY, ts, seed, time) {
    shadow(ctx, cx, baseY, ts * 0.22, ts * 0.08);
    const blades = 5;
    const t = time * 0.001;
    ctx.lineWidth = Math.max(1.5, ts * 0.05);
    for (let i = 0; i < blades; i++) {
      const off = (i - (blades - 1) / 2) * ts * 0.08;
      const bx = cx + off;
      const h = ts * (0.5 + rnd1(seed, 900 + i) * 0.25);
      const sway = Math.sin(t * 1.6 + i * 0.7 + rnd1(seed, 910 + i) * 6.28) * ts * 0.12;
      const tone = rnd1(seed, 920 + i);
      ctx.strokeStyle = tone > 0.5 ? rgb(74, 150, 64) : rgb(54, 120, 50);
      ctx.beginPath();
      ctx.moveTo(bx, baseY);
      ctx.quadraticCurveTo(bx + sway * 0.5, baseY - h * 0.6, bx + sway, baseY - h);
      ctx.stroke();
    }
  }

  // こいし：まるくて した影で たちたい感
  function drawRock(ctx, cx, baseY, ts, seed) {
    shadow(ctx, cx, baseY, ts * 0.24, ts * 0.09);
    const rw = ts * (0.18 + rnd1(seed, 1000) * 0.08);
    const rh = rw * 0.8;
    // ほんたい
    ctx.fillStyle = rgb(150, 146, 138);
    ctx.beginPath();
    ctx.ellipse(cx, baseY - rh * 0.6, rw, rh, 0, 0, Math.PI * 2);
    ctx.fill();
    // うえの ハイライト
    ctx.fillStyle = rgba(210, 208, 200, 0.7);
    ctx.beginPath();
    ctx.ellipse(cx - rw * 0.25, baseY - rh * 0.9, rw * 0.45, rh * 0.4, 0, 0, Math.PI * 2);
    ctx.fill();
    // した影がわ
    ctx.fillStyle = rgba(90, 88, 84, 0.5);
    ctx.beginPath();
    ctx.ellipse(cx + rw * 0.2, baseY - rh * 0.3, rw * 0.7, rh * 0.5, 0, 0, Math.PI * 2);
    ctx.fill();
  }

  // まるた：よこに ねた き。きりくちの 年輪
  function drawLog(ctx, cx, baseY, ts, seed) {
    shadow(ctx, cx, baseY, ts * 0.36, ts * 0.1);
    const lw = ts * 0.62, lh = ts * 0.28;
    const x0 = cx - lw / 2, y0 = baseY - lh - ts * 0.02;
    // どうたい
    ctx.fillStyle = rgb(140, 96, 58);
    ctx.beginPath();
    ctx.ellipse(cx, y0 + lh / 2, lw / 2, lh / 2, 0, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = rgb(120, 82, 50);
    ctx.fillRect(x0, y0, lw, lh);
    ctx.beginPath();
    ctx.ellipse(cx, y0 + lh, lw / 2, lh / 2, 0, 0, Math.PI);
    ctx.fill();
    // きりくち（みぎ）：年輪
    ctx.fillStyle = rgb(196, 156, 110);
    ctx.beginPath();
    ctx.ellipse(x0 + lw, y0 + lh / 2, lw * 0.12, lh / 2, 0, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = rgba(120, 82, 50, 0.7);
    ctx.lineWidth = Math.max(1, ts * 0.02);
    for (let r = 1; r <= 2; r++) {
      ctx.beginPath();
      ctx.ellipse(x0 + lw, y0 + lh / 2, lw * 0.12 * (r / 3), lh / 2 * (r / 3), 0, 0, Math.PI * 2);
      ctx.stroke();
    }
    void seed;
  }

  // きのこ：あかい かさ＋しろい てん。すこし たちあがる
  function drawMushroom(ctx, cx, baseY, ts, seed) {
    shadow(ctx, cx, baseY, ts * 0.2, ts * 0.07);
    const stemW = ts * 0.1, stemH = ts * 0.26;
    // じく
    ctx.fillStyle = rgb(245, 238, 222);
    ctx.fillRect(cx - stemW / 2, baseY - stemH, stemW, stemH);
    // かさ
    const capW = ts * 0.34, capY = baseY - stemH;
    const hue = rnd1(seed, 1100);
    const cap = hue > 0.5 ? [220, 60, 60] : [230, 150, 60]; // あか or オレンジ
    ctx.fillStyle = rgb(cap[0], cap[1], cap[2]);
    ctx.beginPath();
    ctx.ellipse(cx, capY, capW / 2, capW / 2 * 0.85, 0, Math.PI, 0);
    ctx.fill();
    ctx.beginPath();
    ctx.ellipse(cx, capY, capW / 2, capW * 0.18, 0, 0, Math.PI * 2);
    ctx.fill();
    // しろい てん
    ctx.fillStyle = rgba(255, 255, 255, 0.9);
    for (let i = 0; i < 3; i++) {
      const dx = (rnd1(seed, 1110 + i) - 0.5) * capW * 0.7;
      const dy = -rnd1(seed, 1120 + i) * capW * 0.25;
      ctx.beginPath();
      ctx.arc(cx + dx, capY + dy, ts * 0.025, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  /* ============================================================
     おち影 shadow
     ============================================================ */
  function shadow(ctx, cx, cy, rx, ry) {
    try {
      ctx.fillStyle = rgba(0, 0, 0, 0.25);
      ctx.beginPath();
      ctx.ellipse(cx, cy, Math.max(1, rx), Math.max(1, ry), 0, 0, Math.PI * 2);
      ctx.fill();
    } catch (e) { /* むし */ }
  }

  /* ============================================================
     キャラ chibi（クロノ/DQ風 2.5とうしん。(cx,cy)=あしもと）
     ============================================================ */
  function chibi(ctx, cx, cy, ts, dir, walkPhase, kind, night) {
    try {
      dir = dir || 'down';
      walkPhase = walkPhase || 0;
      const isCpu = (kind === 'cpu');
      // あしぶみ：walkPhase で うえした バウンド＋あしの ぶれ
      const stride = Math.sin(walkPhase * Math.PI * 2);
      const bounce = Math.abs(Math.sin(walkPhase * Math.PI * 2)) * ts * 0.06;

      // からだの きほんサイズ（2.5とうしん）
      const headR = ts * 0.22;
      const bodyH = ts * 0.34;
      const bodyW = ts * 0.30;

      // いろ：player=あか系＋ぼうし、cpu=あお系＋ロボ風アンテナ
      const skin = rgb(255, 222, 190);
      const cloth = isCpu ? rgb(70, 130, 220) : rgb(220, 70, 70);
      const clothD = isCpu ? rgb(48, 96, 170) : rgb(170, 46, 46);
      const hatCol = isCpu ? rgb(180, 200, 220) : rgb(200, 40, 40);

      // あしもとの おち影（かならず）
      shadow(ctx, cx, cy, ts * 0.26, ts * 0.1);

      const footY = cy - bounce;
      const bodyBottom = footY - ts * 0.02;
      const bodyTop = bodyBottom - bodyH;
      const headCy = bodyTop - headR * 0.7;

      // あし（2ほん。walkで まえ／うしろ）
      ctx.fillStyle = clothD;
      const legW = ts * 0.09, legH = ts * 0.1;
      const legSwing = stride * ts * 0.06;
      ctx.fillRect(cx - bodyW * 0.28 - legW / 2 + legSwing, bodyBottom, legW, legH);
      ctx.fillRect(cx + bodyW * 0.28 - legW / 2 - legSwing, bodyBottom, legW, legH);

      // からだ（どう）
      ctx.fillStyle = cloth;
      roundRect(ctx, cx - bodyW / 2, bodyTop, bodyW, bodyH, ts * 0.06);
      ctx.fill();
      // からだの 影がわ（みぎ）
      ctx.fillStyle = clothD;
      roundRect(ctx, cx + bodyW * 0.18, bodyTop, bodyW * 0.32, bodyH, ts * 0.06);
      ctx.fill();

      // うで（むきで いちを かえる）
      ctx.fillStyle = skin;
      const armY = bodyTop + bodyH * 0.2;
      const armR = ts * 0.05;
      if (dir !== 'up') {
        ctx.beginPath(); ctx.arc(cx - bodyW * 0.5, armY + bodyH * 0.3, armR, 0, Math.PI * 2); ctx.fill();
        ctx.beginPath(); ctx.arc(cx + bodyW * 0.5, armY + bodyH * 0.3, armR, 0, Math.PI * 2); ctx.fill();
      }

      // あたま
      ctx.fillStyle = skin;
      ctx.beginPath();
      ctx.arc(cx, headCy, headR, 0, Math.PI * 2);
      ctx.fill();

      // かみ／ぼうし（player は ぼうし、cpu は メタル頭＋アンテナ）
      if (isCpu) {
        // メタルな あたまカバー
        ctx.fillStyle = hatCol;
        ctx.beginPath();
        ctx.arc(cx, headCy - headR * 0.1, headR * 0.95, Math.PI, 0);
        ctx.fill();
        ctx.fillRect(cx - headR * 0.95, headCy - headR * 0.1, headR * 1.9, headR * 0.3);
        // アンテナ
        ctx.strokeStyle = rgb(120, 140, 160);
        ctx.lineWidth = Math.max(1, ts * 0.02);
        ctx.beginPath();
        ctx.moveTo(cx, headCy - headR);
        ctx.lineTo(cx, headCy - headR * 1.7);
        ctx.stroke();
        ctx.fillStyle = rgb(255, 90, 90);
        ctx.beginPath();
        ctx.arc(cx, headCy - headR * 1.8, ts * 0.04, 0, Math.PI * 2);
        ctx.fill();
      } else {
        // ぼうし（つば つき）
        ctx.fillStyle = hatCol;
        ctx.beginPath();
        ctx.arc(cx, headCy - headR * 0.15, headR * 0.95, Math.PI, 0);
        ctx.fill();
        // つば（むきで まえに でる）
        const brim = dir === 'left' ? -headR : (dir === 'right' ? headR : 0);
        ctx.beginPath();
        ctx.ellipse(cx + brim * 0.6, headCy - headR * 0.1, headR * (dir === 'down' ? 1.1 : 0.8), headR * 0.28, 0, 0, Math.PI * 2);
        ctx.fill();
      }

      // かお（dir で め／むきを かえる。up は うしろむき→かお なし）
      if (dir !== 'up') {
        ctx.fillStyle = rgb(40, 40, 50);
        const eyeY = headCy + headR * 0.1;
        const eR = ts * 0.025;
        if (dir === 'down') {
          ctx.beginPath(); ctx.arc(cx - headR * 0.35, eyeY, eR, 0, Math.PI * 2); ctx.fill();
          ctx.beginPath(); ctx.arc(cx + headR * 0.35, eyeY, eR, 0, Math.PI * 2); ctx.fill();
        } else if (dir === 'left') {
          ctx.beginPath(); ctx.arc(cx - headR * 0.4, eyeY, eR, 0, Math.PI * 2); ctx.fill();
        } else if (dir === 'right') {
          ctx.beginPath(); ctx.arc(cx + headR * 0.4, eyeY, eR, 0, Math.PI * 2); ctx.fill();
        }
      }

      if (night) {
        // よる は うっすら あおい りんかく
        ctx.fillStyle = rgba(20, 30, 70, 0.18);
        ctx.beginPath();
        ctx.ellipse(cx, (headCy + bodyBottom) / 2, bodyW * 0.8, (bodyBottom - headCy) * 0.65, 0, 0, Math.PI * 2);
        ctx.fill();
      }
    } catch (e) { /* むし */ }
  }

  // かどまる しかく ヘルパ
  function roundRect(ctx, x, y, w, h, r) {
    r = Math.min(r, w / 2, h / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  /* ============================================================
     けはい sign（ゆれる くさむら＋「！」がふわっと）
     ============================================================ */
  function sign(ctx, cx, cy, ts, time) {
    try {
      time = time || 0;
      const t = time * 0.001;
      // あしもとの おち影
      shadow(ctx, cx, cy, ts * 0.24, ts * 0.09);
      // ゆれる くさむら（3〜4ぼん）
      ctx.lineWidth = Math.max(1.5, ts * 0.06);
      for (let i = 0; i < 4; i++) {
        const off = (i - 1.5) * ts * 0.1;
        const bx = cx + off;
        const h = ts * (0.4 + (i % 2) * 0.12);
        const sway = Math.sin(t * 3 + i * 0.9) * ts * 0.1;
        ctx.strokeStyle = i % 2 ? rgb(74, 150, 64) : rgb(54, 120, 50);
        ctx.beginPath();
        ctx.moveTo(bx, cy);
        ctx.quadraticCurveTo(bx + sway * 0.5, cy - h * 0.6, bx + sway, cy - h);
        ctx.stroke();
      }
      // 「！」がふわっと うえした
      const floaty = Math.sin(t * 2.4) * ts * 0.08;
      const exY = cy - ts * 0.7 + floaty;
      // ふきだし まる
      ctx.fillStyle = rgba(255, 240, 120, 0.95);
      ctx.beginPath();
      ctx.arc(cx, exY, ts * 0.16, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = rgb(200, 150, 30);
      ctx.lineWidth = Math.max(1, ts * 0.02);
      ctx.stroke();
      // 「！」もじ
      ctx.fillStyle = rgb(200, 60, 40);
      ctx.fillRect(cx - ts * 0.02, exY - ts * 0.09, ts * 0.04, ts * 0.1);
      ctx.beginPath();
      ctx.arc(cx, exY + ts * 0.05, ts * 0.025, 0, Math.PI * 2);
      ctx.fill();
    } catch (e) { /* むし */ }
  }

  /* ============================================================
     よるの あんまく nightOverlay（ぜんたい＋プレイヤーまわりの まるい あかり）
     ============================================================ */
  function nightOverlay(ctx, W, H, lx, ly, r) {
    try {
      r = Math.max(1, r || 1);
      ctx.save();
      let g;
      try { g = ctx.createRadialGradient(lx, ly, r * 0.2, lx, ly, r); }
      catch (e) { g = null; }
      if (g) {
        // ちゅうしんは すきとおり、そとは こい あお
        g.addColorStop(0, rgba(10, 14, 40, 0));
        g.addColorStop(0.55, rgba(10, 14, 40, 0.30));
        g.addColorStop(1, rgba(6, 8, 28, 0.78));
        ctx.fillStyle = g;
        ctx.fillRect(0, 0, W, H);
      } else {
        // グラデが つかえない ときは ぜんめん いちまい
        ctx.fillStyle = rgba(6, 8, 28, 0.6);
        ctx.fillRect(0, 0, W, H);
      }
      // あかりの ふちに あったかい にじみ
      ctx.fillStyle = rgba(255, 220, 150, 0.05);
      ctx.beginPath();
      ctx.arc(lx, ly, r * 0.5, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    } catch (e) { /* むし */ }
  }

  /* ---- こうかい（グローバル const Tiles に まとめる） ---- */
  return {
    ground: ground,
    transition: transition,
    cliff: cliff,
    tree: tree,
    deco: deco,
    shadow: shadow,
    chibi: chibi,
    sign: sign,
    nightOverlay: nightOverlay,
  };
})();
