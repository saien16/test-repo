/* ============================================================
   むしとりバトル — data/nets.js（あみデータ＆小関数）
   ・NETS … あみのずかん（きほん＋変種5種）
   ・netHit(id, distM) … きょり別の命中率（0.05〜0.97）
   ・netHitMark(p) … ◎○△のめやす（catch.js と整合）
   ・netRiskLabel(id) … こわれやすさのめやす（lv 0..2）
   ・drawNetGlyph(ctx,cx,cy,size,id) … Canvas に あみアイコン
   ※ import/export しない。グローバル共有。トップレベルで document を触らない。
   ※ 例外でおちない（try/catch・ガードあり）。
   ============================================================ */

/* ---- あみずかん（キー＝英数id） ----
   range … いちばん とくいな きょり(m)
   hit   … きょり(0..3 など)ごとの 命中率（0..1）
   breakP… 1かい ふるごとの こわれる かくりつ（0..1）
   basic … きほんのあみ（つねに もっている・むげん）
   rare  … レア（フィールドで でにくい）
   dropW … フィールドの でやすさ（おおきいほど でやすい・basicは0）

   せんりゃくの ねらい:
   ・ちかいほど あたるが こわれやすい（close）
   ・とおくでも あんしんだが あたりにくい（long）
   ・じょうぶで バランスよい（reinf）
   ・ひろいはんいで そこそこ（big）
   ・どこでも つよくて こわれにくい けど めったに でない（gold） */
const NETS = {
  basic: {
    id: 'basic', name: 'きほんのあみ', short: '2mで げんき・ちかいほど あたる・こわれやすい',
    color: '#cfe8ff', range: 2,
    hit: { 0: 0.45, 1: 0.80, 2: 0.62, 3: 0.30 },
    breakP: 0.18, basic: true, rare: false, dropW: 0
  },
  close: {
    id: 'close', name: '1mのあみ', short: 'すごく ちかづくと どんぴしゃ・でも こわれやすい',
    color: '#ffd1e0', range: 1,
    hit: { 0: 0.74, 1: 0.93, 2: 0.44, 3: 0.16 },
    breakP: 0.30, basic: false, rare: false, dropW: 0.9
  },
  long: {
    id: 'long', name: '3mのあみ', short: 'とおくから そっと・あたりにくいが こわれにくい',
    color: '#cfead0', range: 3,
    hit: { 0: 0.34, 1: 0.50, 2: 0.57, 3: 0.62 },
    breakP: 0.06, basic: false, rare: false, dropW: 0.9
  },
  reinf: {
    id: 'reinf', name: 'じょうぶな2mのあみ', short: '2mで バランスよし・とても じょうぶ',
    color: '#e0d3b8', range: 2,
    hit: { 0: 0.50, 1: 0.86, 2: 0.74, 3: 0.42 },
    breakP: 0.05, basic: false, rare: false, dropW: 0.8
  },
  big: {
    id: 'big', name: 'おおあみ', short: 'ひろい はんい・なかきょりに つよい',
    color: '#bfe3f0', range: 2,
    hit: { 0: 0.42, 1: 0.70, 2: 0.80, 3: 0.66 },
    breakP: 0.12, basic: false, rare: false, dropW: 0.8
  },
  gold: {
    id: 'gold', name: '👑きんのあみ', short: 'どこでも つよくて こわれにくい・レア！',
    color: '#ffd54a', range: 2,
    hit: { 0: 0.65, 1: 0.86, 2: 0.82, 3: 0.76 },
    breakP: 0.04, basic: false, rare: true, dropW: 0.15
  }
};

/* ---- きょり別 命中率 ----
   表を つかい d=clamp(round(distM),0,maxKey)。
   とおすぎ(round(distM)>=4)は きゅうに さがる:
     さいえん値×0.4 から さらに -0.05/m、0.05が したかぎり。
   さいごに 0.05〜0.97 に clamp。 */
function netHit(id, distM) {
  try {
    var n = (typeof NETS !== 'undefined' && NETS[id]) ? NETS[id] : null;
    if (!n || !n.hit) return 0.3;
    var keys = Object.keys(n.hit).map(Number);
    if (!keys.length) return 0.3;
    var mx = Math.max.apply(null, keys);
    var dRaw = Math.round(Number(distM));
    if (!isFinite(dRaw)) dRaw = 0;
    var far = (typeof n.hit[mx] === 'number') ? n.hit[mx] : 0.3;
    var v;
    if (dRaw >= 4) {
      // とおすぎ：きゅうに げんすい
      v = far * 0.4 - (dRaw - 3) * 0.05;
    } else {
      var d = Math.max(0, Math.min(mx, dRaw));
      v = (typeof n.hit[d] === 'number') ? n.hit[d] : 0.3;
    }
    return Math.max(0.05, Math.min(0.97, v));
  } catch (e) {
    return 0.3;
  }
}

/* ---- ◎○△ のめやす（catch.js の csHitMark と おなじ きじゅん） ---- */
function netHitMark(p) {
  var v = (typeof p === 'number' && isFinite(p)) ? p : 0;
  if (v >= 0.75) return { mark: '◎', cls: 'good', word: 'ねらいめ！' };
  if (v >= 0.55) return { mark: '○', cls: 'ok', word: 'いけそう' };
  return { mark: '△', cls: 'bad', word: 'むずかしい' };
}

/* ---- こわれやすさ の めやす（lv 0..2） ----
   breakP>=0.25 → こわれやすい(2) / >=0.10 → ふつう(1) / それ未満 → じょうぶ(0) */
function netRiskLabel(id) {
  var n = (typeof NETS !== 'undefined' && NETS[id]) ? NETS[id] : null;
  var p = (n && typeof n.breakP === 'number') ? n.breakP : 0.15;
  if (p >= 0.25) return { word: 'こわれやすい', lv: 2 };
  if (p >= 0.10) return { word: 'ふつう', lv: 1 };
  return { word: 'じょうぶ', lv: 0 };
}

/* ---- Canvas に あみアイコンを かく ----
   color で わ／え／あみめ の いろどり。gold は きんいろ。
   size は だいたいの はんけい(px)。れいがいじは かんたんな まる。 */
function drawNetGlyph(ctx, cx, cy, size, id) {
  if (!ctx) return;
  var s = (typeof size === 'number' && size > 0) ? size : 16;
  var n = null;
  try { n = (typeof NETS !== 'undefined' && NETS[id]) ? NETS[id] : null; } catch (e) { n = null; }
  var col = n ? n.color : '#cfe8ff';
  var isGold = !!(n && n.rare) || id === 'gold';
  try {
    ctx.save();
    // え（とって）：ななめした へ のびる ぼう
    var hx = cx - s * 0.34, hy = cy + s * 0.62;
    ctx.lineCap = 'round';
    ctx.strokeStyle = isGold ? '#a87a14' : '#7a4a22';
    ctx.lineWidth = Math.max(2, s * 0.14);
    ctx.beginPath();
    ctx.moveTo(hx, hy);
    ctx.lineTo(cx - s * 0.04, cy + s * 0.06);
    ctx.stroke();

    // わ（リング）：ふちどり
    var ringX = cx, ringY = cy - s * 0.14, r = s * 0.42;
    ctx.lineWidth = Math.max(2, s * 0.12);
    ctx.strokeStyle = isGold ? '#caa029' : '#9a7a4a';
    ctx.beginPath();
    ctx.arc(ringX, ringY, r, 0, Math.PI * 2);
    ctx.stroke();

    // あみ（うちがわ）：いろつき
    ctx.fillStyle = col;
    ctx.globalAlpha = isGold ? 0.92 : 0.78;
    ctx.beginPath();
    ctx.arc(ringX, ringY, r * 0.86, 0, Math.PI * 2);
    ctx.fill();
    ctx.globalAlpha = 1;

    // あみめ（がら）：たて・よこの ほそい せん
    ctx.save();
    ctx.beginPath();
    ctx.arc(ringX, ringY, r * 0.86, 0, Math.PI * 2);
    ctx.clip();
    ctx.strokeStyle = isGold ? 'rgba(120,90,10,0.55)' : 'rgba(60,50,40,0.30)';
    ctx.lineWidth = Math.max(0.6, s * 0.04);
    var step = r * 0.42;
    for (var gx = ringX - r; gx <= ringX + r; gx += step) {
      ctx.beginPath(); ctx.moveTo(gx, ringY - r); ctx.lineTo(gx, ringY + r); ctx.stroke();
    }
    for (var gy = ringY - r; gy <= ringY + r; gy += step) {
      ctx.beginPath(); ctx.moveTo(ringX - r, gy); ctx.lineTo(ringX + r, gy); ctx.stroke();
    }
    ctx.restore();

    // ツヤ
    ctx.fillStyle = 'rgba(255,255,255,0.45)';
    ctx.beginPath();
    ctx.ellipse(ringX - r * 0.32, ringY - r * 0.34, r * 0.26, r * 0.16, -0.5, 0, Math.PI * 2);
    ctx.fill();

    // gold は きらり
    if (isGold) {
      ctx.fillStyle = 'rgba(255,255,255,0.9)';
      var sx = ringX + r * 0.5, sy = ringY - r * 0.5, sr = Math.max(1.5, s * 0.1);
      ctx.beginPath();
      ctx.moveTo(sx, sy - sr); ctx.lineTo(sx + sr * 0.3, sy - sr * 0.3);
      ctx.lineTo(sx + sr, sy); ctx.lineTo(sx + sr * 0.3, sy + sr * 0.3);
      ctx.lineTo(sx, sy + sr); ctx.lineTo(sx - sr * 0.3, sy + sr * 0.3);
      ctx.lineTo(sx - sr, sy); ctx.lineTo(sx - sr * 0.3, sy - sr * 0.3);
      ctx.closePath();
      ctx.fill();
    }
    ctx.restore();
  } catch (e) {
    // れいがい：かんたんな まる で フォールバック
    try {
      ctx.save();
      ctx.fillStyle = col;
      ctx.beginPath();
      ctx.arc(cx, cy, s * 0.4, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    } catch (e2) { /* むし */ }
  }
}
