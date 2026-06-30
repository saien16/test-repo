/* data/sprites.js — マルこれ キャラ＆ノードのSVGスプライト（インライン・外部アセット不使用）
   ・SPRITES.mal(id, opt)    マルウェアのキャラ。opt={expr:'normal'|'attack', gen:0..2}
   ・SPRITES.node(kind, opt) 敵のサーバ/PC/本命/装置。db は opt={state:'ok'|'hurt'|'crit'}
   むしとりバトルの data/bugs.js（SVGスプライト方式）に倣う。 */
const SPRITES = (() => {
  // ---- マルウェア・キャラ（ゆるかわ路線）。各キャラは body と目の位置 eyes を持つ ----
  const mal = {
    zeus: { // 怪盗トロイ（マスク＋¥コイン）
      eyes: [[42, 57], [58, 57]],
      body: `<ellipse cx="50" cy="92" rx="26" ry="6" fill="#0006"/>
        <rect x="22" y="36" width="56" height="50" rx="22" fill="#3fae6a" stroke="#2c8c52" stroke-width="2"/>
        <path d="M26 42 Q50 18 74 42 Z" fill="#23303a"/>
        <rect x="24" y="40" width="52" height="7" rx="3" fill="#1a2630"/>
        <rect x="30" y="51" width="40" height="13" rx="6" fill="#1a2630"/>
        <circle cx="42" cy="57" r="5" fill="#fff"/><circle cx="43" cy="58" r="2.5" fill="#11202a"/>
        <circle cx="58" cy="57" r="5" fill="#fff"/><circle cx="59" cy="58" r="2.5" fill="#11202a"/>
        <path d="M40 71 Q50 79 60 71" stroke="#1c5a36" stroke-width="3" fill="none" stroke-linecap="round"/>
        <circle cx="50" cy="80" r="7" fill="#ffd34a" stroke="#caa01f" stroke-width="2"/>
        <text x="50" y="84" font-size="9" text-anchor="middle" fill="#8a6a10">¥</text>`,
    },
    iloveyou: { // ラブレター・ワーム（ハート＋封筒）
      eyes: [[42, 54], [58, 54]],
      body: `<ellipse cx="50" cy="92" rx="24" ry="5" fill="#0006"/>
        <path d="M50 87 C16 63 22 34 40 34 C49 34 50 43 50 46 C50 43 51 34 60 34 C78 34 84 63 50 87 Z" fill="#ff8fb3" stroke="#e06a93" stroke-width="2"/>
        <circle cx="42" cy="54" r="4.5" fill="#fff"/><circle cx="43" cy="55" r="2.3" fill="#5a2336"/>
        <circle cx="58" cy="54" r="4.5" fill="#fff"/><circle cx="59" cy="55" r="2.3" fill="#5a2336"/>
        <circle cx="35" cy="62" r="3" fill="#ff5e8a" opacity=".6"/>
        <circle cx="65" cy="62" r="3" fill="#ff5e8a" opacity=".6"/>
        <path d="M44 64 Q50 70 56 64" stroke="#b03a60" stroke-width="2.5" fill="none" stroke-linecap="round"/>
        <rect x="40" y="71" width="20" height="14" rx="2" fill="#fff" stroke="#e06a93" stroke-width="1.5"/>
        <path d="M40 72 L50 79 L60 72" stroke="#e06a93" stroke-width="1.5" fill="none"/>`,
    },
    mydoom: { // ボット・スウォーム（ロボ＋子分ボット）
      eyes: [[41, 52], [58, 52]],
      body: `<ellipse cx="50" cy="92" rx="24" ry="5" fill="#0006"/>
        <line x1="50" y1="34" x2="50" y2="22" stroke="#7a52cc" stroke-width="3"/>
        <circle cx="50" cy="20" r="4" fill="#c8a8ff"/>
        <rect x="26" y="34" width="48" height="46" rx="12" fill="#9b6bff" stroke="#7a52cc" stroke-width="2"/>
        <rect x="36" y="48" width="11" height="9" rx="2" fill="#0d1020"/>
        <rect x="53" y="48" width="11" height="9" rx="2" fill="#0d1020"/>
        <rect x="38" y="50" width="4" height="4" fill="#5cf0ff"/>
        <rect x="55" y="50" width="4" height="4" fill="#5cf0ff"/>
        <rect x="38" y="64" width="24" height="8" rx="2" fill="#0d1020"/>
        <line x1="44" y1="64" x2="44" y2="72" stroke="#9b6bff" stroke-width="1.5"/>
        <line x1="50" y1="64" x2="50" y2="72" stroke="#9b6bff" stroke-width="1.5"/>
        <line x1="56" y1="64" x2="56" y2="72" stroke="#9b6bff" stroke-width="1.5"/>
        <circle cx="22" cy="74" r="6" fill="#c8a8ff" stroke="#7a52cc" stroke-width="1.5"/>
        <circle cx="78" cy="74" r="6" fill="#c8a8ff" stroke="#7a52cc" stroke-width="1.5"/>`,
    },
    blaster: { // 爆裂ワーム（導火線つき爆弾）
      eyes: [[41, 59], [55, 59]],
      body: `<ellipse cx="48" cy="92" rx="24" ry="5" fill="#0006"/>
        <path d="M62 34 q8 -6 10 -14" stroke="#caa01f" stroke-width="2" fill="none"/>
        <circle cx="74" cy="16" r="4" fill="#fff3b0"/><circle cx="74" cy="16" r="2" fill="#ffae3a"/>
        <circle cx="48" cy="58" r="26" fill="#ff8a3a" stroke="#d96a1f" stroke-width="2"/>
        <path d="M36 51 l10 4" stroke="#7a2e00" stroke-width="3" stroke-linecap="round"/>
        <path d="M60 51 l-10 4" stroke="#7a2e00" stroke-width="3" stroke-linecap="round"/>
        <circle cx="41" cy="59" r="4" fill="#fff"/><circle cx="42" cy="60" r="2" fill="#3a1500"/>
        <circle cx="55" cy="59" r="4" fill="#fff"/><circle cx="56" cy="60" r="2" fill="#3a1500"/>
        <path d="M40 69 l4 4 4 -4 4 4 4 -4" stroke="#7a2e00" stroke-width="2.5" fill="none" stroke-linejoin="round"/>`,
    },
  };

  // 攻撃表情の差分: 目の上に怒り眉＋気合いの「!!」
  function attackOverlay(eyes) {
    const [l, r] = eyes;
    return `<path d="M${l[0] - 8} ${l[1] - 8} l13 5" stroke="#111" stroke-width="3.4" stroke-linecap="round" opacity=".8"/>` +
      `<path d="M${r[0] + 8} ${r[1] - 8} l-13 5" stroke="#111" stroke-width="3.4" stroke-linecap="round" opacity=".8"/>` +
      `<text x="82" y="30" font-size="20" font-weight="900" fill="#ffd34a" stroke="#a8000a" stroke-width="0.6">!!</text>`;
  }
  // 被弾表情の差分: X目＋汗＋衝撃マーク（やられ顔）
  function hurtOverlay(eyes) {
    const [l, r] = eyes;
    const x = (c) => `<path d="M${c[0] - 4} ${c[1] - 4} l8 8 M${c[0] + 4} ${c[1] - 4} l-8 8" stroke="#11202a" stroke-width="2.6" stroke-linecap="round"/>`;
    return x(l) + x(r) +
      `<path d="M26 26 q5 7 0 12 q-5 -5 0 -12" fill="#7fd0ff" opacity=".9"/>` +
      `<g stroke="#ff5252" stroke-width="2.4" stroke-linecap="round"><path d="M80 22 l8 -7 M82 30 l9 -2 M78 16 l3 -9"/></g>`;
  }
  // 世代進化の差分: gen1=オーラ環 / gen2=きらめき星も追加
  function genOverlay(gen) {
    let s = '';
    if (gen >= 1) s += `<circle cx="50" cy="58" r="41" fill="none" stroke="#ffd34a" stroke-width="2.5" opacity=".55"/>`;
    if (gen >= 2) s += `<g fill="#fff3b0"><path d="M18 28 l2 5 5 2 -5 2 -2 5 -2 -5 -5 -2 5 -2 z"/>` +
      `<path d="M84 38 l1.5 4 4 1.5 -4 1.5 -1.5 4 -1.5 -4 -4 -1.5 4 -1.5 z"/>` +
      `<circle cx="28" cy="86" r="2"/></g>`;
    return s;
  }

  function malSprite(id, opt) {
    opt = opt || {};
    const m = mal[id]; if (!m) return '';
    let inject = '';
    if (opt.expr === 'attack') inject += attackOverlay(m.eyes);
    else if (opt.expr === 'hurt') inject += hurtOverlay(m.eyes);
    inject += genOverlay(opt.gen || 0);
    return `<svg viewBox="0 0 100 100">${m.body}${inject}</svg>`;
  }

  // ---- 敵ノード ----
  const node = {
    outside: `<g fill="#5b7a92" stroke="#3f5970" stroke-width="2">
        <rect x="32" y="50" width="42" height="18" rx="9"/>
        <circle cx="40" cy="50" r="13"/><circle cx="58" cy="46" r="16"/><circle cx="70" cy="54" r="11"/></g>`,
    pc: `<rect x="20" y="28" width="60" height="42" rx="6" fill="#2b3a48" stroke="#1c2731" stroke-width="2"/>
        <rect x="26" y="34" width="48" height="30" rx="3" fill="#7fd0ff"/>
        <circle cx="42" cy="46" r="3" fill="#11202a"/><circle cx="58" cy="46" r="3" fill="#11202a"/>
        <path d="M44 54 q6 4 12 0" stroke="#11202a" stroke-width="2" fill="none"/>
        <rect x="44" y="70" width="12" height="8" fill="#1c2731"/>
        <rect x="32" y="78" width="36" height="5" rx="2" fill="#1c2731"/>`,
    fw: `<rect x="24" y="42" width="52" height="38" rx="2" fill="#b6553a" stroke="#8a3c26" stroke-width="1.5"/>
        <g stroke="#8a3c26" stroke-width="1.5">
        <line x1="24" y1="55" x2="76" y2="55"/><line x1="24" y1="68" x2="76" y2="68"/>
        <line x1="42" y1="42" x2="42" y2="55"/><line x1="60" y1="55" x2="60" y2="68"/>
        <line x1="42" y1="68" x2="42" y2="80"/></g>
        <path d="M50 28 l15 5 v10 c0 11 -8 17 -15 21 c-7 -4 -15 -10 -15 -21 v-10 Z" fill="#e0564a" stroke="#a83228" stroke-width="2"/>
        <path d="M44 47 l5 6 9 -10" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round"/>`,
  };

  // 本命DB: HP状態で表情・ヒビ・王冠が変化（やられ顔の差分）
  function dbSprite(state) {
    const crownTilt = state === 'crit' ? 'transform="rotate(-16 50 30)"' : '';
    let face;
    if (state === 'crit') { // X目＋苦悶＋ヒビ
      face = `<path d="M38 58 l8 8 M46 58 l-8 8" stroke="#11202a" stroke-width="2.5" stroke-linecap="round"/>
        <path d="M54 58 l8 8 M62 58 l-8 8" stroke="#11202a" stroke-width="2.5" stroke-linecap="round"/>
        <path d="M43 74 q7 -5 14 0" stroke="#11202a" stroke-width="2.5" fill="none" stroke-linecap="round"/>
        <path d="M40 46 l4 10 -6 8 5 10" stroke="#11202a" stroke-width="1.6" fill="none" opacity=".7"/>
        <path d="M62 48 l-3 9 5 7" stroke="#11202a" stroke-width="1.6" fill="none" opacity=".7"/>`;
    } else if (state === 'hurt') { // 困り顔＋汗
      face = `<circle cx="42" cy="60" r="3" fill="#11202a"/><circle cx="58" cy="60" r="3" fill="#11202a"/>
        <path d="M43 73 q7 4 14 0" stroke="#11202a" stroke-width="2.5" fill="none" stroke-linecap="round"/>
        <path d="M68 54 q4 6 0 9 q-4 -3 0 -9" fill="#7fd0ff" opacity=".9"/>`;
    } else { // 平常（¥顔）
      face = `<circle cx="42" cy="60" r="3" fill="#dcefff"/><circle cx="58" cy="60" r="3" fill="#dcefff"/>
        <text x="50" y="76" font-size="13" text-anchor="middle" fill="#dcefff">¥</text>`;
    }
    return `<svg viewBox="0 0 100 100">
      <g ${crownTilt}><path d="M32 24 l6 9 12 -11 12 11 6 -9 -2 16 -32 0 Z" fill="#ffd34a" stroke="#caa01f" stroke-width="1.5"/></g>
      <rect x="26" y="44" width="48" height="36" fill="#4a6b8a" stroke="#33506a" stroke-width="2"/>
      <ellipse cx="50" cy="80" rx="24" ry="8" fill="#4a6b8a" stroke="#33506a" stroke-width="2"/>
      <ellipse cx="50" cy="44" rx="24" ry="8" fill="#5e84a8" stroke="#33506a" stroke-width="2"/>
      ${face}</svg>`;
  }

  function nodeSprite(kind, opt) {
    opt = opt || {};
    if (kind === 'db') return dbSprite(opt.state || 'ok');
    const inner = node[kind]; if (!inner) return '';
    return `<svg viewBox="0 0 100 100">${inner}</svg>`;
  }

  // ---- カード固有のキャラ（イカタコ など） ----
  const card = {
    ikatako: `<svg viewBox="0 0 100 100">
      <ellipse cx="50" cy="93" rx="20" ry="4" fill="#0006"/>
      <path d="M33 30 Q23 26 30 41 Z" fill="#ff7aa6"/>
      <path d="M67 30 Q77 26 70 41 Z" fill="#ff7aa6"/>
      <path d="M50 16 Q68 28 66 52 Q66 60 50 60 Q34 60 34 52 Q32 28 50 16 Z" fill="#ff8fb3" stroke="#e06a93" stroke-width="2"/>
      <circle cx="43" cy="44" r="5.5" fill="#fff"/><circle cx="44" cy="45" r="2.6" fill="#3a1020"/>
      <circle cx="57" cy="44" r="5.5" fill="#fff"/><circle cx="58" cy="45" r="2.6" fill="#3a1020"/>
      <circle cx="38" cy="51" r="2.4" fill="#ff5e8a" opacity=".6"/><circle cx="62" cy="51" r="2.4" fill="#ff5e8a" opacity=".6"/>
      <path d="M45 53 q5 4 10 0" stroke="#b03a60" stroke-width="2" fill="none" stroke-linecap="round"/>
      <g stroke="#ff8fb3" stroke-width="5" fill="none" stroke-linecap="round">
        <path d="M40 60 q-4 11 -9 15"/><path d="M47 62 q-2 12 -3 19"/>
        <path d="M53 62 q2 12 3 19"/><path d="M60 60 q4 11 9 15"/>
      </g>
      <g stroke="#e06a93" stroke-width="1.4" fill="none" stroke-linecap="round" opacity=".6">
        <path d="M40 60 q-4 11 -9 15"/><path d="M60 60 q4 11 9 15"/>
      </g></svg>`,
  };
  function cardSprite(id) { return card[id] || ''; }

  return { mal: malSprite, node: nodeSprite, card: cardSprite };
})();

if (typeof globalThis !== 'undefined') globalThis.SPRITES = SPRITES;
