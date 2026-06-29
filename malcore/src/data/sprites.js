/* data/sprites.js — マルこれ キャラ＆ノードのSVGスプライト（インライン・外部アセット不使用）
   ・SPRITES.mal(id)   マルウェアのファンシーなキャラ（艦これ的擬人化）
   ・SPRITES.node(kind) 敵のサーバ/PC/本命/防御装置のアイコン
   むしとりバトルの data/bugs.js（SVGスプライト方式）に倣う。 */
const SPRITES = (() => {
  // ---- マルウェア・キャラ（ゆるかわ路線） ----
  const mal = {
    // Zeus: 怪盗トロイ（マスク＋¥コイン）
    zeus: `<svg viewBox="0 0 100 100">
      <ellipse cx="50" cy="92" rx="26" ry="6" fill="#0006"/>
      <rect x="22" y="36" width="56" height="50" rx="22" fill="#3fae6a" stroke="#2c8c52" stroke-width="2"/>
      <path d="M26 42 Q50 18 74 42 Z" fill="#23303a"/>
      <rect x="24" y="40" width="52" height="7" rx="3" fill="#1a2630"/>
      <rect x="30" y="51" width="40" height="13" rx="6" fill="#1a2630"/>
      <circle cx="42" cy="57" r="5" fill="#fff"/><circle cx="43" cy="58" r="2.5" fill="#11202a"/>
      <circle cx="58" cy="57" r="5" fill="#fff"/><circle cx="59" cy="58" r="2.5" fill="#11202a"/>
      <path d="M40 71 Q50 79 60 71" stroke="#1c5a36" stroke-width="3" fill="none" stroke-linecap="round"/>
      <circle cx="50" cy="80" r="7" fill="#ffd34a" stroke="#caa01f" stroke-width="2"/>
      <text x="50" y="84" font-size="9" text-anchor="middle" fill="#8a6a10">¥</text></svg>`,
    // ILOVEYOU: ラブレター・ワーム（ハート＋封筒）
    iloveyou: `<svg viewBox="0 0 100 100">
      <ellipse cx="50" cy="92" rx="24" ry="5" fill="#0006"/>
      <path d="M50 87 C16 63 22 34 40 34 C49 34 50 43 50 46 C50 43 51 34 60 34 C78 34 84 63 50 87 Z" fill="#ff8fb3" stroke="#e06a93" stroke-width="2"/>
      <circle cx="42" cy="54" r="4.5" fill="#fff"/><circle cx="43" cy="55" r="2.3" fill="#5a2336"/>
      <circle cx="58" cy="54" r="4.5" fill="#fff"/><circle cx="59" cy="55" r="2.3" fill="#5a2336"/>
      <circle cx="35" cy="62" r="3" fill="#ff5e8a" opacity=".6"/>
      <circle cx="65" cy="62" r="3" fill="#ff5e8a" opacity=".6"/>
      <path d="M44 64 Q50 70 56 64" stroke="#b03a60" stroke-width="2.5" fill="none" stroke-linecap="round"/>
      <rect x="40" y="71" width="20" height="14" rx="2" fill="#fff" stroke="#e06a93" stroke-width="1.5"/>
      <path d="M40 72 L50 79 L60 72" stroke="#e06a93" stroke-width="1.5" fill="none"/></svg>`,
    // MyDoom: ボット・スウォーム（ロボ＋子分ボット）
    mydoom: `<svg viewBox="0 0 100 100">
      <ellipse cx="50" cy="92" rx="24" ry="5" fill="#0006"/>
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
      <circle cx="78" cy="74" r="6" fill="#c8a8ff" stroke="#7a52cc" stroke-width="1.5"/></svg>`,
    // Blaster: 爆裂ワーム（導火線つき爆弾）
    blaster: `<svg viewBox="0 0 100 100">
      <ellipse cx="48" cy="92" rx="24" ry="5" fill="#0006"/>
      <path d="M62 34 q8 -6 10 -14" stroke="#caa01f" stroke-width="2" fill="none"/>
      <circle cx="74" cy="16" r="4" fill="#fff3b0"/><circle cx="74" cy="16" r="2" fill="#ffae3a"/>
      <circle cx="48" cy="58" r="26" fill="#ff8a3a" stroke="#d96a1f" stroke-width="2"/>
      <path d="M36 51 l10 4" stroke="#7a2e00" stroke-width="3" stroke-linecap="round"/>
      <path d="M60 51 l-10 4" stroke="#7a2e00" stroke-width="3" stroke-linecap="round"/>
      <circle cx="41" cy="59" r="4" fill="#fff"/><circle cx="42" cy="60" r="2" fill="#3a1500"/>
      <circle cx="55" cy="59" r="4" fill="#fff"/><circle cx="56" cy="60" r="2" fill="#3a1500"/>
      <path d="M40 69 l4 4 4 -4 4 4 4 -4" stroke="#7a2e00" stroke-width="2.5" fill="none" stroke-linejoin="round"/></svg>`,
  };

  // ---- 敵ノード（サーバ/PC/本命/装置） ----
  const node = {
    // 外部（インターネット雲）
    outside: `<svg viewBox="0 0 100 100">
      <g fill="#5b7a92" stroke="#3f5970" stroke-width="2">
        <rect x="32" y="50" width="42" height="18" rx="9"/>
        <circle cx="40" cy="50" r="13"/><circle cx="58" cy="46" r="16"/><circle cx="70" cy="54" r="11"/>
      </g></svg>`,
    // 社員PC（顔つきモニタ）
    pc: `<svg viewBox="0 0 100 100">
      <rect x="20" y="28" width="60" height="42" rx="6" fill="#2b3a48" stroke="#1c2731" stroke-width="2"/>
      <rect x="26" y="34" width="48" height="30" rx="3" fill="#7fd0ff"/>
      <circle cx="42" cy="46" r="3" fill="#11202a"/><circle cx="58" cy="46" r="3" fill="#11202a"/>
      <path d="M44 54 q6 4 12 0" stroke="#11202a" stroke-width="2" fill="none"/>
      <rect x="44" y="70" width="12" height="8" fill="#1c2731"/>
      <rect x="32" y="78" width="36" height="5" rx="2" fill="#1c2731"/></svg>`,
    // 本命：勘定系DB（王冠つきデータベース＝銀行）
    db: `<svg viewBox="0 0 100 100">
      <path d="M32 24 l6 9 12 -11 12 11 6 -9 -2 16 -32 0 Z" fill="#ffd34a" stroke="#caa01f" stroke-width="1.5"/>
      <rect x="26" y="44" width="48" height="36" fill="#4a6b8a" stroke="#33506a" stroke-width="2"/>
      <ellipse cx="50" cy="80" rx="24" ry="8" fill="#4a6b8a" stroke="#33506a" stroke-width="2"/>
      <ellipse cx="50" cy="44" rx="24" ry="8" fill="#5e84a8" stroke="#33506a" stroke-width="2"/>
      <path d="M26 58 a24 8 0 0 0 48 0" fill="none" stroke="#33506a" stroke-width="2"/>
      <path d="M26 70 a24 8 0 0 0 48 0" fill="none" stroke="#33506a" stroke-width="2"/>
      <text x="50" y="64" font-size="15" text-anchor="middle" fill="#dcefff">¥</text></svg>`,
    // 境界FW（レンガ＋シールド）
    fw: `<svg viewBox="0 0 100 100">
      <rect x="24" y="42" width="52" height="38" rx="2" fill="#b6553a" stroke="#8a3c26" stroke-width="1.5"/>
      <g stroke="#8a3c26" stroke-width="1.5">
        <line x1="24" y1="55" x2="76" y2="55"/><line x1="24" y1="68" x2="76" y2="68"/>
        <line x1="42" y1="42" x2="42" y2="55"/><line x1="60" y1="55" x2="60" y2="68"/>
        <line x1="42" y1="68" x2="42" y2="80"/></g>
      <path d="M50 28 l15 5 v10 c0 11 -8 17 -15 21 c-7 -4 -15 -10 -15 -21 v-10 Z" fill="#e0564a" stroke="#a83228" stroke-width="2"/>
      <path d="M44 47 l5 6 9 -10" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round"/></svg>`,
  };

  return { mal: (id) => mal[id] || '', node: (k) => node[k] || '' };
})();

if (typeof globalThis !== 'undefined') globalThis.SPRITES = SPRITES;
