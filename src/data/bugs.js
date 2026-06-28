/* ============================================================
   むしとりバトル — data/bugs.js（虫データ＆みため）
   ・BUGS … 虫ずかんの正データ（20種いじょう）
   ・DAY_KEYS / NIGHT_KEYS … time でふりわけたキーの配列
   ・pickSpecies(night) … レア度 w で重みづけ抽選
   ・bugSprite(key, sizePx) … インラインSVG文字列（shape ごとに描き分け）
   ・drawBugMini(ctx, key, cx, cy, r) … Canvas にちいさく描く（任意）
   ※ import/export しない。グローバル共有。トップレベルで document を触らない。
   ============================================================ */

/* ---- 虫ずかん（キー＝英数id） ----
   w: 3=ふつう / 2=中堅 / 1=レア。レア度と pts/alertBase/sizeBase を相関させ、
   出現は w でしぼる（夜は w3 を出さない、昼は w1 を出さない）。 */
const BUGS = {
  /* === ふつう（w:3）：出やすい・低得点・おとなしい === */
  monshiro:  { name: 'もんしろちょう',   color: '#fdfdf6', accent: '#cfcfc2', w: 3, pts: 10, alertBase: 4,  sizeBase: 45,  time: 'day',   shape: 'butterfly' },
  monki:     { name: 'もんきちょう',     color: '#f7e96b', accent: '#c2a72e', w: 3, pts: 12, alertBase: 5,  sizeBase: 48,  time: 'day',   shape: 'butterfly' },
  onbubatta: { name: 'おんぶばった',     color: '#a4c489', accent: '#5a9a3a', w: 3, pts: 9,  alertBase: 4,  sizeBase: 42,  time: 'both',  shape: 'grasshopper' },
  nanahoshi: { name: 'ななほしてんとう', color: '#d83a2a', accent: '#1a1712', w: 3, pts: 11, alertBase: 3,  sizeBase: 8,   time: 'both',  shape: 'ladybug' },
  kokuwa:    { name: 'こくわがた',       color: '#4a3a2a', accent: '#241a0f', w: 3, pts: 16, alertBase: 6,  sizeBase: 38,  time: 'both',  shape: 'stag' },
  kokabuto:  { name: 'こかぶとむし',     color: '#5a4632', accent: '#2e2214', w: 3, pts: 18, alertBase: 6,  sizeBase: 40,  time: 'both',  shape: 'beetle' },
  niinii:    { name: 'にいにいぜみ',     color: '#6b6252', accent: '#332e24', w: 3, pts: 14, alertBase: 7,  sizeBase: 35,  time: 'day',   shape: 'cicada' },
  shiokara:  { name: 'しおからとんぼ',   color: '#7ab2c9', accent: '#3a6a8a', w: 3, pts: 15, alertBase: 8,  sizeBase: 50,  time: 'day',   shape: 'dragonfly' },
  enma:      { name: 'えんまこおろぎ',   color: '#4a4036', accent: '#241f16', w: 3, pts: 13, alertBase: 6,  sizeBase: 30,  time: 'night', shape: 'grasshopper' },
  mitsubachi:{ name: 'みつばち',         color: '#d9b441', accent: '#7a5a10', w: 3, pts: 17, alertBase: 9,  sizeBase: 14,  time: 'day',   shape: 'bee' },

  /* === 中堅（w:2）：そこそこ・中得点・やや警戒つよめ === */
  ageha:     { name: 'あげはちょう',     color: '#ffd84d', accent: '#3d3a2e', w: 2, pts: 30, alertBase: 11, sizeBase: 90,  time: 'day',   shape: 'butterfly' },
  nokogiri:  { name: 'のこぎりくわがた', color: '#6b3a1a', accent: '#33180a', w: 2, pts: 42, alertBase: 12, sizeBase: 60,  time: 'both',  shape: 'stag' },
  kanabun:   { name: 'かなぶん',         color: '#8a6a3a', accent: '#42300f', w: 2, pts: 28, alertBase: 10, sizeBase: 28,  time: 'day',   shape: 'beetle' },
  kumabachi: { name: 'くまばち',         color: '#e8b53d', accent: '#4a3a10', w: 2, pts: 32, alertBase: 13, sizeBase: 22,  time: 'night', shape: 'bee' },
  kokama:    { name: 'こかまきり',       color: '#9a7a4a', accent: '#5a4226', w: 2, pts: 30, alertBase: 12, sizeBase: 55,  time: 'both',  shape: 'mantis' },
  akiakane:  { name: 'あきあかね',       color: '#c14e34', accent: '#8a2a15', w: 2, pts: 30, alertBase: 11, sizeBase: 38,  time: 'day',   shape: 'dragonfly' },
  minmin:    { name: 'みんみんぜみ',     color: '#4a6e4a', accent: '#1f3a1f', w: 2, pts: 45, alertBase: 13, sizeBase: 60,  time: 'day',   shape: 'cicada' },
  tonosama:  { name: 'とのさまばった',   color: '#6aa84f', accent: '#2e5e1f', w: 2, pts: 34, alertBase: 12, sizeBase: 65,  time: 'night', shape: 'grasshopper' },

  /* === レア（w:1）：出にくい・高得点・とても警戒つよい === */
  kabuto:    { name: 'かぶとむし',       color: '#6b4226', accent: '#33200f', w: 1, pts: 60, alertBase: 15, sizeBase: 80,  time: 'both',  shape: 'rhino' },
  miyama:    { name: 'みやまくわがた',   color: '#5a4a2e', accent: '#2a2010', w: 1, pts: 58, alertBase: 16, sizeBase: 70,  time: 'night', shape: 'stag' },
  yanma:     { name: 'おにやんま',       color: '#2f9078', accent: '#1f6e5a', w: 1, pts: 70, alertBase: 18, sizeBase: 100, time: 'both',  shape: 'dragonfly' },
  ohkama:    { name: 'おおかまきり',     color: '#6aa84f', accent: '#2e5e1f', w: 1, pts: 55, alertBase: 16, sizeBase: 95,  time: 'night', shape: 'mantis' },
  suzumebachi:{ name:'おおすずめばち',   color: '#ff9b2e', accent: '#5a3a10', w: 1, pts: 80, alertBase: 19, sizeBase: 40,  time: 'day',   shape: 'bee' },
  tamamushi: { name: 'たまむし',         color: '#2a9a6e', accent: '#c95a3d', w: 1, pts: 85, alertBase: 17, sizeBase: 38,  time: 'day',   shape: 'beetle' },
  kumazemi:  { name: 'くまぜみ',         color: '#26241f', accent: '#5fd0c0', w: 1, pts: 75, alertBase: 16, sizeBase: 65,  time: 'night', shape: 'cicada' },
};

/* ---- 昼夜キー（time でふりわけ。both は両方へ） ---- */
const DAY_KEYS = Object.keys(BUGS).filter(k => BUGS[k].time === 'day' || BUGS[k].time === 'both');
const NIGHT_KEYS = Object.keys(BUGS).filter(k => BUGS[k].time === 'night' || BUGS[k].time === 'both');

/* ---- レア度抽選 ----
   夜は w3 を出さない（夜=レア寄り）、昼は w1 を出さない（昼=ふつう寄り）。
   候補の w をそのまま重みに使う（w 大=出やすい）。 */
function pickSpecies(night) {
  const pool = night ? NIGHT_KEYS : DAY_KEYS;
  // この時間帯で出してよい候補（昼=w1除外 / 夜=w3除外）
  const cands = pool.filter(k => {
    const w = BUGS[k].w;
    if (night) return w !== 3;   // 夜は ふつう を出さない
    return w !== 1;              // 昼は レア を出さない
  });
  if (!cands.length) return pool[0]; // 念のため
  let total = 0;
  for (let i = 0; i < cands.length; i++) total += BUGS[cands[i]].w;
  let r = Math.random() * total;
  for (let i = 0; i < cands.length; i++) {
    r -= BUGS[cands[i]].w;
    if (r < 0) return cands[i];
  }
  return cands[cands.length - 1];
}

/* ============================================================
   SVG みため（shape ごとに描き分け）
   viewBox="0 0 100 100" / 背景とうめい / 左右対称 / </svg> でとじる
   ============================================================ */
function bugSprite(key, sizePx) {
  const b = BUGS[key] || { color: '#888', accent: '#333', shape: 'beetle', name: '?' };
  const C = b.color, A = b.accent;
  const px = sizePx || 64;
  const head = `<svg xmlns="http://www.w3.org/2000/svg" width="${px}" height="${px}" viewBox="0 0 100 100" aria-label="${b.name}">`;
  const tail = `</svg>`;
  // ちょっとした白いツヤ
  const sheen = (x, y, rx, ry, op) => `<ellipse cx="${x}" cy="${y}" rx="${rx}" ry="${ry}" fill="#fff" opacity="${op == null ? 0.25 : op}"/>`;
  let body = '';

  switch (b.shape) {
    /* ===== ちょう：ひらいた4まいばね・触角・どうたい ===== */
    case 'butterfly': {
      const wing = `
        <path d="M50 50 C 30 22, 8 24, 12 44 C 14 56, 36 56, 50 54 Z" fill="${C}" stroke="${A}" stroke-width="2"/>
        <path d="M50 54 C 34 58, 14 64, 20 80 C 26 90, 44 78, 50 60 Z" fill="${C}" stroke="${A}" stroke-width="2"/>
        <circle cx="28" cy="40" r="5" fill="${A}" opacity="0.85"/>
        <circle cx="30" cy="70" r="3.5" fill="${A}" opacity="0.7"/>`;
      body = `
        ${wing}
        <g transform="translate(100 0) scale(-1 1)">${wing}</g>
        <ellipse cx="50" cy="55" rx="4" ry="18" fill="${A}"/>
        <circle cx="50" cy="35" r="5" fill="${A}"/>
        <circle cx="47.5" cy="34" r="1.4" fill="#fff"/><circle cx="52.5" cy="34" r="1.4" fill="#fff"/>
        <path d="M48 31 Q 40 18, 34 14 M52 31 Q 60 18, 66 14" fill="none" stroke="${A}" stroke-width="2" stroke-linecap="round"/>
        <circle cx="34" cy="14" r="2.4" fill="${A}"/><circle cx="66" cy="14" r="2.4" fill="${A}"/>
        ${sheen(22, 38, 6, 4, 0.3)}`;
      break;
    }

    /* ===== かぶとむし系（rhino）：おおきな一本ヅノ ===== */
    case 'rhino': {
      const legs = `
        <path d="M40 56 L 22 48 M40 66 L 20 66 M42 74 L 24 84" stroke="${A}" stroke-width="3.4" fill="none" stroke-linecap="round"/>
        <g transform="translate(100 0) scale(-1 1)">
          <path d="M40 56 L 22 48 M40 66 L 20 66 M42 74 L 24 84" stroke="${A}" stroke-width="3.4" fill="none" stroke-linecap="round"/>
        </g>`;
      body = `
        ${legs}
        <ellipse cx="50" cy="66" rx="24" ry="22" fill="${C}" stroke="${A}" stroke-width="2.4"/>
        <line x1="50" y1="46" x2="50" y2="86" stroke="${A}" stroke-width="2"/>
        <ellipse cx="50" cy="42" rx="14" ry="12" fill="${C}" stroke="${A}" stroke-width="2.2"/>
        <ellipse cx="50" cy="30" rx="8" ry="7" fill="${C}" stroke="${A}" stroke-width="2"/>
        <!-- 一本ヅノ：先がふたまた -->
        <path d="M50 27 L 50 8 M50 8 L 44 2 M50 8 L 56 2" stroke="${A}" stroke-width="4" fill="none" stroke-linecap="round"/>
        <path d="M50 18 L 45 12 M50 18 L 55 12" stroke="${A}" stroke-width="3" fill="none" stroke-linecap="round"/>
        <circle cx="45" cy="30" r="2" fill="#fff"/><circle cx="55" cy="30" r="2" fill="#fff"/>
        ${sheen(40, 56, 8, 6, 0.22)}`;
      break;
    }

    /* ===== くわがた（stag）：大きなはさみ（おおあご） ===== */
    case 'stag': {
      const legs = `
        <path d="M40 58 L 24 50 M40 68 L 22 70 M42 76 L 26 86" stroke="${A}" stroke-width="3.2" fill="none" stroke-linecap="round"/>
        <g transform="translate(100 0) scale(-1 1)">
          <path d="M40 58 L 24 50 M40 68 L 22 70 M42 76 L 26 86" stroke="${A}" stroke-width="3.2" fill="none" stroke-linecap="round"/>
        </g>`;
      const jaw = `<path d="M44 32 Q 30 20, 26 8 Q 34 16, 40 18 Q 34 12, 36 6 Q 44 14, 48 24 Z" fill="${C}" stroke="${A}" stroke-width="2"/>`;
      body = `
        ${legs}
        <ellipse cx="50" cy="64" rx="22" ry="24" fill="${C}" stroke="${A}" stroke-width="2.4"/>
        <line x1="50" y1="42" x2="50" y2="86" stroke="${A}" stroke-width="2"/>
        <ellipse cx="50" cy="42" rx="13" ry="10" fill="${C}" stroke="${A}" stroke-width="2.2"/>
        <ellipse cx="50" cy="32" rx="9" ry="7" fill="${C}" stroke="${A}" stroke-width="2"/>
        ${jaw}
        <g transform="translate(100 0) scale(-1 1)">${jaw}</g>
        <circle cx="46" cy="32" r="2" fill="#fff"/><circle cx="54" cy="32" r="2" fill="#fff"/>
        ${sheen(40, 56, 8, 7, 0.2)}`;
      break;
    }

    /* ===== こうちゅう（beetle）：まるいせなか・会合線 ===== */
    case 'beetle': {
      const legs = `
        <path d="M38 52 L 20 44 M38 64 L 18 64 M40 74 L 22 84" stroke="${A}" stroke-width="3.2" fill="none" stroke-linecap="round"/>
        <g transform="translate(100 0) scale(-1 1)">
          <path d="M38 52 L 20 44 M38 64 L 18 64 M40 74 L 22 84" stroke="${A}" stroke-width="3.2" fill="none" stroke-linecap="round"/>
        </g>`;
      body = `
        ${legs}
        <ellipse cx="50" cy="60" rx="26" ry="28" fill="${C}" stroke="${A}" stroke-width="2.4"/>
        <line x1="50" y1="36" x2="50" y2="86" stroke="${A}" stroke-width="2"/>
        <ellipse cx="50" cy="34" rx="14" ry="10" fill="${C}" stroke="${A}" stroke-width="2.2"/>
        <ellipse cx="50" cy="24" rx="8" ry="6" fill="${A}"/>
        <path d="M46 21 Q 40 12, 36 10 M54 21 Q 60 12, 64 10" fill="none" stroke="${A}" stroke-width="2" stroke-linecap="round"/>
        <circle cx="46" cy="24" r="1.6" fill="#fff"/><circle cx="54" cy="24" r="1.6" fill="#fff"/>
        ${sheen(40, 50, 10, 8, 0.28)}`;
      break;
    }

    /* ===== てんとうむし（ladybug）：まるくて 黒い水玉 ===== */
    case 'ladybug': {
      const legs = `
        <path d="M40 52 L 26 44 M40 64 L 24 64 M42 74 L 28 84" stroke="${A}" stroke-width="2.8" fill="none" stroke-linecap="round"/>
        <g transform="translate(100 0) scale(-1 1)">
          <path d="M40 52 L 26 44 M40 64 L 24 64 M42 74 L 28 84" stroke="${A}" stroke-width="2.8" fill="none" stroke-linecap="round"/>
        </g>`;
      body = `
        ${legs}
        <circle cx="50" cy="58" r="28" fill="${C}" stroke="${A}" stroke-width="2.4"/>
        <line x1="50" y1="32" x2="50" y2="86" stroke="${A}" stroke-width="2"/>
        <path d="M30 40 A 28 28 0 0 1 70 40 Z" fill="${A}"/>
        <circle cx="38" cy="54" r="4.5" fill="${A}"/><circle cx="62" cy="54" r="4.5" fill="${A}"/>
        <circle cx="42" cy="70" r="4" fill="${A}"/><circle cx="58" cy="70" r="4" fill="${A}"/>
        <circle cx="50" cy="62" r="3.5" fill="${A}"/>
        <circle cx="43" cy="38" r="2" fill="#fff"/><circle cx="57" cy="38" r="2" fill="#fff"/>
        ${sheen(40, 50, 7, 5, 0.3)}`;
      break;
    }

    /* ===== かまきり（mantis）：かまの前あし・ほそながい体 ===== */
    case 'mantis': {
      const arm = `<path d="M48 44 L 32 36 L 26 26 L 34 30 L 30 22" fill="none" stroke="${A}" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/>`;
      const legs = `
        <path d="M46 60 L 30 70 M48 70 L 34 84" stroke="${A}" stroke-width="2.8" fill="none" stroke-linecap="round"/>
        <g transform="translate(100 0) scale(-1 1)">
          <path d="M46 60 L 30 70 M48 70 L 34 84" stroke="${A}" stroke-width="2.8" fill="none" stroke-linecap="round"/>
        </g>`;
      body = `
        ${legs}
        <ellipse cx="50" cy="62" rx="11" ry="26" fill="${C}" stroke="${A}" stroke-width="2.2"/>
        <rect x="46" y="40" width="8" height="20" rx="4" fill="${C}" stroke="${A}" stroke-width="2"/>
        ${arm}
        <g transform="translate(100 0) scale(-1 1)">${arm}</g>
        <path d="M44 36 L 56 36 L 53 26 L 47 26 Z" fill="${C}" stroke="${A}" stroke-width="2"/>
        <circle cx="47" cy="29" r="2.4" fill="${A}"/><circle cx="53" cy="29" r="2.4" fill="${A}"/>
        <circle cx="47" cy="29" r="0.9" fill="#fff"/><circle cx="53" cy="29" r="0.9" fill="#fff"/>
        <path d="M47 26 Q 44 16, 41 12 M53 26 Q 56 16, 59 12" fill="none" stroke="${A}" stroke-width="1.8" stroke-linecap="round"/>
        ${sheen(46, 56, 4, 12, 0.2)}`;
      break;
    }

    /* ===== とんぼ（dragonfly）：ながい胴・4まいの薄ばね・おおきな目 ===== */
    case 'dragonfly': {
      const wing = `<ellipse cx="30" cy="40" rx="24" ry="8" transform="rotate(-18 30 40)" fill="${C}" opacity="0.55" stroke="${A}" stroke-width="1.6"/>`;
      const wing2 = `<ellipse cx="32" cy="58" rx="22" ry="7" transform="rotate(16 32 58)" fill="${C}" opacity="0.55" stroke="${A}" stroke-width="1.6"/>`;
      body = `
        ${wing}${wing2}
        <g transform="translate(100 0) scale(-1 1)">${wing}${wing2}</g>
        <rect x="47" y="46" width="6" height="46" rx="3" fill="${C}" stroke="${A}" stroke-width="2"/>
        <path d="M48 56 H52 M48 64 H52 M48 72 H52 M48 80 H52" stroke="${A}" stroke-width="1.6"/>
        <ellipse cx="50" cy="44" rx="8" ry="9" fill="${C}" stroke="${A}" stroke-width="2"/>
        <circle cx="44" cy="34" r="6" fill="${A}"/><circle cx="56" cy="34" r="6" fill="${A}"/>
        <circle cx="44" cy="33" r="2" fill="#fff"/><circle cx="56" cy="33" r="2" fill="#fff"/>
        ${sheen(24, 36, 8, 3, 0.3)}`;
      break;
    }

    /* ===== はち（bee）：しましま腹・はり・透明ばね ===== */
    case 'bee': {
      const wing = `<ellipse cx="34" cy="40" rx="16" ry="9" transform="rotate(-22 34 40)" fill="#eaf4ff" opacity="0.7" stroke="${A}" stroke-width="1.6"/>`;
      body = `
        ${wing}
        <g transform="translate(100 0) scale(-1 1)">${wing}</g>
        <ellipse cx="50" cy="60" rx="18" ry="24" fill="${C}" stroke="${A}" stroke-width="2.2"/>
        <path d="M34 52 Q 50 48, 66 52 M33 62 Q 50 60, 67 62 M36 72 Q 50 72, 64 72" stroke="${A}" stroke-width="5" fill="none"/>
        <path d="M50 84 L 46 94 L 54 94 Z" fill="${A}"/>
        <circle cx="50" cy="34" r="11" fill="${A}"/>
        <circle cx="45" cy="32" r="2" fill="#fff"/><circle cx="55" cy="32" r="2" fill="#fff"/>
        <path d="M44 26 Q 40 16, 37 12 M56 26 Q 60 16, 63 12" fill="none" stroke="${A}" stroke-width="2" stroke-linecap="round"/>
        <circle cx="37" cy="12" r="2.2" fill="${A}"/><circle cx="63" cy="12" r="2.2" fill="${A}"/>
        ${sheen(42, 50, 5, 8, 0.25)}`;
      break;
    }

    /* ===== せみ（cicada）：三角がたの体・大きな透明ばね ===== */
    case 'cicada': {
      const wing = `<path d="M48 36 C 26 32, 10 50, 18 78 C 26 84, 44 70, 48 50 Z" fill="${C}" opacity="0.5" stroke="${A}" stroke-width="1.8"/>`;
      body = `
        ${wing}
        <g transform="translate(100 0) scale(-1 1)">${wing}</g>
        <path d="M50 30 C 40 30, 38 44, 42 64 C 44 84, 56 84, 58 64 C 62 44, 60 30, 50 30 Z" fill="${C}" stroke="${A}" stroke-width="2.2"/>
        <path d="M44 50 Q 50 52, 56 50 M44 60 Q 50 62, 56 60 M45 70 Q 50 72, 55 70" stroke="${A}" stroke-width="1.6" fill="none"/>
        <ellipse cx="50" cy="30" rx="12" ry="8" fill="${C}" stroke="${A}" stroke-width="2"/>
        <circle cx="42" cy="28" r="4" fill="${A}"/><circle cx="58" cy="28" r="4" fill="${A}"/>
        <circle cx="42" cy="27" r="1.4" fill="#fff"/><circle cx="58" cy="27" r="1.4" fill="#fff"/>
        ${sheen(44, 44, 5, 8, 0.22)}`;
      break;
    }

    /* ===== ばった/こおろぎ（grasshopper）：太い後あし・ながい触角 ===== */
    case 'grasshopper': {
      const backleg = `<path d="M54 56 L 84 40 L 90 50 L 60 64 Z" fill="${C}" stroke="${A}" stroke-width="2"/>
        <path d="M86 44 L 96 74 L 90 84" stroke="${A}" stroke-width="3" fill="none" stroke-linecap="round"/>`;
      body = `
        ${backleg}
        <path d="M40 58 L 34 76 M50 60 L 48 80" stroke="${A}" stroke-width="2.6" fill="none" stroke-linecap="round"/>
        <path d="M24 54 Q 50 46, 78 54 Q 84 58, 76 64 Q 50 68, 28 62 Q 22 58, 24 54 Z" fill="${C}" stroke="${A}" stroke-width="2.2"/>
        <path d="M30 54 Q 56 50, 76 56" stroke="${A}" stroke-width="1.4" fill="none" opacity="0.6"/>
        <path d="M24 54 Q 20 46, 26 42 Q 34 44, 34 54 Z" fill="${C}" stroke="${A}" stroke-width="2"/>
        <ellipse cx="20" cy="52" rx="8" ry="9" fill="${C}" stroke="${A}" stroke-width="2"/>
        <circle cx="16" cy="49" r="3" fill="${A}"/>
        <circle cx="15.4" cy="48.2" r="1" fill="#fff"/>
        <path d="M16 47 Q 6 30, 0 22" fill="none" stroke="${A}" stroke-width="1.8" stroke-linecap="round"/>
        ${sheen(46, 52, 14, 3, 0.18)}`;
      break;
    }

    default: {
      body = `<circle cx="50" cy="55" r="26" fill="${C}" stroke="${A}" stroke-width="2.4"/>
        <circle cx="42" cy="48" r="3" fill="${A}"/><circle cx="58" cy="48" r="3" fill="${A}"/>`;
    }
  }
  return head + body + tail;
}

/* ---- Canvas にミニ虫（任意・簡易）。けはい演出などに使える ---- */
function drawBugMini(ctx, key, cx, cy, r) {
  const b = BUGS[key] || { color: '#888', accent: '#333', shape: 'beetle' };
  ctx.save();
  // どうたい
  ctx.fillStyle = b.color;
  ctx.strokeStyle = b.accent;
  ctx.lineWidth = Math.max(1, r * 0.16);
  ctx.beginPath();
  ctx.ellipse(cx, cy, r, r * 1.1, 0, 0, Math.PI * 2);
  ctx.fill();
  ctx.stroke();
  // shape ごとのちょいアクセント
  if (b.shape === 'butterfly') {
    ctx.fillStyle = b.color;
    ctx.beginPath(); ctx.ellipse(cx - r, cy - r * 0.4, r * 0.9, r * 0.7, 0, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
    ctx.beginPath(); ctx.ellipse(cx + r, cy - r * 0.4, r * 0.9, r * 0.7, 0, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
  } else if (b.shape === 'rhino' || b.shape === 'stag') {
    ctx.strokeStyle = b.accent;
    ctx.beginPath(); ctx.moveTo(cx, cy - r); ctx.lineTo(cx, cy - r * 1.8); ctx.stroke();
  } else if (b.shape === 'dragonfly' || b.shape === 'bee') {
    ctx.globalAlpha = 0.5;
    ctx.beginPath(); ctx.ellipse(cx - r * 0.8, cy - r * 0.6, r, r * 0.4, -0.4, 0, Math.PI * 2); ctx.fill();
    ctx.beginPath(); ctx.ellipse(cx + r * 0.8, cy - r * 0.6, r, r * 0.4, 0.4, 0, Math.PI * 2); ctx.fill();
    ctx.globalAlpha = 1;
  } else if (b.shape === 'ladybug') {
    ctx.fillStyle = b.accent;
    ctx.beginPath(); ctx.arc(cx - r * 0.4, cy, r * 0.18, 0, Math.PI * 2); ctx.fill();
    ctx.beginPath(); ctx.arc(cx + r * 0.4, cy, r * 0.18, 0, Math.PI * 2); ctx.fill();
  }
  // め
  ctx.fillStyle = b.accent;
  ctx.beginPath(); ctx.arc(cx - r * 0.3, cy - r * 0.6, r * 0.15, 0, Math.PI * 2); ctx.fill();
  ctx.beginPath(); ctx.arc(cx + r * 0.3, cy - r * 0.6, r * 0.15, 0, Math.PI * 2); ctx.fill();
  ctx.restore();
}
