/* game/core.js — マルこれ MVP コアエンジン
   ・前半: 純粋ロジック（DOM非依存・テスト可能）
   ・後半: UI（document があるときだけ動く）
   ダメージ式・綱引き・監査・ターン制限は docs/MALCORE_BALANCE.md / MALCORE_STAGE_MODEL.md 準拠。 */

/* ===== 乱数（テストで差し替え可能） ===== */
let _rng = Math.random;
function setRng(fn) { _rng = fn; }

/* ===== ゲーム状態生成 ===== */
function createGame(stage) {
  const db = stage.nodes.db;
  return {
    stage,
    turn: 1,
    maxTurn: stage.turnLimit,
    warning: 0,
    res: { info: 40, tech: 20, res: 20 }, // 初期資源
    hand: ['zeus', 'iloveyou', 'mydoom', 'blaster'],
    footholds: { outside: true, pc: false, db: false },
    botnet: false,    // 踏み台をボット化したか（A火力+10%）
    fwOpen: false,    // 境界FWを開通したか
    reconDone: false, // 本命を偵察したか
    diagDone: false,  // ブルーのセキュリティ診断が発動済みか
    cut: { hHack: 0, vDiag: 0 }, // カットイン残ターン
    db: {
      C: db.C, I: db.I, A: db.A,
      baseH: db.H, baseV: db.V, mit: db.mit,
      initTotal: db.C + db.I + db.A,
    },
    log: ['◆ 出撃: ' + stage.name + '（制限 ' + stage.turnLimit + 'T）'],
    result: null, // null | 'win' | 'lose_turn' | 'lose_warn'
  };
}

/* ===== 実効ステータス（カットイン込み） ===== */
function effH(g) { return Math.max(0, Math.min(100, g.db.baseH - (g.cut.hHack > 0 ? 20 : 0))); }
function effV(g) { return Math.max(0, Math.min(100, g.db.baseV + (g.cut.vDiag > 0 ? 25 : 0))); }

/* ===== ダメージ計算（1ゲージ分） ===== */
function gaugeDamage(g, base, gauge) {
  const H = effH(g), V = effV(g);
  const defMul = 0.5 + H / 100;
  const mit = Math.min(0.80, (g.db.mit[gauge] || 0) * defMul);
  const hit = 0.6 + (V / 100) * 0.8;
  const crit = _rng() < V / 100 ? 1.5 : 1.0;
  return { dmg: base * (1 - mit) * hit * crit, crit: crit > 1 };
}

/* ===== 行動一覧（状態に応じて可否を返す） ===== */
function listActions(g) {
  if (g.result) return [];
  const f = g.footholds, A = [];
  const can = (id, label, ok, reason, hint) => A.push({ id, label, enabled: ok, reason, hint });

  can('recon', '🔍 偵察（本命）', !g.reconDone, '偵察済み',
      '本命の防御を開示。偵察カットインの前提。 W+2');
  can('breach', '🚪 初期侵害（社員PC）', !f.pc, '侵害済み',
      'フィッシングで踏み台に足場確立。 W+5');
  can('botnet', '🏴 ボット化（社員PC）', f.pc && !g.botnet, f.pc ? '実施済み' : '踏み台が必要',
      '踏み台をボット化。可用性火力+10%。 W+5');
  can('fw_evade', '🌫️ 境界FWを回避', f.pc && !g.fwOpen && g.res.info >= 15, f.pc ? (g.fwOpen ? '開通済み' : '情報15が必要') : '踏み台が必要',
      '正規経路に偽装して通す。情報-15 / W+2');
  const hasBreaker = g.hand.some(id => (malById(id) || {}).breaker);
  can('fw_break', '💥 境界FWを破壊', f.pc && !g.fwOpen && hasBreaker, f.pc ? (g.fwOpen ? '開通済み' : '装置破壊ロールが必要') : '踏み台が必要',
      '装置破壊ロールで強行突破。 W+25（派手）');
  can('pivot', '↔️ 横展開 → 本命DB', f.pc && g.fwOpen && !f.db, f.db ? '到達済み' : (g.fwOpen ? '踏み台が必要' : '境界FWが閉'),
      '本命へ到達。 W+5');
  can('ci_recon', '🛠️ 偵察カットイン（H -20/3T）', g.reconDone && g.res.info >= 20, g.reconDone ? '情報20が必要' : '先に偵察が必要',
      'ハードニングを下げ通りやすくする。情報-20 / W+5');
  can('ci_diag', '🧪 診断カットイン（V +25/3T）', g.res.tech >= 15, '技術15が必要',
      '脆弱性を露出させ命中・会心UP。技術-15 / W+5');

  // 撃破（本命に到達後、手持ちごと）
  g.hand.forEach(id => {
    const m = malById(id);
    can('strike:' + id, '⚔️ 撃破: ' + m.name, f.db, '本命未到達',
        'C' + m.C + '/I' + m.I + '/A' + m.A + ' で攻撃。 W+10');
  });
  return A;
}

/* ===== 行動の適用 ===== */
function applyAction(g, actionId) {
  if (g.result) return { ok: false, msg: '決着済み' };
  const valid = listActions(g).find(a => a.id === actionId && a.enabled);
  if (!valid) return { ok: false, msg: 'その行動は今できない' };

  let warn = 0, msg = '';
  if (actionId === 'recon') {
    g.reconDone = true; warn = 2;
    msg = '偵察完了: 本命 H' + g.db.baseH + ' / V' + g.db.baseV + '（機密性が厚い）';
  } else if (actionId === 'breach') {
    g.footholds.pc = true; warn = 5; msg = 'フィッシング成功: 社員PCに足場を確立';
  } else if (actionId === 'botnet') {
    g.botnet = true; warn = 5; msg = '社員PCをボット化: 可用性火力 +10%';
  } else if (actionId === 'fw_evade') {
    g.fwOpen = true; g.res.info -= 15; warn = 2; msg = '境界FWを回避: 正規経路に偽装して通過';
  } else if (actionId === 'fw_break') {
    g.fwOpen = true; warn = 25; msg = '境界FWを破壊: 経路は開いたが警戒度が跳ね上がった';
  } else if (actionId === 'pivot') {
    g.footholds.db = true; warn = 5; msg = '横展開成功: 本命「勘定系DB」へ到達';
  } else if (actionId === 'ci_recon') {
    g.cut.hHack = 3; g.res.info -= 20; warn = 5; msg = '🛠️ 偵察カットイン発動! ハードニング -20（3T）';
    g.banner = { name: 'ポート・スキャン！', en: 'Port Scan', tone: 'ci' };
  } else if (actionId === 'ci_diag') {
    g.cut.vDiag = 3; g.res.tech -= 15; warn = 5; msg = '🧪 診断カットイン発動! 脆弱性 +25（3T）';
    g.banner = { name: 'ヴァルナラビリティ・スキャン！', en: 'Vulnerability Scan', tone: 'ci' };
  } else if (actionId.startsWith('strike:')) {
    const m = malById(actionId.slice(7));
    const aBonus = g.botnet ? 1.10 : 1.0;
    const rc = gaugeDamage(g, m.C, 'C');
    const ri = gaugeDamage(g, m.I, 'I');
    const ra = gaugeDamage(g, m.A * aBonus, 'A');
    g.db.C = Math.max(0, g.db.C - rc.dmg);
    g.db.I = Math.max(0, g.db.I - ri.dmg);
    g.db.A = Math.max(0, g.db.A - ra.dmg);
    // 戦利品（削った量に応じて資源獲得）
    g.res.info += Math.floor(rc.dmg / 10);
    g.res.tech += Math.floor(ri.dmg / 10);
    g.res.res += Math.floor(ra.dmg / 10);
    warn = 10;
    const crit = (rc.crit || ri.crit || ra.crit);
    const w = m.waza || { name: m.name + ' 撃破', en: '', gauge: 'C' };
    // 技名カットイン演出（攻撃名を必殺技として表示）
    g.banner = { name: w.name, en: w.en, tone: 'strike', gauge: w.gauge, crit, defense: w.defense };
    msg = '⚡ ' + w.name + (crit ? ' 会心!' : '') + ' 🔵-' + Math.round(rc.dmg) +
          ' 🟢-' + Math.round(ri.dmg) + ' 🟡-' + Math.round(ra.dmg);
  }

  g.warning = Math.min(100, g.warning + warn);
  g.log.push('T' + g.turn + '  ' + msg);
  endTurn(g);
  return { ok: true, msg };
}

/* ===== ターン終了処理（監査・診断・カットイン減衰・判定） ===== */
function endTurn(g) {
  // カットイン残ターン減衰
  if (g.cut.hHack > 0) g.cut.hHack--;
  if (g.cut.vDiag > 0) g.cut.vDiag--;

  // ブルー: システム監査（一定ターン毎にH↑）
  if (g.turn % g.stage.audit.every === 0) {
    g.db.baseH = Math.min(100, g.db.baseH + g.stage.audit.hardenUp);
    g.log.push('T' + g.turn + '  🔵 システム監査: ハードニング +' + g.stage.audit.hardenUp + '（→' + g.db.baseH + '）');
  }
  // ブルー: セキュリティ診断（警戒度が閾値超えで一度だけV↓）
  if (!g.diagDone && g.warning >= g.stage.diag.warnThreshold) {
    g.db.baseV = Math.max(0, g.db.baseV - g.stage.diag.vulnDown);
    g.diagDone = true;
    g.log.push('T' + g.turn + '  🔵 セキュリティ診断: 脆弱性 -' + g.stage.diag.vulnDown + '（→' + g.db.baseV + '）');
  }

  checkEnd(g);
  if (!g.result) g.turn++;
}

/* ===== 勝敗判定 ===== */
function checkEnd(g) {
  const total = g.db.C + g.db.I + g.db.A;
  if (total <= g.db.initTotal * g.stage.win.ratio) { g.result = 'win'; return; }
  if (g.warning >= 100) { g.result = 'lose_warn'; return; }
  if (g.turn >= g.maxTurn) { g.result = 'lose_turn'; return; }
}

/* ===== 防御官の総評（攻撃と対策はセット、という学び） ===== */
function debrief(g) {
  if (g.result === 'win') {
    return '攻略成功。だが現実なら——機密性を抜かれたのは多要素認証と取引の異常検知が甘かったから。' +
           'カットイン（偵察・診断）に崩されたのは、攻撃者に弱点を先に診断され尽くした証だ。';
  }
  if (g.result === 'lose_turn') {
    return 'タイムオーバー。ブルーチームの封じ込めが間に合った。' +
           '＝ネットワーク分離とログ監視で攻撃者の滞留時間を稼ぎ、素早く追い出した防御の勝利だ。';
  }
  return '警戒度MAXで足場を一斉駆除された。派手に動きすぎ＝EDR/IDSに検知された。静かな攻撃ほど怖い、という教訓だ。';
}

/* ===== エクスポート（テスト/UI共用） ===== */
const MALCORE = {
  createGame, listActions, applyAction, endTurn, checkEnd,
  effH, effV, gaugeDamage, debrief, setRng,
  STAGE: (typeof STAGE_ZENITH !== 'undefined') ? STAGE_ZENITH : null,
};
if (typeof globalThis !== 'undefined') globalThis.MALCORE = MALCORE;

/* =======================================================================
   UI 層（document があるときだけ）
   ======================================================================= */
if (typeof document !== 'undefined' && document.getElementById) {
  let G = null;

  const $ = (id) => document.getElementById(id);
  const show = (id) => {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    $(id).classList.add('active');
  };

  function bar(label, val, max, cls) {
    const pct = Math.max(0, Math.min(100, (val / max) * 100));
    return '<div class="bar"><span class="bar-label">' + label + '</span>' +
      '<span class="bar-track"><i class="bar-fill ' + cls + '" style="width:' + pct + '%"></i></span>' +
      '<span class="bar-num">' + Math.round(val) + '</span></div>';
  }

  function renderBattle() {
    const g = G, d = g.db;
    const hops = g.stage.path.map((n, i) => {
      const reached = n === 'outside' ? true : g.footholds[n];
      const nm = n === 'outside' ? '外部' : g.stage.nodes[n].name.split('（')[0];
      const hop = '<span class="hop ' + (reached ? 'on' : '') + '">' + nm + '</span>';
      if (i === g.stage.path.length - 1) return hop;
      // pc → db の間だけ境界FW（開通=─▶ / 閉鎖=🚧▶）
      const next = g.stage.path[i + 1];
      const arrow = (next === 'db') ? (g.fwOpen ? '─▶' : '🚧▶') : '─▶';
      return hop + '<span class="hop-arrow">' + arrow + '</span>';
    }).join('');
    const pathHtml = hops;

    const cutBadges =
      (g.cut.hHack > 0 ? '<span class="badge ci">🛠️H-20(' + g.cut.hHack + 'T)</span>' : '') +
      (g.cut.vDiag > 0 ? '<span class="badge ci">🧪V+25(' + g.cut.vDiag + 'T)</span>' : '');

    const acts = listActions(g).map(a =>
      '<button class="act ' + (a.enabled ? '' : 'off') + '" data-act="' + a.id + '" ' +
      (a.enabled ? '' : 'disabled title="' + a.reason + '"') + '>' +
      '<b>' + a.label + '</b><small>' + (a.enabled ? a.hint : a.reason) + '</small></button>'
    ).join('');

    $('battle-root').innerHTML =
      '<div class="hud">' +
        '<span class="pill turn">⏳ T ' + g.turn + ' / ' + g.maxTurn + '</span>' +
        '<span class="pill info">📡 情報 ' + g.res.info + '</span>' +
        '<span class="pill tech">🧬 技術 ' + g.res.tech + '</span>' +
        '<span class="pill resr">⚙️ 資源 ' + g.res.res + '</span>' +
      '</div>' +
      bar('🚨 警戒度', g.warning, 100, 'warn') +
      '<div class="path">' + pathHtml + '</div>' +
      '<div class="boss">' +
        '<div class="boss-head">★ ' + g.stage.nodes.db.name +
          ' <span class="hv">H ' + effH(g) + ' / V ' + effV(g) + '</span> ' + cutBadges + '</div>' +
        bar('🔵 機密性', d.C, 160, 'c') +
        bar('🟢 完全性', d.I, 100, 'i') +
        bar('🟡 可用性', d.A, 100, 'a') +
        '<div class="boss-foot">勝利: CIA合計を ' + Math.round(d.initTotal * g.stage.win.ratio) +
          ' 以下に（現在 ' + Math.round(d.C + d.I + d.A) + '）</div>' +
      '</div>' +
      '<div class="acts">' + acts + '</div>' +
      '<div class="logbox">' + g.log.slice(-6).reverse().map(l => '<div>' + l + '</div>').join('') + '</div>';

    $('battle-root').querySelectorAll('.act:not(.off)').forEach(b =>
      b.addEventListener('click', () => { applyAction(G, b.dataset.act); afterAction(); }));
  }

  function popBanner(b) {
    const el = document.createElement('div');
    el.className = 'banner ' + (b.tone || '') + (b.crit ? ' crit' : '');
    el.innerHTML =
      '<div class="banner-name">⚡ ' + b.name + '</div>' +
      (b.en ? '<div class="banner-en">' + b.en + '</div>' : '') +
      (b.crit ? '<div class="banner-crit">会心!</div>' : '');
    $('app').appendChild(el);
    setTimeout(() => el.remove(), 1100);
  }

  function afterAction() {
    if (G.banner) { popBanner(G.banner); G.banner = null; }
    if (G.result) return renderResult();
    renderBattle();
  }

  function renderResult() {
    show('result-screen');
    const win = G.result === 'win';
    $('result-body').innerHTML =
      '<div class="verdict ' + (win ? 'win' : 'lose') + '">' +
        (win ? '🏆 攻略成功' : (G.result === 'lose_turn' ? '⏳ タイムオーバー' : '🚨 駆除された')) + '</div>' +
      '<div class="stat">残りCIA合計 ' + Math.round(G.db.C + G.db.I + G.db.A) +
        ' ／ 使用 ' + (G.turn) + 'T ／ 警戒度 ' + G.warning + '</div>' +
      '<div class="debrief"><b>防御官の総評</b><p>' + debrief(G) + '</p></div>';
  }

  function startGame() { G = createGame(STAGE_ZENITH); show('battle-screen'); renderBattle(); }

  function renderBriefing() {
    const handHtml = ['zeus', 'iloveyou', 'mydoom', 'blaster'].map(id => {
      const m = malById(id);
      return '<div class="card"><div class="card-top"><b>' + m.name + '</b><span>' + m.year + '</span></div>' +
        '<div class="card-cia">🔵' + m.C + ' 🟢' + m.I + ' 🟡' + m.A + '</div>' +
        '<div class="card-role">' + m.role + ' / ' + m.sub + '</div>' +
        (m.waza ? '<div class="card-waza">⚡ ' + m.waza.name + '</div>' : '') +
        '<div class="card-desc">' + m.desc + '</div></div>';
    }).join('');
    $('briefing-body').innerHTML =
      '<p class="intro">' + STAGE_ZENITH.intro + '</p>' +
      '<p class="hint">王道: 偵察 → 初期侵害 → ボット化 → 横展開(FW回避) → 偵察CI → 診断CI → 撃破×2。' +
      'カットインで本命を「通りやすく」してから Zeus で機密性を抜け。</p>' +
      '<div class="cards">' + handHtml + '</div>';
  }

  document.addEventListener('DOMContentLoaded', () => {
    $('btn-start').addEventListener('click', () => { renderBriefing(); show('briefing-screen'); });
    $('btn-sortie').addEventListener('click', startGame);
    $('btn-retry').addEventListener('click', startGame);
    $('btn-title').addEventListener('click', () => show('title-screen'));
  });
}
