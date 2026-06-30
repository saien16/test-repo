/* game/core.js — マルこれ MVP コアエンジン
   ・前半: 純粋ロジック（DOM非依存・テスト可能）
   ・後半: UI（document があるときだけ動く）
   ダメージ式・綱引き・監査・ターン制限は docs/MALCORE_BALANCE.md / MALCORE_STAGE_MODEL.md 準拠。 */

/* ===== 乱数（テストで差し替え可能） ===== */
let _rng = Math.random;
function setRng(fn) { _rng = fn; }

/* ===== ゲーム状態生成 ===== */
function createGame(stage, equipped, levels) {
  const db = stage.nodes.db;
  return {
    stage,
    turn: 1,
    maxTurn: stage.turnLimit,
    warning: 0,
    res: { info: 40, tech: 20, res: 20 }, // 初期資源
    hand: ['zeus', 'iloveyou', 'mydoom', 'blaster'],
    levels: levels || {},               // 世代進化レベル（id→0..2）
    equipped: (equipped || []).slice(0, 3), // 装備した攻撃手法カード（最大3）
    footholds: { outside: true, pc: false, db: false },
    botnet: false,    // 踏み台をボット化したか（A火力+10%）
    reconDone: false, // 本命を偵察したか
    diagDone: false,  // ブルーのセキュリティ診断が発動済みか
    cut: { hHack: 0, vDiag: 0 }, // カットイン残ターン
    defenses: (stage.defenses || []).map(d => ({ ...d, state: 'active' })), // 対策の状態
    db: {
      C: db.C, I: db.I, A: db.A,
      baseH: db.H, baseV: db.V, baseDef: db.baseDef || {},
      initTotal: db.C + db.I + db.A,
    },
    log: ['◆ 出撃: ' + stage.name + '（制限 ' + stage.turnLimit + 'T）'],
    result: null, // null | 'win' | 'lose_turn' | 'lose_warn'
  };
}

/* ===== 実効ステータス（カットイン込み） ===== */
function effH(g) { return Math.max(0, Math.min(100, g.db.baseH - (g.cut.hHack > 0 ? 20 : 0))); }
function effV(g) { return Math.max(0, Math.min(100, g.db.baseV + (g.cut.vDiag > 0 ? 25 : 0))); }

/* ===== 資源コスト ===== */
function canAfford(g, cost) {
  if (!cost) return true;
  return (g.res.info >= (cost.info || 0)) && (g.res.tech >= (cost.tech || 0)) && (g.res.res >= (cost.res || 0));
}
function payCost(g, cost) {
  if (!cost) return;
  g.res.info -= (cost.info || 0); g.res.tech -= (cost.tech || 0); g.res.res -= (cost.res || 0);
}
function costLabel(cost) {
  if (!cost) return '';
  const p = [];
  if (cost.info) p.push('情報' + cost.info);
  if (cost.tech) p.push('技術' + cost.tech);
  if (cost.res) p.push('資源' + cost.res);
  return p.join('/');
}

/* ===== 防御力（本体 + 有効な対策の寄与） ===== */
function defenseDef(d) { return d.def || {}; }
// ゲージの素の防御力（本体 + active な対策）。0..∞（後でハードニング倍率・上限0.8）
function gaugeDefRaw(g, gauge) {
  let d = (g.db.baseDef && g.db.baseDef[gauge]) || 0;
  (g.defenses || []).forEach(df => { if (df.state === 'active') d += (defenseDef(df)[gauge] || 0); });
  return d;
}
// 実効緩和率（ハードニング倍率込み・上限0.8）
function gaugeMit(g, gauge, ignoreH) {
  const H = ignoreH ? 0 : effH(g);
  return Math.min(0.80, gaugeDefRaw(g, gauge) * (0.5 + H / 100));
}
// 経路ゲート（境界FW等）が開いているか
function gateOpen(g) {
  const gate = (g.defenses || []).find(d => d.gate);
  return !gate || gate.state !== 'active';
}
// その対策に有効な無効化手段が残っているか
function activeDefenses(g) { return (g.defenses || []).filter(d => d.state === 'active'); }

/* 移動/偵察系アクションの技名（実在の攻撃手法名。軽量フラッシュで提示） */
const ACT_TECH = {
  recon: { name: 'ポートスキャニング', en: 'Port Scanning' },
  breach: { name: 'スピアフィッシング', en: 'Spearphishing' },
  botnet: { name: 'ボットネット編入', en: 'Botnet Conscription' },
  pivot: { name: 'ラテラルムーブメント', en: 'Lateral Movement / Pass-the-Hash' },
  evade: { name: 'リビング・オフ・ザ・ランド', en: 'Living off the Land' },
  brk: { name: 'サービス・クラッシュ', en: 'Service Crash / DoS' },
};

/* ===== 検知（警戒度）モデル ===== */
const GAUGE_NOISE = { C: 0.5, I: 1.0, A: 1.5 }; // 機密性=静か / 可用性=派手
function primGauge(cia) {
  let g = 'C', best = -1;
  ['C', 'I', 'A'].forEach(k => { if ((cia[k] || 0) > best) { best = cia[k] || 0; g = k; } });
  return g;
}
function detectMul(g, gauge, level) {
  let m = 1 + 0.35 * (level || 0);         // 世代が進むほど検知されやすい（進化＝火力↑だが目立つ）
  if (g.stage.edr) m += 0.3;               // EDR/振る舞い検知
  activeDefenses(g).forEach(d => {
    if (d.detect && d.detect[gauge]) m += d.detect[gauge]; // 監視対策が有効ならそのゲージは検知UP
    if (d.detect && d.detect.all) m += d.detect.all;
  });
  return m;
}
function strikeWarn(g, gauge, level, base) {
  return Math.max(1, Math.round((base || 13) * (GAUGE_NOISE[gauge] || 1) * detectMul(g, gauge, level)));
}

/* ステージ開始時に提示する敵の防御（プロキシ/DLP/ハードニング等）。多いほど手強い印象。 */
function defenseIntro(g) {
  const items = [];
  activeDefenses(g).forEach(d => items.push({ name: d.name, sub: d.gate ? '展開' : '監視中' }));
  if (g.db.baseH >= 50) items.push({ name: 'ハードニング', sub: '堅牢 H' + g.db.baseH });
  if (g.stage.edr) items.push({ name: 'EDR / 振る舞い検知', sub: '稼働' });
  return items;
}

/* ===== ダメージ計算（1ゲージ分） ===== */
function gaugeDamage(g, base, gauge, opt) {
  opt = opt || {};
  const V = effV(g);
  const mit = gaugeMit(g, gauge, opt.ignoreH); // ゼロデイ等はハードニング無視
  const hit = 0.6 + (V / 100) * 0.8;
  const crit = _rng() < V / 100 ? 1.5 : 1.0;
  return { dmg: base * (1 - mit) * hit * crit, crit: crit > 1 };
}

/* ===== 世代進化 ===== */
const EVO_MAX = 2;
const EVO_SUFFIX = ['', '・改', '・改弐'];
function evoMul(level) { return 1 + 0.25 * (level || 0); }        // Lv0=1.0 / Lv1=1.25 / Lv2=1.5
function evoCost(level) { return level <= 0 ? 2 : 3; }            // 次の世代への開発Pコスト
function malStats(m, level) {
  const k = evoMul(level);
  return { C: Math.round(m.C * k), I: Math.round(m.I * k), A: Math.round(m.A * k) };
}
function wazaName(m, level) {
  const base = (m.waza ? m.waza.name : m.name).replace(/！+$/, '');
  return base + (EVO_SUFFIX[level] || '') + '！！';
}

/* ===== 撃破の共通処理（マルウェア・カード共用） =====
   cia: {C,I,A} の基礎攻撃力。opt.ignoreH / opt.botnet(可用性ボーナス) */
function resolveStrike(g, cia, opt) {
  opt = opt || {};
  const aBonus = opt.botnet ? 1.10 : 1.0;
  const rc = gaugeDamage(g, cia.C || 0, 'C', opt);
  const ri = gaugeDamage(g, cia.I || 0, 'I', opt);
  const ra = gaugeDamage(g, (cia.A || 0) * aBonus, 'A', opt);
  g.db.C = Math.max(0, g.db.C - rc.dmg);
  g.db.I = Math.max(0, g.db.I - ri.dmg);
  g.db.A = Math.max(0, g.db.A - ra.dmg);
  // 戦利品（削った量に応じて資源獲得）
  g.res.info += Math.floor(rc.dmg / 10);
  g.res.tech += Math.floor(ri.dmg / 10);
  g.res.res += Math.floor(ra.dmg / 10);
  return { rc, ri, ra, crit: (rc.crit || ri.crit || ra.crit) };
}

/* ===== 行動一覧（状態に応じて可否を返す） ===== */
function listActions(g) {
  if (g.result) return [];
  const f = g.footholds, A = [];
  const can = (id, label, ok, reason, hint) => A.push({ id, label, enabled: ok, reason, hint });

  can('recon', '🔍 ポートスキャニング', !g.reconDone, '偵察済み',
      '本命の防御を偵察で開示。CIカットインの前提。 W+2');
  can('breach', '🚪 スピアフィッシング', !f.pc, '侵害済み',
      '踏み台(社員PC)を初期侵害し足場確立。 W+5');
  can('botnet', '🏴 ボットネット編入', f.pc && !g.botnet, f.pc ? '実施済み' : '踏み台が必要',
      '踏み台をボット化。可用性火力+10%。 W+5');
  // 対策の無効化（回避/破壊）。剥がすと防御力が一気に低下し、本体防御だけが残る。
  const hasBreaker = g.hand.some(id => (malById(id) || {}).breaker);
  activeDefenses(g).forEach(d => {
    if (d.evade) {
      can('evade:' + d.id, '🌫️ ' + d.name + 'を回避', f.pc && canAfford(g, d.evade),
          f.pc ? '資源不足(' + costLabel(d.evade) + ')' : '踏み台が必要',
          '正規に偽装し無効化。防御力↓＆検知↓。' + costLabel(d.evade) + ' / W+2');
    }
    if (d.breakable) {
      can('break:' + d.id, '💥 ' + d.name + 'を破壊', f.pc && hasBreaker,
          f.pc ? '装置破壊ロールが必要' : '踏み台が必要',
          '装置破壊ロールで強行無効化。防御力↓だが W+25（派手）');
    }
  });
  can('pivot', '↔️ ラテラルムーブメント', f.pc && gateOpen(g) && !f.db, f.db ? '到達済み' : (gateOpen(g) ? '踏み台が必要' : '境界FWが閉'),
      'パス・ザ・ハッシュで本命へ横展開。 W+5');
  can('ci_recon', '🛠️ アタックサーフェス・マッピング（H -20/3T）', g.reconDone && g.res.info >= 20, g.reconDone ? '情報20が必要' : '先に偵察が必要',
      'ハードニングを下げ通りやすくする。情報-20 / W+5');
  can('ci_diag', '🧪 ヴァルネラビリティ・スキャン（V +25/3T）', g.res.tech >= 15, '技術15が必要',
      '脆弱性を露出させ命中・会心UP。技術-15 / W+5');

  // 撃破（本命に到達後、手持ちのマルウェア固有技ごと。世代進化を反映）
  g.hand.forEach(id => {
    const m = malById(id);
    const L = (g.levels && g.levels[id]) || 0;
    const s = malStats(m, L);
    const tag = L > 0 ? EVO_SUFFIX[L].replace('・', '') + ' ' : '';
    const w = strikeWarn(g, primGauge(s), L);
    can('strike:' + id, '⚔️ ' + tag + (m.waza ? m.waza.name.replace(/！+$/, '') : m.name), f.db, '本命未到達',
        'C' + s.C + '/I' + s.I + '/A' + s.A + ' で攻撃。 W+' + w);
  });
  // 装備技カード（本命到達後・資源を満たすとき）
  (g.equipped || []).forEach(id => {
    const c = cardById(id); if (!c) return;
    const ok = f.db && canAfford(g, c.cost);
    const reason = !f.db ? '本命未到達' : '資源不足(' + costLabel(c.cost) + ')';
    const cia = c.cia || {};
    const w = strikeWarn(g, c.gauge || primGauge(cia), 0, 10);
    can('card:' + id, '🃏 ' + c.name, ok, reason,
        'C' + (cia.C || 0) + '/I' + (cia.I || 0) + '/A' + (cia.A || 0) +
        (c.special === 'ignoreH' ? ' 貫通' : '') + ' ' + costLabel(c.cost) + ' W+' + w);
  });
  return A;
}

/* ===== 行動の適用 ===== */
function applyAction(g, actionId) {
  if (g.result) return { ok: false, msg: '決着済み' };
  const valid = listActions(g).find(a => a.id === actionId && a.enabled);
  if (!valid) return { ok: false, msg: 'その行動は今できない' };

  g.counter = null; // ブルー反撃（被弾）フラグ。endTurnで立つ
  g.flash = null;   // 移動/偵察系の軽量技フラッシュ
  let warn = 0, msg = '';
  if (actionId === 'recon') {
    g.reconDone = true; warn = 2; g.flash = ACT_TECH.recon;
    msg = '⚡ ' + ACT_TECH.recon.name + ': 本命 H' + g.db.baseH + ' / V' + g.db.baseV + '（機密性が厚い）';
  } else if (actionId === 'breach') {
    g.footholds.pc = true; warn = 5; g.flash = ACT_TECH.breach;
    msg = '⚡ ' + ACT_TECH.breach.name + ': 社員PCに足場を確立';
  } else if (actionId === 'botnet') {
    g.botnet = true; warn = 5; g.flash = ACT_TECH.botnet;
    msg = '⚡ ' + ACT_TECH.botnet.name + ': 可用性火力 +10%';
  } else if (actionId.startsWith('evade:')) {
    const d = g.defenses.find(x => x.id === actionId.slice(6));
    payCost(g, d.evade); d.state = 'evaded'; warn = 2; g.flash = ACT_TECH.evade;
    msg = '⚡ ' + ACT_TECH.evade.name + ': ' + d.name + 'を回避。防御力↓（本体のみ）＆検知↓';
  } else if (actionId.startsWith('break:')) {
    const d = g.defenses.find(x => x.id === actionId.slice(6));
    d.state = 'destroyed'; warn = 25; g.flash = ACT_TECH.brk;
    msg = '⚡ ' + ACT_TECH.brk.name + ': ' + d.name + 'を破壊。防御力↓だが警戒度が跳ね上がった';
  } else if (actionId === 'pivot') {
    g.footholds.db = true; warn = 5; g.flash = ACT_TECH.pivot;
    msg = '⚡ ' + ACT_TECH.pivot.name + ': 本命「勘定系DB」へ横展開';
  } else if (actionId === 'ci_recon') {
    g.cut.hHack = 3; g.res.info -= 20; warn = 5; msg = '🛠️ アタックサーフェス・マッピング発動! ハードニング -20（3T）';
    g.banner = { name: 'アタックサーフェス・マッピング！', en: 'Attack Surface Mapping', tone: 'ci' };
  } else if (actionId === 'ci_diag') {
    g.cut.vDiag = 3; g.res.tech -= 15; warn = 5; msg = '🧪 ヴァルネラビリティ・スキャン発動! 脆弱性 +25（3T）';
    g.banner = { name: 'ヴァルネラビリティ・スキャン！', en: 'Vulnerability Scan', tone: 'ci' };
  } else if (actionId.startsWith('strike:')) {
    const id = actionId.slice(7);
    const m = malById(id);
    const L = (g.levels && g.levels[id]) || 0;
    const s = malStats(m, L);
    const r = resolveStrike(g, s, { botnet: g.botnet });
    warn = strikeWarn(g, primGauge(s), L);
    const w = m.waza || { name: m.name, en: '', gauge: 'C' };
    const nm = wazaName(m, L);
    // 技名カットイン演出（攻撃名を必殺技として表示・攻撃表情のキャラつき）
    g.banner = { name: nm, en: w.en, tone: 'strike', gauge: w.gauge, crit: r.crit,
                 defense: w.defense, sprId: id, gen: L };
    msg = '⚡ ' + nm + (r.crit ? ' 会心!' : '') + ' 🔵-' + Math.round(r.rc.dmg) +
          ' 🟢-' + Math.round(r.ri.dmg) + ' 🟡-' + Math.round(r.ra.dmg);
  } else if (actionId.startsWith('card:')) {
    const c = cardById(actionId.slice(5));
    payCost(g, c.cost);
    const r = resolveStrike(g, c.cia || {}, { botnet: g.botnet, ignoreH: c.special === 'ignoreH' });
    warn = strikeWarn(g, c.gauge || primGauge(c.cia || {}), 0, 10);
    g.banner = { name: c.name + '！', en: c.en, tone: 'strike', gauge: c.gauge, crit: r.crit, defense: c.defense };
    msg = '🃏 ' + c.name + (r.crit ? ' 会心!' : '') + ' 🔵-' + Math.round(r.rc.dmg) +
          ' 🟢-' + Math.round(r.ri.dmg) + ' 🟡-' + Math.round(r.ra.dmg);
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
    g.counter = { kind: 'audit', label: 'システム監査 H+' + g.stage.audit.hardenUp };
  }
  // ブルー: セキュリティ診断（警戒度が閾値超えで一度だけV↓）
  if (!g.diagDone && g.warning >= g.stage.diag.warnThreshold) {
    g.db.baseV = Math.max(0, g.db.baseV - g.stage.diag.vulnDown);
    g.diagDone = true;
    g.log.push('T' + g.turn + '  🔵 セキュリティ診断: 脆弱性 -' + g.stage.diag.vulnDown + '（→' + g.db.baseV + '）');
    g.counter = { kind: 'diag', label: 'セキュリティ診断 V-' + g.stage.diag.vulnDown };
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
  effH, effV, gaugeDamage, resolveStrike, canAfford, debrief, setRng,
  malStats, wazaName, evoCost, evoMul, EVO_MAX,
  gaugeMit, gaugeDefRaw, gateOpen, strikeWarn, primGauge, defenseIntro,
  STAGE: (typeof STAGE_ZENITH !== 'undefined') ? STAGE_ZENITH : null,
  CARDS: (typeof CARDS !== 'undefined') ? CARDS : [],
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

  // 本命の防御力（ゲージ別の実効緩和％）と、効いている対策を表示
  function defensePanel(g) {
    const pct = (gauge) => Math.round(gaugeMit(g, gauge) * 100);
    const act = activeDefenses(g);
    const list = act.length
      ? act.map(d => '<span class="def-chip">🛡️ ' + d.name + '</span>').join('')
      : '<span class="def-chip none">本体防御のみ</span>';
    return '<div class="defrow">' +
      '<span class="def-title">防御力</span>' +
      '<span class="def-g c">🔵' + pct('C') + '%</span>' +
      '<span class="def-g i">🟢' + pct('I') + '%</span>' +
      '<span class="def-g a">🟡' + pct('A') + '%</span>' +
      '<span class="def-list">' + list + '</span></div>';
  }

  function renderBattle() {
    const g = G, d = g.db;
    const dbState = (function () {
      const r = (d.C + d.I + d.A) / d.initTotal;
      return r > 0.66 ? 'ok' : (r > 0.33 ? 'hurt' : 'crit');
    })();
    const hops = g.stage.path.map((n, i) => {
      const reached = n === 'outside' ? true : g.footholds[n];
      const nm = n === 'outside' ? '外部' : g.stage.nodes[n].name.split('（')[0];
      const sprOpt = n === 'db' ? { state: dbState } : undefined;
      const hop = '<span class="hop ' + (reached ? 'on' : '') + '">' +
        '<span class="nodespr">' + SPRITES.node(n === 'outside' ? 'outside' : n, sprOpt) + '</span>' +
        '<small>' + nm + '</small></span>';
      if (i === g.stage.path.length - 1) return hop;
      const next = g.stage.path[i + 1];
      // pc → db の間に境界FW装置（開通=通路 / 閉鎖=FWアイコン）
      if (next === 'db') {
        const dev = gateOpen(g)
          ? '<span class="hop-arrow open">▶</span>'
          : '<span class="hop fw"><span class="nodespr sm">' + SPRITES.node('fw') + '</span><small>境界FW</small></span>';
        return hop + dev;
      }
      return hop + '<span class="hop-arrow">▶</span>';
    }).join('');
    const pathHtml = hops;

    const cutBadges =
      (g.cut.hHack > 0 ? '<span class="badge ci">🛠️H-20(' + g.cut.hHack + 'T)</span>' : '') +
      (g.cut.vDiag > 0 ? '<span class="badge ci">🧪V+25(' + g.cut.vDiag + 'T)</span>' : '');

    const acts = listActions(g).map(a => {
      const kind = a.id.startsWith('card:') ? ' card' : (a.id.startsWith('strike:') ? ' strike' : '');
      let spr = '';
      if (a.id.startsWith('strike:')) {
        spr = '<span class="actspr">' + SPRITES.mal(a.id.slice(7), { gen: (g.levels && g.levels[a.id.slice(7)]) || 0 }) + '</span>';
      } else if (a.id.startsWith('card:')) {
        const c = cardById(a.id.slice(5));
        if (c && c.icon && SPRITES.card(c.icon)) spr = '<span class="actspr">' + SPRITES.card(c.icon) + '</span>';
      }
      return '<button class="act' + kind + ' ' + (a.enabled ? '' : 'off') + '" data-act="' + a.id + '" ' +
        (a.enabled ? '' : 'disabled title="' + a.reason + '"') + '>' +
        spr + '<span class="act-txt"><b>' + a.label + '</b><small>' + (a.enabled ? a.hint : a.reason) + '</small></span></button>';
    }).join('');

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
        '<div class="boss-head"><span class="bossspr ' + dbState + '">' + SPRITES.node('db', { state: dbState }) + '</span>' +
          '<span class="boss-title">★ ' + g.stage.nodes.db.name +
          '<span class="hv">H ' + effH(g) + ' / V ' + effV(g) + ' ' + cutBadges + '</span></span></div>' +
        '<div class="goal-chip">🎯 勝利まで CIA合計 ' + Math.round(d.C + d.I + d.A) +
          ' → <b>' + Math.round(d.initTotal * g.stage.win.ratio) + '以下</b></div>' +
        bar('🔵 機密性 C', d.C, 160, 'c') +
        bar('🟢 完全性 I', d.I, 100, 'i') +
        bar('🟡 可用性 A', d.A, 100, 'a') +
        defensePanel(g) +
      '</div>' +
      '<div class="acts">' + acts + '</div>' +
      '<div class="logbox">' + g.log.slice(-6).reverse().map(l => '<div>' + l + '</div>').join('') + '</div>';

    $('battle-root').querySelectorAll('.act:not(.off)').forEach(b =>
      b.addEventListener('click', () => {
        Sound.unlock();
        // 音は afterAction 側で出し分け（撃破=技カットイン / 移動=軽量フラッシュ）。
        applyAction(G, b.dataset.act); afterAction();
      }));
  }

  function popBanner(b) {
    // 連続発動で重ならないよう、既存バナーを消してから出す
    document.querySelectorAll('.banner').forEach(e => e.remove());
    const el = document.createElement('div');
    el.className = 'banner ' + (b.tone || '') + (b.crit ? ' crit' : '');
    const spr = b.sprId ? '<div class="banner-spr">' + SPRITES.mal(b.sprId, { expr: 'attack', gen: b.gen || 0 }) + '</div>' : '';
    el.innerHTML = spr +
      '<div class="banner-name">⚡ ' + b.name + '</div>' +
      (b.en ? '<div class="banner-en">' + b.en + '</div>' : '') +
      (b.crit ? '<div class="banner-crit">会心!</div>' : '');
    $('app').appendChild(el);
    Sound.play(b.tone === 'ci' ? 'cutin' : (b.crit ? 'crit' : 'strike'));
    setTimeout(() => el.remove(), 1100);
  }

  function popCounter(c) {
    // ブルーチーム反撃＝こちらの被弾。やられ顔のキャラ＋画面シェイク＋効果音。
    document.querySelectorAll('.banner').forEach(e => e.remove());
    const id = G.hand[(G.turn + 1) % G.hand.length];
    const el = document.createElement('div');
    el.className = 'banner counter';
    el.innerHTML =
      '<div class="banner-spr hurt">' + SPRITES.mal(id, { expr: 'hurt', gen: (G.levels && G.levels[id]) || 0 }) + '</div>' +
      '<div class="banner-name">🛡️ ブルーチーム反撃！</div>' +
      '<div class="banner-en">' + c.label + '</div>';
    $('app').appendChild(el);
    const app = $('app'); app.classList.remove('shake'); void app.offsetWidth; app.classList.add('shake');
    Sound.play('hit');
    setTimeout(() => el.remove(), 1200);
  }

  // 移動/偵察系の軽量フラッシュ（小さく一瞬。撃破の全画面カットインとは格差をつける）
  function popFlash(f) {
    document.querySelectorAll('.techflash').forEach(e => e.remove());
    const el = document.createElement('div');
    el.className = 'techflash';
    el.innerHTML = '⚡ ' + f.name + (f.en ? ' <span>' + f.en + '</span>' : '');
    $('app').appendChild(el);
    setTimeout(() => el.remove(), 760);
  }

  function afterAction() {
    if (G.banner) { popBanner(G.banner); G.banner = null; }
    else if (G.flash) { popFlash(G.flash); Sound.play('select'); G.flash = null; }
    const counter = G.counter; G.counter = null;
    if (G.result) {
      Sound.stopBgm();
      renderBattle();                                   // 最終状態（HP/防御力）を見せる
      setTimeout(() => showFinish(G.result), 650);      // 決め技の後に決着演出
      return;
    }
    renderBattle();
    if (counter) setTimeout(() => popCounter(counter), 720); // 行動バナーの後に被弾演出
  }

  // 勝敗の決着演出（切り替えが速すぎて分かりにくい問題への対応・1.9秒見せる）
  function showFinish(res) {
    const win = res === 'win';
    document.querySelectorAll('.banner').forEach(e => e.remove());
    Sound.play(win ? 'win' : 'lose');
    if (win) document.querySelectorAll('.bossspr').forEach(b => b.classList.add('shatter')); // 本命DBが砕ける
    else { const a = $('app'); a.classList.remove('shake'); void a.offsetWidth; a.classList.add('shake'); }
    const title = win ? '🏆 制圧成功！' : (res === 'lose_turn' ? '⏳ タイムオーバー' : '🚨 駆除された');
    const sub = win ? '本命「勘定系DB」を掌握した'
      : (res === 'lose_turn' ? 'ブルーチームの封じ込めが間に合った' : '警戒度MAX — 足場を一斉駆除された');
    const el = document.createElement('div');
    el.className = 'finish ' + (win ? 'win' : 'lose');
    el.innerHTML = '<div class="finish-big">' + title + '</div><div class="finish-sub">' + sub + '</div>';
    $('app').appendChild(el);
    setTimeout(() => { el.remove(); renderResult(); }, 1900);
  }

  function renderResult() {
    show('result-screen');
    const win = G.result === 'win';
    let reward = '';
    if (win) {
      // 戦利品（余剰の情報/技術/資源）を開発Pに変換＝「攻略→進化資金」を1本につなぐ
      const surplus = Math.floor((G.res.info + G.res.tech + G.res.res) / 20);
      const gain = 3 + surplus;
      devP += gain; saveJSON('malcore.devP', devP);
      reward = '<div class="reward">🛠️ 開発P +' + gain + '（基本3＋戦利品' + surplus + ' / 所持 ' + devP + '）— 世代進化に使える</div>';
      // 未入手の技カードを1枚アンロック＝収集ループ
      const locked = CARDS.filter(c => !isUnlocked(c.id));
      if (locked.length) {
        const nc = locked[Math.floor(_rng() * locked.length) % locked.length];
        unlockedCards.push(nc.id); saveJSON('malcore.cards', unlockedCards);
        Sound.play('cutin');
        reward += '<div class="reward unlock">🃏 新カード入手！「' + nc.name + '」（図鑑 ' +
          unlockedCards.length + '/' + CARDS.length + '）</div>';
      } else {
        reward += '<div class="reward">🃏 技図鑑コンプリート（' + CARDS.length + '/' + CARDS.length + '）</div>';
      }
    }
    $('result-body').innerHTML =
      '<div class="verdict ' + (win ? 'win' : 'lose') + '">' +
        (win ? '🏆 攻略成功' : (G.result === 'lose_turn' ? '⏳ タイムオーバー' : '🚨 駆除された')) + '</div>' +
      '<div class="stat">残りCIA合計 ' + Math.round(G.db.C + G.db.I + G.db.A) +
        ' ／ 使用 ' + (G.turn) + 'T ／ 警戒度 ' + G.warning + '</div>' +
      reward +
      '<div class="debrief"><b>防御官の総評</b><p>' + debrief(G) + '</p></div>';
  }

  let equipped = []; // 装備中の攻撃手法カード（最大3）

  // 世代進化の永続状態（localStorage、無ければデモ用に開発P=4で開始）
  let levels = loadJSON('malcore.levels', {});
  let devP = loadJSON('malcore.devP', 4);
  // 入手済み技カード（初期は基本3枚。勝利で増える＝収集ループ）
  let unlockedCards = loadJSON('malcore.cards', ['sqli', 'slowloris', 'csrf']);
  function isUnlocked(id) { return unlockedCards.indexOf(id) >= 0; }
  function loadJSON(key, def) {
    try { const v = localStorage.getItem(key); return v == null ? def : JSON.parse(v); } catch (e) { return def; }
  }
  function saveJSON(key, val) { try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) {} }

  function startGame() {
    G = createGame(STAGE_ZENITH, equipped, levels);
    Sound.bgm(); show('battle-screen'); renderBattle();
    playDefenseIntro(defenseIntro(G)); // 敵の防御を開幕カットインで提示（多いほど手強い印象）
  }

  // 開幕の防御カットイン（プロキシ/DLP/ハードニング等を1つずつ提示）
  function popDefBanner(it, total, idx) {
    document.querySelectorAll('.banner').forEach(e => e.remove());
    const el = document.createElement('div');
    el.className = 'banner def';
    el.innerHTML =
      '<div class="banner-head">🛡️ 敵防御 ' + (idx + 1) + '/' + total + '</div>' +
      '<div class="banner-name">' + it.name + '</div>' +
      '<div class="banner-en">' + it.sub + '</div>';
    $('app').appendChild(el);
    Sound.play('shield');
    setTimeout(() => el.remove(), 880);
  }
  function playDefenseIntro(items) {
    if (!items || !items.length) return;
    // テンポ重視: 先頭2件だけバナー化（残りは防御パネルのチップで常時可視）
    const show = items.slice(0, 2);
    show.forEach((it, i) => setTimeout(() => popDefBanner(it, items.length, i), 350 + i * 500));
  }

  function evolve(id) {
    const L = levels[id] || 0;
    if (L >= EVO_MAX) return;
    const cost = evoCost(L);
    if (devP < cost) return;
    devP -= cost; levels[id] = L + 1;
    saveJSON('malcore.levels', levels); saveJSON('malcore.devP', devP);
    Sound.play('cutin');
    renderBriefing();
  }

  function renderBriefing() {
    const handHtml = ['zeus', 'iloveyou', 'mydoom', 'blaster'].map(id => {
      const m = malById(id);
      const L = levels[id] || 0;
      const s = MALCORE.malStats(m, L);
      const badge = L > 0 ? '<span class="evo-badge">' + ['', '改', '改弐'][L] + '</span>' : '';
      const maxed = L >= EVO_MAX;
      const cost = evoCost(L);
      const evoBtn = '<button class="evo-btn" data-evo="' + id + '" ' + (maxed || devP < cost ? 'disabled' : '') + '>' +
        (maxed ? '進化MAX' : '⬆ 進化（開発P ' + cost + '）') + '</button>';
      return '<div class="card"><div class="card-top">' +
        '<span class="malspr evo' + L + '">' + SPRITES.mal(id, { gen: L }) + '</span>' +
        '<span class="card-name"><b>' + m.name + badge + '</b><span>' + m.year + ' / 世代Lv' + L + '</span></span></div>' +
        '<div class="card-cia">🔵' + s.C + ' 🟢' + s.I + ' 🟡' + s.A + '</div>' +
        '<div class="card-role">' + m.role + ' / ' + m.sub + '</div>' +
        (m.waza ? '<div class="card-waza">⚡ ' + MALCORE.wazaName(m, L) + '</div>' : '') +
        evoBtn + '</div>';
    }).join('');
    // 装備技カードの選択（入手済みのみ装備可。未入手は🔒）
    equipped = equipped.filter(isUnlocked); // 念のため未所持を除外
    const ownIcon = (c) => (c.icon && SPRITES.card(c.icon)) ? '<span class="equip-spr">' + SPRITES.card(c.icon) + '</span>' : '🃏 ';
    const equipHtml = CARDS.map(c => {
      if (!isUnlocked(c.id)) {
        return '<button class="equip locked" disabled><b>🔒 ' + c.name + '</b><small>未入手（勝利で入手）</small></button>';
      }
      return '<button class="equip ' + (equipped.includes(c.id) ? 'on' : '') + '" data-card="' + c.id + '">' +
        '<b>' + ownIcon(c) + c.name + '</b><small>' + gaugeMark(c) + ' ' + costLabel(c.cost) +
        (c.special === 'ignoreH' ? ' / 貫通' : '') + '</small></button>';
    }).join('');
    $('briefing-body').innerHTML =
      '<p class="intro">' + STAGE_ZENITH.intro + '</p>' +
      '<h2 class="sub">編成（固有技）<small>🛠️ 開発P ' + devP + '</small></h2>' +
      '<div class="cards">' + handHtml + '</div>' +
      '<h2 class="sub">装備技カード <small id="equip-count">' + equipped.length + '/3 ・ 図鑑 ' + unlockedCards.length + '/' + CARDS.length + '</small></h2>' +
      '<div class="equips">' + equipHtml + '</div>';
    $('briefing-body').querySelectorAll('.equip:not(.locked)').forEach(b =>
      b.addEventListener('click', () => { toggleEquip(b.dataset.card); renderBriefing(); }));
    $('briefing-body').querySelectorAll('.evo-btn').forEach(b =>
      b.addEventListener('click', () => { Sound.unlock(); evolve(b.dataset.evo); }));
  }

  function gaugeMark(c) {
    const cia = c.cia || {};
    return (cia.C ? '🔵' + cia.C + ' ' : '') + (cia.I ? '🟢' + cia.I + ' ' : '') + (cia.A ? '🟡' + cia.A : '');
  }

  function toggleEquip(id) {
    const i = equipped.indexOf(id);
    if (i >= 0) equipped.splice(i, 1);
    else if (equipped.length < 3) equipped.push(id);
  }

  // 図鑑（全カードを英名・型・世代・対策つきで一覧）
  function renderCodex() {
    const groups = [['C', '🔵 機密性'], ['I', '🟢 完全性'], ['A', '🟡 可用性']];
    const html = groups.map(([g, title]) => {
      const items = CARDS.filter(c => c.gauge === g).map(c =>
        '<div class="codex-card"><div class="cc-top"><b>' +
        (c.icon && SPRITES.card(c.icon) ? '<span class="cc-spr">' + SPRITES.card(c.icon) + '</span>' : '⚡ ') + c.name + '</b>' +
        '<span class="cc-gen">' + (isUnlocked(c.id) ? '<span class="cc-own">✓所持</span> ' : '<span class="cc-lock">🔒未入手</span> ') + '世代' + c.gen + '</span></div>' +
        '<div class="cc-en">' + c.en + ' ・ ' + c.type + ' ・ ' + c.tactic + '</div>' +
        '<div class="cc-desc">' + c.desc + '</div>' +
        '<div class="cc-def">🛡️ ' + c.defense + '</div></div>'
      ).join('');
      return '<h2 class="sub">' + title + '</h2>' + items;
    }).join('');
    $('codex-body').innerHTML = html;
  }

  function initUI() {
    // click だけでなく touchend も拾う（スマホでの取りこぼし防止）
    const tap = (id, fn) => {
      const el = $(id); if (!el) return;
      const h = (e) => { e.preventDefault(); Sound.unlock(); fn(); };
      el.addEventListener('click', h);
    };
    tap('btn-start', () => { Sound.play('select'); renderBriefing(); show('briefing-screen'); });
    tap('btn-codex', () => { Sound.play('select'); renderCodex(); show('codex-screen'); });
    tap('btn-codex-back', () => show('title-screen'));
    tap('btn-sortie', () => { Sound.play('select'); startGame(); });
    tap('btn-retry', () => { Sound.play('select'); Sound.stopBgm(); renderBriefing(); show('briefing-screen'); });
    tap('btn-title', () => { Sound.stopBgm(); show('title-screen'); });
    $('btn-mute').addEventListener('click', () => {
      Sound.unlock();
      const m = !Sound.isMuted();
      Sound.setMuted(m);
      $('btn-mute').textContent = m ? '🔇' : '🔊';
      if (!m) Sound.play('select');
    });
  }
  // スクリプトは body 末尾。DOMが既に準備済みなら即時初期化（DOMContentLoaded取りこぼし対策）
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initUI);
  else initUI();
}
