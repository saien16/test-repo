/* game/core.js — マルこれ MVP コアエンジン
   ・前半: 純粋ロジック（DOM非依存・テスト可能）
   ・後半: UI（document があるときだけ動く）
   ダメージ式・綱引き・監査・ターン制限は docs/MALCORE_BALANCE.md / MALCORE_STAGE_MODEL.md 準拠。 */

/* ===== 乱数（テストで差し替え可能） ===== */
let _rng = Math.random;
function setRng(fn) { _rng = fn; }

/* ===== ゲーム状態生成 ===== */
function createGame(stage, equipped, levels, party, buffs) {
  const db = stage.nodes.db;
  const footholds = {};
  buffs = buffs || {}; // 母港バフ（メタ進行）: info/tech/crit/stealth/scan の各レベル
  stage.path.forEach((n, i) => { footholds[n] = (i === 0); }); // 外部のみ最初から到達
  return {
    stage,
    turn: 1,
    maxTurn: stage.turnLimit,
    warning: 0,
    buffs: buffs,
    res: { info: 40 + (buffs.info || 0) * 10, tech: 20 + (buffs.tech || 0) * 5, res: 20 }, // 初期資源（母港バフで底上げ）
    hand: (party && party.length ? party.slice(0, 3) : ['zeus', 'iloveyou', 'mydoom', 'blaster']),
    levels: levels || {},               // 世代進化レベル（id→0..2）
    equipped: (equipped || []).slice(0, 3), // 装備した攻撃手法カード（最大3）
    footholds: footholds,
    botnet: false,    // 踏み台をボット化したか（A火力+10%）
    reconDone: false, // 本命を偵察したか
    diagDone: false,  // ブルーのセキュリティ診断が発動済みか
    cut: { hHack: 0, vDiag: 0 }, // カットイン残ターン
    sinceBlue: 0,    // ブルーチームが動いてからの経過ターン
    gateScan: {},    // ゲートid→発見した脆弱性id（脆弱性スキャンの結果。何が出るかは運）
    defenses: (stage.defenses || []).map(d => ({ ...d, state: 'active' })), // 対策の状態
    db: {
      C: db.C, I: db.I, A: db.A,
      baseH: db.H, baseV: db.V, baseDef: db.baseDef || {},
      debuff: { C: 0, I: 0, A: 0 }, // RCE/装置破壊による本命防御力の低下
      initC: db.C, initI: db.I, initA: db.A,
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
  if (g.db.debuff) d -= (g.db.debuff[gauge] || 0); // RCE/装置破壊デバフで本命防御が低下
  return Math.max(0, d);
}
// 実効緩和率（ハードニング倍率込み・上限0.8）
function gaugeMit(g, gauge, ignoreH) {
  const H = ignoreH ? 0 : effH(g);
  return Math.min(0.80, gaugeDefRaw(g, gauge) * (0.5 + H / 100));
}
// ===== 経路（可変段数） =====
function bossId(g) { return g.stage.path[g.stage.path.length - 1]; }
function reachedBoss(g) { return !!g.footholds[bossId(g)]; }
// 到達済みの最深インデックス
function reachedIdx(g) {
  let idx = 0;
  for (let i = 0; i < g.stage.path.length; i++) if (g.footholds[g.stage.path[i]]) idx = i;
  return idx;
}
function currentNodeId(g) { return g.stage.path[reachedIdx(g)]; }
function nextNodeId(g) { const i = reachedIdx(g); return g.stage.path[i + 1]; } // 次の未到達ノード（無ければundefined）
// 区間 a→b を塞ぐゲート（境界FW/WAF）
function gateBetween(g, aId, bId) {
  return (g.defenses || []).find(d => d.gate && d.state === 'active' && d.between && d.between[0] === aId && d.between[1] === bId);
}
function segmentOpen(g, aId, bId) { return !gateBetween(g, aId, bId); }
// 対策を無効化する行動が今できるか（ゲートは手前ノード到達後／監視は内部到達後）
function defActionable(g, d) {
  if (d.gate && d.between) return !!g.footholds[d.between[0]];
  return reachedIdx(g) >= 1; // 監視系は侵入後
}
// その対策に有効な無効化手段が残っているか
function activeDefenses(g) { return (g.defenses || []).filter(d => d.state === 'active'); }
// 互換: 「本命に直接横展開できる状態か」≒ 次の区間が開いているか
function gateOpen(g) { const n = nextNodeId(g); return n ? segmentOpen(g, currentNodeId(g), n) : true; }

/* 移動/偵察系アクションの技名（実在の攻撃手法名。軽量フラッシュで提示） */
const ACT_TECH = {
  recon: { name: 'ポートスキャニング', en: 'Port Scanning' },
  breach: { name: 'スピアフィッシング', en: 'Spearphishing' },
  botnet: { name: 'ボットネット編入', en: 'Botnet Conscription' },
  pivot: { name: 'ラテラルムーブメント', en: 'Lateral Movement / Pass-the-Hash' },
  evade: { name: 'リビング・オフ・ザ・ランド', en: 'Living off the Land' },
  brk: { name: 'サービス・クラッシュ', en: 'Service Crash / DoS' },
  scan: { name: '脆弱性スキャン', en: 'Vulnerability Scanning' },
  penetrate: { name: 'ペネトレーション', en: 'Forced Penetration' },
};

/* ===== NW機器(FW/WAF)の脆弱性 =====
   脆弱性スキャンで1つ発見（何が出るかは運）。エクスプロイトで区間を開通しつつ効果が変わる。
   ・open は「ゲートを無効化して次ノードへ侵攻」を意味する（全脆弱性共通）。
   ・debuff は本命サーバの防御力低下（=装置破壊デバフ）。 */
const GATE_VULNS = {
  filter_bypass: { name: 'フィルタリング・バイパス', en: 'Filtering Bypass', icon: '🌫️', warn: 3, weight: 3,
    short: 'FWの防御を無効化して素通り', hint: 'ACLの穴を突きFW防御を無効化して侵攻。低リスク。 W+3' },
  config_disclosure: { name: 'コンフィグ・ディスクロージャー', en: 'Config Disclosure', icon: '📄', warn: 2, weight: 2,
    reveal: true, loot: { info: 12 }, short: '設定を吸い出し本命を偵察＋情報+12',
    hint: '設定情報を開示させ侵攻＋本命を偵察＋情報+12。静か。 W+2' },
  traffic_leak: { name: 'トラフィック・データ漏洩', en: 'Traffic Data Leak', icon: '📡', warn: 4, weight: 2,
    steal: { C: 34 }, loot: { info: 8 }, short: '通過しつつ機密性を削る＋情報+8',
    hint: '流れるデータを抜き侵攻＋本命の機密性(🔵)を削る。 W+4' },
  rce: { name: '任意コード実行(RCE)', en: 'Remote Code Execution', icon: '🧬', warn: 6, weight: 2,
    debuff: { C: 0.05, I: 0.05, A: 0.05 }, short: '本命の防御力を全体的に低下',
    hint: '機器上でコード実行し侵攻＋本命の防御力を低下（装置破壊デバフ）。 W+6' },
  crash: { name: 'クラッシュ（強制ダウン）', en: 'Crash', icon: '💥', warn: 14, weight: 1,
    short: '強行突破だが警戒度が大幅増', hint: '機器を落として強引に侵攻。防御↓だが W+14（大幅）' },
};
// 脆弱性を重み付きで1つ抽選（何が見つかるかはその時々）
function rollVuln() {
  const ids = Object.keys(GATE_VULNS);
  const total = ids.reduce((s, id) => s + (GATE_VULNS[id].weight || 1), 0);
  let r = _rng() * total;
  for (const id of ids) { r -= (GATE_VULNS[id].weight || 1); if (r < 0) return id; }
  return ids[0];
}
// ゲートを無効化して次ノードへ侵攻（エクスプロイト/貫通の共通処理）
function breachGate(g, d, newState) {
  d.state = newState || 'breached';
  const b = d.between[1];
  g.footholds[b] = true; // ゲートの先へ自動侵攻（横展開連打の解消）
}

/* 経路アクションの役割親和性。編成にこの役割のマルウェアが居れば、その子が実行（進化名つき）。 */
const PATH_AFFINITY = { recon: '偵察', breach: '侵入', botnet: '足場', brk: '装置破壊' };
function pathPerformer(g, actKey) {
  const key = PATH_AFFINITY[actKey]; if (!key) return null;
  for (let i = 0; i < (g.hand || []).length; i++) {
    const m = malById(g.hand[i]); if (!m) continue;
    if (((m.role || '') + '/' + (m.sub || '')).indexOf(key) >= 0) {
      const L = (g.levels && g.levels[g.hand[i]]) || 0;
      return { id: g.hand[i], name: m.name + (['', '改', '改弐'][L] || '') };
    }
  }
  return null;
}
function perfSuffix(g, actKey) { const p = pathPerformer(g, actKey); return p ? '（' + p.name + '）' : ''; }
function flashWith(g, tech, actKey) {
  const p = pathPerformer(g, actKey);
  return { name: tech.name, en: tech.en, by: p ? p.name : null };
}
function flashMsg(f) { return (f.by ? f.by + 'の' : '') + f.name; }

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
// 撃破=高火力だが騒がしい(既定14)、装備カード=低火力だが静か(base 5)。隠密と一気呵成の使い分け。
function strikeWarn(g, gauge, level, base) {
  return Math.max(1, Math.round((base || 14) * (GAUGE_NOISE[gauge] || 1) * detectMul(g, gauge, level)));
}

/* ステージ開始時に提示する敵の防御（プロキシ/DLP/ハードニング等）。多いほど手強い印象。 */
function defenseIntro(g) {
  const items = [];
  activeDefenses(g).forEach(d => items.push({ name: d.name, sub: d.gate ? '展開' : '監視中' }));
  if (g.db.baseH >= 50) items.push({ name: 'ハードニング', sub: '堅牢 H' + g.db.baseH });
  if (g.stage.edr) items.push({ name: 'EDR / 振る舞い検知', sub: '稼働' });
  return items;
}

/* ===== 隠密（低発覚度の報酬）＆ ブルーチーム活動 ===== */
const STEALTH_MAX = 30;   // 発覚度がこれ未満なら「潜伏中」＝奇襲ボーナス
const STEALTH_MUL = 1.30; // 潜伏中の攻撃は刺さる（見つかっていない＝防御が身構えていない）
function stealthMax(g) { return STEALTH_MAX + ((g.buffs && g.buffs.stealth) || 0) * 5; } // 母港バフで潜伏枠拡張
function isStealth(g) { return g.warning < stealthMax(g); }
function scanCost(g) { return Math.max(0, 6 - ((g.buffs && g.buffs.scan) || 0) * 2); } // 母港バフでスキャン費用減
// ブルーチームが動く間隔。発覚度がalert未満なら動かない（潜伏が報われる）。高いほど頻繁。
function blueInterval(g) {
  const b = g.stage.blue || { alert: 40, react: 1.0 };
  if (g.warning < b.alert) return Infinity;          // 潜伏中は動かない
  // alert直後は約5T間隔（稀）、発覚度が上がるほど短く、危険域(90+)では毎ターン介入
  return Math.max(1, Math.ceil((5 - (g.warning - b.alert) / 10) / b.react));
}

/* ===== ダメージ計算（1ゲージ分） ===== */
function gaugeDamage(g, base, gauge, opt) {
  opt = opt || {};
  const V = effV(g);
  const mit = gaugeMit(g, gauge, opt.ignoreH); // ゼロデイ等はハードニング無視
  const hit = 0.6 + (V / 100) * 0.8;
  const crit = _rng() < (V / 100 + ((g.buffs && g.buffs.crit) || 0) * 0.05) ? 1.5 : 1.0; // 母港バフで会心率+
  const stealth = isStealth(g) ? STEALTH_MUL : 1.0; // 潜伏中の奇襲ボーナス
  return { dmg: base * (1 - mit) * hit * crit * stealth, crit: crit > 1 };
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
  const A = [];
  const nodeName = (id) => (g.stage.nodes[id] || {}).name || id;
  const inside = reachedIdx(g) >= 1;     // 最初の内部ノードに到達済みか
  const atBoss = reachedBoss(g);
  const can = (id, label, ok, reason, hint) => A.push({ id, label, enabled: ok, reason, hint });

  can('recon', '🔍 ポートスキャニング' + perfSuffix(g, 'recon'), !g.reconDone, '偵察済み',
      '本命の防御を偵察で開示。CIカットインの前提。 W+3');
  // 初期侵害: 外部 → 最初の内部ノード
  can('breach', '🚪 スピアフィッシング' + perfSuffix(g, 'breach'), !inside, '侵害済み',
      nodeName(g.stage.path[1]) + 'を初期侵害し足場確立。 W+3');
  can('botnet', '🏴 ボットネット編入' + perfSuffix(g, 'botnet'), inside && !g.botnet, inside ? '実施済み' : '踏み台が必要',
      '踏み台をボット化。可用性火力+10%。 W+4');
  const hasBreaker = g.hand.some(id => (malById(id) || {}).breaker);
  activeDefenses(g).forEach(d => {
    const act = defActionable(g, d);
    if (d.gate) {
      // NW機器(FW/WAF): 脆弱性スキャン→エクスプロイト or 貫通で侵攻（横展開連打の解消）
      const b = nodeName(d.between[1]);
      const found = g.gateScan[d.id];
      const sc = scanCost(g);
      can('scan:' + d.id, '🔎 脆弱性スキャン: ' + d.name, act && canAfford(g, { info: sc }),
          act ? '情報' + sc + 'が必要' : '手前に到達が必要',
          (found ? '再スキャンで別の脆弱性を探す' : d.name + 'の弱点を探る（何が出るかは運）') + ' 情報' + sc + ' / W+2');
      if (found) {
        const v = GATE_VULNS[found];
        can('exploit:' + d.id, v.icon + ' ' + v.name + ' → ' + b, act, '手前に到達が必要', v.hint);
      }
      can('penetrate:' + d.id, '💥 貫通攻撃: ' + d.name + ' → ' + b + perfSuffix(g, 'brk'), act, '手前に到達が必要',
          '脆弱性なしで強引に侵攻。本命防御↓だが W+15（派手）');
    } else {
      // 監視系(DLP/IPS/FIM/EDR): 回避/破壊
      if (d.evade) {
        can('evade:' + d.id, '🌫️ ' + d.name + 'を回避', act && canAfford(g, d.evade),
            act ? '資源不足(' + costLabel(d.evade) + ')' : '内部に到達が必要',
            '正規に偽装し無効化。防御力↓＆検知↓。' + costLabel(d.evade) + ' / W+2');
      }
      if (d.breakable) {
        can('break:' + d.id, '💥 ' + d.name + 'を破壊' + perfSuffix(g, 'brk'), act && hasBreaker,
            act ? '装置破壊ロールが必要' : '内部に到達が必要',
            '装置破壊ロールで無効化＋本命防御↓。だが W+25（派手）');
      }
    }
  });
  // 横展開: ゲートの無い区間のみ（脆弱性攻略はゲート側で行う）
  const nxt = nextNodeId(g);
  if (inside && nxt && segmentOpen(g, currentNodeId(g), nxt) && !g.footholds[nxt]) {
    can('pivot', '↔️ ラテラルムーブメント → ' + nodeName(nxt), true, '',
        'パス・ザ・ハッシュで ' + nodeName(nxt) + ' へ横展開。 W+3');
  }
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
    can('strike:' + id, '⚔️ ' + tag + (m.waza ? m.waza.name.replace(/！+$/, '') : m.name), atBoss, '本命未到達',
        'C' + s.C + '/I' + s.I + '/A' + s.A + ' で攻撃。 W+' + w);
  });
  // 装備技カード（本命到達後・資源を満たすとき）
  (g.equipped || []).forEach(id => {
    const c = cardById(id); if (!c) return;
    const ok = atBoss && canAfford(g, c.cost);
    const reason = !atBoss ? '本命未到達' : '資源不足(' + costLabel(c.cost) + ')';
    const cia = c.cia || {};
    const w = strikeWarn(g, c.gauge || primGauge(cia), 0, 5);
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
    g.reconDone = true; warn = 3; g.flash = flashWith(g, ACT_TECH.recon, 'recon');
    msg = '⚡ ' + flashMsg(g.flash) + ': 本命 H' + g.db.baseH + ' / V' + g.db.baseV + 'を偵察';
  } else if (actionId === 'breach') {
    const first = g.stage.path[1]; g.footholds[first] = true; warn = 3;
    g.flash = flashWith(g, ACT_TECH.breach, 'breach');
    msg = '⚡ ' + flashMsg(g.flash) + ': ' + (g.stage.nodes[first].name) + 'に足場を確立';
  } else if (actionId === 'botnet') {
    g.botnet = true; warn = 4; g.flash = flashWith(g, ACT_TECH.botnet, 'botnet');
    msg = '⚡ ' + flashMsg(g.flash) + ': 可用性火力 +10%';
  } else if (actionId.startsWith('evade:')) {
    const d = g.defenses.find(x => x.id === actionId.slice(6));
    payCost(g, d.evade); d.state = 'evaded'; warn = 2; g.flash = ACT_TECH.evade;
    msg = '⚡ ' + ACT_TECH.evade.name + ': ' + d.name + 'を回避。防御力↓（本体のみ）＆検知↓';
  } else if (actionId.startsWith('break:')) {
    const d = g.defenses.find(x => x.id === actionId.slice(6));
    d.state = 'destroyed'; warn = 25; g.flash = flashWith(g, ACT_TECH.brk, 'brk');
    ['C', 'I', 'A'].forEach(k => g.db.debuff[k] += 0.04); // 装置破壊デバフ: 本命防御が低下
    msg = '⚡ ' + flashMsg(g.flash) + ': ' + d.name + 'を破壊。本命防御↓だが発覚度が跳ね上がった';
  } else if (actionId.startsWith('scan:')) {
    const d = g.defenses.find(x => x.id === actionId.slice(5));
    payCost(g, { info: scanCost(g) });
    const vid = rollVuln(); g.gateScan[d.id] = vid;
    const v = GATE_VULNS[vid]; warn = 2;
    g.flash = { name: ACT_TECH.scan.name + ': ' + v.name + ' 発見', en: v.en, by: null };
    msg = '🔎 脆弱性スキャン: ' + d.name + ' に「' + v.name + '」を発見（' + v.short + '）';
  } else if (actionId.startsWith('exploit:')) {
    const d = g.defenses.find(x => x.id === actionId.slice(8));
    const v = GATE_VULNS[g.gateScan[d.id]];
    breachGate(g, d, 'breached'); warn = v.warn;
    let extra = '';
    if (v.debuff) { ['C', 'I', 'A'].forEach(k => g.db.debuff[k] += (v.debuff[k] || 0)); extra += ' 本命防御↓'; }
    if (v.reveal) { g.reconDone = true; extra += ' 本命偵察'; }
    if (v.loot) { g.res.info += (v.loot.info || 0); g.res.tech += (v.loot.tech || 0); g.res.res += (v.loot.res || 0); extra += ' +資源'; }
    if (v.steal) { const dmg = v.steal.C || 0; g.db.C = Math.max(0, g.db.C - dmg); g.res.info += Math.floor(dmg / 10); extra += ' 🔵-' + dmg; }
    g.banner = { name: v.name + '！', en: v.en, tone: 'strike', gauge: 'C' };
    msg = v.icon + ' ' + v.name + ': ' + d.name + 'を突破し ' + g.stage.nodes[d.between[1]].name + ' へ侵攻。' + extra;
  } else if (actionId.startsWith('penetrate:')) {
    const d = g.defenses.find(x => x.id === actionId.slice(10));
    breachGate(g, d, 'penetrated'); warn = 15;
    ['C', 'I', 'A'].forEach(k => g.db.debuff[k] += 0.03); // 強行突破でも軽い装置破壊デバフ
    g.flash = flashWith(g, ACT_TECH.penetrate, 'brk');
    msg = '💥 ' + flashMsg(g.flash) + ': ' + d.name + 'を強引に突破し ' + g.stage.nodes[d.between[1]].name + ' へ侵攻（本命防御↓ / 発覚度+15）';
  } else if (actionId === 'pivot') {
    const nxt = nextNodeId(g); g.footholds[nxt] = true; warn = 2; g.flash = ACT_TECH.pivot;
    msg = '⚡ ' + ACT_TECH.pivot.name + ': ' + g.stage.nodes[nxt].name + 'へ横展開';
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
    warn = strikeWarn(g, c.gauge || primGauge(c.cia || {}), 0, 5);
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
  // ブルーチーム活動: 発覚度がalert未満なら動かない（潜伏が報われる）。
  // alert超えで動き始め、発覚度が高いほど頻繁に介入する（＝ブルーが本格始動）。
  const b = g.stage.blue || { alert: 40, react: 1.0 };
  if (g.warning >= b.alert) {
    g.sinceBlue++;
    if (g.sinceBlue >= blueInterval(g)) {
      g.sinceBlue = 0;
      g.db.baseH = Math.min(100, g.db.baseH + g.stage.audit.hardenUp);
      g.warning = Math.min(100, g.warning + 5);
      let eff = '敵ハードニング+' + g.stage.audit.hardenUp + '（あなたの攻撃が通りにくく）';
      // 高発覚度ではセキュリティ診断(V↓)も併発
      if (g.warning >= g.stage.diag.warnThreshold && !g.diagDone) {
        g.db.baseV = Math.max(0, g.db.baseV - g.stage.diag.vulnDown);
        g.diagDone = true;
        eff += ' / 敵脆弱性-' + g.stage.diag.vulnDown + '（命中・会心↓）';
      }
      g.log.push('T' + g.turn + '  🔵 ブルーチーム介入: ' + eff + ' / 発覚度+5');
      g.counter = { kind: 'audit', label: 'ブルーチーム介入', effect: eff, warn: 5 };
    }
  } else {
    g.sinceBlue = 0; // 潜伏に戻れば落ち着く
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
  isStealth, blueInterval, STEALTH_MAX, STEALTH_MUL,
  reachedBoss, bossId, reachedIdx, currentNodeId, nextNodeId, segmentOpen,
  STAGE: (typeof STAGE_ZENITH !== 'undefined') ? STAGE_ZENITH : null,
  STAGES: (typeof STAGES !== 'undefined') ? STAGES : [],
  CARDS: (typeof CARDS !== 'undefined') ? CARDS : [],
};
if (typeof globalThis !== 'undefined') globalThis.MALCORE = MALCORE;

/* =======================================================================
   UI 層（document があるときだけ）
   ======================================================================= */
if (typeof document !== 'undefined' && document.getElementById) {
  let G = null;

  const $ = (id) => document.getElementById(id);
  const HUB_SCREENS = ['home-screen', 'codex-screen', 'develop-screen', 'stage-screen'];
  const show = (id) => {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    $(id).classList.add('active');
    const tb = $('tabbar'); // 母港系の画面でだけ下部タブバーを出す
    if (tb) {
      tb.hidden = HUB_SCREENS.indexOf(id) < 0;
      tb.querySelectorAll('.tabbar-btn').forEach(b => b.classList.toggle('on', b.dataset.tab === id));
    }
    if (id !== 'home-screen' && typeof stopHubIdle === 'function') stopHubIdle(); // 母港を離れたら表情サイクル停止
  };

  // val=最新値 / from=前回表示値（省略時は val=アニメ無し）。前回値から現在値へバー幅と数値をトゥイーン。
  function bar(label, val, max, cls, from) {
    const f = (from == null ? val : from);
    const toPct = Math.max(0, Math.min(100, (val / max) * 100));
    const fromPct = Math.max(0, Math.min(100, (f / max) * 100));
    const dir = val < f - 0.5 ? ' drop' : (val > f + 0.5 ? ' rise' : '');
    return '<div class="bar"><span class="bar-label">' + label + '</span>' +
      '<span class="bar-track"><i class="bar-fill ' + cls + dir + '" style="width:' + fromPct + '%" data-w="' + toPct.toFixed(2) + '"></i></span>' +
      '<span class="bar-num" data-from="' + Math.round(f) + '" data-to="' + Math.round(val) + '">' + Math.round(f) + '</span></div>';
  }
  // 数値カウントアップ/ダウン（easeOutCubic）
  function tweenNum(el, from, to, dur) {
    if (typeof requestAnimationFrame === 'undefined' || typeof performance === 'undefined' || from === to) { el.textContent = to; return; }
    const t0 = performance.now();
    (function step(now) {
      const p = Math.min(1, (now - t0) / dur);
      const e = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(from + (to - from) * e);
      if (p < 1) requestAnimationFrame(step);
    })(t0);
  }
  // 直近 renderBattle 後に、幅トランジション始動＋数値トゥイーンを実行
  function animateBattle() {
    if (typeof requestAnimationFrame === 'undefined') return;
    const root = $('battle-root'); if (!root) return;
    root.querySelectorAll('.bar-fill[data-w]').forEach(el => {
      const to = el.getAttribute('data-w');
      requestAnimationFrame(() => { el.style.width = to + '%'; });
    });
    root.querySelectorAll('.bar-num[data-to], .ci-total[data-to]').forEach(el =>
      tweenNum(el, +el.getAttribute('data-from'), +el.getAttribute('data-to'), 600));
    root.querySelectorAll('.def-g[data-to]').forEach(el => {
      const n = el.querySelector('.dg-n'); if (n) tweenNum(n, +el.getAttribute('data-from'), +el.getAttribute('data-to'), 600);
    });
  }

  // 本命の防御力（ゲージ別の実効緩和％）と、効いている対策を表示
  function defensePanel(g) {
    const pct = (gauge) => Math.round(gaugeMit(g, gauge) * 100);
    const sd = g._shownDef || {};
    const gspan = (gauge, mark, cls) => {
      const to = pct(gauge), from = (sd[gauge] == null ? to : sd[gauge]);
      const dir = to > from ? ' up' : (to < from ? ' dn' : ''); // up=硬化(敵有利/赤) dn=剥がれた(自分有利/緑)
      return '<span class="def-g ' + cls + dir + '" data-from="' + from + '" data-to="' + to + '">' +
        mark + '<i class="dg-n">' + from + '</i>%</span>';
    };
    const act = activeDefenses(g);
    const list = act.length
      ? act.map(d => '<span class="def-chip">🛡️ ' + d.name + '</span>').join('')
      : '<span class="def-chip none">本体防御のみ</span>';
    return '<div class="defrow">' +
      '<span class="def-title">防御力</span>' +
      gspan('C', '🔵', 'c') + gspan('I', '🟢', 'i') + gspan('A', '🟡', 'a') +
      '<span class="def-list">' + list + '</span></div>';
  }

  function renderBattle() {
    const g = G, d = g.db;
    const sh = g._shown || {};                         // 前回表示した C/I/A・発覚度・CIA合計
    const shTotal = (sh.total == null ? d.C + d.I + d.A : sh.total);
    const dbState = (function () {
      const r = (d.C + d.I + d.A) / d.initTotal;
      return r > 0.66 ? 'ok' : (r > 0.33 ? 'hurt' : 'crit');
    })();
    // ノードid → スプライト種別（pc/db以外の中間ノードは汎用サーバ）
    const sprKind = (n) => {
      if (n === 'outside') return 'outside';
      const k = (g.stage.nodes[n] || {}).kind;
      return k === 'pc' ? 'pc' : k === 'db' ? 'db' : 'server';
    };
    const lastI = g.stage.path.length - 1;
    const hops = g.stage.path.map((n, i) => {
      const reached = n === 'outside' ? true : g.footholds[n];
      const nm = n === 'outside' ? '外部' : g.stage.nodes[n].name.split('（')[0];
      const sprOpt = n === bossId(g) ? { state: dbState } : undefined;
      const hop = '<span class="hop ' + (reached ? 'on' : '') + '">' +
        '<span class="nodespr">' + SPRITES.node(sprKind(n), sprOpt) + '</span>' +
        '<small>' + nm + '</small></span>';
      if (i === lastI) return hop;
      const next = g.stage.path[i + 1];
      // 区間にゲート(FW/WAF)があるか（剥がす前=閉/剥がした後=開通）
      const stGate = (g.stage.defenses || []).find(x => x.gate && x.between && x.between[0] === n && x.between[1] === next);
      if (stGate) {
        const live = gateBetween(g, n, next); // active のみ返る
        if (live) {
          const ico = /waf/.test(live.id) ? 'waf' : 'fw';
          const vid = g.gateScan[live.id];
          const vTag = vid ? '<span class="vuln-tag">' + GATE_VULNS[vid].icon + '脆弱性発見</span>' : '';
          return hop + '<span class="hop gate"><span class="nodespr sm">' + SPRITES.node(ico) + '</span><small>' + live.name + '</small>' + vTag + '</span>';
        }
        return hop + '<span class="hop-arrow open">▶</span>'; // ゲート突破済み
      }
      return hop + '<span class="hop-arrow">▶</span>';
    }).join('');
    const pathHtml = hops;

    const cutBadges =
      (g.cut.hHack > 0 ? '<span class="badge ci">🛠️H-20(' + g.cut.hHack + 'T)</span>' : '') +
      (g.cut.vDiag > 0 ? '<span class="badge ci">🧪V+25(' + g.cut.vDiag + 'T)</span>' : '');

    // 行動をカテゴリ分けしてタブ化（コンテンツが増えてもボタンの壁にしない）
    const renderBtn = (a) => {
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
    };
    const ACT_CATS = [
      { key: 'intrude', label: '🚪 侵入', match: a => a.id === 'recon' || a.id === 'breach' || a.id === 'botnet' },
      { key: 'pivot', label: '🧭 侵攻', match: a => a.id === 'pivot' || /^(scan|exploit|penetrate|evade|break):/.test(a.id) },
      { key: 'support', label: '🛠️ 支援', match: a => a.id === 'ci_recon' || a.id === 'ci_diag' },
      { key: 'strike', label: '⚔️ 撃破', match: a => a.id.startsWith('strike:') },
      { key: 'card', label: '🃏 カード', match: a => a.id.startsWith('card:') },
    ];
    const allActs = listActions(g);
    const cats = ACT_CATS.map(c => ({ key: c.key, label: c.label, acts: allActs.filter(c.match) })).filter(c => c.acts.length);
    // アクティブタブ決定（保持しつつ、無効なら自動選択：本命到達後は撃破優先、なければ有効な行動を持つ最初）
    let curTab = actTab;
    if (!curTab || !cats.some(c => c.key === curTab)) {
      const withEnabled = cats.filter(c => c.acts.some(a => a.enabled));
      const pick = (reachedBoss(g) && withEnabled.find(c => c.key === 'strike')) || withEnabled[0] || cats[0];
      curTab = pick ? pick.key : null;
    }
    const tabRow = cats.map(c => {
      const en = c.acts.filter(a => a.enabled).length;
      return '<button class="acttab' + (c.key === curTab ? ' on' : '') + '" data-acttab="' + c.key + '">' +
        c.label + (en ? '<span class="tabbadge">' + en + '</span>' : '') + '</button>';
    }).join('');
    const activeCat = cats.find(c => c.key === curTab);
    const actList = activeCat ? activeCat.acts.map(renderBtn).join('') : '';
    const actDock = cats.length
      ? '<div class="acttabs">' + tabRow + '</div><div class="acts">' + actList + '</div>'
      : '<div class="acts"></div>';

    $('battle-root').innerHTML =
      '<div class="hud">' +
        '<span class="pill turn">⏳ T ' + g.turn + ' / ' + g.maxTurn + '</span>' +
        '<span class="pill info">📡 情報 ' + g.res.info + '</span>' +
        '<span class="pill tech">🧬 技術 ' + g.res.tech + '</span>' +
        '<span class="pill resr">⚙️ 資源 ' + g.res.res + '</span>' +
      '</div>' +
      bar('🚨 発覚度', g.warning, 100, 'warn', sh.warn) +
      (function () {
        const alert = (g.stage.blue || {}).alert || 40;
        let cls, txt;
        if (isStealth(g)) { cls = 'stealth'; txt = '🥷 潜伏中: 攻撃+' + Math.round((STEALTH_MUL - 1) * 100) + '%・ブルーは動かない'; }
        else if (g.warning < alert) { cls = 'calm'; txt = '🟢 未察知: ブルーはまだ動いていない'; }
        else if (g.warning < g.stage.diag.warnThreshold) { cls = 'alert'; txt = '🟡 警戒: ブルーチームが動き始めた（介入が増える）'; }
        else { cls = 'danger'; txt = '🔴 危険: ブルーが頻繁に介入（100で駆除）'; }
        return '<div class="warn-note ' + cls + '">' + txt + '</div>';
      })() +
      '<div class="path">' + pathHtml + '</div>' +
      '<div class="boss">' +
        '<div class="boss-head"><span class="bossspr ' + dbState + '">' + SPRITES.node('db', { state: dbState }) + '</span>' +
          '<span class="boss-title">★ ' + g.stage.nodes.db.name +
          '<span class="hv">H ' + effH(g) + ' / V ' + effV(g) + ' ' + cutBadges + '</span></span></div>' +
        '<div class="goal-chip">🎯 勝利まで CIA合計 <b class="ci-total" data-from="' + Math.round(shTotal) +
          '" data-to="' + Math.round(d.C + d.I + d.A) + '">' + Math.round(shTotal) + '</b>' +
          ' → <b>' + Math.round(d.initTotal * g.stage.win.ratio) + '以下</b></div>' +
        bar('🔵 機密性 C', d.C, d.initC, 'c', sh.C) +
        bar('🟢 完全性 I', d.I, d.initI, 'i', sh.I) +
        bar('🟡 可用性 A', d.A, d.initA, 'a', sh.A) +
        defensePanel(g) +
      '</div>' +
      actDock +
      '<div class="logbox">' + g.log.slice(-6).reverse().map(l => '<div>' + l + '</div>').join('') + '</div>';

    $('battle-root').querySelectorAll('.acttab').forEach(t =>
      t.addEventListener('click', () => { Sound.unlock(); Sound.play('select'); actTab = t.dataset.acttab; renderBattle(); }));

    $('battle-root').querySelectorAll('.act:not(.off)').forEach(b =>
      b.addEventListener('click', () => {
        Sound.unlock();
        // 音は afterAction 側で出し分け（撃破=技カットイン / 移動=軽量フラッシュ）。
        applyAction(G, b.dataset.act); afterAction();
      }));

    animateBattle();                                   // バー幅トランジション＋数値カウント始動
    // 今回の表示値を記録（次回 render の「前回値」＝アニメ始点）
    g._shown = { warn: g.warning, C: d.C, I: d.I, A: d.A, total: d.C + d.I + d.A };
    g._shownDef = { C: Math.round(gaugeMit(g, 'C') * 100), I: Math.round(gaugeMit(g, 'I') * 100), A: Math.round(gaugeMit(g, 'A') * 100) };
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
      '<div class="banner-en">' + c.label + '</div>' +
      '<div class="counter-eff">' + (c.effect || '') + '</div>' +
      (c.warn ? '<div class="counter-cost">🚨 こちらの発覚度 +' + c.warn + '（駆除に近づく）</div>' : '');
    $('app').appendChild(el);
    const app = $('app'); app.classList.remove('shake'); void app.offsetWidth; app.classList.add('shake');
    Sound.play('hit');
    setTimeout(() => el.remove(), 2400); // 反撃は2秒以上しっかり見せる
  }

  // 移動/偵察系の軽量フラッシュ（小さく一瞬。撃破の全画面カットインとは格差をつける）
  function popFlash(f) {
    document.querySelectorAll('.techflash').forEach(e => e.remove());
    const el = document.createElement('div');
    el.className = 'techflash';
    el.innerHTML = '⚡ ' + (f.by ? '<i>' + f.by + '</i> ' : '') + f.name + (f.en ? ' <span>' + f.en + '</span>' : '');
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

  // 制圧報酬を確定して永続化（1回だけ）。結果画面と溢れ出し演出の両方が参照する。
  function grantWin() {
    const stage = STAGES[selectedStage];
    const loot = { stageName: null, devP: 0, reward: { info: 0, tech: 0, res: 0 }, card: null, malware: null, minerLeft: 0 };
    if (selectedStage + 1 < STAGES.length && selectedStage + 2 > unlockedStages) {
      unlockedStages = Math.min(STAGES.length, selectedStage + 2);
      saveJSON('malcore.unlocked', unlockedStages);
      loot.stageName = STAGES[selectedStage + 1].name;
    }
    // 制圧報酬: ステージ毎の 情報/技術/リソース が本命から溢れ出す → ストックへ（次の出撃で使える）
    const rw = stage.reward || { info: 20, tech: 12, res: 15 };
    stock.info += rw.info; stock.tech += rw.tech; stock.res += rw.res; saveStock();
    loot.reward = { info: rw.info, tech: rw.tech, res: rw.res };
    // 開発P（今回の余剰資源から）
    const surplus = Math.floor((G.res.info + G.res.tech + G.res.res) / 20);
    loot.devP = 3 + surplus; devP += loot.devP; saveJSON('malcore.devP', devP);
    // コインマイナー設置
    plantMiner(stage.id); loot.minerLeft = miners[stage.id];
    // 低確率ドロップ: 攻撃カード（30%）
    const lockedC = CARDS.filter(c => !isUnlocked(c.id));
    if (lockedC.length && _rng() < 0.30) {
      const nc = lockedC[Math.floor(_rng() * lockedC.length) % lockedC.length];
      unlockedCards.push(nc.id); saveJSON('malcore.cards', unlockedCards); loot.card = nc.name;
    }
    // 低確率ドロップ: マルウェア（12%）
    const lockedM = MAL.filter(m => !malUnlocked(m.id));
    if (lockedM.length && _rng() < 0.12) {
      const nm = lockedM[Math.floor(_rng() * lockedM.length) % lockedM.length];
      unlockedMal.push(nm.id); saveJSON('malcore.malunlocked', unlockedMal); refreshRoster(); loot.malware = nm.name;
    }
    G._loot = loot;
    return loot;
  }
  // 宝箱がポップして開き、中から戦利品が飛び出す演出
  const CHEST_SVG = '<svg viewBox="0 0 100 100">' +
    '<g class="chest-glow"><ellipse cx="50" cy="54" rx="30" ry="14" fill="#fff3b0"/>' +
    '<g stroke="#ffe066" stroke-width="2.4" stroke-linecap="round" opacity=".85">' +
    '<path d="M50 54 L26 20 M50 54 L50 12 M50 54 L74 20 M50 54 L14 44 M50 54 L86 44"/></g></g>' +
    '<rect x="22" y="52" width="56" height="32" rx="5" fill="#8a5a2a" stroke="#4e3216" stroke-width="2.5"/>' +
    '<rect x="22" y="60" width="56" height="8" fill="#c08a3a"/>' +
    '<rect x="43" y="62" width="14" height="15" rx="2" fill="#ffd34a" stroke="#a8791f" stroke-width="1.5"/>' +
    '<circle cx="50" cy="69" r="2.2" fill="#4e3216"/>' +
    '<g class="chest-lid"><path d="M22 56 v-4 a28 14 0 0 1 56 0 v4 Z" fill="#9a6a34" stroke="#4e3216" stroke-width="2.5"/>' +
    '<rect x="22" y="50" width="56" height="7" fill="#c08a3a"/>' +
    '<rect x="43" y="47" width="14" height="8" rx="2" fill="#ffd34a" stroke="#a8791f" stroke-width="1.5"/></g></svg>';
  function spawnLootBurst(loot) {
    const cx = (window.innerWidth || 390) / 2;
    const cy = (window.innerHeight || 800) * 0.6;
    const layer = document.createElement('div'); layer.className = 'loot-layer';
    const chest = document.createElement('div'); chest.className = 'loot-chest';
    chest.style.left = cx + 'px'; chest.style.top = cy + 'px';
    chest.innerHTML = '<div class="chest-inner">' + CHEST_SVG + '</div>';
    layer.appendChild(chest);
    const parts = [];
    const push = (g, n) => { for (let i = 0; i < n; i++) parts.push(g); };
    push('📡', Math.min(6, Math.max(1, Math.ceil(loot.reward.info / 12))));
    push('🧬', Math.min(6, Math.max(1, Math.ceil(loot.reward.tech / 12))));
    push('💾', Math.min(6, Math.max(1, Math.ceil(loot.reward.res / 12))));
    if (loot.card) push('🃏', 3);
    if (loot.malware) push('🦠', 3);
    parts.forEach((g, i) => {
      const s = document.createElement('span'); s.className = 'loot-p'; s.textContent = g;
      const t = parts.length > 1 ? i / (parts.length - 1) : 0.5;
      const ang = -Math.PI / 2 + (t - 0.5) * Math.PI * 1.15; // 宝箱の口から上向きに扇状
      const dist = 76 + Math.random() * 72;
      s.style.left = cx + 'px'; s.style.top = (cy - 16) + 'px';
      s.style.setProperty('--dx', Math.round(Math.cos(ang) * dist) + 'px');
      s.style.setProperty('--dy', Math.round(Math.sin(ang) * dist) + 'px');
      s.style.animationDelay = (0.5 + i * 0.05).toFixed(2) + 's'; // フタが開いてから噴出
      layer.appendChild(s);
    });
    $('app').appendChild(layer);
    setTimeout(() => layer.remove(), 2000);
  }

  // 勝敗の決着演出（切り替えが速すぎて分かりにくい問題への対応・1.9秒見せる）
  function showFinish(res) {
    const win = res === 'win';
    document.querySelectorAll('.banner').forEach(e => e.remove());
    Sound.play(win ? 'win' : 'lose');
    if (win) {
      const loot = grantWin();                                          // 報酬を確定
      document.querySelectorAll('.bossspr').forEach(b => b.classList.add('shatter')); // 本命DBが砕ける
      spawnLootBurst(loot);                                             // 戦利品が溢れ出す
      if (loot.card || loot.malware) Sound.play('cutin');
    }
    else { const a = $('app'); a.classList.remove('shake'); void a.offsetWidth; a.classList.add('shake'); }
    const title = win ? '🏆 制圧成功！' : (res === 'lose_turn' ? '⏳ タイムオーバー' : '🚨 駆除された');
    const sub = win ? '本命「' + G.stage.nodes.db.name.replace('（本命）', '') + '」を掌握した'
      : (res === 'lose_turn' ? 'ブルーチームの封じ込めが間に合った' : '発覚度MAX — 足場を一斉駆除された');
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
      const loot = G._loot || grantWin(); // 通常は showFinish で確定済み
      if (loot.stageName) reward += '<div class="reward unlock">🗺️ 新ステージ解放！「' + loot.stageName + '」</div>';
      // 制圧報酬: 本命から溢れ出た 情報/技術/リソース（次の出撃で使える）
      reward += '<div class="reward loot">💥 制圧報酬が溢れ出た！ 📡情報+' + loot.reward.info +
        ' 🧬技術+' + loot.reward.tech + ' 💾リソース+' + loot.reward.res + '（ストックへ → 次の出撃で投入）</div>';
      reward += '<div class="reward">🛠️ 開発P +' + loot.devP + '（所持 ' + devP + '）— 母港バフに使える</div>';
      reward += '<div class="reward">⛏️ コインマイナー設置！「' + STAGES[selectedStage].name +
        '」で ' + loot.minerLeft + '回の出撃までビットコイン等を採掘</div>';
      if (loot.card) reward += '<div class="reward unlock">🃏 攻撃カード・ドロップ！「' + loot.card +
        '」（図鑑 ' + unlockedCards.length + '/' + CARDS.length + '）</div>';
      if (loot.malware) reward += '<div class="reward unlock">🦠 マルウェア・ドロップ！「' + loot.malware +
        '」が仲間に（母港 ' + unlockedMal.length + '/' + MAL.length + '）</div>';
      G._loot = null;
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
  let party = ['zeus', 'iloveyou', 'mydoom']; // 出撃マルウェア（最大3）
  let selectedStage = 0;
  let briefTab = 'party';   // ブリーフィングのサブタブ: 'party'|'equip'
  let actTab = null;        // バトルの行動カテゴリ: intrude|pivot|support|strike|card（nullで自動選択）
  let codexTab = 'mal';     // 図鑑タブ: 'mal'|'card'
  let codexGauge = 'all';   // 図鑑ゲージ絞り込み: all|C|I|A
  let codexOwned = false;   // 図鑑: 所持のみ（カード用）

  // 世代進化の永続状態（localStorage、無ければデモ用に開発P=4で開始）
  let levels = loadJSON('malcore.levels', {});
  let devP = loadJSON('malcore.devP', 4);
  // 母港バフ（恒久メタ進行。開発Pの使い道。出撃時に効果を発揮）
  const PORT_BUFFS = [
    { key: 'info', name: '諜報ネットワーク', icon: '📡', max: 3, cost: [2, 3, 4], effect: '出撃時の初期情報 +10 / Lv' },
    { key: 'tech', name: '開発ラボ', icon: '🧬', max: 3, cost: [2, 3, 4], effect: '出撃時の初期技術 +5 / Lv' },
    { key: 'crit', name: '精密解析', icon: '🎯', max: 3, cost: [3, 4, 5], effect: '会心率 +5% / Lv' },
    { key: 'stealth', name: '低ノイズ実装', icon: '🥷', max: 3, cost: [3, 4, 5], effect: '潜伏の上限 +5 / Lv（見つかりにくく）' },
    { key: 'scan', name: '自動偵察ツール', icon: '🔎', max: 2, cost: [3, 5], effect: '脆弱性スキャンの情報コスト -2 / Lv' },
  ];
  let portBuffs = loadJSON('malcore.port', {});
  // 入手済み技カード（初期は基本3枚。勝利で増える＝収集ループ）
  let unlockedCards = loadJSON('malcore.cards', ['sqli', 'slowloris', 'csrf']);
  function isUnlocked(id) { return unlockedCards.indexOf(id) >= 0; }
  // 解放済みステージ数（初期1。勝利で次が解放）
  let unlockedStages = loadJSON('malcore.unlocked', 1);

  // ===== マルウェア収集（初期は4体のみ。新規開発 or 低確率ドロップで増える） =====
  const INITIAL_MAL = ['zeus', 'iloveyou', 'mydoom', 'blaster'];
  let unlockedMal = loadJSON('malcore.malunlocked', INITIAL_MAL.slice());
  function malUnlocked(id) { return unlockedMal.indexOf(id) >= 0; }
  function devCost(m) { return 8 + (m.gen || 0) * 4; } // 新規開発のビットコインコスト（gen0=8 / gen1=12）
  function btcEvoCost(level) { return level <= 0 ? 5 : 8; } // 改良（世代進化）のビットコインコスト

  // ===== コインマイナー＆採掘ストック（攻略後にステージへ仕込まれ、数回の出撃の間だけ微量採掘） =====
  let miners = loadJSON('malcore.miners', {}); // stageId → 残り出撃回数
  let stock = Object.assign({ btc: 0, info: 0, tech: 0, res: 0 }, loadJSON('malcore.stock', {}));
  function saveStock() { saveJSON('malcore.stock', stock); }
  // 出撃1回あたりの採掘（微量）。深いステージほど少し多い。
  function minerYield(stageId) {
    const idx = STAGES.findIndex(s => s.id === stageId);
    const t = 1 + Math.max(0, idx) * 0.15;
    return { btc: Math.round(2 * t), info: Math.round(5 * t), tech: Math.round(3 * t), res: Math.round(4 * t) };
  }
  // 出撃のたびに全マイナーが採掘→ストックへ。残り0で駆除。レポートを返す。
  function tickMiners() {
    const rep = { btc: 0, info: 0, tech: 0, res: 0, sites: 0, cleaned: [] };
    Object.keys(miners).forEach(sid => {
      if (miners[sid] <= 0) { delete miners[sid]; return; }
      const y = minerYield(sid);
      stock.btc += y.btc; stock.info += y.info; stock.tech += y.tech; stock.res += y.res;
      rep.btc += y.btc; rep.info += y.info; rep.tech += y.tech; rep.res += y.res; rep.sites++;
      miners[sid]--;
      if (miners[sid] <= 0) { delete miners[sid]; rep.cleaned.push(sid); }
    });
    saveJSON('malcore.miners', miners); saveStock();
    return rep;
  }
  function plantMiner(stageId) { miners[stageId] = 3 + Math.floor(_rng() * 6); saveJSON('malcore.miners', miners); } // 3..8回
  function minerCount() { return Object.keys(miners).filter(k => miners[k] > 0).length; }

  let ROSTER = unlockedMal.slice(); // 編成候補＝解放済みマルウェア
  function refreshRoster() { ROSTER = unlockedMal.slice(); }

  function renderStageSelect() {
    const html = STAGES.map((s, i) => {
      const open = i < unlockedStages;
      const cleared = i < unlockedStages - 1;
      const thick = ['C', 'I', 'A'].filter(k => (s.nodes.db.baseDef[k] || 0) >= 0.15)
        .map(k => ({ C: '🔵', I: '🟢', A: '🟡' }[k])).join('') || '—';
      return '<button class="stage-card ' + (open ? '' : 'locked') + '" ' + (open ? 'data-stage="' + i + '"' : 'disabled') + '>' +
        '<div class="st-top"><b>' + (open ? '' : '🔒 ') + (i + 1) + '. ' + s.name + '</b>' +
        '<span class="st-gen">世代' + s.gen + ' / ' + s.turnLimit + 'T</span></div>' +
        (open
          ? '<div class="st-meta">本命CIA ' + s.nodes.db.C + '/' + s.nodes.db.I + '/' + s.nodes.db.A +
            ' ・ 厚い ' + thick + (s.edr ? ' ・ EDR' : '') + ' ・ 対策' + s.defenses.length + '</div>' +
            '<div class="st-intro">' + s.intro + '</div>' +
            (cleared ? '<div class="st-clear">✓ 攻略済</div>' : '')
          : '<div class="st-meta">前のステージを攻略すると解放</div>') +
        '</button>';
    }).join('');
    $('stage-body').innerHTML = '<div class="stages">' + html + '</div>';
    $('stage-body').querySelectorAll('.stage-card:not(.locked)').forEach(b =>
      b.addEventListener('click', () => {
        Sound.unlock(); Sound.play('select');
        selectedStage = parseInt(b.dataset.stage, 10);
        renderBriefing(); show('briefing-screen');
      }));
  }
  function loadJSON(key, def) {
    try { const v = localStorage.getItem(key); return v == null ? def : JSON.parse(v); } catch (e) { return def; }
  }
  function saveJSON(key, val) { try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) {} }

  function startGame() {
    const rep = tickMiners(); // 出撃のたびに既設マイナーが採掘
    G = createGame(STAGES[selectedStage], equipped, levels, party, portBuffs);
    // 採掘した情報/技術/資源は今回の出撃に注ぎ込む（ビットコインはストックに残る＝開発資金）
    if (rep.sites) {
      G.res.info += stock.info; G.res.tech += stock.tech; G.res.res += stock.res;
      G.log.push('⛏️ コインマイナー' + rep.sites + '拠点が採掘: ₿+' + rep.btc +
        ' 情報+' + stock.info + ' 技術+' + stock.tech + ' 資源+' + stock.res + ' を投入');
      if (rep.cleaned.length) G.log.push('🧹 ' + rep.cleaned.map(id => (STAGES.find(s => s.id === id) || {}).name).join('・') + ' のマイナーは駆除された');
      stock.info = 0; stock.tech = 0; stock.res = 0; saveStock();
    }
    actTab = null; // カテゴリタブを初期化（自動で侵入から）
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
    const cost = btcEvoCost(L);
    if (stock.btc < cost) return;
    stock.btc -= cost; levels[id] = L + 1;
    saveJSON('malcore.levels', levels); saveStock();
    Sound.play('cutin');
    renderBriefing();
  }

  function toggleParty(id) {
    const i = party.indexOf(id);
    if (i >= 0) { if (party.length > 1) party.splice(i, 1); }     // 最低1体
    else if (party.length < 3) party.push(id);                    // 最大3体
  }

  function renderBriefing() {
    const stage = STAGES[selectedStage];
    $('briefing-title').textContent = '作戦: ' + stage.name;
    // 1体分のカードHTML
    const malCard = (id) => {
      const m = malById(id);
      const L = levels[id] || 0;
      const s = MALCORE.malStats(m, L);
      const inParty = party.includes(id);
      const badge = L > 0 ? '<span class="evo-badge">' + ['', '改', '改弐'][L] + '</span>' : '';
      const maxed = L >= EVO_MAX;
      const cost = btcEvoCost(L);
      const evoBtn = '<button class="evo-btn" data-evo="' + id + '" ' + (maxed || stock.btc < cost ? 'disabled' : '') + '>' +
        (maxed ? '改良MAX' : '⬆ 改良（₿ ' + cost + '）') + '</button>';
      const partyBtn = '<button class="party-btn ' + (inParty ? 'on' : '') + '" data-party="' + id + '">' +
        (inParty ? '✅ 出撃' : '出撃する') + '</button>';
      return '<div class="card' + (inParty ? ' inparty' : '') + '"><div class="card-top">' +
        '<span class="malspr evo' + L + '">' + SPRITES.mal(id, { gen: L }) + '</span>' +
        '<span class="card-name"><b>' + m.name + badge + '</b><span>' + m.year + ' / 世代Lv' + L + '</span></span></div>' +
        '<div class="card-cia">🔵' + s.C + ' 🟢' + s.I + ' 🟡' + s.A + '</div>' +
        '<div class="card-role">' + m.role + ' / ' + m.sub + '</div>' +
        (m.waza ? '<div class="card-waza">⚡ ' + MALCORE.wazaName(m, L) + '</div>' : '') +
        partyBtn + evoBtn + '</div>';
    };
    // アーキタイプ別にグルーピング（12体以上でも役割で探せる）
    const ARCH_ORDER = ['機密特化', '完全DoT', '可用DoS', '装置破壊', '横展開', 'バフ支援', '貫通'];
    const byArch = {};
    ROSTER.forEach(id => { const a = (malById(id) || {}).archetype || 'その他'; (byArch[a] = byArch[a] || []).push(id); });
    const archKeys = ARCH_ORDER.filter(a => byArch[a]).concat(Object.keys(byArch).filter(a => ARCH_ORDER.indexOf(a) < 0));
    const handHtml = archKeys.map(a =>
      '<h3 class="arch-h">' + a + ' <small>' + byArch[a].length + '</small></h3>' +
      '<div class="cards">' + byArch[a].map(malCard).join('') + '</div>'
    ).join('');
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
    const tabs = '<div class="brieftabs">' +
      '<button class="brieftab' + (briefTab === 'party' ? ' on' : '') + '" data-brief="party">🦠 編成 ' + party.length + '/3</button>' +
      '<button class="brieftab' + (briefTab === 'equip' ? ' on' : '') + '" data-brief="equip">🃏 装備 ' + equipped.length + '/3</button></div>';
    const body = briefTab === 'equip'
      ? '<h2 class="sub">装備技カード <small id="equip-count">' + equipped.length + '/3 ・ 図鑑 ' + unlockedCards.length + '/' + CARDS.length + '</small></h2>' +
        '<div class="equips">' + equipHtml + '</div>'
      : '<h2 class="sub">編成（出撃 ' + party.length + '/3）<small>₿ ' + stock.btc + '（改良に使用）</small></h2>' +
        handHtml;
    $('briefing-body').innerHTML =
      '<p class="intro">' + stage.intro + '</p>' + tabs + body;
    $('briefing-body').querySelectorAll('.brieftab').forEach(b =>
      b.addEventListener('click', () => { Sound.unlock(); Sound.play('select'); briefTab = b.dataset.brief; renderBriefing(); }));
    $('briefing-body').querySelectorAll('.party-btn').forEach(b =>
      b.addEventListener('click', () => { Sound.unlock(); Sound.play('select'); toggleParty(b.dataset.party); renderBriefing(); }));
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

  // 図鑑（マルウェア／攻撃カード。タブ＋ゲージ/所持フィルタで50+件でも探せる）
  function renderCodex() {
    const GB = { C: '🔵', I: '🟢', A: '🟡' };
    const tabRow = '<div class="brieftabs">' +
      '<button class="brieftab' + (codexTab === 'mal' ? ' on' : '') + '" data-cxtab="mal">🦠 マルウェア ' + MAL.length + '</button>' +
      '<button class="brieftab' + (codexTab === 'card' ? ' on' : '') + '" data-cxtab="card">🃏 攻撃カード ' + CARDS.length + '</button></div>';
    const gChip = (g, lbl) => '<button class="cxchip' + (codexGauge === g ? ' on' : '') + '" data-cxg="' + g + '">' + lbl + '</button>';
    let filterRow = '<div class="cxfilter">' + gChip('all', 'すべて') + gChip('C', '🔵C') + gChip('I', '🟢I') + gChip('A', '🟡A');
    if (codexTab === 'card') filterRow += '<button class="cxchip owned' + (codexOwned ? ' on' : '') + '" data-cxowned="1">✓ 所持のみ</button>';
    filterRow += '</div>';

    let entries;
    if (codexTab === 'mal') {
      const list = MAL.filter(m => codexGauge === 'all' || (m.waza && m.waza.gauge === codexGauge));
      entries = list.map(m => {
        const s = MALCORE.malStats(m, 0);
        const own = malUnlocked(m.id);
        return '<div class="cxentry mal' + (own ? '' : ' locked') + '"><div class="cx-top">' +
          '<span class="cx-spr">' + SPRITES.mal(m.id, { gen: 0 }) + '</span>' +
          '<span class="cx-name"><b>' + m.name + '</b><span class="cx-meta">' +
          (own ? '<span class="cc-own">✓開発済</span>' : '<span class="cc-lock">🔒未開発</span>') + ' 世代' + m.gen + ' / ' + m.year + '</span></span>' +
          '<span class="cx-arch">' + (m.archetype || '') + '</span></div>' +
          '<div class="cx-cia">🔵' + s.C + ' 🟢' + s.I + ' 🟡' + s.A + '</div>' +
          (m.waza ? '<div class="cx-waza">⚡ ' + m.waza.name.replace(/！+$/, '') + '</div>' : '') +
          '<div class="cc-desc">' + m.desc + '</div>' +
          (m.waza && m.waza.defense ? '<div class="cc-def">🛡️ ' + m.waza.defense + '</div>' : '') + '</div>';
      }).join('');
    } else {
      let list = CARDS.filter(c => codexGauge === 'all' || c.gauge === codexGauge);
      if (codexOwned) list = list.filter(c => isUnlocked(c.id));
      entries = list.map(c =>
        '<div class="cxentry card"><div class="cx-top">' +
        '<span class="cx-spr">' + (c.icon && SPRITES.card(c.icon) ? SPRITES.card(c.icon) : GB[c.gauge] || '⚡') + '</span>' +
        '<span class="cx-name"><b>' + c.name + '</b><span class="cx-meta">' +
        (isUnlocked(c.id) ? '<span class="cc-own">✓所持</span>' : '<span class="cc-lock">🔒未入手</span>') + ' 世代' + c.gen + '</span></span></div>' +
        '<div class="cx-cia">' + gaugeMark(c) + '</div>' +
        '<div class="cx-en">' + c.en + ' ・ ' + c.tactic + '</div>' +
        '<div class="cc-desc">' + c.desc + '</div>' +
        '<div class="cc-def">🛡️ ' + c.defense + '</div></div>'
      ).join('');
    }
    $('codex-body').innerHTML = tabRow + filterRow +
      (entries ? '<div class="cxgrid">' + entries + '</div>' : '<p class="intro">該当なし</p>');
    $('codex-body').querySelectorAll('.brieftab').forEach(b =>
      b.addEventListener('click', () => { Sound.unlock(); Sound.play('select'); codexTab = b.dataset.cxtab; renderCodex(); }));
    $('codex-body').querySelectorAll('.cxchip[data-cxg]').forEach(b =>
      b.addEventListener('click', () => { Sound.play('select'); codexGauge = b.dataset.cxg; renderCodex(); }));
    const ob = $('codex-body').querySelector('.cxchip[data-cxowned]');
    if (ob) ob.addEventListener('click', () => { Sound.play('select'); codexOwned = !codexOwned; renderCodex(); });
  }

  // 母港ハブ: マルウェアが屯するサークル風シーン＋進捗＋母港バフ
  function showHubInfo(id) {
    const pop = $('hub-pop'); if (!pop) return;
    const m = malById(id); const L = levels[id] || 0; const s = MALCORE.malStats(m, L);
    const inParty = party.includes(id);
    pop.innerHTML = '<div class="hub-pop-card"><div class="hub-pop-top">' +
      '<span class="hub-pop-spr">' + SPRITES.mal(id, { gen: L }) + '</span>' +
      '<span class="hub-pop-name"><b>' + m.name + (['', '改', '改弐'][L] || '') + '</b>' +
      '<small>' + (m.archetype || '') + ' ・ 世代' + m.gen + '</small></span>' +
      '<button class="hub-pop-toggle' + (inParty ? ' on' : '') + '" data-toggle="' + id + '">' +
      (inParty ? '✅ 出撃中' : '➕ 出撃に加える') + '</button></div>' +
      '<div class="hub-pop-cia">🔵' + s.C + ' 🟢' + s.I + ' 🟡' + s.A + '</div>' +
      (m.waza ? '<div class="hub-pop-waza">⚡ ' + m.waza.name.replace(/！+$/, '') + '</div>' : '') +
      '<div class="cc-desc">' + m.desc + '</div></div>';
    const tg = pop.querySelector('.hub-pop-toggle');
    if (tg) tg.addEventListener('click', () => { Sound.unlock(); Sound.play('select'); toggleParty(id); renderHome(); showHubInfo(id); });
  }
  // 表情差分（母港でころころ変わる／タップで反応）
  const HUB_EXPR = ['happy', 'surprised', 'angry'];
  let hubIdleTimer = null;
  function setHubExpr(el, expr, ms) {
    if (!el || !el.isConnected) return;
    const id = el.dataset.hubmal; if (!id) return;
    const L = levels[id] || 0;
    const spr = el.querySelector('.hub-spr'); if (!spr) return;
    spr.innerHTML = SPRITES.mal(id, { gen: L, expr: expr });
    el.classList.add('reacting');
    clearTimeout(el._exprT);
    el._exprT = setTimeout(() => {
      if (!el.isConnected) return;
      spr.innerHTML = SPRITES.mal(id, { gen: L });
      el.classList.remove('reacting');
    }, ms || 1000);
  }
  function startHubIdle() {
    stopHubIdle();
    hubIdleTimer = setInterval(() => {
      const home = $('home-screen');
      if (!home || !home.classList.contains('active')) return;
      const els = home.querySelectorAll('.hub-mal');
      if (!els.length) return;
      setHubExpr(els[Math.floor(Math.random() * els.length)], HUB_EXPR[Math.floor(Math.random() * HUB_EXPR.length)], 1100);
    }, 1500);
  }
  function stopHubIdle() { if (hubIdleTimer) { clearInterval(hubIdleTimer); hubIdleTimer = null; } }

  function renderHome() {
    // マルウェアを母港に散りばめる（屯している雰囲気。出撃メンバーは大きく前面に）
    const scene = ROSTER.map((id, i) => {
      const m = malById(id); const L = levels[id] || 0;
      const inParty = party.includes(id);
      const col = i % 4, row = Math.floor(i / 4);
      let left = 12 + col * 25 + (i % 2 ? 4 : -3);
      let top = 16 + row * 27 + (((i % 3) - 1) * 5);
      left = Math.max(6, Math.min(88, left)); top = Math.max(8, Math.min(82, top));
      const delay = ((i % 5) * 0.4).toFixed(1);
      return '<button class="hub-mal' + (inParty ? ' party' : '') + '" data-hubmal="' + id + '" ' +
        'style="left:' + left + '%;top:' + top + '%;animation-delay:' + delay + 's">' +
        '<span class="hub-spr">' + SPRITES.mal(id, { gen: L }) + '</span>' +
        (inParty ? '<span class="hub-badge">出撃</span>' : '') +
        '<span class="hub-name">' + m.name + '</span></button>';
    }).join('');
    const owned = PORT_BUFFS.filter(b => (portBuffs[b.key] || 0) > 0);
    const buffLine = owned.length ? owned.map(b => b.icon + b.name + ' Lv' + portBuffs[b.key]).join(' ／ ') : 'なし（開発で強化）';
    // コインマイナー採掘中の演出: 各所から粒子が奥のサーバへ吸い出される
    const mining = minerCount();
    let siphon = '';
    if (mining > 0) {
      const glyphs = ['₿', '📡', '⚙️', '🧬'];
      for (let k = 0; k < Math.min(8, mining * 3); k++) {
        const sx = 12 + (k * 29) % 76, gl = glyphs[k % glyphs.length], dl = (k * 0.5).toFixed(1);
        siphon += '<span class="siphon" style="left:' + sx + '%;animation-delay:' + dl + 's">' + gl + '</span>';
      }
    }
    $('home-body').innerHTML =
      '<div class="hub-scene' + (mining ? ' mining' : '') + '">' + SPRITES.hubBg() + siphon + scene + '</div>' +
      '<p class="hub-hint">タップでマルウェアの詳細・出撃メンバーの入替。出撃 ' + party.length + '/3' +
      (mining ? ' ／ ⛏️ 採掘中 ' + mining + '拠点' : '') + '</p>' +
      '<div id="hub-pop"></div>' +
      '<div class="home-card">' +
      '<p class="home-meta">₿ <b>' + stock.btc + '</b>（改良・開発に使用） ／ 🛠️ 開発P <b>' + devP + '</b> ／ 🦠 母港 ' + unlockedMal.length + '/' + MAL.length + '</p>' +
      '<p class="home-meta">🗺️ 解放ステージ ' + unlockedStages + '/' + STAGES.length + ' ／ 📖 図鑑 ' + unlockedCards.length + '/' + CARDS.length +
      ' ／ ⛏️ 採掘拠点 ' + mining + '</p>' +
      '<p class="home-meta">🏅 母港バフ: ' + buffLine + '</p></div>' +
      '<button id="home-sortie" class="big-btn">⚔️ 出撃（ステージ選択）</button>';
    $('home-body').querySelectorAll('.hub-mal').forEach(b =>
      b.addEventListener('click', () => {
        Sound.unlock(); Sound.play('select');
        setHubExpr(b, HUB_EXPR[Math.floor(Math.random() * HUB_EXPR.length)], 950); // タップで驚き/喜び/怒り
        showHubInfo(b.dataset.hubmal);
      }));
    const hs = $('home-sortie');
    if (hs) hs.addEventListener('click', () => { Sound.unlock(); Sound.play('select'); renderStageSelect(); show('stage-screen'); });
    startHubIdle(); // 表情がころころ変わる
  }

  // 開発: 母港バフの購入（開発Pの使い道＝メタ進行）
  function buyBuff(key) {
    const b = PORT_BUFFS.find(x => x.key === key); if (!b) return;
    const lv = portBuffs[key] || 0; if (lv >= b.max) return;
    const cost = b.cost[lv]; if (devP < cost) return;
    devP -= cost; portBuffs[key] = lv + 1;
    saveJSON('malcore.port', portBuffs); saveJSON('malcore.devP', devP);
    Sound.play('cutin'); renderDevelop();
  }
  // 新規開発: ビットコインで未開発マルウェアを仲間に
  function buyDevelop(id) {
    if (malUnlocked(id)) return;
    const m = malById(id); if (!m) return;
    const cost = devCost(m); if (stock.btc < cost) return;
    stock.btc -= cost; unlockedMal.push(id);
    saveJSON('malcore.malunlocked', unlockedMal); saveStock(); refreshRoster();
    Sound.play('cutin'); renderDevelop();
  }
  function renderDevelop() {
    const buffRows = PORT_BUFFS.map(b => {
      const lv = portBuffs[b.key] || 0, maxed = lv >= b.max, cost = maxed ? 0 : b.cost[lv];
      const pips = Array.from({ length: b.max }, (_, i) => '<span class="pip' + (i < lv ? ' on' : '') + '"></span>').join('');
      return '<div class="dev-row"><div class="dev-info"><b>' + b.icon + ' ' + b.name + '</b>' +
        '<small>' + b.effect + '</small><span class="dev-pips">' + pips + '</span></div>' +
        '<button class="dev-buy" data-buff="' + b.key + '" ' + (maxed || devP < cost ? 'disabled' : '') + '>' +
        (maxed ? 'MAX' : '⬆ 開発P ' + cost) + '</button></div>';
    }).join('');
    const locked = MAL.filter(m => !malUnlocked(m.id));
    const malRows = locked.length ? locked.map(m => {
      const cost = devCost(m), s = MALCORE.malStats(m, 0);
      return '<div class="dev-row"><span class="dev-mal-spr">' + SPRITES.mal(m.id, { gen: 0 }) + '</span>' +
        '<div class="dev-info"><b>' + m.name + '</b>' +
        '<small>' + (m.archetype || '') + '・世代' + m.gen + '・🔵' + s.C + ' 🟢' + s.I + ' 🟡' + s.A + '</small></div>' +
        '<button class="dev-mal-buy" data-devmal="' + m.id + '" ' + (stock.btc < cost ? 'disabled' : '') + '>⬆ ₿ ' + cost + '</button></div>';
    }).join('') : '<p class="home-meta">全マルウェア開発済み（' + MAL.length + '/' + MAL.length + '）</p>';
    $('develop-body').innerHTML =
      '<p class="home-meta">₿ ビットコイン <b>' + stock.btc + '</b>（コインマイナーで採掘） ／ 🛠️ 開発P <b>' + devP + '</b></p>' +
      '<h2 class="sub">🦠 マルウェア新規開発 <small>₿ 消費 ・ 母港 ' + unlockedMal.length + '/' + MAL.length + '</small></h2>' +
      '<div class="dev-list">' + malRows + '</div>' +
      '<h2 class="sub">🏅 母港バフ <small>開発P 消費・出撃時に発揮</small></h2>' +
      '<div class="dev-list">' + buffRows + '</div>';
    $('develop-body').querySelectorAll('.dev-buy').forEach(b =>
      b.addEventListener('click', () => { Sound.unlock(); buyBuff(b.dataset.buff); }));
    $('develop-body').querySelectorAll('.dev-mal-buy').forEach(b =>
      b.addEventListener('click', () => { Sound.unlock(); buyDevelop(b.dataset.devmal); }));
  }

  function initUI() {
    // click だけでなく touchend も拾う（スマホでの取りこぼし防止）
    const tap = (id, fn) => {
      const el = $(id); if (!el) return;
      const h = (e) => { e.preventDefault(); Sound.unlock(); fn(); };
      el.addEventListener('click', h);
    };
    // タイトル → 母港ハブ（以降は下部タブバーで移動）
    tap('btn-start', () => { Sound.play('select'); renderHome(); show('home-screen'); });
    tap('btn-brief-back', () => { renderStageSelect(); show('stage-screen'); });
    tap('btn-codex', () => { Sound.play('select'); renderCodex(); show('codex-screen'); });
    tap('btn-sortie', () => { Sound.play('select'); startGame(); });
    tap('btn-retry', () => { Sound.play('select'); Sound.stopBgm(); renderBriefing(); show('briefing-screen'); });
    tap('btn-title', () => { Sound.stopBgm(); renderHome(); show('home-screen'); });
    // 下部タブバー: 母港/図鑑/開発/出撃
    const goTab = (id) => {
      if (id === 'home-screen') renderHome();
      else if (id === 'codex-screen') renderCodex();
      else if (id === 'develop-screen') renderDevelop();
      else if (id === 'stage-screen') renderStageSelect();
      show(id);
    };
    document.querySelectorAll('.tabbar-btn').forEach(b =>
      b.addEventListener('click', (e) => { e.preventDefault(); Sound.unlock(); Sound.play('select'); goTab(b.dataset.tab); }));
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
