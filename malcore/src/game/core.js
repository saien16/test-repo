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

/* ===== ダメージ計算（1ゲージ分） ===== */
function gaugeDamage(g, base, gauge, opt) {
  opt = opt || {};
  const H = opt.ignoreH ? 0 : effH(g); // ゼロデイ等はハードニング無視
  const V = effV(g);
  const defMul = 0.5 + H / 100;
  const mit = Math.min(0.80, (g.db.mit[gauge] || 0) * defMul);
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

  // 撃破（本命に到達後、手持ちのマルウェア固有技ごと。世代進化を反映）
  g.hand.forEach(id => {
    const m = malById(id);
    const L = (g.levels && g.levels[id]) || 0;
    const s = malStats(m, L);
    const tag = L > 0 ? EVO_SUFFIX[L].replace('・', '') + ' ' : '';
    can('strike:' + id, '⚔️ ' + tag + (m.waza ? m.waza.name.replace(/！+$/, '') : m.name), f.db, '本命未到達',
        'C' + s.C + '/I' + s.I + '/A' + s.A + ' で攻撃。 W+10');
  });
  // 装備技カード（本命到達後・資源を満たすとき）
  (g.equipped || []).forEach(id => {
    const c = cardById(id); if (!c) return;
    const ok = f.db && canAfford(g, c.cost);
    const reason = !f.db ? '本命未到達' : '資源不足(' + costLabel(c.cost) + ')';
    const cia = c.cia || {};
    can('card:' + id, '🃏 ' + c.name, ok, reason,
        'C' + (cia.C || 0) + '/I' + (cia.I || 0) + '/A' + (cia.A || 0) +
        (c.special === 'ignoreH' ? ' 貫通' : '') + ' ' + costLabel(c.cost) + ' W+8');
  });
  return A;
}

/* ===== 行動の適用 ===== */
function applyAction(g, actionId) {
  if (g.result) return { ok: false, msg: '決着済み' };
  const valid = listActions(g).find(a => a.id === actionId && a.enabled);
  if (!valid) return { ok: false, msg: 'その行動は今できない' };

  g.counter = null; // ブルー反撃（被弾）フラグ。endTurnで立つ
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
    const id = actionId.slice(7);
    const m = malById(id);
    const L = (g.levels && g.levels[id]) || 0;
    const s = malStats(m, L);
    const r = resolveStrike(g, s, { botnet: g.botnet });
    warn = 10;
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
    warn = 8;
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
        const dev = g.fwOpen
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
      const spr = a.id.startsWith('strike:')
        ? '<span class="actspr">' + SPRITES.mal(a.id.slice(7), { gen: (g.levels && g.levels[a.id.slice(7)]) || 0 }) + '</span>' : '';
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
        bar('🔵 機密性', d.C, 160, 'c') +
        bar('🟢 完全性', d.I, 100, 'i') +
        bar('🟡 可用性', d.A, 100, 'a') +
        '<div class="boss-foot">勝利: CIA合計を ' + Math.round(d.initTotal * g.stage.win.ratio) +
          ' 以下に（現在 ' + Math.round(d.C + d.I + d.A) + '）</div>' +
      '</div>' +
      '<div class="acts">' + acts + '</div>' +
      '<div class="logbox">' + g.log.slice(-6).reverse().map(l => '<div>' + l + '</div>').join('') + '</div>';

    $('battle-root').querySelectorAll('.act:not(.off)').forEach(b =>
      b.addEventListener('click', () => {
        Sound.unlock();
        const act = b.dataset.act;
        // 撃破/カード/カットインは banner 側で音が出る。移動系だけ select 音。
        if (!/^(strike:|card:|ci_)/.test(act)) Sound.play('select');
        applyAction(G, act); afterAction();
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

  function afterAction() {
    if (G.banner) { popBanner(G.banner); G.banner = null; }
    const counter = G.counter; G.counter = null;
    if (G.result) {
      Sound.stopBgm();
      Sound.play(G.result === 'win' ? 'win' : 'lose');
      return renderResult();
    }
    renderBattle();
    if (counter) setTimeout(() => popCounter(counter), 720); // 行動バナーの後に被弾演出
  }

  function renderResult() {
    show('result-screen');
    const win = G.result === 'win';
    let reward = '';
    if (win) { // 勝利で開発P獲得（次の進化資金）
      devP += 3; saveJSON('malcore.devP', devP);
      reward = '<div class="reward">🛠️ 開発P +3（所持 ' + devP + '）— ブリーフィングで世代進化に使える</div>';
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
  function loadJSON(key, def) {
    try { const v = localStorage.getItem(key); return v == null ? def : JSON.parse(v); } catch (e) { return def; }
  }
  function saveJSON(key, val) { try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) {} }

  function startGame() { G = createGame(STAGE_ZENITH, equipped, levels); Sound.bgm(); show('battle-screen'); renderBattle(); }

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
    // 装備技カードの選択（最大3）
    const equipHtml = CARDS.map(c =>
      '<button class="equip ' + (equipped.includes(c.id) ? 'on' : '') + '" data-card="' + c.id + '">' +
      '<b>🃏 ' + c.name + '</b><small>' + gaugeMark(c) + ' ' + costLabel(c.cost) +
      (c.special === 'ignoreH' ? ' / 貫通' : '') + '</small></button>'
    ).join('');
    $('briefing-body').innerHTML =
      '<p class="intro">' + STAGE_ZENITH.intro + '</p>' +
      '<h2 class="sub">編成（固有技）<small>🛠️ 開発P ' + devP + '</small></h2>' +
      '<div class="cards">' + handHtml + '</div>' +
      '<h2 class="sub">装備技カード <small id="equip-count">' + equipped.length + '/3</small></h2>' +
      '<div class="equips">' + equipHtml + '</div>';
    $('briefing-body').querySelectorAll('.equip').forEach(b =>
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
        '<div class="codex-card"><div class="cc-top"><b>⚡ ' + c.name + '</b>' +
        '<span class="cc-gen">世代' + c.gen + '</span></div>' +
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
