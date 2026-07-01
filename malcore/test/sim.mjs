/* test/sim.mjs — ヘッドレス検証
   dist/index.html の <script> を vm で実行（document 無し＝UI層は動かない）し、
   純粋ロジックの MALCORE を取り出して各シナリオを再生、バランスが破綻しないか検証する。
   使い方: node build.mjs && node test/sim.mjs */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const __dir = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(resolve(__dir, '../dist/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*)<\/script>/)[1];

const sandbox = {};
vm.createContext(sandbox);            // document/window を渡さない → UI層はスキップ
new vm.Script(script).runInContext(sandbox);
const M = sandbox.MALCORE;
if (!M) throw new Error('MALCORE が見つからない（連結/エクスポートを確認）');

let fails = 0;
const assert = (cond, msg) => { if (!cond) { console.error('  ✗ ' + msg); fails++; } else { console.log('  ✓ ' + msg); } };
const newGame = (eq, lv, party) => { M.setRng(() => 0.99); return M.createGame(M.STAGE, eq, lv, party); }; // 会心なし=最悪ケース
const playAll = (g, acts) => acts.forEach(a => { if (!g.result) M.applyAction(g, a); });
const tot = (g) => Math.round(g.db.C + g.db.I + g.db.A);
// 対策idがゲート(FW/WAF)か
const isGate = (g, actId) => { const id = actId.split(':')[1]; const d = (g.stage.defenses || []).find(x => x.id === id); return !!(d && d.gate); };
// 本命まで到達（区間ゲートは回避で突破。監視系は触らない）
function toBoss(g) {
  M.applyAction(g, 'breach');
  for (let k = 0; k < 24 && !M.reachedBoss(g) && !g.result; k++) {
    const acts = M.listActions(g);
    const piv = acts.find(a => a.id === 'pivot' && a.enabled);
    if (piv) { M.applyAction(g, 'pivot'); continue; }
    // ゲート(NW機器): 脆弱性スキャン→エクスプロイト。無ければ貫通で強行。
    const ex = acts.find(a => a.id.startsWith('exploit:') && a.enabled);
    if (ex) { M.applyAction(g, ex.id); continue; }
    const sc = acts.find(a => a.id.startsWith('scan:') && a.enabled);
    if (sc) { M.applyAction(g, sc.id); continue; }
    const pen = acts.find(a => a.id.startsWith('penetrate:') && a.enabled);
    if (pen) { M.applyAction(g, pen.id); continue; }
    break;
  }
  return g;
}
// 監視系(非ゲート)対策を全部回避
function evadeMonitors(g) {
  M.listActions(g).filter(a => a.id.startsWith('evade:') && a.enabled && !isGate(g, a.id)).forEach(a => { if (!g.result) M.applyAction(g, a.id); });
}
// 撃破を決着まで繰り返す
function strikeUntilEnd(g, id, max) { for (let i = 0; i < (max || 6) && !g.result; i++) { const a = M.listActions(g).find(x => x.id === 'strike:' + id); if (!a || !a.enabled) break; M.applyAction(g, 'strike:' + id); } }

// 1) 王道ルート（侵害→各層を横展開→対策を剥がす→撃破）で勝てる
console.log('シナリオ1: 王道ルート（多段を抜けて撃破）');
const g1 = newGame();
toBoss(g1); evadeMonitors(g1); strikeUntilEnd(g1, 'zeus', 5);
console.log('  結果', g1.result, '/ T' + g1.turn + ' / 警戒' + g1.warning + ' / 残CIA合計' + tot(g1) +
            '（閾値' + Math.round(g1.db.initTotal * g1.stage.win.ratio) + '）');
assert(g1.result === 'win', '会心なしでも王道ルートで勝利できる（バランス成立）');

// 2) 撃破は本命到達前は選べない／ゲート(NW機器)は脆弱性攻略が必要（横展開連打ではない）
console.log('シナリオ2: 経路ゲート（脆弱性攻略）');
const g2 = newGame();
assert(!(M.listActions(g2).find(a => a.id === 'strike:zeus') || {}).enabled, '本命未到達では撃破が無効');
M.applyAction(g2, 'breach');
const g2acts = M.listActions(g2);
assert(!g2acts.some(a => a.id === 'pivot' && a.enabled), 'ゲート区間ではラテラルムーブメント連打はできない');
assert(g2acts.some(a => a.id.startsWith('scan:') && a.enabled), 'ゲート手前で脆弱性スキャンが選べる');
assert(g2acts.some(a => a.id.startsWith('penetrate:') && a.enabled), 'ゲート手前で貫通攻撃(強行)が選べる');
assert(!M.reachedBoss(g2), 'ゲートを抜くまで本命に到達しない');
// スキャンすると発見した脆弱性のエクスプロイトが出現する
M.applyAction(g2, M.listActions(g2).find(a => a.id.startsWith('scan:')).id);
assert(M.listActions(g2).some(a => a.id.startsWith('exploit:') && a.enabled), 'スキャンで脆弱性を発見するとエクスプロイトが出る');

// 3) 厚いゲージに合わない武器（Blasterは🔵が弱い）だと制限ターン内に落とせず敗北
console.log('シナリオ3: 武器選択ミス（Blasterで機密性厚の本命）');
const g3 = newGame();
toBoss(g3); evadeMonitors(g3); strikeUntilEnd(g3, 'blaster', 6);
console.log('  結果', g3.result, '/ T' + g3.turn + ' / 残CIA合計' + tot(g3));
assert(g3.result && g3.result !== 'win', '相性の悪い編成は制限ターン内に攻略できず敗北');

// 4) 貫通(強行突破)は警戒度が跳ね、本命防御を下げつつ侵攻する
console.log('シナリオ4: 貫通突破の警戒度＆装置破壊デバフ');
const g4 = newGame();
M.applyAction(g4, 'breach');
const pen4 = M.listActions(g4).find(a => a.id.startsWith('penetrate:') && a.enabled);
const wBefore = g4.warning;
const defBefore = M.gaugeDefRaw(g4, 'C');
const nextNode = g4.stage.defenses.find(d => d.id === pen4.id.slice(10)).between[1];
M.applyAction(g4, pen4.id);
assert(g4.warning - wBefore >= 15, '貫通攻撃で警戒度が大きく上昇（+15）');
assert(g4.footholds[nextNode], '貫通でゲートの先へ侵攻できる');
assert(M.gaugeDefRaw(g4, 'C') < defBefore, '貫通の装置破壊デバフで本命防御力が下がる');

// 5) 撃破で技名カットイン（banner）が立つ／全マルウェアが固有技を持つ
console.log('シナリオ5: 技名カットイン');
const g5 = newGame();
toBoss(g5); M.applyAction(g5, 'strike:zeus');
assert(g5.banner && g5.banner.name && g5.banner.name.indexOf('マン・イン・ザ・ブラウザ') === 0,
       '撃破時に固有技名のカットインが立つ（Zeus=マン・イン・ザ・ブラウザ）');
assert(sandbox.MAL.every(m => m.waza && m.waza.name && m.waza.en && m.waza.defense),
       '全マルウェアが固有技（技名・英名・対策）を持つ');

// 6) 図鑑データが整っている
console.log('シナリオ6: カード図鑑データ');
const cards = sandbox.CARDS || M.CARDS;
assert(cards.length >= 10, 'カードが10枚以上ある（' + cards.length + '枚）');
assert(cards.every(c => c.name && c.en && c.type && c.tactic !== undefined && c.defense && c.cia && c.cost),
       '全カードが技名・英名・型・戦術・対策・配分・コストを持つ');

// 7) 装備技カードで撃破でき、資源不足ならゲートされ、技名カットインが立つ
console.log('シナリオ7: 装備技カードの撃破');
const g7 = newGame(['sqli']);
toBoss(g7);
assert((M.listActions(g7).find(a => a.id === 'card:sqli') || {}).enabled, '装備したSQLiが本命到達後に撃てる');
g7.res.info = 5;
assert(!(M.listActions(g7).find(a => a.id === 'card:sqli') || {}).enabled, '資源不足ならカードはゲートされる');
g7.res.info = 40;
M.applyAction(g7, 'card:sqli');
assert(g7.banner && g7.banner.name.indexOf('SQL・インジェクション') === 0, '撃破時にカードの技名カットインが立つ');

// 8) ゼロデイはハードニング無視で機密性を強く貫通
console.log('シナリオ8: ゼロデイ貫通');
const gz = newGame(['zeroday']);
toBoss(gz);
const cBeforeZ = gz.db.C;
gz.res.info = 99; gz.res.tech = 99;
M.applyAction(gz, 'card:zeroday');
const zDmg = cBeforeZ - gz.db.C;
// ハードニング無視で、同条件の通常攻撃(約41)より明確に大きい
assert(zDmg > 48, 'ゼロデイはハードニング無視で機密性を強く貫通（' + Math.round(zDmg) + '）');

// 9) スプライト
console.log('シナリオ9: スプライト');
const SP = sandbox.SPRITES;
assert(SP && ['zeus', 'iloveyou', 'mydoom', 'blaster'].every(id => /^<svg/.test(SP.mal(id))), '全マルウェアにキャラSVGがある');
assert(['outside', 'pc', 'db', 'fw'].every(k => /^<svg/.test(SP.node(k))), '全ノードにSVGがある');

// 10) キャラ差分
console.log('シナリオ10: キャラ差分');
assert(SP.mal('zeus', { expr: 'attack' }) !== SP.mal('zeus', { expr: 'normal' }), '攻撃表情は通常と差分がある');
assert(SP.node('db', { state: 'crit' }) !== SP.node('db', { state: 'ok' }), '本命DBの瀕死顔は平常と差分がある');
assert(SP.mal('zeus', { gen: 2 }) !== SP.mal('zeus', { gen: 0 }), '世代進化で見た目が変わる');

// 11) 世代進化: ステータスと技名が強化される
console.log('シナリオ11: 世代進化');
const zeus = sandbox.MAL.find(m => m.id === 'zeus');
assert(M.malStats(zeus, 2).C === Math.round(zeus.C * 1.5), '改弐(Lv2)で機密性攻撃が1.5倍');
assert(/改弐/.test(M.wazaName(zeus, 2)), '改弐の技名に「改弐」が付く');
const base = newGame([], { zeus: 0 }), evo = newGame([], { zeus: 2 });
toBoss(base); toBoss(evo);
const cBase = base.db.C, cEvo = evo.db.C;
M.applyAction(base, 'strike:zeus'); M.applyAction(evo, 'strike:zeus');
assert((cEvo - evo.db.C) > (cBase - base.db.C) + 5, '改弐Zeusは素のZeusより本命を多く削る');

// 12) 被弾: 高発覚度でブルーが介入し counter フラグが立つ
console.log('シナリオ12: 被弾リアクション');
assert(SP.mal('zeus', { expr: 'hurt' }) !== SP.mal('zeus', { expr: 'normal' }), '被弾(hurt)表情は通常と差分がある');
const gco = newGame();
toBoss(gco);
gco.warning = 90; // 危険域＝ブルーが頻繁に介入
M.applyAction(gco, 'strike:zeus');
assert(gco.counter && gco.counter.kind === 'audit', '高発覚度ではブルーチームが介入する(被弾)');

// 13) BGM API（ヘッドレスでは no-op で例外なし）
console.log('シナリオ13: BGM API');
assert(sandbox.Sound && typeof sandbox.Sound.bgm === 'function' && typeof sandbox.Sound.stopBgm === 'function', 'Sound.bgm/stopBgm が公開されている');
let threw = false; try { sandbox.Sound.bgm(); sandbox.Sound.stopBgm(); } catch (e) { threw = true; }
assert(!threw, 'ヘッドレスでBGM呼び出しが例外を投げない(no-op)');

// 14) 防御力モデル: 対策を剥がすと防御力が低下し、本体防御のみ残る
console.log('シナリオ14: 防御力（本体+対策）');
const gd = newGame();
toBoss(gd); // DLPはまだ有効
const cMitBefore = M.gaugeMit(gd, 'C');
M.applyAction(gd, 'evade:dlp');
const cMitAfter = M.gaugeMit(gd, 'C');
assert(cMitAfter < cMitBefore - 0.1, '対策(DLP)を回避すると機密性の防御力が一気に低下（' +
       Math.round(cMitBefore * 100) + '%→' + Math.round(cMitAfter * 100) + '%）');
assert(Math.abs(M.gaugeDefRaw(gd, 'C') - (M.STAGE.nodes.db.baseDef.C)) < 1e-9, '全対策を剥がすと本体防御のみ残る');

// 15) 検知モデル: ゲージ別ノイズ＋世代/対策依存
console.log('シナリオ15: 検知モデル');
const ge = newGame();
toBoss(ge); // DLP(C監視)はまだ有効
const wC = M.strikeWarn(ge, 'C', 0), wA = M.strikeWarn(ge, 'A', 0);
assert(wA > wC, '可用性(🟡)攻撃は機密性(🔵)攻撃より検知されやすい（' + wC + ' vs ' + wA + '）');
assert(M.strikeWarn(ge, 'C', 2) > M.strikeWarn(ge, 'C', 0), '世代が進むと検知されやすくなる（EDR/振る舞い）');
const wCdlpOn = M.strikeWarn(ge, 'C', 0);
M.applyAction(ge, 'evade:dlp');
assert(M.strikeWarn(ge, 'C', 0) < wCdlpOn, '監視対策(DLP)を回避すると機密性攻撃が検知されにくくなる（対策次第）');

// 16) イカタコ上書きカードとキャラ
console.log('シナリオ16: イカタコ上書き');
const ika = (sandbox.CARDS || M.CARDS).find(c => c.id === 'ikatako');
assert(ika && ika.gauge === 'I' && ika.cia.I >= 60, 'イカタコ上書きは完全性破壊カード');
assert(/^<svg/.test(SP.card('ikatako')), 'イカタコのキャラSVGがある');

// 17) 開幕の防御カットイン（対策が多いほど項目が多い＝手強い印象）
console.log('シナリオ17: 防御カットイン');
const gi = newGame();
const intro0 = M.defenseIntro(gi);
assert(intro0.length >= 3, '開幕でFW/DLP/ハードニング等の防御が複数提示される（' + intro0.length + '件）');
assert(intro0.some(x => /プロキシ|DLP/.test(x.name)) && intro0.some(x => /ハードニング/.test(x.name)),
       'プロキシ/DLP と ハードニング が含まれる');
toBoss(gi); evadeMonitors(gi);
assert(M.defenseIntro(gi).length < intro0.length, '対策を剥がすと提示される防御カットインが減る');

// 18) 移動/偵察系に技名（軽量フラッシュ）が付く＝撃破の全画面カットインと別系統
console.log('シナリオ18: 移動/偵察の技名フラッシュ');
const gf = newGame();
M.applyAction(gf, 'recon');
assert(gf.flash && /ポートスキャニング/.test(gf.flash.name) && !gf.banner, '偵察=ポートスキャニング(軽量flash・bannerではない)');
M.applyAction(gf, 'breach');
assert(gf.flash && /スピアフィッシング/.test(gf.flash.name), '初期侵害=スピアフィッシング');
M.applyAction(gf, M.listActions(gf).find(a => a.id.startsWith('scan:')).id);
assert(gf.flash && /脆弱性スキャン/.test(gf.flash.name), 'スキャン=脆弱性スキャン(軽量flash)');
M.applyAction(gf, M.listActions(gf).find(a => a.id.startsWith('penetrate:')).id);
assert(gf.flash && /ペネトレーション/.test(gf.flash.name), '貫通突破=ペネトレーション');
assert(M.listActions(gf).length >= 0, 'listActions が機能');
const labels = M.listActions(M.createGame(M.STAGE)).map(a => a.label).join(' ');
assert(/ポートスキャニング/.test(labels) && /スピアフィッシング/.test(labels), '行動ボタンが技名表記になっている');
// 撃破は依然として全画面カットイン(banner・スプライト付き)
M.applyAction(gf, 'strike:zeus');
assert(gf.banner && gf.banner.sprId && gf.banner.tone === 'strike', '撃破は全画面カットイン(banner+sprite)のまま');

// 19) 5ステージ: 構造が揃い、入門ステージは素直に勝てる、本命CIAがバー最大値に入る
console.log('シナリオ19: 7ステージ＋可変段数');
const STG = M.STAGES;
assert(STG.length === 7, 'ステージが7つある');
assert(STG.every(s => s.nodes.db && s.defenses.length >= 1 && s.turnLimit >= 5 && s.win && s.path.length >= 3), '全ステージに本命/対策/制限ターン/勝利条件と2段以上の経路がある');
// 段数(=outside以外のノード数): 1-3=2段(path3) / 4-7=3段(path4)。各内部ホップにゲート。
assert(STG[0].path.length === 3 && STG[2].path.length === 3, 'ステージ1-3は2段構成');
assert(STG[3].path.length === 4 && STG[5].path.length === 4, 'ステージ4-6は3段構成');
assert(STG[6].path.length === 4, 'ステージ7は3段構成');
const gm = M.createGame(STG[0]); // マチ町工業
assert(gm.db.initC === STG[0].nodes.db.C, 'バー最大値=本命CIA初期値(ステージ別)');
M.setRng(() => 0.99);
const gmw = M.createGame(STG[0], [], {}, ['zeus', 'iloveyou', 'mydoom']);
toBoss(gmw); evadeMonitors(gmw); strikeUntilEnd(gmw, 'zeus', 5);
assert(gmw.result === 'win', '入門ステージ(マチ町)は素直な編成で勝てる');

// 20) キャラ入替(編成): party に応じて hand/撃破選択肢が変わる
console.log('シナリオ20: 編成(party)');
const gp = M.createGame(M.STAGE, [], {}, ['zeus']);
assert(gp.hand.length === 1 && gp.hand[0] === 'zeus', 'partyでhandが変わる(Zeusのみ)');
toBoss(gp);
const ids = M.listActions(gp).map(a => a.id);
assert(ids.includes('strike:zeus') && !ids.includes('strike:blaster'), '編成外(Blaster)の撃破は出ない');
assert(!ids.some(x => x.startsWith('break:')), 'Blaster未編成なら装置破壊が出ない');

// 21) 反撃で発覚度(警戒度)が上がり、効果が明示される
console.log('シナリオ21: 反撃の明確化');
const gco2 = M.createGame(M.STAGE, [], {});
toBoss(gco2);
gco2.warning = 85;
const wPre = gco2.warning;
M.applyAction(gco2, 'strike:zeus'); // 高発覚度→ブルー介入
assert(gco2.counter && gco2.counter.warn >= 1 && gco2.counter.effect, '反撃に発覚度コストと効果説明がある');
assert(gco2.warning > wPre, '反撃でこちらの発覚度(警戒度)が上がる');

// 21b) 隠密: 低発覚度で潜伏ボーナス＆ブルー不動。高発覚度でブルーの介入が頻繁に
console.log('シナリオ21b: 隠密と発覚度連動のブルー活動');
assert(M.blueInterval(M.createGame(M.STAGE)) === Infinity, '潜伏中(低発覚度)はブルーが動かない');
const gHi = M.createGame(M.STAGE); gHi.warning = 90;
const gMid = M.createGame(M.STAGE); gMid.warning = 50;
assert(M.blueInterval(gHi) <= M.blueInterval(gMid), '発覚度が高いほどブルーの介入間隔が短い');
M.setRng(() => 0.99);
const gStl = M.createGame(M.STAGE); toBoss(gStl);
assert(M.isStealth(gStl), '対策を剥がして本命到達時はまだ潜伏中(奇襲ボーナス)');
const cS = gStl.db.C; M.applyAction(gStl, 'strike:zeus'); const dS = cS - gStl.db.C;
const gNo = M.createGame(M.STAGE); toBoss(gNo);
gNo.warning = 35; // 潜伏圏外(だがalert42未満なのでブルーは不動・条件をH等揃える)
const cN = gNo.db.C; M.applyAction(gNo, 'strike:zeus'); const dN = cN - gNo.db.C;
assert(dS > dN + 5, '潜伏中の撃破は非潜伏より大きい（奇襲ボーナス ' + Math.round(dS) + ' vs ' + Math.round(dN) + '）');

// 22) 経路技が編成マルウェアの進化名で表示される
console.log('シナリオ22: 経路技の編成反映');
const gpe = M.createGame(M.STAGE, [], { iloveyou: 1 }, ['zeus', 'iloveyou', 'mydoom']);
const breachLabel = M.listActions(gpe).find(a => a.id === 'breach').label;
assert(/ILOVEYOU改/.test(breachLabel), '初期侵害に侵入ロールのILOVEYOU改が反映される（' + breachLabel + '）');

// 23) コンテンツ倫理lint（商用/ストア/B2Bのゲート）: 実行可能な悪用情報を含めない＆対策必須
console.log('シナリオ23: コンテンツ倫理lint（抽象化契約）');
{
  const MALS = sandbox.MAL, CARDSL = sandbox.CARDS || M.CARDS;
  // 危険パターン: CVE番号 / IPv4 / コピペ可能なコマンド。実マルウェア名(Zeus等)は歴史的アーキタイプとして許容。
  const DANGER = [
    { re: /CVE-\d{4}-\d{3,}/i, name: '実CVE番号' },
    { re: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, name: '実IPアドレス' },
    { re: /https?:\/\/\S+/i, name: '外部URL' },
    { re: /(rm\s+-rf|curl\s+-|wget\s+http|powershell\s|cmd\.exe|\/bin\/sh|base64\s+-d|nc\s+-[a-z])/i, name: '実行可能コマンド' },
  ];
  const scan = (label, obj, fields) => {
    const text = fields.map(f => f.split('.').reduce((o, k) => (o || {})[k], obj)).filter(Boolean).join(' ／ ');
    DANGER.forEach(d => assert(!d.re.test(text), label + ' に' + d.name + 'が無い（抽象化契約）'));
  };
  // 全マルウェア: waza.defense 必須＋危険文言なし
  assert(MALS.every(m => m.waza && m.waza.defense && m.waza.defense.length > 3), '全マルウェアに対策(waza.defense)がある');
  MALS.forEach(m => scan('マルウェア「' + m.name + '」', m, ['name', 'desc', 'waza.name', 'waza.defense']));
  // 全カード: defense 必須＋危険文言なし
  assert(CARDSL.every(c => c.defense && c.defense.length > 3), '全カードに対策(defense)がある');
  CARDSL.forEach(c => scan('カード「' + c.name + '」', c, ['name', 'desc', 'defense']));
  assert(true, 'コンテンツlint完了（' + MALS.length + 'ユニット / ' + CARDSL.length + 'カード）');
}

console.log(fails === 0 ? '\n✅ すべて通過' : `\n❌ ${fails}件 失敗`);
process.exit(fails === 0 ? 0 : 1);
