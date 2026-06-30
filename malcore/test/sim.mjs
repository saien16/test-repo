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
const newGame = (eq, lv) => { M.setRng(() => 0.99); return M.createGame(M.STAGE, eq, lv); }; // 会心なし=最悪ケース
const playAll = (g, acts) => acts.forEach(a => { if (!g.result) M.applyAction(g, a); });
const tot = (g) => Math.round(g.db.C + g.db.I + g.db.A);

// 1) 王道ルート（偵察→侵害→FW回避→横展開→DLP回避→撃破×3 = 8T）で勝てる
//    対策を剥がして本体防御だけにしてから抜く、が新モデルの王道。
console.log('シナリオ1: 王道ルート（対策を剥がして撃破・8T）');
const g1 = newGame();
playAll(g1, ['recon', 'breach', 'evade:fw', 'pivot', 'evade:dlp', 'strike:zeus', 'strike:zeus', 'strike:zeus']);
console.log('  結果', g1.result, '/ T' + g1.turn + ' / 警戒' + g1.warning + ' / 残CIA合計' + tot(g1) +
            '（閾値' + Math.round(g1.db.initTotal * g1.stage.win.ratio) + '）');
assert(g1.result === 'win', '会心なしでも王道ルートで勝利できる（バランス成立）');
assert(g1.warning < 100, '警戒度は上限未満（静かに通せる）');

// 2) 撃破は本命到達前は選べない／境界FWが閉なら横展開不可（経路ゲート）
console.log('シナリオ2: 経路ゲート');
const g2 = newGame();
assert(!(M.listActions(g2).find(a => a.id === 'strike:zeus') || {}).enabled, '本命未到達では撃破が無効');
M.applyAction(g2, 'breach');
assert(!(M.listActions(g2).find(a => a.id === 'pivot') || {}).enabled, '境界FW開通前は横展開が無効');
assert(!M.gateOpen(g2), '境界FWが有効な間はゲートが閉じている');

// 3) 厚いゲージに合わない武器（Blasterは🔵が弱い）だと制限ターン内に落とせず敗北
console.log('シナリオ3: 武器選択ミス（Blasterで機密性厚の本命）');
const g3 = newGame();
playAll(g3, ['recon', 'breach', 'evade:fw', 'pivot', 'strike:blaster', 'strike:blaster', 'strike:blaster', 'strike:blaster']);
console.log('  結果', g3.result, '/ T' + g3.turn + ' / 残CIA合計' + tot(g3));
assert(g3.result && g3.result !== 'win', '相性の悪い編成は制限ターン内に攻略できず敗北');

// 4) 破壊ルートは警戒度が跳ねる
console.log('シナリオ4: 破壊ルートの警戒度');
const g4 = newGame();
M.applyAction(g4, 'breach');
const wBefore = g4.warning;
M.applyAction(g4, 'break:fw');
assert(g4.warning - wBefore >= 25, '境界FW破壊で警戒度が大きく上昇（+25）');
assert(M.gateOpen(g4), '破壊でゲートが開く');

// 5) 撃破で技名カットイン（banner）が立つ／全マルウェアが固有技を持つ
console.log('シナリオ5: 技名カットイン');
const g5 = newGame();
playAll(g5, ['breach', 'evade:fw', 'pivot', 'strike:zeus']);
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
['breach', 'evade:fw', 'pivot'].forEach(a => M.applyAction(g7, a));
assert((M.listActions(g7).find(a => a.id === 'card:sqli') || {}).enabled, '装備したSQLiが本命到達後に撃てる');
g7.res.info = 5;
assert(!(M.listActions(g7).find(a => a.id === 'card:sqli') || {}).enabled, '資源不足ならカードはゲートされる');
g7.res.info = 40;
M.applyAction(g7, 'card:sqli');
assert(g7.banner && g7.banner.name.indexOf('SQL・インジェクション') === 0, '撃破時にカードの技名カットインが立つ');

// 8) ゼロデイはハードニング無視で機密性を強く貫通
console.log('シナリオ8: ゼロデイ貫通');
const gz = newGame(['zeroday']);
['breach', 'evade:fw', 'pivot'].forEach(a => M.applyAction(gz, a));
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
['breach', 'evade:fw', 'pivot'].forEach(a => { M.applyAction(base, a); M.applyAction(evo, a); });
const cBase = base.db.C, cEvo = evo.db.C;
M.applyAction(base, 'strike:zeus'); M.applyAction(evo, 'strike:zeus');
assert((cEvo - evo.db.C) > (cBase - base.db.C) + 5, '改弐Zeusは素のZeusより本命を多く削る');

// 12) 被弾: ブルー監査ターンで counter フラグが立ち、hurt表情が描ける
console.log('シナリオ12: 被弾リアクション');
assert(SP.mal('zeus', { expr: 'hurt' }) !== SP.mal('zeus', { expr: 'normal' }), '被弾(hurt)表情は通常と差分がある');
const gco = newGame();
['recon', 'breach', 'evade:fw', 'pivot'].forEach(a => M.applyAction(gco, a)); // T4=pivotでシステム監査
assert(gco.counter && gco.counter.kind === 'audit', '監査ターンにブルー反撃(被弾)フラグが立つ');

// 13) BGM API（ヘッドレスでは no-op で例外なし）
console.log('シナリオ13: BGM API');
assert(sandbox.Sound && typeof sandbox.Sound.bgm === 'function' && typeof sandbox.Sound.stopBgm === 'function', 'Sound.bgm/stopBgm が公開されている');
let threw = false; try { sandbox.Sound.bgm(); sandbox.Sound.stopBgm(); } catch (e) { threw = true; }
assert(!threw, 'ヘッドレスでBGM呼び出しが例外を投げない(no-op)');

// 14) 防御力モデル: 対策を剥がすと防御力が低下し、本体防御のみ残る
console.log('シナリオ14: 防御力（本体+対策）');
const gd = newGame();
['breach', 'evade:fw', 'pivot'].forEach(a => M.applyAction(gd, a)); // DLPはまだ有効
const cMitBefore = M.gaugeMit(gd, 'C');
M.applyAction(gd, 'evade:dlp');
const cMitAfter = M.gaugeMit(gd, 'C');
assert(cMitAfter < cMitBefore - 0.1, '対策(DLP)を回避すると機密性の防御力が一気に低下（' +
       Math.round(cMitBefore * 100) + '%→' + Math.round(cMitAfter * 100) + '%）');
assert(Math.abs(M.gaugeDefRaw(gd, 'C') - (M.STAGE.nodes.db.baseDef.C)) < 1e-9, '全対策を剥がすと本体防御のみ残る');

// 15) 検知モデル: ゲージ別ノイズ＋世代/対策依存
console.log('シナリオ15: 検知モデル');
const ge = newGame();
['breach', 'evade:fw', 'pivot'].forEach(a => M.applyAction(ge, a)); // DLP(C監視)はまだ有効
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
['breach', 'evade:fw', 'evade:dlp'].forEach(a => M.applyAction(gi, a));
assert(M.defenseIntro(gi).length < intro0.length, '対策を剥がすと提示される防御カットインが減る');

console.log(fails === 0 ? '\n✅ すべて通過' : `\n❌ ${fails}件 失敗`);
process.exit(fails === 0 ? 0 : 1);
