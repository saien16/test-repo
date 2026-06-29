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
const newGame = () => { M.setRng(() => 0.99); return M.createGame(M.STAGE); }; // 会心なし=最悪ケース
const playAll = (g, acts) => acts.forEach(a => { if (!g.result) M.applyAction(g, a); });
const tot = (g) => Math.round(g.db.C + g.db.I + g.db.A);

// 1) 王道ルート（偵察→侵害→FW回避→横展開→偵察CI→診断CI→撃破×2 = 8T）で勝てる
console.log('シナリオ1: 王道ルート（カットイン活用・8T）');
const g1 = newGame();
playAll(g1, ['recon', 'breach', 'fw_evade', 'pivot', 'ci_recon', 'ci_diag', 'strike:zeus', 'strike:zeus']);
console.log('  結果', g1.result, '/ T' + g1.turn + ' / 警戒' + g1.warning + ' / 残CIA合計' + tot(g1) +
            '（閾値' + Math.round(g1.db.initTotal * g1.stage.win.ratio) + '）');
assert(g1.result === 'win', '会心なしでも王道ルートで勝利できる（バランス成立）');
assert(g1.warning < 100, '警戒度は上限未満（静かに通せる）');

// 2) 撃破は本命到達前は選べない（経路ゲートが機能）
console.log('シナリオ2: 経路ゲート');
const g2 = newGame();
const strikeBefore = M.listActions(g2).find(a => a.id === 'strike:zeus');
assert(strikeBefore && !strikeBefore.enabled, '本命未到達では撃破が無効');
M.applyAction(g2, 'breach');
const fwBefore = M.listActions(g2).find(a => a.id === 'pivot');
assert(fwBefore && !fwBefore.enabled, '境界FW開通前は横展開が無効');

// 3) 厚いゲージに合わない武器（Blasterは🔵が弱い）だと制限ターン内に落とせず敗北
console.log('シナリオ3: 武器選択ミス（Blasterで機密性厚の本命）');
const g3 = newGame();
playAll(g3, ['recon', 'breach', 'fw_evade', 'pivot', 'strike:blaster', 'strike:blaster', 'strike:blaster', 'strike:blaster']);
console.log('  結果', g3.result, '/ T' + g3.turn + ' / 残CIA合計' + tot(g3));
assert(g3.result && g3.result !== 'win', '相性の悪い編成は制限ターン内に攻略できず敗北（タイムオーバー）');

// 4) 派手に壊しまくると警戒度で敗北しうる（破壊ルートのリスク）— 警戒度が確実に積み上がることを確認
console.log('シナリオ4: 破壊ルートの警戒度');
const g4 = newGame();
M.applyAction(g4, 'breach');
const wBefore = g4.warning;
M.applyAction(g4, 'fw_break');
assert(g4.warning - wBefore >= 25, '境界FW破壊で警戒度が大きく上昇（+25）');

// 5) 撃破で技名カットイン（banner）が立つ／全マルウェアが固有技を持つ
console.log('シナリオ5: 技名カットイン');
const g5 = newGame();
playAll(g5, ['breach', 'fw_evade', 'pivot', 'strike:zeus']);
assert(g5.banner && g5.banner.name && g5.banner.name.indexOf('マン・イン・ザ・ブラウザ') === 0,
       '撃破時に固有技名のカットインが立つ（Zeus=マン・イン・ザ・ブラウザ）');
assert(sandbox.MAL.every(m => m.waza && m.waza.name && m.waza.en && m.waza.defense),
       '全マルウェアが固有技（技名・英名・対策）を持つ');

// 6) 図鑑データが整っている（全カードが技名/英名/型/世代/対策/コストを持つ）
console.log('シナリオ6: カード図鑑データ');
const cards = sandbox.CARDS || M.CARDS;
assert(cards.length >= 10, 'カードが10枚以上ある（' + cards.length + '枚）');
assert(cards.every(c => c.name && c.en && c.type && c.tactic !== undefined && c.defense && c.cia && c.cost),
       '全カードが技名・英名・型・戦術・対策・配分・コストを持つ');

// 7) 装備技カードで撃破でき、資源不足ならゲートされ、技名カットインが立つ
console.log('シナリオ7: 装備技カードの撃破');
M.setRng(() => 0.99);
const g7 = M.createGame(M.STAGE, ['sqli']);
['breach', 'fw_evade', 'pivot'].forEach(a => M.applyAction(g7, a));
assert((M.listActions(g7).find(a => a.id === 'card:sqli') || {}).enabled,
       '装備したSQLインジェクションが本命到達後に撃てる');
g7.res.info = 5; // コスト(情報10)に満たない
assert(!(M.listActions(g7).find(a => a.id === 'card:sqli') || {}).enabled,
       '資源不足ならカードはゲートされる');
g7.res.info = 40;
M.applyAction(g7, 'card:sqli');
assert(g7.banner && g7.banner.name.indexOf('SQL・インジェクション') === 0, '撃破時にカードの技名カットインが立つ');

// 8) ゼロデイはハードニング無視（同条件で通常より機密性ダメージが大きい）
console.log('シナリオ8: ゼロデイ貫通');
M.setRng(() => 0.99);
const gz = M.createGame(M.STAGE, ['zeroday']);
['breach', 'fw_evade', 'pivot'].forEach(a => M.applyAction(gz, a)); // baseH55、監査でT4後70
const cBeforeZ = gz.db.C;
gz.res.info = 99; gz.res.tech = 99; // ゼロデイのコストを賄う
M.applyAction(gz, 'card:zeroday');
const zDmg = cBeforeZ - gz.db.C;
// 比較: 同じ威力80でハードニング有り(プロキシ緩和0.30×防御力倍率)の理論値より大きいはず
assert(zDmg > 80 * (1 - 0.30) * (0.6 + 0.35 * 0.8) - 1, 'ゼロデイはハードニング無視で機密性を強く貫通（' + Math.round(zDmg) + '）');

console.log(fails === 0 ? '\n✅ すべて通過' : `\n❌ ${fails}件 失敗`);
process.exit(fails === 0 ? 0 : 1);
