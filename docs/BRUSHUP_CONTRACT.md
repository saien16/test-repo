# ブラッシュアップ 統合契約（3エージェント並列・ファイル所有分離）

レビュー結果を実装する。**単一HTML・import/export禁止・グローバル共有**は不変。
ファイル所有を分け、互いのファイルは編集しない:
- **CATCH担当**: `src/game/catch.js` ＋ `src/styles-catch.css`（新規。catch用CSSは全部ここ。`styles.css`は触らない）
- **CORE/UI担当**: `src/game/core.js` ＋ `src/styles.css` ＋ `src/index.template.html`（`.cs-*`は触らない）
- **FIELD担当**: `src/field/field-cpu.js`

CSSは `build.mjs` が `styles.css` → `styles-catch.css` の順で連結（後勝ちで上書き可）。
連結ORDER(JS): data/bugs → audio/sound → game/core → game/catch → render/tiles → field/field-cpu。

## 新しい共有グローバル / DOM（CORE/UI が定義・他は読むだけ）
- `G.combo`（int, 既定0）… 連続捕獲数。**core が管理**: returnToField で caught:true→`G.combo++`、caught:false→`G.combo=0`。
- `comboMult(n)`（core定義の関数）… 倍率 = `Math.min(2, 1 + 0.25*(n-1))`（combo1→×1, 2→×1.25, 3→×1.5, 4→×1.75, 5+→×2）。
  得点加算は core.returnToField 内で `gained = Math.round(result.pts * comboMult(G.combo))`。**catch.js は pts に combo を掛けない**（baseのみ渡す。big の×2は従来どおり catch 側で pts に反映済みでよい）。
- `G.best.seen`（配列）… 捕獲済み種キー。core が persistSave/loadSave に含める。総数 = `Object.keys(BUGS).length`。
- 新DOM（CORE/UI が index.template.html に追加し、core が制御）:
  - `#hud-combo`（HUD内のピル。combo>=2 で表示「🔥コンボ ×N」）
  - `#toast`（フィールド復帰時の得点トースト用。既定 display:none）
  - `#btn-retry`（リザルトの「もう一回」。直前の `G.mode/G.cpuLv/G.night` のまま `startRun()`）
- catch.js は `G.combo`(数)を**読んで表示に使ってよい**（未定義ガード）。書き換えない。

## CATCH 担当の実装（catch.js ＋ styles-catch.css）
レビューTOP: コアの手応え強化。#catch-screen の `overflow:hidden;height:100%`（高さ固定）を壊さない。新演出は transform/keyframes/opacity で完結。
1. **網スイング＋命中フラッシュ**: あみ時に `.cs-hunter`(🥅) を虫へ振るアニメ。命中で白フラッシュ＋虫が網へ吸い込まれ消える（big はキラキラ追加）。はずれは虫が素早く回避＋小ゆれ、逃走は虫が画面外へダッシュ＋土ぼこり。クラス付与→アニメ後に外す方式。
2. **虫の生きてる感**: `.cs-bug` を常時ふわふわ（idle bob）。警戒≥70 で `.tremble`（小刻みに震える）付与、解除で外す。
3. **「ちかすぎ！」明示＋命中目安**: 実効命中は 2m≒72% / 1m≒86% / 0m≒42%（NET_HIT+近接ボーナス）。0m(round)では「ちかすぎ！てづかみは むずかしい」をログ＋網ボタンに表示。距離バッジ(.cs-dist)と網ボタンに命中目安 **◎(>=0.75)/○(>=0.55)/△(それ未満)** を色つきで出す（数値%も維持）。これで「1mが最適、0mは一発勝負」を直感化。
4. **危険演出**: 警戒≥90 でゲージ(.cs-alert-fill.danger)を鼓動パルス、`.cs-arena.warn-glow` を明滅（CSSアニメ）。
5. **予告誘導**: 予告(warn)中は `.cs-warn-pop` に「いま あみ！」、網ボタンを強調（パルス）。
6. **警戒ゲージの色依存是正**（UIレビュー反映）: ゲージ脇に状態の絵文字＋ことば（例 <40「よゆう😺」/<70「ちゅうい😼」/<90「あぶない🙀」/≥90「にげる！😾」）。色だけに頼らない。
7. （任意・軽）でかい!! をレア度と相関: w が小さい(レア)ほど大物が出やすい等、軽い味付け（やり過ぎない）。
- combo>=2 の時、開始ログ等に「コンボ ×N つづいてる！」を出すと盛り上がる（G.combo を読むだけ）。

## CORE/UI 担当の実装（core.js ＋ styles.css ＋ index.template.html）
1. **コンボ系**: G.combo・comboMult を定義。returnToField で増減＋`gained`加点（上記契約）。`#hud-combo` を updateHud で制御（combo>=2 表示・パルス）。
2. **ずかんコンプ**: `G.best.seen` 追加。caught時に種キーを seen へ（重複なし）。persist/load 反映。showResult に「ずかん N/25」表示、捕獲一覧で**初収集に NEW バッジ**。
3. **復帰トースト＋HUDパルス**: returnToField の caught時、`#toast` に「+{gained}pt {name}！」（でかい!!/コンボ×N を併記）を一瞬出す。`#hud-score` を一瞬パルス。
4. **「もう一回」**: リザルトに `#btn-retry`（直前条件で startRun）。既存「つぎへ」(#btn-again→gotoModeSelect)は残す。
5. **dパッド改善**(UIレビュー): `.dpad` の下に `env(safe-area-inset-bottom)` 余白、`.dbtn` を 62→68px程度に拡大し配置調整。誤タップ低減。
6. **誤タップ「やめる」確認**: #btn-giveup を即終了でなく、1回目はラベル変化＋トースト「もういちど おすと やめる」、2.5秒内の2回目で endRun。
7. **押下フィードバック**: `.hud-give`/`.mute-btn`/`.cpu-lv` に `:active` の視覚変化。
- `.cs-*`（捕獲画面CSS）は CATCH 担当の領分。**触らない**。

## FIELD 担当の実装（field-cpu.js）
1. **けはいのレアヒント**: sign 描画で `BUGS[sign.key].w` を見て、レア(w<=1)は大きめ＋きらめき、中堅(w==2)は中、ふつう(w==3)は小、と差をつける（`Tiles.sign` の呼び方を工夫、または前後に光のリングを描く）。色ヒントに `BUGS[key].color` を使ってもよい。探索でどのけはいを狙うかの判断を生む。
2. （任意・軽）テンポ: 場のけはいが枯れないよう、捕獲中でも目安数を保つ微調整（やり過ぎない）。既存ロジック・連結性は維持。

## 厳守（全員）
- import/export 禁止。関数宣言／グローバルconst。例外で落ちない。日本語ひらがな多め。
- 自分の所有ファイル以外を編集しない。共有グローバル/DOMの名前を厳守。
- 変更後 `node build.mjs && npm run check` が通ること（各自、可能なら最終確認）。
