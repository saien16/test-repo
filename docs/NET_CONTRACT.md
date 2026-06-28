# あみ（網）システム 統合契約（3エージェント並列・ファイル所有分離）

## ねらい（ゲーム設計）
- **きほんのあみ(2m)**: 常備・無限。近づくほど命中UPだが**壊れやすい**。壊れると**その捕獲中だけ**「てづかみ(0m)」に成り下がる→**次の虫で復活**（ソフトロックなし）。
- **変種網（フィールドで拾う・5種）**: 使い切り。壊れたら持ち物から消える。距離別命中と破損率がちがい、**どれで振るか戦略**になる。
- 捕獲シーンで**網を選んで**「あみを ふる！」。距離別命中◎○△と破損リスクを見て選ぶ。

## ファイル所有（互いのファイルは触らない）
- **NETS-DATA担当**: `src/data/nets.js`（新規）
- **CATCH担当**: `src/game/catch.js` ＋ `src/styles-catch.css`（網選択UI・命中/破損ロジック・てづかみ）
- **FIELD担当**: `src/field/field-cpu.js`（網アイテムの spawn/描画/ひろう）
- core.js は更新済み（下記の共有を提供）。**core.js/template/styles.css は触らない**。

連結ORDER(JS): data/bugs → **data/nets** → audio/sound → game/core → game/catch → render/tiles → field/field-cpu。
（nets.js は純データ＋小関数。状態に依存しない。）

## core が用意ずみ（読むだけ・名前厳守）
- `CONFIG.NET_ITEM_TARGET`(=3) / `CONFIG.NET_RESPAWN_MS`(=9000)
- `G.nets`（{id:count} 変種網のもちもの。'basic'は入れない＝常備無限）／`G.curNet`（選択中id・既定'basic'）／`G.netItems`（[{tx,ty,id,iid}]・FIELDが管理）／`G.netSeq`
- `pickupNet(id)`（FIELDから呼ぶ。`G.nets[id]++`＋トースト＋音＋updateHud）
- `startRun` で nets/curNet/netItems/netSeq はリセット済み。

## NETS-DATA 担当（src/data/nets.js）
グローバル `const NETS = {...}` と小関数を提供（import/export禁止・関数宣言/const・例外で落ちない・document不使用）。
- `NETS[id]` = `{ id, name(日本語ひらがな), short(一言の特徴), color('#rrggbb'), range(最適m), hit(きょり別命中表 例 {0:..,1:..,2:..,3:..}), breakP(1回ふるごとの破損確率0..1), basic(bool), rare(bool), dropW(フィールド出現の重み・gold等は小さく) }`。
- **必須id**: `basic`（きほんのあみ・2m・壊れやすい・basic:true・dropWは0=落ちない）。以下は**おまかせで5種**つくる（例: `close`1mのあみ/`long`3mのあみ/`reinf`じょうぶな2mのあみ/`big`おおあみ/`gold`👑きんのあみ rare）。下の推奨値を土台に微調整可:
  - basic: hit{0:0.45,1:0.80,2:0.62,3:0.30} breakP0.18 basic:true dropW0
  - close(1m): hit{0:0.72,1:0.92,2:0.45,3:0.18} breakP0.30 dropW0.9
  - long(3m): hit{0:0.35,1:0.50,2:0.56,3:0.60} breakP0.06 dropW0.9
  - reinf(2m強): hit{0:0.50,1:0.86,2:0.74,3:0.42} breakP0.05 dropW0.8
  - big(おおあみ): hit{0:0.42,1:0.70,2:0.80,3:0.66} breakP0.12 dropW0.8
  - gold(👑): hit{0:0.65,1:0.86,2:0.82,3:0.76} breakP0.04 rare:true dropW0.15
- `netHit(id, distM)` → 命中率0..1。表を使い、`d=clamp(round(distM),0,maxKey)`。**遠すぎ(d≥4)は急減**（例 表の最遠値×0.4からさらに-0.05/mし0.05下限）。0.05〜0.97にclamp。
- `netHitMark(p)` → `{mark:'◎'|'○'|'△', cls:'good'|'ok'|'bad', word}`（◎≥0.75/○≥0.55/△未満。既存catchと整合）。
- `netRiskLabel(id)` → 破損の目安（例 breakP≥0.25「こわれやすい」/≥0.10「ふつう」/未満「じょうぶ」）と段階(0..2)。
- `drawNetGlyph(ctx, cx, cy, size, id)` → Canvasに網アイコンを描く（color で輪・柄。gold は金）。FIELDの落ちてる網描画とUIに使える。例外時は簡単な丸でフォールバック。

## CATCH 担当（catch.js ＋ styles-catch.css）
現状: `csHitRate()` は `CONFIG.NET_HIT` 固定。これを**選択中の網ベース**に置き換える。`#catch-screen` の overflow:hidden/高さ固定を壊さない。新CSSは styles-catch.css のみ。
1. **アクティブ網の管理**: `G.cs` に `net`（現在id）と `basicBroken`(bool) を持つ。`enterCatch` で `cs.net = (G.curNet!=='basic' && (G.nets[G.curNet]||0)>0) ? G.curNet : 'basic'`、`cs.basicBroken=false`。
2. **命中**: `csHitRate()` を `netHit(cs.net, cs.dist)` に。basicが壊れている時は「てづかみ」= `netHit('basic',0)`相当の0m手づかみ（実質 hit('basic',dist) だが網なし→0mのみ有効）。簡単化: basicBroken時は `cs.net='hand'` 扱いで hit = (round(dist)<=0?0.30:0.05)。表示も「てづかみ」。
3. **網セレクタUI**: 行動ボタンの上あたりに**横並びチップ**を出す（コンパクト。アリーナはflexで縮む）。チップ= `drawNetGlyph` か絵文字＋名前＋現在距離の◎○△＋破損目安＋（変種は ×のこり数）。タップで `cs.net` 切替＆`G.curNet`更新＆再描画。basicは常時、変種は `G.nets[id]>0` のものだけ。アクティブを強調。
4. **網ボタン表示**: 「あみを ふる！」に 選択網名＋◎○△＋%＋破損目安。basicBroken時は「てづかみ」。
5. **ふる(csSwing)**: 命中判定は上記。**破損判定**は毎スイング（成功・失敗どちらでも）`U.chance(NETS[cs.net].breakP)`（手づかみは破損なし）。壊れたら:
   - basic → `cs.basicBroken=true`（このエンカウントだけ手づかみへ）。ログ/演出「あみが こわれた！ てづかみで がんばれ！」。
   - 変種 → `G.nets[cs.net]--`（0で delete）。ログ「◯◯が こわれた！」。アクティブを basic（壊れてなければ）へ戻す。網アイコンが割れる小演出があると良い（CSS）。
   - 破損音は `Sound.sfx.miss()` 等の既存で代用可。
6. 既存の警戒/逃走/まつ/ちかよる/そっと、命中演出・命中目安・状態絵文字・連打防止は維持。`csFinish/returnToField` の戻り値（base pts。combo はcore）も不変。
7. レイアウト: セレクタ追加で崩さないこと（必要なら font/padding 圧縮）。スマホ縦で破綻しない。

## FIELD 担当（field-cpu.js）
1. **網アイテムの spawn**: `genMap` で `G.netItems=[]` にして `CONFIG.NET_ITEM_TARGET` 個 `spawnNetItem()`。歩けて他物（player/cpu/sign/他netItem）と被らないタイルに `{tx,ty,id,iid:++G.netSeq}`。`id` は **basic以外**を `NETS[id].dropW` 重みで抽選（rare/goldは出にくい）。`pickSpecies` のように軽い抽選関数を作る。
2. **描画**: netItem を奥行きソートに含め、`drawNetGlyph(ctx, sx, sy, size, id)` で描く（落ちてる感＝小さな落ち影＋ふわっと上下 or きらり）。レア(gold)は少し光らせる。
3. **ひろう**: プレイヤーが netItem のタイルに到達したら（`_checkReachSign` と同様の到達判定で）その item を `G.netItems` から外し `pickupNet(item.id)` を呼ぶ。`CONFIG.NET_RESPAWN_MS` 後に `spawnNetItem()` で数を保つ。
4. 既存のけはい到達・CPU・カメラ・連結性は維持。`NETS` 未定義でも落ちないようガード。CPUは網に影響しない（プレイヤー専用でよい）。

## 厳守（全員）
- import/export禁止・関数宣言/グローバルconst・例外で落ちない・日本語ひらがな多め。
- 自分の所有ファイル以外を編集しない。共有名（NETS/netHit/netHitMark/drawNetGlyph/G.nets/G.curNet/G.netItems/pickupNet/CONFIG.NET_*）を厳守。
- 変更後 `node build.mjs && npm run check` が通ること。
