# 統合契約（エージェント必読）

単一HTMLゲーム「むしとりバトル」。`src/` を `build.mjs` が ORDER 順に **ただ連結** して
`dist/index.html` の1つの `<script>` にする。**import/export 禁止**。全モジュールはグローバル共有。

連結ORDER: `data/bugs.js` → `audio/sound.js` → `game/core.js` → `game/catch.js` → `field/field-cpu.js`

`core.js` は完成済み。そこで定義される共有物を使うこと（再定義しない）:

## 共有グローバル
- `CONFIG` … チューニング値（MAP_W/MAP_H/STEP_MS/SIGN_TARGET/SIGN_RESPAWN_MS/ROUND_SEC/START_DIST/NET_HIT/ALERT_FLEE/ALERT_WARN/WARN_FLEE_P/CPU_STEP_MS/CPU_CATCH_P/CPU_CHASE_R/WIN_BONUS）
- `G` … 全状態。主なフィールド:
  - `G.mode`('solo'|'vs'), `G.cpuLv`(1..5), `G.night`(bool)
  - `G.running`, `G.timeLeft`, `G.score`, `G.cpuScore`, `G.caught[]`, `G.cpuCaught[]`
  - `G.map` = `{w,h,tiles:Int8Array}` tiles値: 0草 1水 2岩 3木 4道 5砂利（歩けるのは 0/4/5）
  - `G.signs[]` = `[{tx,ty,key,id}]`（けはい）, `G.signSeq`（採番カウンタ）
  - `G.player` = `{tx,ty,x,y,dir,moving,mvT,fx,fy,busy}`（x,yはピクセル中心。fx,fy=補間元）
  - `G.cpu` = `{tx,ty,x,y,dir,moving,mvT,fx,fy,stopUntil,path,targetId}`
  - `G.input` = `{dx,dy}`（押されている方向。-1/0/1）
  - `G.cs` … 捕獲中の状態（catch.jsが管理。非捕獲時は null）
- `U` … `rnd()/rint(a,b)/pick(arr)/chance(p)/clamp(v,a,b)/walkable(tx,ty)/tile(tx,ty)`
- `D` … DOM参照（core管理）
- `showScreen(id)` … 'title-screen'|'mode-screen'|'field-screen'|'catch-screen'|'result-screen'

## core が呼ぶ → 各モジュールが提供すべき関数（関数宣言で定義 = ホイスト前提）
- field-cpu.js: `genMap()` / `startField()` / `stopField()` / `setupCpu()`
- catch.js: `enterCatch(sign)`（signは G.signs の要素 or {tx,ty,key}）
- core が提供（呼ぶだけ）: `returnToField(result)` … result = `{caught:bool, key, name, pts, mm, big}` か null
- core が提供: `updateHud()`

## data/bugs.js が提供すべきもの
- `BUGS` = オブジェクト。キー(英数id) → `{ name(日本語ひらがな), color('#rrggbb' 体色), accent('#rrggbb'), w(レア度 3=ふつう/2=中堅/1=レア), pts(基本点), alertBase(初期警戒0-20), sizeBase(基準mm), time('day'|'night'|'both'), shape('butterfly'|'beetle'|'stag'|'mantis'|'dragonfly'|'bee'|'ladybug'|'cicada'|'grasshopper'|'rhino') }`。最低18種。昼/夜/両方をバランスよく。
- `DAY_KEYS` / `NIGHT_KEYS` … BUGSキーの配列（time で振り分け。both は両方に入れる）
- `pickSpecies(night)` … bool night を受け、レア度 w で重み付け抽選してBUGSキーを返す。
  夜は w3 を出さない、昼は w1 を出さない（v33準拠）。中堅/レアは出にくく。
- `bugSprite(key, sizePx)` … その虫の **インラインSVG文字列**(`<svg ...>...</svg>`)を返す。
  捕獲シーンとリザルトで使う。shape と color/accent で描き分け。背景透過。幅=高さ=sizePx。
- `drawBugMini(ctx, key, cx, cy, r)` … （任意）Canvasにミニ虫を描く。フィールドのけはい演出に使えるが必須ではない。

## audio/sound.js が提供すべきもの
- `const Sound = (() => { ... })();` IIFE。Web Audio合成のみ（外部ファイル禁止）。公開API:
  - `Sound.unlock()` … 初回タッチでAudioContext再開
  - `Sound.setMuted(bool)` / `Sound.isMuted()`
  - `Sound.bgm(name)` … name: 'title'|'field'|'vs'|'result'。多重再生しない（前を止めて切替）
  - `Sound.stop()`
  - `Sound.sfx` = `{ select(), step(), catch(), miss(), flee(), big(), win(), lose(), warn() }`
- muted時は何も鳴らさない。例外を投げない（AudioContext未対応でも安全に no-op）。

## game/catch.js が提供すべきもの
- `enterCatch(sign)`:
  1. `G.player.busy = true`、`G.cs` を初期化、`#catch-root` にUIを構築、`showScreen('catch-screen')`。
  2. 種は `sign.key`。`BUGS[key]` から名前/見た目/点。サイズmm = sizeBase × 個体差(0.85〜1.35) ×(夜:+0.06)。
     `big = (個体差係数 >= 1.25)`。big なら pts ×2。
  3. UI: きょり表示・警戒ゲージ（fill幅=alert%、warn(≥70)/danger(≥90)で色変化）・横視点アリーナ
     （`bugSprite(key, …)` を右に、ハンター🥅を左下に）・行動ボタン4つ・ログ。
  4. 行動（`CONFIG`準拠）:
     - **ちかよる**: dist-2、警戒up大（距離係数: 遠い8m×0.6→近い0m×1.0 で増加）
     - **そっと**: dist-1、警戒up小
     - **まつ**: dist を 30%-0.5/30%-1/20%±0/20%+1.5 程度で変動。逃走判定1回（予告中でも まつ では飛ばない）
     - **あみ**: 命中 = `CONFIG.NET_HIT[clamp(round(dist),0,2)]` + 近接ボーナス。
       命中→捕獲成功（`Sound.sfx.catch()`、big なら `Sound.sfx.big()`）。
       はずれ→警戒大up（`Sound.sfx.miss()`）。
  5. 警戒 alert: ≥`ALERT_WARN`(70) で予告（`Sound.sfx.warn()`、1回猶予→以後 まつ以外で `WARN_FLEE_P` で逃走）。
     ≥`ALERT_FLEE`(100) で即逃走（`Sound.sfx.flee()`）。
  6. 終了時 `returnToField({caught, key, name, pts, mm, big})`（逃走/失敗時は caught:false で pts/mm 任意）。
  7. **#catch-screen はスクロール禁止**を壊さない（高さ固定・overflow:hidden 維持）。

## field/field-cpu.js が提供すべきもの
- `genMap()`:
  - `G.map` を `CONFIG.MAP_W × MAP_H` で生成。外周は木(3)。横断する川(1)や岩(2)で通路を絞る。
    必ず全歩行可能タイルが連結していること（プレイヤー初期位置から到達可能）。
  - `G.player` を歩けるタイルへ配置（x,y はピクセル中心へ）。`G.signs=[]` にして `SIGN_TARGET` 個 `spawnSign()`。
  - 関連: タイルサイズはCanvas幅/MAP_W で算出。`G.night` 時は暗めに描画。
- `spawnSign()`（内部）: 歩けて他物と被らないタイルに `{tx,ty,key:pickSpecies(G.night),id:++G.signSeq}` を追加。
- `startField()`: rAFループ開始。`stopField()`: ループ停止（複数回呼ばれても安全に）。
- ループ毎フレーム:
  1. プレイヤー移動: `G.input` 方向へ、未移動かつ移動先 `U.walkable` なら `STEP_MS` で1マス補間。`Sound.sfx.step()` は控えめに。
  2. けはい到達判定: プレイヤーのタイルに sign があれば、その sign を `G.signs` から外し `enterCatch(sign)`。
     その後 `SIGN_RESPAWN_MS` 後に `spawnSign()`（場の数を保つ）。
  3. vsモード時 `cpuTick(dtMs)`: CPUは `CPU_STEP_MS[lv]` 間隔で移動。`CPU_CHASE_R` 以内の最寄りけはいへ
     BFS追跡（`cpuPathStep` 内部）。到達で `CPU_CATCH_P[lv]` 判定→成功なら `G.cpuScore += BUGS[key].pts`、
     `G.cpuCaught.push`、その sign除去＋`updateHud()`。失敗時もそのsignは消費（再 spawn）。
  4. Canvas描画: タイル（草/水/岩/木/道）、けはい（ゆれる草/「！」マーク）、プレイヤー＆CPUのチビキャラ。
     縦長マップが Canvas に収まるよう全体表示（カメラ不要）。`G.night` は暗幕＋プレイヤー周囲だけ明るく。
- `setupCpu()`: vs用に `G.cpu` を初期化（プレイヤーと離れた歩行可能タイル）。
- BFSは `U.walkable` を使う。経路が無ければ徘徊（隣接の歩けるマスへランダム）。

## 注意
- 文言・コメントは日本語（ひらがな多め・子ども向け）。
- すべて **関数宣言**（`function foo(){}`）かグローバル`const`で定義し、上記の名前を厳守。
- トップレベル実行時に他モジュールの値へ依存しない（実行時=ハンドラ/ループ内でのみ呼ぶ）。
- 変更後は `node build.mjs && npm run check` が通ること。
