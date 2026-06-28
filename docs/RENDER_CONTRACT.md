# 描画リッチ化 統合契約（SNES風・ドラクエ6/クロノ・トリガー級）

目的: 平面的なフィールドを、**カメラ追従でスクロールする広いマップ**＋**奥行きのある立体的な
2D描画**へ刷新する。ゲームロジック（移動・けはい到達・CPUのBFS）は維持する。

連結ORDER: `data/bugs` → `audio/sound` → `game/core` → `game/catch` → **`render/tiles`** → `field/field-cpu`
（`render/tiles.js` は純粋な描画関数のみ。ゲーム状態に依存しない。`field-cpu.js` がこれを呼ぶ。）

共有: `CONFIG.MAP_W=30 / MAP_H=34 / VIEW_TILE=40 / SIGN_TARGET=9`、`G`、`U.walkable/U.tile`、`G.night`。

## マップデータの形（genMap が作る）
`G.map = { w, h, tiles:Int8Array, deco:Int8Array }`
- `tiles`（衝突＆地面種）: **0=草 / 1=水 / 2=崖（岩棚・通れない）/ 3=森（木・通れない）/ 4=道 / 5=砂利**
  - **歩けるのは 0/4/5**（`U.walkable` の定義は変えない）。水1・崖2・森3 は壁。
- `deco`（見た目だけの装飾。歩けるタイルの上にのみ置く）: 0=なし / 1=花 / 2=せいたか草 / 3=小石 / 4=丸太 / 5=きのこ
- **連結性保証は必須**: プレイヤー初期位置から全歩行可能タイルへ到達できること（壁配置後にBFSで検査し、孤立を砂利の小道で本体へつなぐ）。

## render/tiles.js が提供する `Tiles`（純粋関数・関数宣言かグローバルconst）
すべて **スクリーン座標**で受け取る（カメラ適用は呼び出し側 field-cpu が行う）。`ctx`=2D。`ts`=タイルpx。
`seed`=整数（例 tx*73856093 ^ ty*19349663）で安定したランダム見た目。`time`=ms（水/草のアニメ）。
例外を投げないこと（範囲外でも安全）。`document`をトップレベルで触らない。

- `Tiles.ground(ctx, sx, sy, ts, kind, seed, time, night)`
  地面1タイルを描く。kind: `'grass'|'path'|'gravel'|'water'`。
  - grass: 2〜3色の微妙な濃淡＋まばらな草の点描（seedで配置固定）。チェッカー過ぎない自然な質感。
  - water: 波のきらめきを `time` でアニメ（横に流れる明色のさざ波／反射）。
  - path/gravel: 土・砂利の粒感。
- `Tiles.transition(ctx, sx, sy, ts, base, mask, time)`
  地面の境界をなじませる縁取りを **base タイルの上**に重ねる。`mask`={n,e,s,w,ne,nw,se,sw}(bool)
  で「その向きの隣が“ちがう/低い地形”」を示す。用途: 水辺の白い波/砂の岸（base前提=land側 or water側どちらでも良いが仕様を README コメントに明記）、道のふちのなじみ。角(ne等)も丸める。
- `Tiles.cliff(ctx, sx, sy, ts, opts)` opts={faceH(下に出す崖面の高さ・ts基準の倍率 例0..1.2), capTop(bool), shadow(bool), seed, night}
  岩棚ブロック。`faceH>0` のとき**南向きの垂直な崖面**＋根元に落ち影。`capTop`で上面（草or岩の天端）。
  ごつごつした陰影で「高さ」を感じさせる。複数段は呼び出し側が縦に積んで表現してもよい。
- `Tiles.tree(ctx, sx, sy, ts, variant, time, night)`
  木。**樹冠がタイルより上に立ち上がる**（高さ ~1.6×ts）＋幹＋根元の楕円の落ち影。`time`でゆれ。
  variant(0..)で大きさ/形/色を数種。針葉樹/広葉樹など。
- `Tiles.deco(ctx, sx, sy, ts, kind, seed, time)`
  装飾。kind: `'flower'|'tallgrass'|'rock'|'log'|'mushroom'`。花は数色、せいたか草は `time` でそよぐ、
  きのこ/丸太/小石はそれぞれらしく。せいたか草・きのこ・丸太は少し上に立ち上がる（影つき）。
- `Tiles.shadow(ctx, cx, cy, rx, ry)` … (cx,cy)中心の半透明だ円の落ち影。
- `Tiles.chibi(ctx, cx, cy, ts, dir, walkPhase, kind, night)`
  キャラ。`dir`='up'|'down'|'left'|'right'、`walkPhase`(0..1で歩き足ぶみ/上下バウンド)、
  `kind`='player'|'cpu'（cpuは色ちがい＋ロボ風アンテナ）。**根元に落ち影**を必ず描く。
  クロノ/DQ風の2.5頭身。(cx,cy)はキャラの**足元（接地点）**。
- `Tiles.sign(ctx, cx, cy, ts, time)`
  けはい。ゆれる草むら＋「！」がふわっと上下。`time`でアニメ。(cx,cy)は足元。
- `Tiles.nightOverlay(ctx, W, H, lx, ly, r)`
  夜の暗幕（画面全体 W×H）＋ (lx,ly) 中心・半径 r の円形ライト（プレイヤー周囲だけ明るく）。

## field/field-cpu.js（改修）
**既存のゲームロジックは保持**（1マス補間移動・G.input・けはい到達 `enterCatch`・respawn・CPUのBFS追跡と捕獲判定・updateHud）。元ファイルからこれらを引き継ぐ。変えるのは「マップ生成の豊かさ」「カメラ」「描画」。

- `genMap()`: 上記データ形で 30×34 を生成。
  - 自然な地形: 草原ベースに、うねる**川（湖/池含む）**と**はし(道4)**、**崖の尾根（2）**で高低差感、
    **森のかたまり（3）**、**道(4)/砂利(5)の小径**。装飾 deco（花畑・せいたか草・きのこ・丸太・小石）をちらす。
  - 連結性保証（必須）。プレイヤーを歩けるタイルへ、CPUは（vs時 setupCpuで）離れた歩けるタイルへ。
  - けはい SIGN_TARGET 個。
- **カメラ**: `VIEW_TILE` をタイルpxとし、プレイヤーのピクセル中心にカメラを合わせ、マップ端でクランプ。
  毎フレーム滑らかに追従（線形補間でややワンテンポ遅れて追うとリッチ）。canvas論理サイズ420×600。
  画面に映る範囲だけ描く（カリング）。`devicePixelRatio` 対応で高精細に（startFieldでcanvas.width/heightをDPR倍、ctx.scale）。
- **描画パイプライン（毎フレーム）**:
  1. カメラ更新→可視タイル範囲算出。
  2. 地面レイヤ: 可視タイルすべてに `Tiles.ground(...)`、必要箇所に `Tiles.transition(...)`（水辺/道）。
  3. **奥行きソート**: 立ち上がる物（木・崖ブロック・せいたか草/きのこ/丸太・けはい・プレイヤー・CPU）を
     **足元のワールドY**でソートし、後ろ→前に描く（painter's algorithm）。平らな装飾（花・小石）は地面の直後。
     崖(2)は `Tiles.cliff` で面＋影、森(3)は `Tiles.tree`。
  4. エンティティ: `Tiles.chibi`（player/cpu, dir, walkPhase）, `Tiles.sign`。各自 `Tiles.shadow` 相当の落ち影。
  5. `G.night` 時は最後に `Tiles.nightOverlay`（プレイヤー画面座標中心のライト）。
  6. 水・草・けはいの `time` アニメを進める。
- `setupCpu()`/`cpuTick(dtMs)`/BFS は機能維持（座標系はタイル基準のまま。描画だけカメラ変換）。
- `startField()`/`stopField()` は rAF 管理（多重起動・停止に安全）。

## 厳守
- import/export 禁止。`Tiles` は1つのグローバル（`const Tiles = {...}` か関数群）。名前厳守。
- 文言・コメントは日本語ひらがな多め。
- 60fpsを目標に軽量に（毎タイル重いgradientを多用しない。seedキャッシュ等は任意）。
- 変更後 `node build.mjs && npm run check` が通ること。
- 既存の `U.walkable`(0/4/5) を壊さない。`G.map.tiles` の意味（2=崖, 3=森）に注意。
