# むしとりバトル 🐛⚔️

対戦型の むしとりゲーム（日本語・子ども向け・スマホ縦画面）。
**ソロモード**と**CPU対戦（Lv1〜5）**の2つで あそべる。単一HTMLで動作・外部依存なし。

元プロジェクト「むしとりクエスト」のコンセプト（フィールド探索→けはい発見→捕獲シーンの駆け引き）を
継承し、対戦＋ソロに焦点をしぼって新規に再構成したもの。

## あそびかた
- **ソロ**: せいげんじかん内に できるだけ おおく・大きく つかまえてハイスコアをめざす。
- **たいせん**: CPUライバルより たくさん つかまえれば かち。かつと つぎのレベルが解放。
- フィールドを dパッド（またはキー WASD / 矢印）で うごき、ゆれる草「けはい」へ ふれると捕獲シーンへ。
- 捕獲シーン: **ちかよる / そっと / まつ** で きょりを つめ、**あみ** でつかまえる。
  近いほど命中するが警戒が上がる。警戒MAXで にげられる。

## クイックスタート
```bash
node build.mjs        # src を連結して dist/index.html を生成
npm run check         # 構文チェック
npx serve dist        # ブラウザで開く（http推奨）
node build.mjs --watch  # 開発中の自動ビルド
```

## 構成（単一HTML・モジュール分割方式）
```
src/
├─ index.template.html  HTML骨組み（/*__CSS__*/ /*__JS__*/ に流し込む）
├─ styles.css           全CSS
├─ data/bugs.js         虫25種データ・SVGスプライト・pickSpecies
├─ audio/sound.js       テクノBGM(4曲)＋効果音9種（Web Audio合成）
├─ game/core.js         状態・設定・画面フロー・入力・統合点（せなか骨）
├─ game/catch.js        捕獲シーンの駆け引き
└─ field/field-cpu.js   マップ生成・探索描画・CPU対戦AI(BFS)
docs/
├─ CONTRACT.md          モジュール統合契約
└─ ...
build.mjs               src を ORDER 順に連結し dist/index.html を生成
```
ORDER: `data/bugs` → `audio/sound` → `game/core` → `game/catch` → `field/field-cpu`

## 開発ルール
- **`dist/index.html` を手編集しない**（生成物）。編集は `src/`、`node build.mjs` で再生成。
- **ESモジュール化しない**（import/export禁止）。連結順にグローバル共有。
- 文言・コメントは日本語（ひらがな多め）。
