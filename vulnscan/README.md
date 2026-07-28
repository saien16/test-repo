# GRIMOIRE

**LLMベースのソースコード脆弱性スキャナー。**

`vulnscan` から改称しました。コマンド名は `grimoire`、短縮エイリアスは `grim` です。

## 名前の由来 — 禁書「九五九」

同梱している MITRE CWE カタログの収録数が **959件**。
「959の弱点（呪い）を綴じた1冊の魔道書」に見立てて GRIMOIRE と名付けました。

雰囲気は進捗表示とヘルプ文言にだけ乗せています。
**検出結果・警告・エラーメッセージは実務で読むものなので、雰囲気より明快さを優先**しています。

## インストールと実行

```bash
npm install
npm run build

# ビルド済みバイナリ
grimoire            # カレントディレクトリを走査
grim ./services/api # 短縮エイリアス

# ソースから直接
npm run dev -- ./path/to/repo
```

Node.js 20 以降が必要です。

## 使い方

```bash
# 既定（人間向けのCLIレポート）
grimoire

# CI向け。critical/high があれば非ゼロ終了
grimoire --fail-on high

# 既存の負債では落とさず、新規検出だけでゲートする
grimoire --fail-on high --fail-on-new-only

# JSON / SARIF / Markdown / HTML
grimoire -f json > report.json
grimoire -f sarif -o report.sarif
```

主なオプション:

| オプション | 説明 |
| --- | --- |
| `-f, --format <fmt>` | `cli` / `json` / `sarif` / `markdown` / `html` |
| `-o, --output <path>` | レポートの書き出し先。省略時は stdout |
| `--fail-on <severity>` | この深刻度以上が残っていれば非ゼロ終了。`never` で無効化 |
| `--fail-on-new-only` | ベースラインとの差分（新規）だけでゲートする |
| `-m, --model` / `-e, --effort` | 使用モデルと思考の深さ（`low`〜`max`） |
| `-c, --concurrency` / `--budget` | LLMの同時実行数と出力トークン上限 |
| `--no-kill-chain` / `--no-self-verify` | 高速化のために工程を落とす |
| `--no-architecture` / `--no-heatmap` | アーキテクチャ推定・ヒートマップを行わない |
| `--baseline <path>` / `--update-baseline` | ベースラインの参照先と更新 |
| `--ignore-file <path>` | 抑制リストの参照先 |
| `--no-color` / `-q, --quiet` | 色を切る / 進捗を完全に黙らせる |

### 出力先の約束

- **stdout はレポート本体だけ**。`grimoire -f json > out.json` は常に正しいJSONになります。
- **進捗・警告・エラーは stderr**。パイプやリダイレクトを壊しません。

## 設定ファイル

リポジトリルートの `.grimoire.yml` を自動で読み込みます。
雛形は [`.grimoire.yml.example`](./.grimoire.yml.example) にあります。

探索順（先に見つかったものを採用）:

1. `.grimoire.yml`
2. `.grimoire.yaml`
3. `.vulnscan.yml` — **旧名。後方互換のため読み続けます**
4. `.vulnscan.yaml` — 同上

既定パスも同様に旧名へフォールバックします。

| 用途 | 新しい既定 | 旧名（存在すれば自動で使用） |
| --- | --- | --- |
| ベースライン | `.grimoire/baseline.json` | `.vulnscan/baseline.json` |
| 抑制リスト | `.grimoireignore` | `.vulnignore` |

新しい方が存在すれば常に新しい方が優先されます。
旧名を使ったときは移行を促す警告が1行出るだけで、動作は変わりません。

## 走査の流れ

5つのステージを順に通し、共有モデルを育てていきます。
途中のステージが失敗しても、可能な限り部分結果を返します（何も出ないより途中まで出る方が有用なため）。

| # | ステージ | 詠唱名（進捗表示） | やること |
| --- | --- | --- | --- |
| ① | コンテキスト収集 | 索敵 | ファイル走査・シンボル抽出・コールグラフ・入口と信頼境界の特定 |
| ② | ソースコード分析 | 解析詠唱 | チャンク単位でレンズ別にLLM分析＋自己検証パス |
| ③ | 脆弱性情報管理 | 照合 | 正規化・CVSS算出・重複統合・依存脆弱性(OSV)照合・ベースライン差分 |
| ④ | キルチェーン分析 | 連鎖演算 | 個別の検出を攻撃経路として連鎖させ、到達性で評価する |
| ⑤ | レポート生成 | 編纂 | 優先度付け・要約・各形式へのレンダリング |

分析レンズは `injection` / `authz` / `crypto-secrets` / `deserialization-ssrf` / `web-output` の5種類。
`--lens` で絞り込めます。

## 進捗アニメーション

TTY で実行すると、魔法陣を模したスピナーがステージごとの進捗を表示します。
実装は [`src/cli/animation.ts`](./src/cli/animation.ts) に隔離されています。

```
✦ GRIMOIRE — 禁書「九五九」を開きます
✔ [1/5] 索敵（コンテキスト収集） — 128 ファイル 0:02
◓ [2/5] 解析詠唱 ▓▓▓▓▓░░░░░░░ 34/87 チャンク 0:41
```

守っている約束:

- `process.stderr.isTTY !== true` なら**アニメーションを一切出さず**、1行ずつのプレーンなログへ落ちます（CIログを汚さない）。
- 出力先は常に stderr。stdout は触りません。
- `--quiet` で完全に沈黙、`--no-color` で色だけを落とします（表示自体は出ます）。
- 終了時・エラー時・SIGINT/SIGTERM 受信時のいずれでも**必ずカーソルを復帰**します。`stop()` は冪等です。
- 描画は行の上書きで、更新は約12fps。端末幅を超えません。

## 設計の要点

### 事実と推測を混ぜない

MITRE 由来の値（CWE の説明・Common_Consequences・Likelihood_Of_Exploit・親子関係）は**事実**、
カテゴリ定義・レンズ振り分け・C/I/A への変換規則は本ツール側の**解釈**として区別しています。
レポートの reasoning でもこの区別を保ちます。導けないものは既定値で埋めず、正直に「不明」を返します。

### 設定ファイルは未信頼入力

`.grimoire.yml` は**スキャン対象リポジトリの中身**です。
サードパーティのリポジトリやCIの未信頼PRブランチを解析する運用では、攻撃者が内容を制御できます。
したがって:

- パス系設定（`baselinePath` / `ignorePath`）は**リポジトリ内へ封じ込め**ます。絶対パスや `..` での脱出は拒否し、既定値へフォールバックしたうえで警告を出します。
- リポジトリ外を指してよいのは、オペレータが CLI フラグ（`--baseline` / `--ignore-file`）で明示した場合だけです。出所は `config.pathSources` に記録されます。
- 封じ込め対象のキーは `src/types/config-spec.ts` の `kind: 'path'` から導出しています（手書きの allowlist は無く、書き忘れはコンパイルエラーになります）。
- 設定ファイルから `pathSources` を書いて信頼レベルを詐称することはできません。

### エラーメッセージから情報を漏らさない

レポートはCI成果物やPRコメントとして公開されうるため、
ホストの絶対パスや生の例外メッセージ（`JSON.parse` の `SyntaxError` はファイル先頭を含みます）は載せません。
errno コードのような無害な情報だけを付けます。

### 落とさずに縮退する

CWEカタログが読めない、OSVに繋がらない、YAMLが壊れている——
いずれも例外にはせず、警告を積んで走査を続けます。

### 外部依存を増やさない

色付け（`src/reporter/ansi.ts`）・全角を考慮した表示幅計算と禁則処理つき折り返し（`src/reporter/text.ts`）・
glob 照合・進捗表示は、いずれも自前実装です。

## ビルド

```bash
npm run build   # tsc → dist、そのあと data/ を dist へ同梱
```

`tsc` は `readFileSync` で読むデータファイルをコピーしません。
そのままだと `dist` だけを配布したときに CWE カタログ959件が見つからず、
**例外も出さずに空のカタログへ縮退**します（気づきにくい壊れ方です）。
これを防ぐため、ビルドの後段で [`scripts/copy-data.mjs`](./scripts/copy-data.mjs) が
`src/**/data/` を `dist` の同じ相対位置へコピーします。
新しい npm 依存は使わず、Node 標準の `fs` だけで実装しています（`cp -r` はWindowsで壊れるため使いません）。

## 開発

```bash
npm run typecheck   # tsc --noEmit
npm test            # vitest run
npm run test:watch
npm run dev -- .    # ビルドせずに実行
```

## ライセンス

MIT
