# GRIMOIRE 設計書

禁書「九五九」— MITRE CWE 959件を収めた、LLMベースのソースコード脆弱性スキャナー。

実装は `vulnscan/`（パッケージ名 `grimoire`、コマンド `grimoire` / `grim`）。
TypeScript / Node.js 20+、ESM、ネイティブ依存なし。

> この文書は**実装済みのものだけ**を書いている。
> 未実装の構想は「§10 未実装」にまとめ、本文には混ぜない。
> 使い方は [`vulnscan/README.md`](../vulnscan/README.md) を参照。

---

## 1. 設計方針

**LLM中心、ただし数字は機械で出す。**
脆弱性の判定と攻撃経路の推論はLLMに任せる。一方で集計・優先順位・CVSS・
ヒートマップの算出は決定的な純粋関数で行う。LLMが使えなくても数字と順序は必ず出る。

**誤検知の抑制を最優先。**
LLMスキャナー最大の欠点である。対策は3段構え:
データフロー根拠を構造化出力で必須にする / 別プロンプトで反証を試みる自己検証パス /
確信度しきい値による切り捨て。

**事実と推測を型で分離する。**
アーキテクチャ推定とヒートマップは本質的に推測を含む。全項目を `Claim<T>` で包み、
`observed`（引用付きの事実）/ `inferred`（確信度と根拠付きの推測）/ `assumed`（根拠なしの仮定）
を混ぜずに報告する（§4）。

**スキャン対象リポジトリは未信頼入力として扱う。**
サードパーティのリポジトリやCIの未信頼PRブランチを解析する運用では、
`.grimoire.yml` の内容もFindingのタイトルも攻撃者が制御できる（§7）。

**部分的失敗を許容する。ただし何を見られなかったかを必ず返す。**
LLM呼び出しが失敗しても続行して部分結果を出すが、それを「完走した結果」と
区別できなければ「検出0件＝安全」という誤った結論になる（§5）。

**コストと再現性の制御。**
チャンク単位の結果キャッシュ、プロンプトキャッシュ、トークン予算上限、
ベースライン比較。同じ入力からは同じ順序のレポートが出る。

---

## 2. パイプライン全体

```
リポジトリ
   │
   ▼
① collectContext     ──► ScanContext          リポジトリの事実収集（LLM不使用）
   │
   ▼
② analyze            ──► RawFinding[] + AnalysisStats
   │                                          レンズ×チャンクのLLM走査＋自己検証
   ▼
③ manageFindings     ──► Finding[]            正規化・CVSS・OSV照合・重複統合・差分
   │
   ├──────────────┬─────────────────────────── ④⑤ は並列（データ依存なし）
   ▼              ▼
④ analyzeKillChains  ⑤ inferArchitecture
   │  AttackChain[]   │  ArchitectureModel     事実収集＋LLM推測
   └──────┬───────┘
          ▼
⑥ buildHeatmap       ──► VulnerabilityHeatmap  実測層×想定層（純粋関数）
          │
          ▼
⑦ analyzeResult      ──► AnalyzedReport        横断分析＋文章化
          │
          ▼
     CLI / JSON / SARIF / Markdown / HTML  +  終了コード
```

`STAGE_SEQUENCE`（`core/orchestrator.ts`）がステージ順の**唯一の真実**で、
`StageName` 型はこの配列から導出する。ステージを足すと
`Record<StageName, _>` 群（CLIのラベル表・アニメーションの語彙表）が一斉に
コンパイルエラーになる。以前は配列とunionを別々に手書きしていて、
ステージを足したのに表示順の配列へ足し忘れても型エラーが出ず、静かに漏れたことがある。

`runScan()` が担うのは ①〜⑥。⑦はCLI側が `analyzeResult()` を呼ぶ
（レポート生成はスキャン結果の消費側であり、`ScanResult` を汚染しない）。

各ステージの失敗は `errors` に積み、可能な限り部分結果を返す。
④は `killChain: false` か Finding 0件でスキップ、⑤は `architecture: false` でスキップ、
⑥は⑤の結果が無ければ生成しない（推測の土台が無いのに想定リスクは語れない）。

---

## 3. 各ステージの詳細

### ① コンテキスト収集 — `src/context/`

リポジトリを走査して、後続ステージが依存する `ScanContext` を作る。LLMは使わない。

| 担当 | モジュール | 手法 |
|---|---|---|
| ファイル走査 | `walk.ts` / `ignore.ts` / `glob.ts` | `.gitignore` と `scan.exclude` を尊重 |
| 言語判定 | `language.ts` | 拡張子・ファイル名。36言語を集計、9言語を深く解析 |
| フレームワーク検出 | `frameworks.ts` | 依存名・設定ファイル |
| 依存関係（軽量SBOM） | `dependencies.ts` | npm / PyPI / Go / Maven / RubyGems / Packagist / crates.io |
| コメント・文字列のマスク | `mask.ts` | 誤爆防止の前処理 |
| シンボル抽出 | `symbols.ts` | 正規表現＋括弧／インデント追跡 |
| 呼び出しグラフ | `callgraph.ts` | 名前解決の確度を `confidence` で持つ |
| エントリポイント | `entrypoints.ts` | HTTPルート・CLI・メッセージハンドラ・`main` |
| 信頼境界 | `trust.ts` | source（汚染源）と sink（危険な出力先）の候補 |
| Gitメタデータ | `git.ts` | ブランチ・HEAD・変更ファイル一覧 |

**tree-sitter は使っていない。** ネイティブ依存を避け、
正規表現とブレース／インデントの追跡による軽量ヒューリスティックで代替している。
精度よりも頑健性を優先した判断で、崩れたコードでも例外を投げずに何らかの結果を返す。
代償として呼び出しグラフの名前解決は不完全であり、それを `CallEdge.confidence` として
下流に伝えている。

深く解析する（シンボル・信頼境界を取る）言語は
TypeScript / JavaScript / Python / Go / Java / Ruby / PHP / Vue / Svelte。
それ以外は言語比率の集計と依存関係の抽出にのみ寄与する。

収集は「壊れないこと」を最優先し、個々の解析失敗は `warnings` に積んで
例外を `collectContext()` の外へ出さない。

### ② ソースコード分析 — `src/analyzer/`

`ScanContext` を入力に、LLMで脆弱性を判定する。中核。

1. **チャンク分割**（`chunker.ts`）— シンボル単位で切る。行スライスではないので意味が壊れない。
2. **文脈の付与**（`context.ts`）— 呼び出し元／呼び出し先のシグネチャ、関連する信頼境界、
   エントリポイントからの到達可能性を各チャンクに添える。`ScanContext` 由来の索引は
   全チャンクで共有する（チャンクごとの全走査を避ける）。
3. **多視点レンズ走査**（`lenses/`）— 単一の万能プロンプトではなく観点別に走査する。
   タスクは**レンズ×チャンク**の直積で、レンズ単位にまとめて並べる
   （同じ system プロンプトが連続し、プロンプトキャッシュが効く）。
   - `injection` … SQLi / コマンド / パス / テンプレート
   - `authz` … IDOR / 権限昇格 / 認可チェックの欠落
   - `crypto-secrets` … ハードコード鍵 / 弱いアルゴリズム
   - `deserialization-ssrf` … デシリアライズ / SSRF / XXE / オープンリダイレクト
   - `web-output` … XSS / CSRF
   - （`dependency` は②の対象外。依存脆弱性は③がOSVで担当する）
4. **構造化出力**（`schema.ts`）— zodスキーマで `RawFinding` を強制。
   位置・CWE・severity・confidence・**データフロー根拠**が必須。
5. **自己検証パス**（`verify.ts`）— 候補ごとに、反証する側から検証させる別プロンプトを走らせる。
   `refuted` は破棄、`uncertain` は減衰、`confirmed` は検証側に重みを置いて合成。
   検証できなかった場合（拒否・予算切れ・失敗）は控えめに減衰して残す。
   これが誤検知の主対策。
6. **正規化と絞り込み**（`filter.ts`）— 減点・`minConfidence` しきい値・重複統合。

出力は `RawFinding[]` と `errors` に加えて **`AnalysisStats`**（§5）。

### ③ 脆弱性情報管理 — `src/vuln/`

生Findingを正規化し、知識ベースで補強して追跡可能にする。

**CVSS v3.0 / v3.1 計算機**（`cvss.ts`）
基本評価基準を仕様どおり実装している。v3.1 の `roundup` は浮動小数の丸め誤差を避けるため
整数演算で行う（v3.0 は従来の切り上げ）。検証は
**既知値21ベクタ**（FIRST公式サンプル＋NVD公表値。Scope Unchanged / Changed の代表例を含む）と
**基本メトリクスの全1944通り**に対して行っている
（後者はスコアが 0.0〜10.0 に収まること、ベクタのラウンドトリップが一致すること）。
LLMがメトリクスを返さない場合は CWE カタログの `Common_Consequences` から
C/I/A を導いて補完する。

**CWEカタログ959件**（`catalog.ts` + `data/cwe-catalog.json`）
出典は OWASP/cwe-sdk-javascript（MITRE 公式データ `cwec_latest.xml` のJSON化）。
`scripts/build-cwe-catalog.mjs` で 8MB → 1.40MB に圧縮して同梱しており、
**実行時にネットワークへ出ない**。提供するのは素引き・親を辿った上位概念への畳み込み・
`Common_Consequences` からのC/I/A導出・`Likelihood_Of_Exploit`・
言語や技術スタックからの逆引き・分析レンズへの振り分け。

959件をそのまま人に見せても扱えないので、**31のカテゴリ**へ畳む
（`CATEGORY_ANCHORS`）。CWE自身から祖先へ向かってアンカー表と突き合わせ、
最初に一致したものを採る。これはMITREのデータではなく本ツールの「解釈」であり、
カタログ側のコメントで事実と解釈の境界を明示している。
OWASP Top 10 2021 の対応は公式マッピングに従う。

**依存脆弱性照合**（`osv.ts`）
OSV.dev の `querybatch` + `vulns/{id}` で①のSBOMを照合し、②を通さずFindingを作る。
ネットワークが使えない環境でも壊れないことを最優先とし、失敗はすべて `errors` に積んで継続する。

**永続化とトリアージ**
- ベースライン（`baseline.ts`）— 前回結果を `.grimoire/baseline.json` に保存し、
  指紋で照合して `new` / `persistent` / `fixed` を算出する
- 指紋（`fingerprint.ts`）— 位置とCWEから再現可能に導出。行がずれても追跡できる
- 抑制リスト（`ignore.ts`）— `.grimoireignore`
- トリアージ状態 — `open` / `confirmed` / `false-positive` / `accepted` / `fixed`

旧名（`.vulnscan.yml` / `.vulnscan/baseline.json` / `.vulnignore`）は後方互換で読む。
新しい既定パスが存在せず旧パスだけがある場合に限り、警告1行を出してフォールバックする。

### ④ キルチェーン分析 — `src/killchain/`

個別Findingを多段の攻撃シナリオへ連鎖させる。単体では中リスクでも、
連鎖でRCEに至るものを浮かび上がらせる。

1. **候補絞り込み**（`grouping.ts` / `reachability.ts`、純粋関数）—
   呼び出しグラフ到達性とデータフローでFindingを束ねる。
   全組み合わせをLLMに投げるのは高価すぎるため、先に機械で候補を作る。
2. **連鎖推論** — グループごとにLLMへ `source → 中間ステップ → sink（影響）` を依頼。
3. **ATT&CKマッピングの検証・補正**（`attack-mapping.ts`）—
   LLMが返した段階を、サイバーキルチェーン7段階と MITRE ATT&CK 11戦術に突き合わせて補正する。
   両方の配列が**唯一の真実**で、zodの `z.enum()` の値もそこから導出する
   （段階を足して配列への追加を忘れると、LLMがその段階を返せなくなるのに型エラーが出ないため）。
4. **再優先度付けとチョークポイント選定**（`scoring.ts`）—
   連鎖を考慮した `priorityScore` と、連鎖を断ち切るのに最も効果的なFindingを決める。

`AttackChain.id` は内容から決定的に導出する（再実行でIDが揺れない）。

### ⑤ アーキテクチャ・デプロイスタック推定 — `src/architecture/`

コードとマニフェストから、システム構成とデプロイ先を推定する。

1. **事実収集**（`collect.ts` / `facts.ts` / `discover.ts`、決定的・引用付き）—
   18種のマニフェストを分類して読む（Dockerfile / compose / k8s / Helm / serverless /
   CloudFormation / Terraform / Pulumi / Vercel / Netlify / Procfile / PaaS設定 /
   GitHub Actions / GitLab CI / CircleCI / Jenkins / パッケージマニフェスト / dotenv）。
   件数上限160で打ち切り、打ち切った事実は警告に残す。
2. **骨格の組み立て**（`model.ts`）— 事実だけでモデルを組む。
3. **推測**（`prompt.ts` / `schema.ts`）— 事実では決まらない項目
   （アーキテクチャ様式・露出度・データ機微度・認証要求・構成要素間のデータフロー）をLLMに委ねる。
4. **引用の実在検証**（`verify.ts`）— LLMが返した引用がファイル内に実在するかを確認し、
   捏造分を落とす。
5. **内訳の集計** — `observed` / `inferred` / `assumed` の件数と推測の平均確信度。

**3以降が失敗しても2の結果（事実部分）は必ず残る。**
推測が得られないことと、事実が失われることは別問題として扱う。

「Dockerfile に `FROM node:20` と書いてある」のは事実だが、
「このサービスがインターネットに公開されている」のは推測にすぎない。
この差を型で保つのが `Claim<T>` の役目（§4）。

### ⑥ 脆弱性ヒートマップ — `src/heatmap/`

「アーキテクチャ構成要素 × 弱点カテゴリ」の格子に、独立した2層を重ねる。

- **実測層**（`observed.ts`）— 検出されたFindingのCVSSと件数から 0..100。事実。
- **想定層**（`inferred.ts`）— CWEカタログの `Likelihood_Of_Exploit` と C/I/A、
  および構成要素の露出度・技術スタックとの適合性から 0..100。推測なので `Claim<number>`。
  言語非依存・技術非依存のCWEは「どのスタックにも当てはまる」＝主張の根拠として弱いので割り引く。

2層に分ける理由は、**両者の食い違いにこそ価値がある**ため:

| | 想定 高 | 想定 低 |
|---|---|---|
| **実測 高** | 予想どおりの弱点。優先的に直す | 想定外。設計レビューの見落とし |
| **実測 低** | **死角(blind spot)** | 現時点で懸念薄 |

**第3象限（死角）の可視化がこのヒートマップの主目的である。**
単に検出結果を色分けするだけならFinding一覧で足りる。

死角はさらに原因で切り分ける（`blindspots.ts`）。
対応が変わるので、ここを一緒にしてはいけない:

- `not-scanned` … 除外設定やレンズ未有効で走査していない → **設定を直す**
- `no-matching-lens` … そのカテゴリを見るレンズが無い → **ツールの限界。別手段で見る**
- `genuinely-absent` … 該当する実装自体が無さそう → **対応不要**
- `unknown` … 切り分けられなかった → **人が確認する**

`buildHeatmap()` は**純粋関数**である。LLMを呼ばず、時刻も乱数も参照せず、
引数を書き換えず、同じ入力からは必ず同じ出力を返す。想定層はカタログと⑤の結果から
機械的に導けるので、LLMを挟む必要がない。再現性とテスト可能性を優先した判断。

`inferenceRatio`（0..1）でヒートマップ全体がどれだけ推測に依存しているかを返す。
1に近いほど「話半分に読むべき」ことを意味する。

カタログへの接続は `catalog-adapter.ts` 1箇所に閉じる。ヒートマップ本体が
`vuln/catalog.ts` を直接importすると、カタログ側のシグネチャ変更が4ファイルに波及するため。

### ⑦ レポーター — `src/reporter/`

**他機能の出力を分析して読み物に再構成する**のが役目で、羅列ではない。
役割分担を機械とLLMで明確に分けている。

**機械で導出する**（`summarize.ts` / `priority.ts`、LLM不使用・決定的）
- サマリ集計、深刻度分布
- Finding × AttackChain の相関 — どのチェーンに何回登場するか、チョークポイントか
- 優先度スコア — チョークポイント(1000) > 複数チェーンに登場(300/本) > CVSS(×20) > 深刻度。
  こうすると「単独では高CVSSだが孤立した問題」より
  「CVSSは中程度でも複数の攻撃経路の要になっている問題」が上に来る
- `prioritizedActions` — 「1回の修正で片付く」Findingを1アクションに集約し、工数を推定する
  （依存は修正版の有無、コードはファイル数・CWEの性質・データフロー長から）

**LLMに任せる**（`narrative.ts`）
- `executiveSummary` — 非技術者向けの3-5文
- `riskNarrative` — 攻撃者視点の筋書き
- `trendNarrative` — 前回との比較

LLMが拒否・予算切れ・障害のいずれで失敗しても、**機械生成の文章に切り替えて必ず成立させる**。
フォールバックした場合はその事実をレポート本文に残す
（LLMが書いたのか機械が書いたのか読み手に分からないのは不誠実だから）。

**出力形式**（`formatters/`）
| 形式 | 用途 |
|---|---|
| `cli` | 端末向け。色付き・端末幅に追従・全角文字幅を数える |
| `json` | 機械可読。`ScanResult` と `AnalyzedReport` の両方 |
| `sarif` | SARIF 2.1.0。GitHub Code Scanning 連携 |
| `markdown` | PRコメント・成果物向け |
| `html` | 単一ファイル完結。ライト／ダーク両対応 |

HTMLレポートには**アーキテクチャ図にヒートマップを重ねたSVG**を描く
（`formatters/architecture-map.ts`。⑤⑥が揃っている場合のみ）。
行列表ではなく実際のトポロジ上に載せる。
構成要素を露出度（`public-internet` → `internal` → `local`）で層に並べ、
信頼境界を破線で仕切り、3つの独立した視覚チャンネルに情報を割り当てる:

- **塗りの濃さ** = 実測リスク（5段階）
- **破線のハロー** = 想定リスク（3段階の太さ）
- **45°ハッチング＋▲バッジ** = 死角

レイアウトは決定的で、同じ入力からは同じ図が出る。

---

## 4. 事実と推測の分離 — `src/types/evidence.ts`

このスキャナの中心的な約束。⑤⑥が扱う値のほとんどは推測であり、
それを事実と混ぜて報告してはいけない。

```ts
type Provenance =
  | { kind: 'observed'; citations: Citation[] }          // 事実。引用が必須
  | { kind: 'inferred'; confidence: number; inferredBy: Inferrer;
      basis: Citation[]; reasoning: string; alternatives?: string[] }
  | { kind: 'assumed'; reasoning: string };               // 根拠なしの仮定

interface Claim<T> { value: T; provenance: Provenance }
```

設計上の約束:

- **`observed` は必ず1件以上の引用を持つ。** `observed()` は引用0件で例外を投げる。
  引用のない「事実」は事実ではないので、呼び出し側のバグとして落とす。
- **`inferred` は根拠・理由・確信度を必ず持つ。** `reasoning` は読み手が反証できる粒度で書く。
  `alternatives` には検討したが採らなかった対立仮説を入れ、推測の幅を示す。
- **`assumed` は確信度を持たない。** 数値として集計してはいけない、という意図を型で表す。
- **推測の上に推測を重ねると確信度は減衰する。** ⑤の推測を材料にした⑥の想定層は、
  その分だけ確信度が下がる。
- `inferredBy` で導出主体を区別する — `heuristic`（再現可能）/ `llm`（再現性は低いが文脈を扱える）/
  `catalog`（静的知識）。

`summarizeEvidence()` が `observed` / `inferred` / `assumed` の件数と
推測の平均確信度を集計し、レポートで「どれだけ推測に依っているか」を示す。

---

## 5. 走査の健全性 — `src/types/health.ts`

**検出結果とは独立した軸**として「走査が完走したか」を持ち回す。

このスキャナは部分的失敗を許容する設計なので、LLM呼び出しが失敗しても
`errors` に積んで続行する。だが**検出件数だけを見ると、認証エラー・ネットワーク断・
予算超過・安全分類器の拒否でタスクが全滅しても「検出0件」になる**。

実際にAPIキー未設定で走らせると、12タスク全滅・検出0件でも `--fail-on high` が
終了コード0を返し、レポートには「対応を要する脆弱性は検出されませんでした」と出ていた。
本ツールが掲げる「検出されなかった≠安全」を、ツール自身が破っていた。

②は `AnalysisStats`（レンズ×チャンク単位の `total` / `succeeded` / `failed` / `refused` /
`fromCache` / `budgetExhausted`）を返し、`assessAnalysisHealth()` が `ScanHealth` を算出する。
判定の順序に意味がある:

1. **未走査タスクが残っている**（`total` と実行結果の差 > 0。予算切れで打ち切られた）→ `failed`。
   見ていない範囲があることが確定しているので、失敗率より優先する
2. 失敗率が50%超 → `failed`
3. 分析対象が0件（空リポジトリ・全除外・レンズ0件）→ `degraded`。
   失敗ではないが「見た結果0件」とも言えない
4. 1件でも失敗・拒否 → `degraded`
5. 検出パスは完走し**自己検証パスだけ**予算切れ → `degraded`。
   走査範囲は欠けていないので `failed` にはしない
6. それ以外 → `complete`

`zeroFindingsIsMeaningful` が true になるのは `complete` のときだけで、
これがCIゲートとレポート文言の両方を切り替える。
自己検証パスの失敗は検出範囲を狭めず確信度を控えめに下げるだけなので、
`AnalysisStats` には含めず `errors` の記録に留める。

### CIゲート — `src/reporter/gate.ts`

独立した2軸で判定する。

| コード | 意味 | CI側の対応 |
|---|---|---|
| `0` | 完走し、閾値以上の検出なし | 進める |
| `1` | 閾値以上の検出あり | トリアージ |
| `2` | 引数・設定などツール自体のエラー | コマンドを直す |
| `3` | **走査が完走しなかった** | 認証・ネットワーク・予算を直して再実行 |

`1` と `3` を分けているのは、CI側の対応が別だから。

健全性の判定は**検出件数より先**に評価し、`failOn` からは独立して効く。
`failOn: 'never'` は「検出結果でビルドを落とさない」という指定であって、
「壊れた走査を成功として報告してよい」という指定ではない。
無効化は `failOnIncompleteScan: false`（`--no-fail-on-incomplete`）のみ。

レポート側も同じ判定を参照する。未完走時は「検出されませんでした」を出さず、
件数より前に「判定できていない」ことを言う。CLI・Markdown・HTMLは冒頭に警告ブロック、
SARIFは `executionSuccessful: false` と通知の先頭、JSONは `result.health`。

---

## 6. 横断的関心事

### LLMアダプタ — `src/llm/client.ts`

全ステージはこのアダプタ経由でのみLLMを呼ぶ。集約している関心事:

- **構造化出力の強制** — `messages.parse()` + `zodOutputFormat()`。
  SDKの `zodOutputFormat` は **`zod/v4`** のスキーマを要求するので、
  各ステージのスキーマも必ず `import * as z from 'zod/v4'` から作る
- **プロンプトキャッシュ** — 安定した system プロンプトを前方に置き `cache_control` を付ける。
  可変部分は user 側に置く
- **トークン予算上限** — 超過したら以降の呼び出しを打ち切り、それまでの結果を返す
- **結果キャッシュ** — `.grimoire/cache`。キーは
  sha256(cacheKey + systemプロンプト + モデル名)。分析タスクの `cacheKey` には
  ファイル内容ハッシュ・レンズID・チャンク識別子が入るので、変更のないコードは再分析されない。
  キャッシュ内容も読み出し時にスキーマ検証する（スキーマ変更後の古い結果を弾くため）
- **拒否(refusal)時のフォールバック** — 脆弱性スキャナーはまさにサイバーセキュリティ領域の
  入力を送るため、安全分類器が正当な解析を稀に拒否しうる。拒否は
  HTTP 200 + `stop_reason: 'refusal'` で返るので、**content を読む前に必ず
  `stop_reason` を確認する**。拒否されたらフォールバックモデルで再試行する

失敗は例外ではなく判別可能な結果型で返す
（`refusal` / `budget-exhausted` / `error` を呼び出し側が区別できるように）。

モデルは既定 `claude-opus-5`、拒否時のフォールバックが `claude-opus-4-8`。
`effort` は `low` / `medium` / `high` / `xhigh` / `max`（既定 `high`）。

### 並列実行 — `src/llm/pool.ts`

`mapPool` によるワーカープール。同時実行数は設定可能（既定4）。
④⑤はデータ依存がないので `Promise.all` で並列に走らせる。
共有する `LlmClient` の可変状態は使用量カウンタと予算判定だけなので並行実行しても壊れない
（予算打ち切りの精度がわずかに落ちるだけ）。その代わり進捗フックの呼び出し順は乱れる。

### 設定 — `src/types/config-spec.ts` / `src/config/`

`CONFIG_SPEC` が設定フィールドの**単一の定義元**で、そこから派生するもの:

- `DEFAULT_CONFIG` — 既定値
- `PATH_KEYS` — リポジトリ内へ封じ込めるキー一覧（`kind: 'path'` から導出）
- `PathSources` — パス系設定の出所の型
- `.grimoire.yml.example` — サンプル設定（`config/example.ts` が生成）

以前は `config/index.ts` に手書きの allowlist があり、
新しいパス設定を足したのにそちらへ足し忘れると
**サニタイズも出所記録も素通りする値が下流へ流れる**構造だった。
「足し忘れ＝デフォルト許可」を「足し忘れ＝コンパイルエラー」に変えるのがこの spec の目的。

型の網羅性は `types/config.ts` 末尾で**片方向に**検査する。
`satisfies Record<keyof VulnScanConfig, FieldSpec>` を使わないのは
`VulnScanConfig → PathSources → PathKey → CONFIG_SPEC` と型が循環するため。
両方が定義され終わった位置で `_Eq<ConfigKey, Exclude<keyof VulnScanConfig, 'pathSources'>>` を
検査し、さらに架空フィールドを足した型で検査が false になることを
`@ts-expect-error` で固定している（検査が素通りするようになれば
「未使用の @ts-expect-error」として tsc が落ちる）。

サンプル設定と既定値の一致もテストで固定してある。以前サンプルを手書きしていて
`architecture` / `heatmap` / `minInferenceConfidence` が漏れていた。

### 進捗表示 — `src/cli/animation.ts`

魔法陣／詠唱モチーフのアニメーション。実用性のための制約を守っている:

1. **stderr にしか書かない** — stdout はレポート本体の出力先であり、
   `grimoire -f json > out.json` を壊してはならない
2. **TTYでなければアニメーションを出さない** — CIログをエスケープシーケンスで
   汚さないため、非TTYでは1行ずつのプレーンなログへ落とす
3. `quiet` なら完全に沈黙し、`color=false` なら SGR を一切出さない
4. **終了・エラー・シグナルのいずれでも必ずカーソルを戻す**。
   カーソルを隠したまま死ぬと端末が壊れたままになる。`stop()` は冪等
5. 更新は12fps（80ms）。端末とCPUを無駄に焼かない

---

## 7. セキュリティ設計（自分自身の安全性）

**スキャン対象リポジトリは攻撃者が内容を制御しうる未信頼入力である。**
サードパーティのリポジトリ、フォーク、CIの未信頼PRブランチを解析する運用を想定する。

**設定ファイルの信頼境界。**
`.grimoire.yml` はスキャン対象リポジトリの中にあるファイルなので未信頼として扱う。
特にパス系設定（`baselinePath` / `ignorePath`）はそのまま使うと任意ファイルの
読み書きに直結するため、リポジトリ内へ封じ込める。絶対パスや `..` による脱出は
警告を出して既定値へフォールバックする（例外では落とさず、スキャンは続行する）。

一方CLIフラグ由来の値はオペレータが明示指定したものなので信頼する。
どちらの出所かを `config.pathSources` に `'default' | 'config-file' | 'cli'` として記録し、
**リポジトリ外を許すのは `'cli'` のときだけ**。出所の詐称を防ぐため、
`pathSources` は設定ファイルから指定できない（読み込み時に捨てる）。

パス解決は `util/path.ts` の `resolveInside` に一元化している。

**レポート出力のエスケープ。**
Findingのタイトル・ファイルパス・依存パッケージ名・LLMの生成文はすべて未信頼入力である。
Markdownフォーマッタは `<details>` などの生HTMLを出力しており、
HTMLを有効にしたレンダラで表示される前提なので、埋め込む値は必ずエスケープする
（本文 / 表のセル / コードスパン / URL で別のエスケープ関数を使い分ける。
URLは `^https?://` を検証してから出す）。

**エラーメッセージ。**
設定ファイルの読み込み失敗などの例外メッセージは絶対パスやファイル内容の抜粋を
含みうるため、レポートには載せない。

**ネットワークアクセス。**
CWEカタログは同梱で実行時にネットワークへ出ない。外部通信は
Anthropic API と OSV.dev のみ。OSVは失敗しても `errors` に積んで継続する。

---

## 8. ディレクトリ構成（実際）

```
vulnscan/
  src/
    cli/            # コマンド定義・オプション・進捗アニメーション
    core/           # オーケストレーター（STAGE_SEQUENCE）
    context/        # ① 走査・言語・依存・シンボル・呼び出しグラフ・信頼境界
    analyzer/       # ② チャンク分割・文脈付与・レンズ・自己検証・絞り込み
    llm/            # LLMアダプタ・ワーカープール
    vuln/           # ③ 正規化・CVSS・CWEカタログ・OSV・ベースライン・抑制
    killchain/      # ④ 候補絞り込み・連鎖推論・ATT&CKマッピング・スコアリング
    architecture/   # ⑤ 事実収集・骨格・推測・引用検証
    heatmap/        # ⑥ 実測層・想定層・死角・カタログアダプタ
    reporter/       # ⑦ 集計・優先順位・文章化・5フォーマッタ・CIゲート
    types/          # 共有型（context / finding / killchain / architecture /
                    #        heatmap / evidence / health / config / report）
    util/           # path / num / severity（横断ヘルパ）
  scripts/          # CWEカタログ生成・データ同梱
```

規模: 実装107ファイル・約25,000行、テスト42ファイル・886件。

**共有不変条件は1箇所に置く。** 深刻度の順序（`util/severity.ts`）、
CWE ID正規化（`vuln/catalog.ts`）、パス正規化（`util/path.ts`）、
`clamp01` / `round1`（`util/num.ts`）はいずれも定義元が1つ。
以前はこれらが複数ステージに散在しており、
たとえば深刻度の順序を変えると3ステージで挙動が食い違う状態だった。

**バレルには外から呼ばれる入口だけを並べる。** 内部ヘルパまで並べると
公開APIに見えてしまい、シグネチャを変えるたびに
「外部利用があるかもしれない」という判断が必要になる。
テストや内部モジュールは具象モジュールを直接importする。

---

## 9. 技術選定（実際）

| 用途 | 採用 | 備考 |
|---|---|---|
| 構文解析 | 自前ヒューリスティック | tree-sitter は**採用せず**。ネイティブ依存を避けた（§3①） |
| LLM | `@anthropic-ai/sdk` ^0.115.0 | `messages.parse()` / `zodOutputFormat()` |
| スキーマ検証 | zod（**`zod/v4`**） | SDKの `zodOutputFormat` が v4 を要求する |
| CWE | MITRE CWE 959件を同梱 | OWASP/cwe-sdk-javascript 由来。オフライン |
| 依存CVE照合 | OSV.dev API | 失敗許容 |
| CLI | commander | |
| レポート | SARIF 2.1.0 | `security-severity` / `partialFingerprints` |
| テスト | vitest | 886件 |

**バージョン指定の注意**: `@anthropic-ai/sdk` は 0.x なので
キャレット（`^0.68.0`）はマイナーを固定してしまう。
`messages.parse()` を使うには `^0.115.0` 以上が必要。

SARIF の `partialFingerprints` というキー名は仕様上の名残だが、
GitHub のアラート継続性のために意図して従来名を維持している。

---

## 10. 未実装

構想にあったが実装していないもの。将来やるならここから。

- **差分スキャン** — `GitContext.changedFiles` は収集しているが、
  走査対象の絞り込みには使っていない。CIでの高速化に効くはず
  （`--diff` 相当のフラグと、ベースの解決規則を決める必要がある）
- **レート制限の明示的な制御** — SDKの `maxRetries: 3` に任せており、
  独自のバックオフやトークンバケットは持たない
- **`dependency` レンズ** — レンズIDとしては定義してあるが②では走らせず、
  依存脆弱性は③のOSV照合が担当する。②に入れると同じ問題を二重に報告することになる
- **深く解析できる言語の拡張** — 現在9言語。
  正規表現ベースなので、言語ごとに `mask.ts` の構文プロファイルと
  `symbols.ts` の定義パターンを足す必要がある
