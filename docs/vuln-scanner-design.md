# ソースコード脆弱性スキャナー 設計書

LLMベースの検出エンジンを中核に据えた、CLI型のソースコード脆弱性スキャナー。
TypeScript / Node.js で実装する。

---

## 1. 設計方針

- **LLMベース中心**: tree-sitter で構造情報を抽出し、文脈を付与したうえで LLM に脆弱性判定させる。ルールベース（SAST）は依存脆弱性照合など補助的に使う。
- **パイプライン構成**: 5機能を段として直列に繋ぎ、共有データモデル `ScanContext` を各段が育てる。段は疎結合で、単体テスト・差し替えが容易。
- **誤検知の抑制を最優先**: LLMスキャナー最大の課題。データフロー根拠の要求・自己検証パス・confidenceスコアで対処する。
- **コストと再現性の制御**: チャンク単位キャッシュ、差分スキャン、ベースライン比較、トークン予算上限を組み込む。

---

## 2. パイプライン全体

```
リポジトリ
   │
   ▼
① Context Collector ──► ScanContext（リポジトリモデル）
   │
   ▼
② Analyzer (LLM)     ──► RawFinding[]
   │
   ▼
③ Vulnerability Store ──► Finding[]（正規化・重複統合・差分）
   │
   ▼
④ Kill Chain Analyzer ──► AttackChain[]
   │
   ▼
⑤ Reporter           ──► SARIF / JSON / HTML / Markdown / CLI + exit code
```

オーケストレーターが各段を順に呼び出し、進捗・エラー・部分結果を管理する。

---

## 3. 各機能の詳細設計

### ① コンテキスト収集（Context Collector）

LLMに良質な文脈を渡すために、リポジトリを解析して正規化する。

**収集項目**
- リポジトリ構造・ファイル一覧（`.gitignore` 尊重）
- 言語検出／フレームワーク検出（`package.json`, `requirements.txt`, `go.mod` 等）
- 依存関係マニフェスト（軽量SBOM）→ ③でOSVと照合
- **エントリポイント**：HTTPルート、CLIハンドラ、メッセージ受信、`main`
- **信頼境界（trust boundary）**：ユーザー入力の入口（source）と危険な出力先（sink）候補
- 設定ファイル・環境変数・シークレット参照箇所
- tree-sitter による AST → シンボル表・呼び出しグラフ（call graph）
- Git メタデータ（変更履歴・blame）→ 差分スキャンモードで使用

**出力: `ScanContext`**
```ts
interface ScanContext {
  repoRoot: string;
  languages: LanguageInfo[];
  frameworks: FrameworkInfo[];
  dependencies: Dependency[];      // name, version, ecosystem
  files: SourceFile[];             // path, lang, hash
  symbols: SymbolTable;            // 定義・参照
  callGraph: CallGraph;            // 関数間の呼び出し
  entryPoints: EntryPoint[];       // route/handler/main
  trustBoundaries: TrustBoundary[];// source/sink 候補
  git?: GitContext;                // 差分・blame
}
```

### ② ソースコード分析（Analyzer / LLM中心）

`ScanContext` を入力に、LLMで脆弱性を判定する。中核。

**処理ステップ**
1. **チャンク分割**: tree-sitter でシンボル（関数/メソッド/クラス）単位に分割。行スライスではなく構文単位にすることで意味が壊れない。
2. **文脈検索（retrieval）**: 各チャンクに、呼び出し元/呼び出し先・インポート型・関連する信頼境界情報を添付。コンテキストウィンドウを有効活用する。
3. **多視点プロンプト**: 単一の万能プロンプトではなく、観点別レンズで走査する。
   - インジェクション系（SQLi / コマンド / パス / テンプレート）
   - 認証・認可（IDOR / 権限昇格 / 欠落チェック）
   - 暗号・シークレット（ハードコード鍵 / 弱いアルゴリズム）
   - デシリアライズ / SSRF / XXE / オープンリダイレクト
   - Web出力（XSS / CSRF）
4. **構造化出力**: JSON Schema（zod検証）で `RawFinding` を強制。位置・CWE・severity・confidence・**データフロー根拠**を必須にする。
5. **自己検証パス（adversarial verify）**: 各候補に対し「これは本当に悪用可能か、到達経路はあるか」を別プロンプトで再検証。confidenceが低い/反証されたものを落とす。→ 誤検知の主対策。
6. **重複統合**: 同一箇所・同一CWEをマージ。

**出力: `RawFinding`**
```ts
interface RawFinding {
  cwe: string;                     // 例: CWE-89
  category: string;                // OWASP系カテゴリ
  severity: 'critical'|'high'|'medium'|'low'|'info';
  confidence: number;              // 0..1（自己検証後）
  location: { file: string; startLine: number; endLine: number };
  evidence: string;                // 該当コード抜粋
  dataFlow?: DataFlowStep[];       // source→sink の根拠
  reasoning: string;               // なぜ脆弱か
  remediation: string;             // 修正方針
}
```

### ③ 脆弱性情報管理（Vulnerability Store / Knowledge Base）

生Findingを正規化し、知識ベースで補強・追跡する。

**処理**
- **正規化**: severity/CWE/OWASPカテゴリを共通スキーマに揃える。CVSS風スコアを算出。
- **知識ベース照合**:
  - CWE/OWASP Top 10 タクソノミで分類補完
  - 依存脆弱性は **OSV.dev** API で CVE 照合（②を通さず①のSBOMから直接生成）
- **重複・相関統合**: 全Finding横断で近接・同種をまとめる。
- **永続化・トリアージ**:
  - ベースライン（前回スキャン結果）保存
  - 差分算出（**new / fixed / persistent**）
  - 抑制リスト `.vulnignore`（誤検知・受容リスク）
  - トリアージ状態（open / confirmed / false-positive / accepted）

**出力: `Finding[]`（正規化済み）** — `RawFinding` に `id`, `cve?`, `cvssScore`, `status`, `firstSeen`, `fingerprint` を付与。

### ④ キルチェーン分析（Kill Chain Analyzer）

個別Findingを**攻撃経路（多段シナリオ）**へ連鎖させる。単体では中リスクでも、連鎖でRCEに至るものを浮かび上がらせる。

**処理**
- Finding + 呼び出しグラフ + 信頼境界を材料に、LLMで **source → 中間ステップ → sink（影響）** を推論。
- 各ステップを **サイバーキルチェーン / MITRE ATT&CK** 段階にマッピング（偵察・初期侵入・実行・権限昇格・水平移動・持出）。
- **再優先度付け**: 「SSRF → メタデータ endpoint → 資格情報漏洩 → 横展開」のような連鎖は、孤立したhighより上位に。
- 前提条件・成立可能性（likelihood）・想定影響（impact）を付与。

**出力: `AttackChain`**
```ts
interface AttackChain {
  id: string;
  title: string;                   // 例: "SSRF経由の資格情報奪取と横展開"
  steps: ChainStep[];              // findingId, attckTactic, description
  entryPoint: string;
  impact: string;                  // 最終的な影響
  likelihood: 'high'|'medium'|'low';
  priorityScore: number;           // 連鎖を考慮した総合スコア
}
```

### ⑤ レポーター（Reporter）

Finding と AttackChain を各種形式に整形。CIゲートも担う。

**出力形式**
- **CLI**: 色付きサマリ（severity別件数・上位チェーン）
- **SARIF**: GitHub Code Scanning 連携用（PRアノテーション）
- **JSON**: 機械可読・後続処理用
- **HTML / Markdown**: 人間向け詳細レポート（エグゼクティブサマリ + 詳細 + 修正指針 + SBOM）

**CIゲート**
- `--fail-on <severity>` で閾値超過時に非ゼロ exit code。
- 差分モードでは「新規Findingのみ」でゲートも可能。

---

## 4. 横断的関心事（基盤）

- **LLM Adapter**: `@anthropic-ai/sdk` をラップ。構造化出力（zod）・レート制限・リトライ・**トークン予算上限**・チャンク単位キャッシュ（ハッシュ一致でスキップ）。
- **並列実行**: チャンク分析はワーカープール。同時実行数を設定可能。
- **設定ファイル** `.vulnscan.yml`: モデル・観点レンズ・severity閾値・除外パス・並列度・予算。
- **差分スキャン**: 変更ファイルのみ解析（`git diff`）→ コスト削減・CI高速化。

---

## 5. ディレクトリ構成（案）

```
src/
  cli/            # コマンド定義・エントリ（commander/yargs）
  core/           # オーケストレーター（パイプライン制御）
  context/        # ① 各種コレクタ・tree-sitter
  analyzer/       # ② チャンク分割・レンズ・自己検証
  llm/            # LLMアダプタ・プロンプト・スキーマ
  vuln/           # ③ 正規化・知識ベース・OSV・ストア
  killchain/      # ④ 連鎖推論・ATT&CKマッピング
  reporter/       # ⑤ SARIF/JSON/HTML/CLI フォーマッタ
  config/         # 設定ロード
  types/          # 共有型（ScanContext, Finding, AttackChain...）
```

---

## 6. 主要データフロー型（共有モデル）

`ScanContext` → `RawFinding[]` → `Finding[]` → `AttackChain[]` → `Report`。
各段は前段の出力型のみに依存し、内部実装は差し替え可能に保つ。

---

## 7. 技術選定

| 用途 | 採用候補 |
|---|---|
| AST/構文解析 | tree-sitter（`web-tree-sitter` or node bindings） |
| LLM | `@anthropic-ai/sdk`（構造化出力） |
| スキーマ検証 | zod |
| 依存CVE照合 | OSV.dev API |
| CLI | commander または yargs |
| レポート | SARIF 2.1.0 スキーマ準拠 |
| テスト | vitest |

---

## 8. 実装フェーズ（推奨順）

1. **MVP**: Context Collector（ファイル走査 + 言語検出）→ 単一レンズのLLM分析 → CLI/JSON出力。1言語（例: TypeScript/JS）に限定して縦に通す。
2. **精度**: 多視点レンズ + 自己検証パス + confidenceスコア。
3. **管理**: 正規化・ベースライン差分・`.vulnignore`・OSV依存照合。
4. **キルチェーン**: 呼び出しグラフ連携 + 連鎖推論 + ATT&CKマッピング。
5. **統合**: SARIF出力 + CIゲート + 差分スキャン + キャッシュ。

まず縦に一本通してから横（言語・観点）へ広げるのが安全。
