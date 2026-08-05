# OWASP Benchmark v1.2 で GRIMOIRE を測る

OWASP Benchmark は、意図的に脆弱性を仕込んだ Java サーブレット 2,740 件と、
その1件ずつが**本物か偽物かを記した真値CSV**からなるスキャナ評価用スイートです。
検出数を数えるだけでなく、誤検知率まで含めて採点できます。

この文書は、ダウンロードからスキャン、採点までを通しで行う手順です。
実際にこのリポジトリで計測した値を載せています。

---

## 0. 先に知っておくこと

**測る前に、何が測れないかを確定させます。** ベンチマークの11カテゴリのうち、
GRIMOIRE のレンズが担当しているのは10カテゴリです。

| カテゴリ | CWE | 件数(真/偽) | 担当レンズ |
| --- | --- | --- | --- |
| cmdi | 78 | 126 / 125 | injection |
| crypto | 327 | 130 / 116 | crypto-secrets |
| hash | 328 | 129 / 107 | crypto-secrets |
| ldapi | 90 | 27 / 32 | injection |
| pathtraver | 22 | 133 / 135 | injection |
| securecookie | 614 | 36 / 31 | web-output |
| sqli | 89 | 272 / 232 | injection |
| **trustbound** | **501** | **83 / 43** | **なし** |
| weakrand | 330 | 218 / 275 | crypto-secrets |
| xpathi | 643 | 15 / 20 | injection |
| xss | 79 | 246 / 209 | web-output |

`trustbound`（CWE-501: Trust Boundary Violation）は、どのレンズも担当していません。
ここが0検出なのは精度の問題ではなく**設計上の対象外**です。
採点スクリプトは対象内合計と全体合計を別々に出すので、この分を混ぜずに読めます。

ここから2つ決まります。

- **必要なレンズは3つだけ**です。`authz` と `deserialization-ssrf` に対応するカテゴリは
  ベンチマークに1件もありません。この2つを外せば LLM 呼び出しが4割減り、
  スコアは1点も動きません。
- **満点は Youden 指数 1.0 ではありません**。対象内合計で見てください。

コマンドで確認する場合:

```bash
# リポジトリルートで、npm run build 済みのこと
node --input-type=module -e "
import { lensForCwe } from './vulnscan/dist/vuln/catalog.js';
for (const c of ['CWE-78','CWE-327','CWE-328','CWE-90','CWE-22','CWE-614','CWE-89','CWE-501','CWE-330','CWE-643','CWE-79'])
  console.log(c.padEnd(9), '->', lensForCwe(c) ?? '(なし)');
"
```

---

## 1. 落とす

**`--branch 1.2` は失敗します。** このリポジトリに `1.2` というタグは存在せず、
あるのは `1.0` / `1.1` / `1.1final` / `1.2beta` だけです。
v1.2 は既定ブランチの内容そのもので、`pom.xml` に `<version>1.2</version>` と書かれています。

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git
cd BenchmarkJava

# バージョンの確認（1.2 であること）
grep -m1 '<version>' pom.xml
ls expectedresults-1.2.csv
```

既定ブランチは依存更新で動き続けます。計測を再現可能にするなら、
チェックアウトしたコミットを記録するか、固定してください。

```bash
git rev-parse HEAD    # この値をスコアと一緒に残す
```

テストコード本体（`src/main/java/org/owasp/benchmark/testcode/`）は
v1.2 リリース以降変わっていないので、依存更新はスコアに影響しません。

---

## 2. 走査範囲を絞る

リポジトリ全体には HTML が約2,900件含まれていて、そのままだと走査対象の半分が
ベンチマークと無関係なファイルになります。実測値:

| 範囲 | ファイル | チャンク | 3レンズ | 5レンズ |
| --- | ---: | ---: | ---: | ---: |
| 既定（全ファイル） | 5,665 | 5,959 | 17,877 タスク | 29,795 タスク |
| testcode のみ | 2,740 | 2,740 | **8,220 タスク** | 13,700 タスク |
| testcode + helpers | 2,761 | 2,824 | 8,472 タスク | 14,120 タスク |

範囲を testcode に絞り、レンズを3つにすれば **29,795 → 8,220 タスク（72%減）**、
かつ採点結果は変わりません。

`--include` に相当する CLI フラグは無いので、対象リポジトリのルートに
`.grimoire.yml` を置きます。

```bash
cat > .grimoire.yml <<'YAML'
scan:
  include:
    - "src/main/java/org/owasp/benchmark/testcode/**"
  lenses: [injection, crypto-secrets, web-output]
YAML
```

> `helpers/` を含めるかは、測りたいものによります。含めると
> `DatabaseHelper` などの実装をLLMが読めるようになり、到達性の判定が変わりえます。
> ただしそこで出た検出はテストケース外なので採点には入りません（スクリプトが件数だけ報告します）。
> **含める・含めないを揃えずに2回の結果を比べないでください。**

---

## 3. 試走してから本番

いきなり8,220タスクを回さず、100ファイルで試して1タスクあたりの実コストを測ります。

```bash
# 試走: BenchmarkTest000*.java の99件（297タスク）
cd /path/to/BenchmarkJava
cat > .grimoire.yml <<'YAML'
scan:
  include:
    - "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest000*.java"
  lenses: [injection, crypto-secrets, web-output]
YAML

grimoire . \
  --format json --verbose \
  --no-architecture --no-heatmap --no-kill-chain \
  --output /tmp/bench-pilot.json
```

各フラグの理由:

| フラグ | 理由 |
| --- | --- |
| `--verbose` | **必須。** これが無いと JSON から info レベルの検出が落ち、再現率が過小に出ます |
| `--no-architecture` | 採点に使わない。LLM 1回分の節約 |
| `--no-heatmap` | アーキテクチャ推定が無ければどのみち生成されない |
| `--no-kill-chain` | 採点に使わない。グループ数ぶんの LLM 呼び出しを削れる |
| `--lens`（yml側） | `authz` / `deserialization-ssrf` は対象カテゴリが無い |

**自己検証（`--no-self-verify`）は切らないでください。** 誤検知を落とす主対策なので、
切ると FPR が上がってスコアが下がります。速度と引き換えに何を失うかを見たいとき以外は
既定のままにします。

試走の結果からコストを見積もります。

```bash
node -e "
  const r = require('/tmp/bench-pilot.json');
  const s = r.result.summary;
  console.log('health:', r.result.health.state);
  console.log('findings:', r.result.findings.length);
  console.log(JSON.stringify(s.tokenUsage ?? s, null, 2));
"
```

297タスク分の実測が出るので、8,220 タスクへは約27.7倍で外挿できます。
ここで納得してから本番を回してください。

---

## 4. 本番スキャン

```bash
cd /path/to/BenchmarkJava
cat > .grimoire.yml <<'YAML'
scan:
  include:
    - "src/main/java/org/owasp/benchmark/testcode/**"
  lenses: [injection, crypto-secrets, web-output]
YAML

grimoire . \
  --format json --verbose \
  --no-architecture --no-heatmap --no-kill-chain \
  --concurrency 8 \
  --budget 20000000 \
  --output /tmp/bench-full.json
```

- `--concurrency` はレート制限とのにらみ合いです。429 が出るなら下げます。
- `--budget` は出力トークンの上限です。**使い切ると走査は途中で止まり、
  `health` が `degraded` になります。** そのときの検出0件は「無い」ではなく
  「見ていない」なので、採点スクリプトが警告を出します。
- `--update-baseline` は使わないでください。走査が完走しなくてもベースラインを
  上書きしてしまう既知の不具合があります（`docs/getting-started.md` 参照）。

終了コードの読み方:

| コード | 意味 | 採点してよいか |
| --- | --- | --- |
| 0 / 1 | 完走した（1は閾値以上の検出あり） | ✅ |
| 2 | 引数・設定のエラー | ❌ コマンドを直す |
| 3 | **走査が完走しなかった** | ❌ APIキー・予算・ネットワークを直して再実行 |

`3` のまま採点すると、実力ではなく途中で止まった位置を測ることになります。

---

## 5. 採点する

```bash
node /path/to/vulnscan/scripts/benchmark-score.mjs \
  --expected /path/to/BenchmarkJava/expectedresults-1.2.csv \
  --report   /tmp/bench-full.json
```

出力例（形式を示すための架空の値）:

```
テストケース 2740 件 / Finding 124 件

カテゴリ        CWE     TP   FN   FP   TN     TPR     FPR   Youden
────────────────────────────────────────────────────────────────────
cmdi             78    0  126    0  125    0.0%    0.0%     0.0%
...
sqli             89  100  172   10  222   36.8%    4.3%    32.5%
trustbound      501    0   83    0   43    0.0%    0.0%     0.0% ※
────────────────────────────────────────────────────────────────────
対象内合計                112 1220   10 1272    8.4%    0.8%     7.6%
全体合計                 112 1303   10 1315    7.9%    0.8%     7.2%
```

採点規則:

- テストケース1件 = ファイル1つ。そのファイルに**カテゴリの一致する検出**が1件でもあれば検出扱い
- TPR = TP/(TP+FN)、FPR = FP/(FP+TN)、**Youden 指数 = TPR − FPR**
- ランダムに「全部脆弱」と答えるツールは TPR 100% / FPR 100% で Youden 0。
  ここが基準線です

オプション:

| オプション | 用途 |
| --- | --- |
| `--min-confidence 0.7` | 確信度でふるいにかけたときのスコア変化を見る |
| `--strict-cwe` | 近傍CWEを認めず、カテゴリの正式CWEだけで採点する |
| `--json` | 集計結果を機械可読で出す（回帰比較用） |

**近傍CWEの扱いは本ツール側の解釈です。** 既定では、たとえば LDAP インジェクションに
汎用の CWE-943 が返ってきた場合も `ldapi` として数えます。スキャナが正式CWEちょうどを
返すとは限らないためですが、これはベンチマークの定義ではありません。
厳しく測るなら `--strict-cwe` を付け、両方の値を併記してください。
対応表は `scripts/benchmark-score.mjs` の `CWE_ALIASES` にあり、編集できます。

---

## 6. 結果の読み方と限界

**このベンチマークで分かること**は、「教科書的な形で書かれた1ファイル完結の脆弱性を、
偽物と区別して指摘できるか」だけです。次のことは分かりません。

- **ファイルをまたぐ脆弱性**。全テストケースが単一ファイルに閉じており、
  GRIMOIRE の売りである複数箇所の連結（キルチェーン）は測れません。
  今回 `--no-kill-chain` で切っているのも同じ理由です
- **実運用コードでの誤検知率**。テストケースの「偽物」は、
  正しくサニタイズした版という人工的な作りです。実際のコードの雑多さとは違います
- **依存パッケージの既知CVE**。ベンチマークの対象外です

そのうえで、**回帰検出には有効**です。プロンプトやレンズを変えたときに
`--json` の出力を保存して比較すれば、改善したつもりの変更が
どのカテゴリを壊したかが件数で分かります。

---

## 付録: このベンチマークで見つかった GRIMOIRE 側の欠陥

**サーブレットの入口を1つも検出できていませんでした。**

Java の `http-route` 検出は Spring（`@RequestMapping` 系）と JAX-RS（`@Path`）だけを
見ており、Servlet API の `@WebServlet` 注釈と `doGet` / `doPost` を見ていませんでした。
OWASP Benchmark は全件がサーブレットなので、リポジトリ全体で http-route が
**3件**しか出ていませんでした（フレームワーク検出は Servlet API を認識していたので、
「フレームワークは分かっているのに入口は0」というちぐはぐな状態でした）。

入口は信頼境界の解析と、injection レンズが source→sink の到達性を示す土台なので、
この状態で測ると本来の実力より低く出ます。

修正後、同じ範囲で **8,220件**（2,740ファイル × `@WebServlet` + `doGet` + `doPost`）を
検出するようになりました。`src/context/entrypoints.ts` と、
`src/context/manifest.test.ts` の2件のテストが該当します。
