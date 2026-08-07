#!/usr/bin/env node
/**
 * OWASP Benchmark v1.2 の真値CSVと GRIMOIRE のJSONレポートを突き合わせて採点する。
 *
 *   node scripts/benchmark-score.mjs \
 *     --expected /path/to/BenchmarkJava/expectedresults-1.2.csv \
 *     --report   /path/to/report.json
 *
 * 採点規則（OWASP Benchmark の定義に合わせる）:
 *   - テストケース1件 = ファイル1つ（BenchmarkTestNNNNN.java）
 *   - そのファイルに「カテゴリの一致するFinding」が1件でもあれば検出とみなす
 *   - 検出 かつ 真の脆弱性  → TP
 *     未検出 かつ 真の脆弱性 → FN
 *     検出 かつ 偽の脆弱性  → FP
 *     未検出 かつ 偽の脆弱性 → TN
 *   - TPR = TP/(TP+FN)、FPR = FP/(FP+TN)、Youden指数 = TPR - FPR
 *
 * Node 標準ライブラリのみ。新しい依存は足さない。
 */

import { readFileSync } from 'node:fs';

// ---- ベンチマークのカテゴリ定義（expectedresults-1.2.csv の実データ由来） ----
/** カテゴリ → 正式CWE */
const CATEGORY_CWE = {
  cmdi: 78,
  crypto: 327,
  hash: 328,
  ldapi: 90,
  pathtraver: 22,
  securecookie: 614,
  sqli: 89,
  trustbound: 501,
  weakrand: 330,
  xpathi: 643,
  xss: 79,
};

/**
 * CWE → カテゴリの逆引き。
 *
 * ここは**本ツール側の解釈**であって、ベンチマークの定義ではない。
 * スキャナが正式CWEの近傍を返すこと（LDAPインジェクションに CWE-90 ではなく
 * 汎用の CWE-943 を返す等）があるため、近傍CWEも同じカテゴリへ寄せている。
 * 厳密に正式CWEだけで採点したいなら --strict-cwe を付ける。
 */
const CWE_ALIASES = {
  cmdi: [77, 88],
  crypto: [310, 326],
  hash: [916],
  ldapi: [943],
  pathtraver: [23, 35, 36],
  securecookie: [1004],
  sqli: [564, 943],
  weakrand: [335, 338],
  xpathi: [943],
  xss: [80, 83, 85, 87],
  trustbound: [],
};

/** GRIMOIRE のレンズが1つも担当していないカテゴリ（= 設計上の対象外） */
const OUT_OF_LENS_SCOPE = new Set(['trustbound']);

function parseArgs(argv) {
  const out = { minConfidence: 0, strictCwe: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--expected') out.expected = argv[++i];
    else if (a === '--report') out.report = argv[++i];
    else if (a === '--min-confidence') out.minConfidence = Number(argv[++i]);
    else if (a === '--strict-cwe') out.strictCwe = true;
    else if (a === '--json') out.json = true;
    else if (a === '--help' || a === '-h') out.help = true;
    else throw new Error(`不明な引数: ${a}`);
  }
  return out;
}

const USAGE = `使い方:
  node scripts/benchmark-score.mjs --expected <expectedresults-1.2.csv> --report <report.json>

オプション:
  --min-confidence <0..1>  この確信度未満のFindingを捨ててから採点する
  --strict-cwe             近傍CWEを認めず、カテゴリの正式CWEだけで採点する
  --json                   集計結果をJSONで出す（人間向けの表は出さない）
`;

/** 真値CSVを読む。1行目はヘッダコメント */
function readExpected(path) {
  const lines = readFileSync(path, 'utf8').split('\n');
  const cases = new Map();
  for (const line of lines.slice(1)) {
    const row = line.trim();
    if (row === '') continue;
    const [name, category, real, cwe] = row.split(',');
    if (name === undefined || category === undefined) continue;
    cases.set(name, {
      category,
      real: real === 'true',
      cwe: Number(cwe),
    });
  }
  return cases;
}

/** JSONレポートから Finding 配列を取り出す */
function readFindings(path) {
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  const findings = parsed?.result?.findings;
  if (!Array.isArray(findings)) {
    throw new Error(
      'レポートの形が想定と違う（result.findings が配列でない）。grimoire -f json の出力を渡しているか確認する。',
    );
  }
  return { findings, health: parsed?.result?.health };
}

/** 'CWE-89' → 89。数字が取れなければ null */
function cweNumber(raw) {
  const m = /(\d+)/.exec(String(raw ?? ''));
  return m === null ? null : Number(m[1]);
}

/** パスから 'BenchmarkTest00008' を取り出す */
function testCaseOf(file) {
  const m = /(BenchmarkTest\d{5})/.exec(String(file ?? ''));
  return m === null ? null : m[1];
}

/** CWE番号 → 該当しうるカテゴリ集合 */
function buildCweIndex(strict) {
  const index = new Map();
  const add = (cwe, category) => {
    const set = index.get(cwe) ?? new Set();
    set.add(category);
    index.set(cwe, set);
  };
  for (const [category, cwe] of Object.entries(CATEGORY_CWE)) {
    add(cwe, category);
    if (strict) continue;
    for (const alias of CWE_ALIASES[category] ?? []) add(alias, category);
  }
  return index;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help === true || args.expected === undefined || args.report === undefined) {
    process.stdout.write(USAGE);
    process.exit(args.help === true ? 0 : 2);
  }

  const cases = readExpected(args.expected);
  const { findings, health } = readFindings(args.report);
  const cweIndex = buildCweIndex(args.strictCwe);

  // ---- Finding をテストケースへ割り当てる ----
  /** テストケース名 → 検出したとみなすカテゴリ集合 */
  const detected = new Map();
  const unmatched = { notTestCase: 0, unmappedCwe: new Map(), belowConfidence: 0 };

  for (const f of findings) {
    if (typeof f?.confidence === 'number' && f.confidence < args.minConfidence) {
      unmatched.belowConfidence++;
      continue;
    }
    const name = testCaseOf(f?.location?.file);
    if (name === null || !cases.has(name)) {
      unmatched.notTestCase++;
      continue;
    }
    const cwe = cweNumber(f?.cwe);
    const categories = cwe === null ? undefined : cweIndex.get(cwe);
    if (categories === undefined) {
      const key = `CWE-${cwe ?? '?'}`;
      unmatched.unmappedCwe.set(key, (unmatched.unmappedCwe.get(key) ?? 0) + 1);
      continue;
    }
    const set = detected.get(name) ?? new Set();
    for (const c of categories) set.add(c);
    detected.set(name, set);
  }

  // ---- カテゴリごとに集計 ----
  const stats = new Map();
  for (const category of Object.keys(CATEGORY_CWE)) {
    stats.set(category, { tp: 0, fn: 0, fp: 0, tn: 0 });
  }
  for (const [name, tc] of cases) {
    const s = stats.get(tc.category);
    if (s === undefined) continue;
    const hit = detected.get(name)?.has(tc.category) === true;
    if (tc.real && hit) s.tp++;
    else if (tc.real) s.fn++;
    else if (hit) s.fp++;
    else s.tn++;
  }

  const rate = (num, den) => (den === 0 ? 0 : num / den);
  const rows = [...stats.entries()]
    .map(([category, s]) => {
      const tpr = rate(s.tp, s.tp + s.fn);
      const fpr = rate(s.fp, s.fp + s.tn);
      return {
        category,
        cwe: CATEGORY_CWE[category],
        ...s,
        tpr,
        fpr,
        youden: tpr - fpr,
        outOfScope: OUT_OF_LENS_SCOPE.has(category),
      };
    })
    .sort((a, b) => a.category.localeCompare(b.category));

  // 全体は「対象外カテゴリを除いた」ものと「含めた」ものの両方を出す。
  // 片方だけ出すと、設計上見ないカテゴリの分だけ不当に低く（または高く）見える。
  const totalOf = (list) => {
    const t = list.reduce(
      (acc, r) => ({
        tp: acc.tp + r.tp,
        fn: acc.fn + r.fn,
        fp: acc.fp + r.fp,
        tn: acc.tn + r.tn,
      }),
      { tp: 0, fn: 0, fp: 0, tn: 0 },
    );
    const tpr = rate(t.tp, t.tp + t.fn);
    const fpr = rate(t.fp, t.fp + t.tn);
    return { ...t, tpr, fpr, youden: tpr - fpr };
  };
  const overallAll = totalOf(rows);
  const overallInScope = totalOf(rows.filter((r) => !r.outOfScope));

  const summary = {
    testCases: cases.size,
    findings: findings.length,
    health: health?.level ?? null,
    strictCwe: args.strictCwe,
    minConfidence: args.minConfidence,
    perCategory: rows,
    overallInScope,
    overallAll,
    unmatched: {
      notTestCase: unmatched.notTestCase,
      belowConfidence: unmatched.belowConfidence,
      unmappedCwe: Object.fromEntries(unmatched.unmappedCwe),
    },
  };

  if (args.json === true) {
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    return;
  }

  const pct = (v) => `${(v * 100).toFixed(1)}%`;
  const out = [];
  out.push(`テストケース ${cases.size} 件 / Finding ${findings.length} 件`);
  if (health != null && health.level !== 'complete') {
    out.push(`⚠ 走査が完走していない（health=${health.level}）。この採点結果は下振れしている。`);
  }
  out.push('');
  out.push('カテゴリ        CWE     TP   FN   FP   TN     TPR     FPR   Youden');
  out.push('─'.repeat(68));
  for (const r of rows) {
    const mark = r.outOfScope ? ' ※' : '';
    out.push(
      `${r.category.padEnd(14)} ${String(r.cwe).padStart(4)} ` +
        `${String(r.tp).padStart(4)} ${String(r.fn).padStart(4)} ` +
        `${String(r.fp).padStart(4)} ${String(r.tn).padStart(4)} ` +
        `${pct(r.tpr).padStart(7)} ${pct(r.fpr).padStart(7)} ` +
        `${pct(r.youden).padStart(8)}${mark}`,
    );
  }
  out.push('─'.repeat(68));
  const line = (label, t) =>
    `${label.padEnd(14)}      ${String(t.tp).padStart(4)} ${String(t.fn).padStart(4)} ` +
    `${String(t.fp).padStart(4)} ${String(t.tn).padStart(4)} ` +
    `${pct(t.tpr).padStart(7)} ${pct(t.fpr).padStart(7)} ${pct(t.youden).padStart(8)}`;
  out.push(line('対象内合計', overallInScope));
  out.push(line('全体合計', overallAll));
  out.push('');
  out.push('※ = GRIMOIRE のどのレンズも担当していないカテゴリ。検出0は仕様であって精度の問題ではない。');

  const unmappedEntries = [...unmatched.unmappedCwe.entries()].sort((a, b) => b[1] - a[1]);
  if (unmappedEntries.length > 0 || unmatched.notTestCase > 0 || unmatched.belowConfidence > 0) {
    out.push('');
    out.push('採点に使わなかった Finding:');
    if (unmatched.notTestCase > 0) {
      out.push(`  テストケース外のファイル: ${unmatched.notTestCase} 件（helpers/ など）`);
    }
    if (unmatched.belowConfidence > 0) {
      out.push(`  確信度 ${args.minConfidence} 未満: ${unmatched.belowConfidence} 件`);
    }
    for (const [cwe, n] of unmappedEntries) {
      out.push(`  ベンチマークのカテゴリに対応しないCWE ${cwe}: ${n} 件`);
    }
  }
  process.stdout.write(`${out.join('\n')}\n`);
}

main();
