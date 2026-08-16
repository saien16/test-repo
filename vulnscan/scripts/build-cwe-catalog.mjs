#!/usr/bin/env node
/**
 * MITRE CWE 辞書を GRIMOIRE が使う形に圧縮して `src/vuln/data/cwe-catalog.json` を生成する。
 *
 * 出典: OWASP/cwe-sdk-javascript (raw/cwe-dictionary.json)
 *   https://github.com/OWASP/cwe-sdk-javascript
 *   これは MITRE CWE 公式データ(cwec_latest.xml)を JSON 化したもの。
 *
 * 実行時にネットワークへ出ないよう、生成済みJSONをリポジトリに同梱する方針。
 * カタログを更新したいときだけこのスクリプトを実行する:
 *   node scripts/build-cwe-catalog.mjs
 *
 * 元データは8MB超あるが、スキャナが使うのは一部のフィールドだけなので
 * 大幅に削れる。デモコード・観測事例・参考文献・変更履歴は捨てる。
 */

import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_PATH = join(HERE, '..', 'src', 'vuln', 'data', 'cwe-catalog.json');
const SOURCE_URL =
  'https://raw.githubusercontent.com/OWASP/cwe-sdk-javascript/master/raw/cwe-dictionary.json';

/** XMLパーサ由来の「単一要素は配列にならない」揺れを吸収する */
function asArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

/** 混在しうるテキストノード（文字列 / {'#text'} / 配列）を平坦な文字列にする */
function asText(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value.trim();
  if (Array.isArray(value)) return value.map(asText).filter(Boolean).join(' ');
  if (typeof value === 'object') {
    if (typeof value['#text'] === 'string') return value['#text'].trim();
    // <p> や <ul> を含む構造化テキスト
    return Object.entries(value)
      .filter(([k]) => !k.startsWith('@_') && k !== 'attr')
      .map(([, v]) => asText(v))
      .filter(Boolean)
      .join(' ');
  }
  return String(value);
}

function truncate(text, max) {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

/**
 * Common_Consequences の Scope/Impact を CVSS の C/I/A 影響有無に落とす。
 * 手で調整した推定値ではなく MITRE のデータに基づけるのが利点。
 */
function consequencesToCia(consequences) {
  const cia = { c: false, i: false, a: false };
  for (const cons of consequences) {
    for (const scope of asArray(cons.Scope).map(asText)) {
      if (scope === 'Confidentiality') cia.c = true;
      else if (scope === 'Integrity') cia.i = true;
      else if (scope === 'Availability') cia.a = true;
      else if (scope === 'Access Control' || scope === 'Authentication') {
        // 認可・認証の破壊は機密性と完全性の両方に効く
        cia.c = true;
        cia.i = true;
      }
    }
  }
  return cia;
}

function compactEntry(id, raw) {
  const attr = raw.attr ?? {};
  const consequences = asArray(raw.Common_Consequences?.Consequence);

  const platforms = raw.Applicable_Platforms ?? {};
  const languages = asArray(platforms.Language)
    .map((l) => l?.attr?.['@_Name'] ?? l?.attr?.['@_Class'])
    .filter(Boolean);
  const technologies = asArray(platforms.Technology)
    .map((t) => t?.attr?.['@_Name'] ?? t?.attr?.['@_Class'])
    .filter(Boolean);

  const mitigations = asArray(raw.Potential_Mitigations?.Mitigation)
    .map((m) => ({
      phase: asArray(m.Phase).map(asText).filter(Boolean),
      description: truncate(asText(m.Description), 400),
    }))
    .filter((m) => m.description.length > 0)
    .slice(0, 4);

  // 親CWE（ChildOf）だけ拾う。カテゴリ集約や上位概念への畳み込みに使う
  const parents = asArray(raw.Related_Weaknesses?.Related_Weakness)
    .filter((r) => r?.attr?.['@_Nature'] === 'ChildOf')
    .map((r) => r?.attr?.['@_CWE_ID'])
    .filter(Boolean);

  const capec = asArray(raw.Related_Attack_Patterns?.Related_Attack_Pattern)
    .map((r) => r?.attr?.['@_CAPEC_ID'])
    .filter(Boolean);

  // OWASP Top Ten などの外部タクソノミ対応
  const taxonomies = {};
  for (const t of asArray(raw.Taxonomy_Mappings?.Taxonomy_Mapping)) {
    const name = t?.attr?.['@_Taxonomy_Name'];
    if (!name) continue;
    const entry = asText(t.Entry_Name) || asText(t.Entry_ID);
    if (entry) (taxonomies[name] ??= []).push(entry);
  }

  const detectionMethods = asArray(raw.Detection_Methods?.Detection_Method)
    .map((d) => asText(d.Method))
    .filter(Boolean);

  return {
    id: String(id),
    name: attr['@_Name'] ?? `CWE-${id}`,
    abstraction: attr['@_Abstraction'] ?? 'Unknown',
    structure: attr['@_Structure'] ?? 'Unknown',
    status: attr['@_Status'] ?? 'Unknown',
    description: truncate(asText(raw.Description), 500),
    extendedDescription: truncate(asText(raw.Extended_Description), 900),
    likelihood: asText(raw.Likelihood_Of_Exploit) || 'Unknown',
    languages,
    technologies,
    consequences: consequences
      .map((c) => ({
        scope: asArray(c.Scope).map(asText).filter(Boolean),
        impact: asArray(c.Impact).map(asText).filter(Boolean),
      }))
      .filter((c) => c.scope.length > 0),
    cia: consequencesToCia(consequences),
    mitigations,
    parents,
    capec,
    taxonomies,
    detectionMethods,
  };
}

async function loadSource() {
  // ローカルにキャッシュがあれば使う（オフラインでも再生成できるように）
  const cacheArg = process.argv.find((a) => a.startsWith('--from='));
  if (cacheArg) {
    const path = cacheArg.slice('--from='.length);
    process.stderr.write(`ローカルファイルから読み込み: ${path}\n`);
    return JSON.parse(await readFile(path, 'utf8'));
  }
  process.stderr.write(`ダウンロード中: ${SOURCE_URL}\n`);
  const res = await fetch(SOURCE_URL);
  if (!res.ok) throw new Error(`取得に失敗しました: HTTP ${res.status}`);
  return res.json();
}

const dictionary = await loadSource();
const catalog = {};
let skipped = 0;

for (const [id, raw] of Object.entries(dictionary)) {
  if (!/^\d+$/.test(id)) {
    skipped++;
    continue;
  }
  catalog[id] = compactEntry(id, raw);
}

const output = {
  // 再現性のためソースを記録する。生成日時は入れない（差分が毎回出るため）
  source: SOURCE_URL,
  sourceProject: 'OWASP/cwe-sdk-javascript (MITRE CWE 公式データのJSON化)',
  count: Object.keys(catalog).length,
  entries: catalog,
};

await mkdir(dirname(OUT_PATH), { recursive: true });
await writeFile(OUT_PATH, JSON.stringify(output), 'utf8');

const bytes = Buffer.byteLength(JSON.stringify(output));
process.stderr.write(
  `生成しました: ${OUT_PATH}\n` +
    `  エントリ数: ${output.count} (スキップ ${skipped})\n` +
    `  サイズ: ${(bytes / 1024 / 1024).toFixed(2)} MB\n`,
);
