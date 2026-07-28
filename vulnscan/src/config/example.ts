/**
 * `.grimoire.yml.example` の生成。
 *
 * サンプル設定を手で書いていた頃は、設定を1つ足すたびに
 * `DEFAULT_CONFIG` / CLIフラグ / サンプル の3系統を手で揃える必要があり、
 * 実際にドリフトが起きていた（サンプルに存在しない設定があった）。
 * ここでは {@link CONFIG_SPEC} だけを入力にサンプル全体を組み立て、
 * 生成結果と実ファイルの一致を `example.test.ts` で固定する。
 *
 * 出力する YAML は spec の既定値（文字列・数値・真偽値・null・
 * 文字列の配列・平坦なオブジェクト）に限られるので、
 * ここでは依存を増やさず最小限のエミッタを持つ。
 */

import { CONFIG_SPEC, type FieldSpec } from '../types/config-spec.js';

/**
 * 生成では spec のリテラル型（どのキーがどの `kind` か）を使わないため、
 * 共通のインタフェースとして読み直す。並び順は宣言順のまま。
 */
const SPEC_ENTRIES: ReadonlyArray<readonly [string, FieldSpec]> = Object.entries(
  CONFIG_SPEC as Readonly<Record<string, FieldSpec>>,
);

/** ファイル先頭の説明。設定値そのものではないので spec には持たせない */
const HEADER = [
  '# GRIMOIRE 設定ファイルのサンプル',
  '# `.grimoire.yml` にリネームしてリポジトリルートに置くと自動で読み込まれます。',
  '# 指定しなかった項目は既定値が使われます。',
  '# 値はすべて既定値そのものです。',
  '#',
  '# 後方互換: 旧名の `.vulnscan.yml` / `.vulnscan.yaml` も読み込みます。',
  '# 新旧が同居する場合は `.grimoire.yml` が優先されます。',
  '#',
  '# このファイルは src/types/config-spec.ts から生成しています。',
  '# 手で編集せず spec 側を直してください（一致は src/config/example.test.ts が検証します）。',
];

/** コメント行へ整形する（複数行の doc は行ごとに `#` を付ける） */
function commentLines(doc: string, indent: string): string[] {
  return doc.split('\n').map((line) => (line === '' ? `${indent}#` : `${indent}# ${line}`));
}

/**
 * YAML のスカラー表記。
 * 素直に書けない文字（glob の `*` など）を含む場合だけシングルクォートで括る。
 */
function scalar(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  const text = String(value);
  if (text !== '' && /^[A-Za-z0-9._/@:-]+$/.test(text) && !/^[-:]/.test(text)) return text;
  return `'${text.replace(/'/g, "''")}'`;
}

/** キーと値を YAML の行へ展開する（配列・平坦なオブジェクトに対応） */
function emit(key: string, value: unknown, indent: string): string[] {
  if (Array.isArray(value)) {
    if (value.length === 0) return [`${indent}${key}: []`];
    return [`${indent}${key}:`, ...value.map((item) => `${indent}  - ${scalar(item)}`)];
  }
  if (value !== null && typeof value === 'object') {
    const lines = [`${indent}${key}:`];
    for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>)) {
      lines.push(...emit(childKey, childValue, `${indent}  `));
    }
    return lines;
  }
  return [`${indent}${key}: ${scalar(value)}`];
}

/** 入れ子（llm / scan）のブロック。子キーの説明は spec の fieldDocs から差し込む */
function emitNested(
  key: string,
  value: Record<string, unknown>,
  fieldDocs: Readonly<Record<string, string>>,
): string[] {
  const lines = [`${key}:`];
  for (const [childKey, childValue] of Object.entries(value)) {
    const doc = fieldDocs[childKey];
    if (doc) lines.push(...commentLines(doc, '  '));
    lines.push(...emit(childKey, childValue, '  '));
  }
  return lines;
}

/**
 * spec から `.grimoire.yml.example` の中身を生成する。
 * 末尾には改行を1つ置く（実ファイルと同じ形にするため）。
 */
export function generateExample(): string {
  const blocks: string[][] = [HEADER];

  for (const [key, spec] of SPEC_ENTRIES) {
    const block = [...commentLines(spec.doc, '')];
    if (spec.cli) block.push(`# CLIフラグ: ${spec.cli}`);

    if (spec.kind === 'nested') {
      block.push(
        ...emitNested(key, spec.default as Record<string, unknown>, spec.fieldDocs ?? {}),
      );
    } else {
      block.push(...emit(key, spec.default, ''));
    }
    blocks.push(block);
  }

  return `${blocks.map((block) => block.join('\n')).join('\n\n')}\n`;
}
