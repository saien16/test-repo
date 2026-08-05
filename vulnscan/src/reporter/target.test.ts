/**
 * 走査対象の要約。
 *
 * ここで固定したいのは3点:
 *   - ファイルが少なければ実物を、多ければ2階層の集計を出すこと
 *   - README は引用として持ち回り、要約や言い換えをしないこと
 *   - 省略したものを黙って消さないこと
 */

import { describe, expect, it } from 'vitest';
import { parseReadme } from '../context/readme.js';
import type { ScanContext, SourceFile } from '../types/context.js';
import {
  FILE_LIST_THRESHOLD,
  buildTargetSummary,
  formatBytes,
  formatDuration,
  formatTimestamp,
} from './target.js';

function file(path: string, sizeBytes = 100): SourceFile {
  return { path, language: 'typescript', sizeBytes, hash: 'x' };
}

function context(files: SourceFile[], extra: Partial<ScanContext> = {}): ScanContext {
  return {
    repoRoot: '/home/user/app',
    scannedAt: '2026-08-05T09:30:00.000Z',
    readme: null,
    languages: [{ name: 'typescript', ratio: 1, files: files.length, bytes: 0 }],
    frameworks: [],
    dependencies: [],
    files,
    symbols: { symbols: [], byId: {} },
    callGraph: { edges: [], callees: {}, callers: {} },
    entryPoints: [],
    trustBoundaries: [],
    warnings: [],
    ...extra,
  };
}

describe('buildTargetSummary', () => {
  it('ファイルが少なければ一覧をそのまま出す', () => {
    const t = buildTargetSummary(context([file('b.ts'), file('a.ts')]), 1000);
    expect(t.files).toEqual(['a.ts', 'b.ts']);
    expect(t.directories).toBeNull();
  });

  it('閾値を超えたら2階層の集計に切り替える', () => {
    const files = [
      ...Array.from({ length: 8 }, (_, i) => file(`src/analyzer/a${i}.ts`, 10)),
      ...Array.from({ length: 3 }, (_, i) => file(`src/context/c${i}.ts`, 20)),
      file('docs/readme.md', 30),
      file('index.ts', 40),
    ];
    expect(files.length).toBeGreaterThan(FILE_LIST_THRESHOLD);

    const t = buildTargetSummary(context(files), 1000);
    expect(t.files).toBeNull();

    const src = t.directories?.find((d) => d.path === 'src');
    expect(src?.fileCount).toBe(11);
    // 多い順に並ぶ
    expect(src?.children.map((c) => c.path)).toEqual(['src/analyzer', 'src/context']);
    expect(src?.children[0]?.fileCount).toBe(8);

    // ルート直下のファイルは '.' にまとまる
    expect(t.directories?.find((d) => d.path === '.')?.fileCount).toBe(1);
  });

  it('3階層目より深いファイルも2階層目に数える', () => {
    const files = Array.from({ length: 12 }, (_, i) => file(`src/a/b/c/deep${i}.ts`));
    const t = buildTargetSummary(context(files), 0);
    expect(t.directories?.[0]?.path).toBe('src');
    expect(t.directories?.[0]?.children[0]).toMatchObject({ path: 'src/a', fileCount: 12 });
  });

  it('表示を打ち切った上位ディレクトリの数を残す（黙って消さない）', () => {
    // 上位ディレクトリを 14 個（上限は 12）
    const files = Array.from({ length: 14 }, (_, i) => file(`top${i}/f.ts`));
    const t = buildTargetSummary(context(files), 0);
    expect(t.directories).toHaveLength(12);
    expect(t.truncatedDirectories).toBe(2);
  });

  it('表示を打ち切った2階層目の数を残す', () => {
    // src 直下に 8 個のディレクトリ（上限は 6）
    const files = Array.from({ length: 8 }, (_, i) =>
      Array.from({ length: 2 }, (_, j) => file(`src/d${i}/f${j}.ts`)),
    ).flat();
    const t = buildTargetSummary(context(files), 0);
    expect(t.directories?.[0]?.children).toHaveLength(6);
    expect(t.truncatedChildren).toBe(2);
  });

  it('合計サイズを積み上げる', () => {
    const t = buildTargetSummary(context([file('a.ts', 1000), file('b.ts', 24)]), 0);
    expect(t.totalBytes).toBe(1024);
  });

  it('アーキテクチャ推定が無ければ様式は null（推測を捏造しない）', () => {
    expect(buildTargetSummary(context([file('a.ts')]), 0).style).toBeNull();
  });
});

describe('parseReadme', () => {
  it('見出しと導入段落を引用として取り出す', () => {
    const info = parseReadme(
      ['# GRIMOIRE', '', 'LLMベースのソースコード脆弱性スキャナー。', '', '## インストール'].join(
        '\n',
      ),
      'README.md',
    );
    expect(info.title).toBe('GRIMOIRE');
    expect(info.lead).toBe('LLMベースのソースコード脆弱性スキャナー。');
  });

  it('バッジ行と生HTMLを本文と誤認しない', () => {
    const info = parseReadme(
      [
        '# tool',
        '',
        '[![build](https://img.shields.io/x.svg)](https://ci.example)',
        '<p align="center">logo</p>',
        '',
        '本当の説明はここ。',
      ].join('\n'),
      'README.md',
    );
    expect(info.lead).toBe('本当の説明はここ。');
  });

  it('Markdown の装飾とリンクを平文に落とす', () => {
    const info = parseReadme(
      ['# x', '', '**強調**と`コード`と[リンク](https://example.com)を含む説明。'].join('\n'),
      'README.md',
    );
    expect(info.lead).toBe('強調とコードとリンクを含む説明。');
  });

  it('コードブロックを導入段落として拾わない', () => {
    const info = parseReadme(
      ['# x', '', '```sh', 'npm install', '```', '', '説明文。'].join('\n'),
      'README.md',
    );
    expect(info.lead).toBe('説明文。');
  });

  it('見出しが無くても本文だけ拾える', () => {
    expect(parseReadme('ただの説明文。\n', 'README').lead).toBe('ただの説明文。');
  });

  it('空の内容では何も取れない（呼び出し側が次の候補へ進める）', () => {
    const info = parseReadme('', 'README.md');
    expect(info.title).toBe('');
    expect(info.lead).toBe('');
  });
});

describe('表示の整形', () => {
  it('所要時間を人が読める形にする', () => {
    expect(formatDuration(820)).toBe('820ミリ秒');
    expect(formatDuration(45_000)).toBe('45秒');
    expect(formatDuration(133_000)).toBe('2分13秒');
    expect(formatDuration(3_723_000)).toBe('1時間2分3秒');
    expect(formatDuration(-1)).toBe('不明');
  });

  it('バイト数を単位付きにする', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1024)).toBe('1.0 KB');
    expect(formatBytes(4_404_019)).toBe('4.2 MB');
  });

  it('壊れた日時はそのまま返す（勝手に埋めない）', () => {
    expect(formatTimestamp('not-a-date')).toBe('not-a-date');
  });
});
