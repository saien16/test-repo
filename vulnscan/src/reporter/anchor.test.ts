import { describe, it, expect } from 'vitest';
import { renderMarkdown } from './formatters/markdown.js';
import { makeResult, makeFinding } from './fixtures.js';
import { analyzeResult } from './index.js';
import { DEFAULT_CONFIG } from '../types/config.js';

/**
 * Markdown のアンカーはレンダラが見出し文字列から自動生成するため、
 * 見出しとリンクが別々の文字列から作られていると静かにずれる。
 * ここでは「一覧表のリンク先が、実際に出力された見出しから導かれる
 * アンカーと一致すること」を出力そのものから検証する。
 */

/** GitHub 風のスラグ生成（レンダラ側の挙動を模す） */
function slugify(headingText: string): string {
  return headingText
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .trim()
    .replace(/\s+/g, '-');
}

async function renderWith(findings: ReturnType<typeof makeFinding>[]): Promise<string> {
  const result = makeResult({ findings });
  const analyzed = await analyzeResult(result, null as never, DEFAULT_CONFIG);
  return renderMarkdown(result, analyzed, { verbose: true });
}

describe('Markdown のアンカー整合性', () => {
  it('一覧表のリンク先が実際の見出しから導かれるアンカーと一致する', async () => {
    const md = await renderWith([makeFinding({ id: 'VS-aaaaaaaaaaaa', title: 'SQLインジェクション' })]);

    // 出力された見出しを拾ってスラグ化する。
    // 目次は `##` 見出しへも張られるので、両方の階層を対象にする。
    const headings = [...md.matchAll(/^#{2,3} (.+)$/gmu)].map((m) => slugify(m[1] ?? ''));
    // 一覧表のリンク先を拾う
    const links = [...md.matchAll(/\]\(#([^)]+)\)/gu)].map((m) => m[1] ?? '');

    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(headings, `リンク先 #${link} に対応する見出しが無い`).toContain(link);
    }
  });

  it('同じタイトルの Finding が複数あってもアンカーが衝突しない', async () => {
    const md = await renderWith([
      makeFinding({ id: 'VS-111111111111', title: '同じタイトル' }),
      makeFinding({ id: 'VS-222222222222', title: '同じタイトル' }),
    ]);
    const links = [...md.matchAll(/\]\(#([^)]+)\)/gu)].map((m) => m[1] ?? '');
    expect(new Set(links).size).toBe(links.length);
  });

  it('アンカーに Finding ID が含まれる（タイトル変更で切れない）', async () => {
    const md = await renderWith([makeFinding({ id: 'VS-abcdef123456', title: 'なにか' })]);
    const links = [...md.matchAll(/\]\(#([^)]+)\)/gu)].map((m) => m[1] ?? '');
    expect(links.some((l) => l.includes('vs-abcdef123456'))).toBe(true);
  });
});
