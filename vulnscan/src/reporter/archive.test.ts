/**
 * HTML控えの保存。
 *
 * ここで固定したいのは3点:
 *   - ファイル名が日時で必ず変わること（前回を上書きしない）
 *   - latest.html が同じ内容で置かれること（URLを固定できる）
 *   - 対象名が変な文字でもファイル名が壊れないこと
 */

import { mkdtemp, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  LATEST_FILENAME,
  archiveFileName,
  slugifyTarget,
  timestampSlug,
  writeArchive,
} from './archive.js';

const WHEN = new Date(2026, 7, 6, 0, 25, 7); // 2026-08-06 00:25:07 ローカル

describe('timestampSlug', () => {
  it('ゼロ埋めした YYYYMMDD-HHMMSS になる', () => {
    expect(timestampSlug(WHEN)).toBe('20260806-002507');
  });

  it('秒まで含むので、同じ分に2回走らせても衝突しない', () => {
    const a = timestampSlug(new Date(2026, 7, 6, 0, 25, 7));
    const b = timestampSlug(new Date(2026, 7, 6, 0, 25, 8));
    expect(a).not.toBe(b);
  });
});

describe('slugifyTarget', () => {
  it('ディレクトリ名をそのまま使う', () => {
    expect(slugifyTarget('/home/ssm-user/BenchmarkJava')).toBe('BenchmarkJava');
  });

  it('日本語のディレクトリ名は残す', () => {
    expect(slugifyTarget('/srv/在庫管理API')).toBe('在庫管理API');
  });

  it('パス区切りになりうる文字を落とす', () => {
    expect(slugifyTarget('/srv/my app (v2)')).toBe('my-app-v2');
  });

  it('名前が取れないときは scan にする', () => {
    expect(slugifyTarget('/')).toBe('scan');
  });

  it('長すぎる名前は切る', () => {
    expect(slugifyTarget(`/srv/${'a'.repeat(80)}`)).toHaveLength(40);
  });
});

describe('archiveFileName', () => {
  it('対象名と日時が入る', () => {
    expect(archiveFileName('/home/ssm-user/BenchmarkJava', WHEN)).toBe(
      'grimoire-BenchmarkJava-20260806-002507.html',
    );
  });
});

describe('writeArchive', () => {
  it('タイムスタンプ付きと latest.html の2つを書く', async () => {
    const dir = join(await mkdtemp(join(tmpdir(), 'grimoire-archive-')), 'reports');
    const result = await writeArchive('<html>x</html>', dir, '/srv/app', WHEN);

    expect(result.path).toBe(join(dir, 'grimoire-app-20260806-002507.html'));
    expect(result.latestPath).toBe(join(dir, LATEST_FILENAME));
    await expect(readFile(result.path, 'utf8')).resolves.toBe('<html>x</html>');
    await expect(readFile(result.latestPath, 'utf8')).resolves.toBe('<html>x</html>');
  });

  it('ディレクトリが無ければ作る', async () => {
    const base = await mkdtemp(join(tmpdir(), 'grimoire-archive-'));
    const dir = join(base, 'a', 'b', 'reports');
    await writeArchive('<html>x</html>', dir, '/srv/app', WHEN);
    expect(await readdir(dir)).toContain(LATEST_FILENAME);
  });

  it('2回走らせても前回を消さず、latest は最新になる', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'grimoire-archive-'));
    const first = await writeArchive('<html>1</html>', dir, '/srv/app', new Date(2026, 7, 6, 0, 0, 1));
    const second = await writeArchive('<html>2</html>', dir, '/srv/app', new Date(2026, 7, 6, 0, 0, 2));

    expect(first.path).not.toBe(second.path);
    // 前回のものが残っている
    await expect(readFile(first.path, 'utf8')).resolves.toBe('<html>1</html>');
    // latest は後から書いたほう
    await expect(readFile(second.latestPath, 'utf8')).resolves.toBe('<html>2</html>');
  });
});
