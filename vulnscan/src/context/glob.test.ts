import { describe, expect, it } from 'vitest';
import { matchAnyGlob, matchAnyGlobDirectory, matchGlob, normalizePath } from './glob.js';
import { IgnoreMatcher } from './ignore.js';

describe('normalizePath', () => {
  it('区切り文字と冗長な接頭辞を正規化する', () => {
    expect(normalizePath('./src/a.ts')).toBe('src/a.ts');
    expect(normalizePath('src\\a.ts')).toBe('src/a.ts');
    expect(normalizePath('/src/a.ts')).toBe('src/a.ts');
    expect(normalizePath('src/a/')).toBe('src/a');
  });
});

describe('matchGlob', () => {
  it('`**` は0個以上のディレクトリにマッチする', () => {
    expect(matchGlob('**/node_modules/**', 'node_modules/foo/index.js')).toBe(true);
    expect(matchGlob('**/node_modules/**', 'packages/a/node_modules/foo.js')).toBe(true);
    expect(matchGlob('**/node_modules/**', 'src/nodes/foo.js')).toBe(false);
  });

  it('`*` はディレクトリ区切りを越えない', () => {
    expect(matchGlob('src/*.ts', 'src/a.ts')).toBe(true);
    expect(matchGlob('src/*.ts', 'src/nested/a.ts')).toBe(false);
    expect(matchGlob('*.ts', 'src/a.ts')).toBe(false);
  });

  it('`src/**/*.ts` は直下も入れ子もマッチする', () => {
    expect(matchGlob('src/**/*.ts', 'src/a.ts')).toBe(true);
    expect(matchGlob('src/**/*.ts', 'src/a/b/c.ts')).toBe(true);
    expect(matchGlob('src/**/*.ts', 'test/a.ts')).toBe(false);
  });

  it('ブレース展開と文字クラスを解釈する', () => {
    expect(matchGlob('**/*.{ts,tsx}', 'src/a.tsx')).toBe(true);
    expect(matchGlob('**/*.{ts,tsx}', 'src/a.js')).toBe(false);
    expect(matchGlob('src/[ab].ts', 'src/a.ts')).toBe(true);
    expect(matchGlob('src/[!ab].ts', 'src/a.ts')).toBe(false);
    expect(matchGlob('src/[!ab].ts', 'src/c.ts')).toBe(true);
  });

  it('`?` は1文字にマッチする', () => {
    expect(matchGlob('src/?.ts', 'src/a.ts')).toBe(true);
    expect(matchGlob('src/?.ts', 'src/ab.ts')).toBe(false);
  });

  it('ドットなどの正規表現メタ文字はリテラル扱いになる', () => {
    expect(matchGlob('**/*.min.js', 'dist/app.min.js')).toBe(true);
    expect(matchGlob('**/*.min.js', 'dist/appXmin.js')).toBe(false);
  });

  it('既定の exclude 設定が想定通りに効く', () => {
    const exclude = ['**/node_modules/**', '**/dist/**', '**/*.min.js', '**/*.lock'];
    expect(matchAnyGlob(exclude, 'dist/bundle.js')).toBe(true);
    expect(matchAnyGlob(exclude, 'yarn.lock')).toBe(true);
    expect(matchAnyGlob(exclude, 'src/index.ts')).toBe(false);
  });
});

describe('matchAnyGlobDirectory', () => {
  it('末尾が `/**` のパターンはディレクトリ自身も枝刈り対象にする', () => {
    expect(matchAnyGlobDirectory(['**/node_modules/**'], 'node_modules')).toBe(true);
    expect(matchAnyGlobDirectory(['**/dist/**'], 'packages/a/dist')).toBe(true);
    expect(matchAnyGlobDirectory(['**/dist/**'], 'packages/a/src')).toBe(false);
  });
});

describe('IgnoreMatcher', () => {
  it('基本的な .gitignore を解釈する', () => {
    const ignore = new IgnoreMatcher();
    ignore.add(['# コメント', '', 'node_modules/', '*.log', '/build', 'src/generated'].join('\n'));

    expect(ignore.ignores('node_modules', true)).toBe(true);
    expect(ignore.ignores('packages/a/node_modules', true)).toBe(true);
    // ディレクトリ限定ルールは同名ファイルにはマッチしない
    expect(ignore.ignores('node_modules', false)).toBe(false);
    expect(ignore.ignores('logs/app.log', false)).toBe(true);
    expect(ignore.ignores('build', true)).toBe(true);
    // 先頭 `/` のアンカーはルート直下のみ
    expect(ignore.ignores('src/build', true)).toBe(false);
    expect(ignore.ignores('src/generated', true)).toBe(true);
    expect(ignore.ignores('src/index.ts', false)).toBe(false);
  });

  it('否定パターンは後勝ちで再包含する', () => {
    const ignore = new IgnoreMatcher();
    ignore.add(['*.log', '!keep.log'].join('\n'));

    expect(ignore.ignores('app.log', false)).toBe(true);
    expect(ignore.ignores('keep.log', false)).toBe(false);
  });

  it('ネストした .gitignore は自身のディレクトリ配下にのみ効く', () => {
    const ignore = new IgnoreMatcher();
    ignore.add('secret.txt\n', 'packages/a');

    expect(ignore.ignores('packages/a/secret.txt', false)).toBe(true);
    expect(ignore.ignores('packages/a/deep/secret.txt', false)).toBe(true);
    expect(ignore.ignores('packages/b/secret.txt', false)).toBe(false);
  });
});
