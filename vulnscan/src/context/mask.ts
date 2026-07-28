/**
 * ソースコードのコメント・文字列リテラルをマスクするスキャナ。
 *
 * 正規表現ベースの解析はコメント中の擬似コードや文字列中の記号で簡単に
 * 誤爆するため、先に「コメントを潰した行」「コメントと文字列を潰した行」を
 * 作っておき、用途に応じて使い分ける。
 *
 *  - noComment: コメントのみ空白化。ルートパス等の文字列リテラルは残るので
 *               パターンマッチ（エントリポイント・信頼境界）に使う。
 *  - codeOnly : コメントに加えて文字列の中身も空白化。括弧の対応付け
 *               （シンボルの範囲決定）に使う。
 *
 * 文字数と行数は元のソースと完全に一致させるため、置換は空白1文字で行う。
 */

export interface MaskedSource {
  /** 元の行 */
  lines: string[];
  /** コメントを空白化した行 */
  noComment: string[];
  /** コメントと文字列リテラルを空白化した行 */
  codeOnly: string[];
}

interface SyntaxProfile {
  lineComments: string[];
  blockComment: [string, string] | null;
  /** `=begin` / `=end`（Ruby）のような行頭ブロックコメント */
  lineBlockComment: [string, string] | null;
  quotes: string[];
  /** `'''` / `"""` を扱うか（Python） */
  tripleQuotes: boolean;
}

const C_LIKE: SyntaxProfile = {
  lineComments: ['//'],
  blockComment: ['/*', '*/'],
  lineBlockComment: null,
  quotes: ['"', "'", '`'],
  tripleQuotes: false,
};

const PYTHON: SyntaxProfile = {
  lineComments: ['#'],
  blockComment: null,
  lineBlockComment: null,
  quotes: ['"', "'"],
  tripleQuotes: true,
};

const RUBY: SyntaxProfile = {
  lineComments: ['#'],
  blockComment: null,
  lineBlockComment: ['=begin', '=end'],
  quotes: ['"', "'"],
  tripleQuotes: false,
};

const PHP: SyntaxProfile = {
  lineComments: ['//', '#'],
  blockComment: ['/*', '*/'],
  lineBlockComment: null,
  quotes: ['"', "'"],
  tripleQuotes: false,
};

function profileFor(language: string): SyntaxProfile {
  switch (language) {
    case 'python':
      return PYTHON;
    case 'ruby':
    case 'erb':
      return RUBY;
    case 'php':
      return PHP;
    default:
      return C_LIKE;
  }
}

type State = 'code' | 'block-comment' | 'string';

/**
 * ソースをマスクする。どんな入力でも例外を投げない。
 */
export function maskSource(content: string, language: string): MaskedSource {
  const profile = profileFor(language);
  const noComment: string[] = [];
  const codeOnly: string[] = [];
  const lines = content.split('\n');

  let state: State = 'code';
  let quote = '';
  let quoteLen = 1;

  for (const line of lines) {
    let bufNoComment = '';
    let bufCodeOnly = '';
    let i = 0;

    // Ruby の `=begin` / `=end` は行単位で判定する
    if (profile.lineBlockComment) {
      const [open, close] = profile.lineBlockComment;
      if (state === 'code' && line.startsWith(open)) {
        state = 'block-comment';
        noComment.push(' '.repeat(line.length));
        codeOnly.push(' '.repeat(line.length));
        continue;
      }
      if (state === 'block-comment' && !profile.blockComment) {
        const finished = line.startsWith(close);
        noComment.push(' '.repeat(line.length));
        codeOnly.push(' '.repeat(line.length));
        if (finished) state = 'code';
        continue;
      }
    }

    while (i < line.length) {
      const rest = line.slice(i);

      if (state === 'block-comment') {
        const close = profile.blockComment?.[1] ?? '*/';
        if (rest.startsWith(close)) {
          bufNoComment += ' '.repeat(close.length);
          bufCodeOnly += ' '.repeat(close.length);
          i += close.length;
          state = 'code';
        } else {
          bufNoComment += ' ';
          bufCodeOnly += ' ';
          i++;
        }
        continue;
      }

      if (state === 'string') {
        // エスケープシーケンス
        if (line[i] === '\\' && i + 1 < line.length) {
          bufNoComment += line.slice(i, i + 2);
          bufCodeOnly += '  ';
          i += 2;
          continue;
        }
        if (rest.startsWith(quote)) {
          bufNoComment += quote;
          bufCodeOnly += ' '.repeat(quoteLen);
          i += quoteLen;
          state = 'code';
          continue;
        }
        bufNoComment += line[i] as string;
        bufCodeOnly += ' ';
        i++;
        continue;
      }

      // state === 'code'
      const lineComment = profile.lineComments.find((c) => rest.startsWith(c));
      if (lineComment) {
        const remaining = line.length - i;
        bufNoComment += ' '.repeat(remaining);
        bufCodeOnly += ' '.repeat(remaining);
        i = line.length;
        continue;
      }

      if (profile.blockComment && rest.startsWith(profile.blockComment[0])) {
        const open = profile.blockComment[0];
        bufNoComment += ' '.repeat(open.length);
        bufCodeOnly += ' '.repeat(open.length);
        i += open.length;
        state = 'block-comment';
        continue;
      }

      const quoteChar = profile.quotes.find((q) => rest.startsWith(q));
      if (quoteChar) {
        const triple = quoteChar.repeat(3);
        if (profile.tripleQuotes && rest.startsWith(triple)) {
          quote = triple;
          quoteLen = 3;
          bufNoComment += triple;
          bufCodeOnly += '   ';
          i += 3;
        } else {
          quote = quoteChar;
          quoteLen = 1;
          bufNoComment += quoteChar;
          bufCodeOnly += ' ';
          i += 1;
        }
        state = 'string';
        continue;
      }

      bufNoComment += line[i] as string;
      bufCodeOnly += line[i] as string;
      i++;
    }

    // 行コメントは行末で終わる。文字列は複数行を跨ぎうるものだけ継続させる。
    if (state === 'string' && quoteLen === 1 && quote !== '`') {
      // 通常のクォートは行を跨がない（閉じ忘れによる崩壊を防ぐ）
      state = 'code';
    }

    noComment.push(bufNoComment);
    codeOnly.push(bufCodeOnly);
  }

  return { lines, noComment, codeOnly };
}
