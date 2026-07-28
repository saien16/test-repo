/**
 * 文字列整形ユーティリティ。
 *
 * 日本語のレポートを端末に出すため、全角幅を考慮した桁数計算と
 * 禁則処理つきの折り返しを自前で持つ（外部依存を増やさない方針）。
 */

const ANSI_PATTERN = /\u001b\[[0-9;]*m/g;

/** ANSIエスケープを取り除く */
export function stripAnsi(text: string): string {
  return text.replace(ANSI_PATTERN, '');
}

/** 1コードポイントの表示幅（東アジア全角は2桁として数える） */
function codePointWidth(cp: number): number {
  if (cp === 0) return 0;
  // 制御文字
  if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0)) return 0;
  // 結合文字（幅を持たない）
  if (cp >= 0x0300 && cp <= 0x036f) return 0;
  if (cp >= 0x200b && cp <= 0x200f) return 0;
  if (cp === 0xfe0f || cp === 0xfe0e) return 0;
  const wide =
    (cp >= 0x1100 && cp <= 0x115f) || // ハングル字母
    (cp >= 0x2e80 && cp <= 0x303e) || // CJK部首・記号
    (cp >= 0x3041 && cp <= 0x33ff) || // かな・カナ・互換
    (cp >= 0x3400 && cp <= 0x4dbf) ||
    (cp >= 0x4e00 && cp <= 0x9fff) || // CJK統合漢字
    (cp >= 0xa000 && cp <= 0xa4cf) ||
    (cp >= 0xac00 && cp <= 0xd7a3) || // ハングル音節
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xfe10 && cp <= 0xfe19) ||
    (cp >= 0xfe30 && cp <= 0xfe6f) ||
    (cp >= 0xff00 && cp <= 0xff60) || // 全角英数記号
    (cp >= 0xffe0 && cp <= 0xffe6) ||
    (cp >= 0x1f300 && cp <= 0x1f64f) ||
    (cp >= 0x1f900 && cp <= 0x1f9ff) ||
    (cp >= 0x20000 && cp <= 0x3fffd);
  return wide ? 2 : 1;
}

/** ANSIを除いた表示幅（全角=2） */
export function displayWidth(text: string): number {
  let width = 0;
  for (const ch of stripAnsi(text)) {
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;
    width += codePointWidth(cp);
  }
  return width;
}

/** 行頭に来てほしくない文字（軽量な禁則処理） */
const NO_LINE_START = new Set([
  '、', '。', '，', '．', '）', '」', '』', '】', '〕', '〉', '》', '”', '’',
  'ー', 'ぁ', 'ぃ', 'ぅ', 'ぇ', 'ぉ', 'っ', 'ゃ', 'ゅ', 'ょ',
  'ァ', 'ィ', 'ゥ', 'ェ', 'ォ', 'ッ', 'ャ', 'ュ', 'ョ',
  ')', ']', '}', ',', '.', ':', ';', '!', '?',
]);

/** 行末に来てほしくない文字 */
const NO_LINE_END = new Set(['（', '「', '『', '【', '〔', '〈', '《', '“', '‘', '(', '[', '{']);

function isAsciiWordChar(ch: string): boolean {
  return /[A-Za-z0-9_@#$%\-+./:'"]/.test(ch);
}

/**
 * 指定した表示幅で折り返す。
 * 英単語は途中で切らず、日本語は任意位置で改行できる前提で処理する。
 */
export function wrapText(text: string, width: number): string[] {
  const limit = Math.max(8, Math.floor(width));
  const out: string[] = [];

  for (const rawLine of text.split(/\r?\n/)) {
    if (rawLine.trim() === '') {
      out.push('');
      continue;
    }
    let line = '';
    let lineWidth = 0;
    // 未確定の英単語バッファ（単語の途中では折り返さない）
    let word = '';
    let wordWidth = 0;

    const breakLine = (): void => {
      out.push(line.replace(/\s+$/u, ''));
      line = '';
      lineWidth = 0;
    };
    /** 溜めていた英単語を行へ確定する。入りきらないなら先に改行する。 */
    const flushWord = (): void => {
      if (word === '') return;
      if (lineWidth > 0 && lineWidth + wordWidth > limit) breakLine();
      line += word;
      lineWidth += wordWidth;
      word = '';
      wordWidth = 0;
    };

    const chars = Array.from(rawLine);
    for (let i = 0; i < chars.length; i++) {
      const ch = chars[i];
      if (ch === undefined) continue;
      const cp = ch.codePointAt(0) ?? 0;
      const w = codePointWidth(cp);

      if (isAsciiWordChar(ch)) {
        // 単語1つで1行に収まらない場合だけ、諦めて単語の途中で切る
        if (wordWidth + w > limit) {
          flushWord();
          breakLine();
        }
        word += ch;
        wordWidth += w;
        continue;
      }

      flushWord();

      if (ch === ' ' && lineWidth === 0) continue;

      const next = chars[i + 1];
      const overflow = lineWidth + w > limit;
      // 次の文字が行頭禁止なら1文字手前で折り返す
      const nextIsNoStart = next !== undefined && NO_LINE_START.has(next);
      const needBreakForKinsoku =
        nextIsNoStart && lineWidth + w + (codePointWidth(next.codePointAt(0) ?? 0)) > limit;

      if (overflow || needBreakForKinsoku) {
        if (NO_LINE_START.has(ch) && lineWidth > 0) {
          // 行頭禁止文字はぶら下げる
          line += ch;
          lineWidth += w;
          breakLine();
          continue;
        }
        if (line !== '' && NO_LINE_END.has(line.slice(-1))) {
          // 行末禁止文字は次行へ送る
          const last = line.slice(-1);
          line = line.slice(0, -1);
          breakLine();
          line = last;
          lineWidth = displayWidth(last);
        } else if (lineWidth > 0) {
          breakLine();
        }
      }
      // 折り返した直後の行頭に空白を残さない
      if (ch === ' ' && lineWidth === 0) continue;
      line += ch;
      lineWidth += w;
    }
    flushWord();
    if (line !== '' || out.length === 0) out.push(line.replace(/\s+$/u, ''));
  }

  return out.length > 0 ? out : [''];
}

/** 各行にインデントを付けて折り返す */
export function wrapIndented(text: string, width: number, indent: string): string[] {
  return wrapText(text, Math.max(8, width - displayWidth(indent))).map((l) =>
    l === '' ? '' : indent + l,
  );
}

/** 表示幅ベースで末尾を省略 */
export function truncate(text: string, maxWidth: number, ellipsis = '…'): string {
  if (displayWidth(text) <= maxWidth) return text;
  const budget = Math.max(1, maxWidth - displayWidth(ellipsis));
  let out = '';
  let width = 0;
  for (const ch of text) {
    const w = codePointWidth(ch.codePointAt(0) ?? 0);
    if (width + w > budget) break;
    out += ch;
    width += w;
  }
  return out + ellipsis;
}

/** 表示幅ベースの右詰めパディング */
export function padEnd(text: string, width: number, fill = ' '): string {
  const diff = width - displayWidth(text);
  return diff > 0 ? text + fill.repeat(diff) : text;
}

/** 表示幅ベースの左詰めパディング */
export function padStart(text: string, width: number, fill = ' '): string {
  const diff = width - displayWidth(text);
  return diff > 0 ? fill.repeat(diff) + text : text;
}

/** 最初の1文（。/./改行 区切り）を取り出す */
export function firstSentence(text: string, maxWidth = 120): string {
  const normalized = text.replace(/\s+/gu, ' ').trim();
  if (normalized === '') return '';
  const match = /^[\s\S]*?(?:。|．|\. |\.$|！|!|？|\?)/u.exec(normalized);
  const head = match ? match[0] : normalized;
  return truncate(head.trim().replace(/[。．.]$/u, ''), maxWidth);
}

/** 数値を3桁区切りに */
export function formatNumber(value: number): string {
  return Number.isFinite(value) ? Math.round(value).toLocaleString('en-US') : '0';
}

/** ミリ秒を読みやすい単位へ */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '不明';
  if (ms < 1000) return `${Math.round(ms)}ミリ秒`;
  const sec = ms / 1000;
  if (sec < 60) return `${sec.toFixed(1)}秒`;
  const min = Math.floor(sec / 60);
  const rest = Math.round(sec - min * 60);
  if (min < 60) return `${min}分${rest}秒`;
  const hour = Math.floor(min / 60);
  return `${hour}時間${min - hour * 60}分`;
}

/** ISO日時をローカル表現に（失敗したら原文） */
export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const pad = (n: number): string => String(n).padStart(2, '0');
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`
  );
}

/** HTMLエスケープ */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Markdownへ埋め込む未信頼テキストのエスケープ。
 *
 * Markdownレポートは `<details>` などの生HTMLを含んでおり、
 * HTMLを有効にしたレンダラ（GitHub・CIのPRコメントなど）で表示される前提。
 * つまり `<script>` のようなタグはそのまま解釈されうるので、
 * HTML特殊文字を必ず実体参照へ置き換える。
 */
export function escapeMdText(text: string): string {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * コードスパン（`...`）へ埋め込む値のエスケープ。
 *
 * バッククォートを含む値はコードスパンを閉じて任意のMarkdown/HTMLへ
 * 抜け出せてしまうため、無害な文字へ置き換える。改行も潰す。
 */
export function escapeMdCode(text: string): string {
  return escapeMdText(String(text ?? '').replace(/`/g, "'").replace(/\r?\n/g, ' '));
}

/** Markdownのテーブルセル用エスケープ（未信頼文字列前提でHTMLもエスケープする） */
export function escapeMdCell(text: string): string {
  return escapeMdText(text).replace(/\r?\n/g, ' ').replace(/\|/g, '\\|').trim();
}

/** テーブルセル内のコードスパン用エスケープ */
export function escapeMdCodeCell(text: string): string {
  return escapeMdCode(text).replace(/\|/g, '\\|').trim();
}

/** Markdown本文中の記号をエスケープ（見出し・リンク記法の崩れ防止） */
export function escapeMdInline(text: string): string {
  return String(text ?? '').replace(/([*_`[\]])/g, '\\$1');
}

/** リンクとして出してよいURLか（javascript: などのスキームを弾く） */
export function isSafeUrl(url: string): boolean {
  return /^https?:\/\/[^\s<>"'`\\]+$/.test(String(url ?? ''));
}

/** 見出し用のアンカーID（HTML目次で使う） */
export function slugify(text: string, fallback: string): string {
  const slug = text
    .toLowerCase()
    .replace(/[^a-z0-9぀-ヿ一-鿿-]+/gu, '-')
    .replace(/^-+|-+$/g, '');
  return slug === '' ? fallback : slug;
}
