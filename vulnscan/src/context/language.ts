/**
 * 拡張子ベースの言語判定。
 * 構文解析はヒューリスティックなので、ここも拡張子で十分と割り切る。
 */

import type { LanguageInfo, SourceFile } from '../types/context.js';

/** 言語が判定できなかったファイルに付与する名前 */
export const UNKNOWN_LANGUAGE = 'unknown';

const EXTENSION_LANGUAGE: Record<string, string> = {
  // 静的解析の主対象
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.py': 'python',
  '.pyi': 'python',
  '.pyw': 'python',
  '.go': 'go',
  '.java': 'java',
  '.rb': 'ruby',
  '.rake': 'ruby',
  '.php': 'php',
  '.phtml': 'php',
  '.php5': 'php',
  // 参考情報として集計する言語
  '.cs': 'csharp',
  '.rs': 'rust',
  '.kt': 'kotlin',
  '.kts': 'kotlin',
  '.swift': 'swift',
  '.scala': 'scala',
  '.c': 'c',
  '.h': 'c',
  '.cpp': 'cpp',
  '.cc': 'cpp',
  '.cxx': 'cpp',
  '.hpp': 'cpp',
  '.m': 'objective-c',
  '.pl': 'perl',
  '.lua': 'lua',
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
  '.ps1': 'powershell',
  '.sql': 'sql',
  '.vue': 'vue',
  '.svelte': 'svelte',
  '.erb': 'erb',
  '.ejs': 'ejs',
  '.tf': 'terraform',
  '.gradle': 'groovy',
  // データ・設定
  '.json': 'json',
  '.yml': 'yaml',
  '.yaml': 'yaml',
  '.toml': 'toml',
  '.ini': 'ini',
  '.xml': 'xml',
  '.html': 'html',
  '.htm': 'html',
  '.css': 'css',
  '.scss': 'css',
  '.sass': 'css',
  '.less': 'css',
  '.md': 'markdown',
  '.mdx': 'markdown',
  '.txt': 'text',
  '.env': 'dotenv',
};

/** 拡張子を持たない特殊なファイル名 */
const FILENAME_LANGUAGE: Record<string, string> = {
  dockerfile: 'dockerfile',
  makefile: 'make',
  gemfile: 'ruby',
  rakefile: 'ruby',
  vagrantfile: 'ruby',
  procfile: 'text',
  '.env': 'dotenv',
};

/** ヒューリスティック解析（シンボル・信頼境界）を行う言語 */
const ANALYZABLE = new Set([
  'typescript',
  'javascript',
  'python',
  'go',
  'java',
  'ruby',
  'php',
  'vue',
  'svelte',
]);

/** 相対パスから言語名を判定する */
export function detectLanguage(relPath: string): string {
  const base = relPath.slice(relPath.lastIndexOf('/') + 1).toLowerCase();

  const byName = FILENAME_LANGUAGE[base];
  if (byName) return byName;
  // `Dockerfile.prod` のような派生名
  if (base.startsWith('dockerfile.')) return 'dockerfile';

  const dot = base.lastIndexOf('.');
  if (dot <= 0) return UNKNOWN_LANGUAGE;
  const ext = base.slice(dot);
  return EXTENSION_LANGUAGE[ext] ?? UNKNOWN_LANGUAGE;
}

/** その言語をヒューリスティック解析の対象にするか */
export function isAnalyzable(language: string): boolean {
  return ANALYZABLE.has(language);
}

/** ファイル一覧から言語構成比を集計する（unknown は除外） */
export function summarizeLanguages(files: readonly SourceFile[]): LanguageInfo[] {
  const counts = new Map<string, number>();
  for (const file of files) {
    if (file.language === UNKNOWN_LANGUAGE) continue;
    counts.set(file.language, (counts.get(file.language) ?? 0) + 1);
  }
  const total = [...counts.values()].reduce((a, b) => a + b, 0);
  if (total === 0) return [];

  return [...counts.entries()]
    .map(([name, fileCount]) => ({ name, fileCount, ratio: fileCount / total }))
    .sort((a, b) => b.fileCount - a.fileCount || a.name.localeCompare(b.name));
}
