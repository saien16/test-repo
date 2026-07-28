/**
 * エントリポイント検出。
 *
 * 「攻撃者が最初に触れる場所」を洗い出す。②のLLM分析はここを起点に
 * データフローを追うため、多少の誤検出よりも取りこぼしを避ける。
 */

import type { EntryPoint, SymbolInfo, SymbolTable } from '../types/context.js';
import { SymbolLocator, type AnalyzableSource } from './symbols.js';

/** 1ファイルあたりの上限（生成コードで爆発しないためのガード） */
const MAX_PER_FILE = 300;

interface Rule {
  /** 適用する言語。null なら全言語 */
  languages: readonly string[] | null;
  kind: EntryPoint['kind'];
  re: RegExp;
  /** マッチから識別子（ルートパス等）を取り出す */
  identifier: (m: RegExpExecArray) => string;
  /** 補足情報 */
  metadata?: (m: RegExpExecArray, line: string) => Record<string, string>;
}

const JS = ['typescript', 'javascript', 'vue', 'svelte'];

/** `methods=['POST']` / `methods: ['POST']` から HTTP メソッドを拾う */
function methodsFromLine(line: string): string | undefined {
  const m = /methods\s*[=:]\s*\[([^\]]*)\]/i.exec(line);
  if (!m?.[1]) return undefined;
  const methods = m[1].match(/[A-Za-z]+/g);
  return methods ? methods.join(',').toUpperCase() : undefined;
}

const RULES: readonly Rule[] = [
  // ---- JavaScript / TypeScript ----
  {
    // app.get('/users', handler) / router.post('/x', ...)
    languages: JS,
    kind: 'http-route',
    re: /\b([A-Za-z_$][\w$.]*)\s*\.\s*(get|post|put|patch|delete|head|options|all|use)\s*\(\s*['"`](\/[^'"`]*)['"`]/g,
    identifier: (m) => m[3] ?? '',
    metadata: (m) => ({
      method: (m[2] ?? '').toUpperCase(),
      receiver: m[1] ?? '',
    }),
  },
  {
    // app.route('/x')
    languages: JS,
    kind: 'http-route',
    re: /\b[A-Za-z_$][\w$.]*\s*\.\s*route\s*\(\s*['"`](\/[^'"`]*)['"`]/g,
    identifier: (m) => m[1] ?? '',
  },
  {
    // NestJS / TypeScript デコレータ
    languages: JS,
    kind: 'http-route',
    re: /@(Get|Post|Put|Patch|Delete|All|Options|Head)\s*\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)/g,
    identifier: (m) => m[2] ?? '/',
    metadata: (m) => ({ method: (m[1] ?? '').toUpperCase(), framework: 'nest-like' }),
  },
  {
    // AWS Lambda など
    languages: JS,
    kind: 'event-handler',
    re: /\b(?:exports\s*\.\s*(\w+)|module\s*\.\s*exports\s*\.\s*(\w+))\s*=\s*(?:async\s*)?(?:function|\()/g,
    identifier: (m) => m[1] ?? m[2] ?? 'handler',
  },
  {
    // イベント購読
    languages: JS,
    kind: 'event-handler',
    re: /\.\s*(?:on|once|addEventListener|subscribe)\s*\(\s*['"`]([^'"`]+)['"`]/g,
    identifier: (m) => m[1] ?? '',
  },
  {
    // commander / yargs のサブコマンド
    languages: JS,
    kind: 'cli',
    re: /\.\s*command\s*\(\s*['"`]([^'"`]+)['"`]/g,
    identifier: (m) => m[1] ?? '',
  },
  {
    languages: JS,
    kind: 'cli',
    re: /\bprocess\s*\.\s*argv\b/g,
    identifier: () => 'process.argv',
  },

  // ---- Python ----
  {
    // @app.route('/x') / @router.get('/x')（Flask・FastAPI）
    languages: ['python'],
    kind: 'http-route',
    re: /@\s*[\w.]+\s*\.\s*(route|get|post|put|patch|delete|head|options|websocket)\s*\(\s*['"]([^'"]*)['"]/g,
    identifier: (m) => m[2] ?? '',
    metadata: (m, line) => {
      const verb = (m[1] ?? '').toUpperCase();
      const methods = methodsFromLine(line);
      return { method: methods ?? (verb === 'ROUTE' ? 'GET' : verb) };
    },
  },
  {
    // Django の URLconf
    languages: ['python'],
    kind: 'http-route',
    re: /\b(?:path|re_path|url)\s*\(\s*r?['"]([^'"]*)['"]\s*,/g,
    identifier: (m) => m[1] ?? '',
    metadata: () => ({ framework: 'django' }),
  },
  {
    languages: ['python'],
    kind: 'message-handler',
    re: /@\s*(?:shared_task|celery\.task|app\.task|[\w.]*\.task)\s*(?:\(|$)/g,
    identifier: () => 'celery-task',
  },
  {
    languages: ['python'],
    kind: 'cli',
    re: /\b(?:argparse\s*\.\s*ArgumentParser|@\s*click\.command|@\s*app\.command|sys\s*\.\s*argv)\b/g,
    identifier: (m) => m[0] ?? 'cli',
  },
  {
    languages: ['python'],
    kind: 'main',
    re: /^\s*if\s+__name__\s*==\s*['"]__main__['"]\s*:/g,
    identifier: () => '__main__',
  },

  // ---- Go ----
  {
    languages: ['go'],
    kind: 'http-route',
    re: /\b(?:http|\w+)\s*\.\s*(?:HandleFunc|Handle)\s*\(\s*"([^"]*)"/g,
    identifier: (m) => m[1] ?? '',
    metadata: () => ({ framework: 'net/http' }),
  },
  {
    // gin / echo / chi
    languages: ['go'],
    kind: 'http-route',
    re: /\b\w+\s*\.\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any)\s*\(\s*"([^"]*)"/g,
    identifier: (m) => m[2] ?? '',
    metadata: (m) => ({ method: (m[1] ?? '').toUpperCase() }),
  },
  {
    languages: ['go'],
    kind: 'main',
    re: /^func\s+main\s*\(\s*\)/g,
    identifier: () => 'main',
  },
  {
    languages: ['go'],
    kind: 'cli',
    re: /\b(?:cobra\.Command|flag\s*\.\s*(?:String|Int|Bool|Parse)|os\s*\.\s*Args)\b/g,
    identifier: (m) => m[0] ?? 'cli',
  },

  // ---- Java ----
  {
    languages: ['java'],
    kind: 'http-route',
    re: /@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*(?:value\s*=\s*)?["']([^"']*)["']/g,
    identifier: (m) => m[2] ?? '',
    metadata: (m) => ({
      method: (m[1] ?? '').replace('Mapping', '').toUpperCase() || 'ANY',
      framework: 'spring',
    }),
  },
  {
    languages: ['java'],
    kind: 'http-route',
    re: /@(Path)\s*\(\s*["']([^"']*)["']/g,
    identifier: (m) => m[2] ?? '',
    metadata: () => ({ framework: 'jax-rs' }),
  },
  {
    languages: ['java'],
    kind: 'message-handler',
    re: /@(KafkaListener|JmsListener|RabbitListener|EventListener|SqsListener)\b/g,
    identifier: (m) => m[1] ?? '',
  },
  {
    languages: ['java'],
    kind: 'main',
    re: /\bpublic\s+static\s+void\s+main\s*\(/g,
    identifier: () => 'main',
  },

  // ---- Ruby ----
  {
    // Sinatra / Rails routes.rb
    languages: ['ruby'],
    kind: 'http-route',
    re: /^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)['"]/g,
    identifier: (m) => m[2] ?? '',
    metadata: (m) => ({ method: (m[1] ?? '').toUpperCase() }),
  },
  {
    languages: ['ruby'],
    kind: 'http-route',
    re: /^\s*resources?\s+:(\w+)/g,
    identifier: (m) => `/${m[1] ?? ''}`,
    metadata: () => ({ framework: 'rails' }),
  },

  // ---- PHP ----
  {
    languages: ['php'],
    kind: 'http-route',
    re: /Route\s*::\s*(get|post|put|patch|delete|any|match)\s*\(\s*['"]([^'"]*)['"]/g,
    identifier: (m) => m[2] ?? '',
    metadata: (m) => ({ method: (m[1] ?? '').toUpperCase(), framework: 'laravel' }),
  },
  {
    languages: ['php'],
    kind: 'http-route',
    re: /\$\w+\s*->\s*(get|post|put|patch|delete)\s*\(\s*['"](\/[^'"]*)['"]/g,
    identifier: (m) => m[2] ?? '',
    metadata: (m) => ({ method: (m[1] ?? '').toUpperCase() }),
  },
];

/**
 * 言語ごとの適用ルールをモジュール初期化時に1回だけ振り分ける。
 *
 * 行ごとに RULES 全件を回すと、その言語に無関係なルールまで正規表現を
 * 実行してしまう。バケットは RULES の並び順のまま作るので、検出順は変わらない。
 * 言語非依存ルール（languages: null）は全バケットに含める。
 */
const LANGUAGE_AGNOSTIC_RULES: readonly Rule[] = RULES.filter((r) => r.languages === null);

const RULES_BY_LANGUAGE: ReadonlyMap<string, readonly Rule[]> = (() => {
  const languages = new Set<string>();
  for (const rule of RULES) {
    for (const lang of rule.languages ?? []) languages.add(lang);
  }
  const map = new Map<string, Rule[]>();
  for (const lang of languages) map.set(lang, []);
  for (const rule of RULES) {
    for (const lang of rule.languages ?? languages) map.get(lang)?.push(rule);
  }
  return map;
})();

/** その言語に実際に適用されるルールだけを返す */
function rulesFor(language: string): readonly Rule[] {
  return RULES_BY_LANGUAGE.get(language) ?? LANGUAGE_AGNOSTIC_RULES;
}

/** Next.js のファイル規約からルートパスを推定する */
function nextJsRoute(path: string): string | null {
  const apiMatch = /(?:^|\/)pages\/api\/(.+)\.[jt]sx?$/.exec(path);
  if (apiMatch?.[1]) {
    const route = apiMatch[1].replace(/\/index$/, '');
    return `/api/${route}`;
  }
  const appMatch = /(?:^|\/)app\/(.*)route\.[jt]sx?$/.exec(path);
  if (appMatch) {
    const route = (appMatch[1] ?? '').replace(/\/$/, '');
    return `/${route}`;
  }
  return null;
}

/**
 * エントリポイントを検出する。例外は投げず warnings に積む。
 */
export function detectEntryPoints(
  sources: readonly AnalyzableSource[],
  table: SymbolTable,
  warnings: string[],
): EntryPoint[] {
  const locator = new SymbolLocator(table);
  const found: EntryPoint[] = [];
  const seen = new Set<string>();

  // ファイルごとのシンボルを1回だけ索引化する。
  // source ループの中で table.symbols 全件を回すと O(ファイル数 × 全シンボル数) になる。
  const symbolsByFile = new Map<string, SymbolInfo[]>();
  for (const symbol of table.symbols) {
    const list = symbolsByFile.get(symbol.file);
    if (list) list.push(symbol);
    else symbolsByFile.set(symbol.file, [symbol]);
  }

  const push = (entry: EntryPoint): void => {
    const key = `${entry.kind}|${entry.file}|${entry.line}|${entry.identifier}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push(entry);
  };

  for (const source of sources) {
    try {
      let count = 0;

      // ファイル規約によるルート（Next.js）
      const conventional = nextJsRoute(source.path);
      if (conventional !== null) {
        push({
          kind: 'http-route',
          identifier: conventional,
          file: source.path,
          line: 1,
          symbolId: locator.locate(source.path, 1),
          metadata: { framework: 'next.js', source: 'file-convention' },
        });
      }

      const lines = source.masked.noComment;
      const rules = rulesFor(source.language);
      for (let i = 0; i < lines.length && count < MAX_PER_FILE; i++) {
        const line = lines[i] ?? '';
        if (line.trim() === '') continue;

        for (const rule of rules) {
          rule.re.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = rule.re.exec(line)) !== null) {
            const identifier = rule.identifier(match);
            if (identifier === '') continue;
            push({
              kind: rule.kind,
              identifier,
              file: source.path,
              line: i + 1,
              symbolId: locator.locate(source.path, i + 1),
              metadata: rule.metadata?.(match, line),
            });
            count++;
            if (count >= MAX_PER_FILE) break;
            // 幅ゼロマッチによる無限ループを防ぐ
            if (match.index === rule.re.lastIndex) rule.re.lastIndex++;
          }
        }
      }

      // `main` 関数はシンボル表からも拾う（言語規約が正規表現に載らない場合の保険）
      for (const symbol of symbolsByFile.get(source.path) ?? []) {
        if (symbol.name !== 'main' || symbol.kind === 'module') continue;
        push({
          kind: 'main',
          identifier: 'main',
          file: symbol.file,
          line: symbol.startLine,
          symbolId: `${symbol.file}:${symbol.name}`,
        });
      }
    } catch (err) {
      warnings.push(`エントリポイント検出に失敗しました: ${source.path} (${String(err)})`);
    }
  }

  // ルートやコマンドが1つも無い場合はライブラリとみなし、公開APIを入口として扱う
  if (found.length === 0) {
    for (const symbol of table.symbols) {
      if (!symbol.exported || symbol.kind === 'module') continue;
      if (!/(?:^|\/)(?:index|main|mod)\.[\w]+$/.test(symbol.file)) continue;
      push({
        kind: 'export',
        identifier: symbol.name,
        file: symbol.file,
        line: symbol.startLine,
        symbolId: `${symbol.file}:${symbol.name}`,
      });
    }
  }

  found.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  return found;
}
