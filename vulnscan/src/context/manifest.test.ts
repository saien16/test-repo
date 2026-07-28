import { describe, expect, it } from 'vitest';
import { collectDependencies } from './dependencies.js';
import { detectEntryPoints } from './entrypoints.js';
import { detectFrameworks } from './frameworks.js';
import { detectLanguage, summarizeLanguages } from './language.js';
import { maskSource } from './mask.js';
import { buildSymbolTable, type AnalyzableSource } from './symbols.js';
import { looksBinary } from './walk.js';

function src(path: string, language: string, lines: string[]): AnalyzableSource {
  return { path, language, masked: maskSource(lines.join('\n'), language) };
}

function entryPointsOf(source: AnalyzableSource) {
  const table = buildSymbolTable([source], []);
  return detectEntryPoints([source], table, []);
}

describe('detectLanguage', () => {
  it('拡張子から言語を判定する', () => {
    expect(detectLanguage('src/a.ts')).toBe('typescript');
    expect(detectLanguage('src/a.tsx')).toBe('typescript');
    expect(detectLanguage('src/a.mjs')).toBe('javascript');
    expect(detectLanguage('app/views.py')).toBe('python');
    expect(detectLanguage('main.go')).toBe('go');
    expect(detectLanguage('Main.java')).toBe('java');
    expect(detectLanguage('app.rb')).toBe('ruby');
    expect(detectLanguage('index.php')).toBe('php');
    expect(detectLanguage('Dockerfile')).toBe('dockerfile');
    expect(detectLanguage('LICENSE')).toBe('unknown');
  });
});

describe('summarizeLanguages', () => {
  it('件数と比率を集計し unknown を除外する', () => {
    const languages = summarizeLanguages([
      { path: 'a.ts', language: 'typescript', sizeBytes: 1, hash: 'x' },
      { path: 'b.ts', language: 'typescript', sizeBytes: 1, hash: 'x' },
      { path: 'c.py', language: 'python', sizeBytes: 1, hash: 'x' },
      { path: 'LICENSE', language: 'unknown', sizeBytes: 1, hash: 'x' },
    ]);
    expect(languages[0]).toEqual({ name: 'typescript', fileCount: 2, ratio: 2 / 3 });
    expect(languages.map((l) => l.name)).not.toContain('unknown');
  });
});

describe('looksBinary', () => {
  it('NUL バイトを含む内容をバイナリと判定する', () => {
    expect(looksBinary(Buffer.from('hello world'))).toBe(false);
    expect(looksBinary(Buffer.from([0x68, 0x00, 0x69]))).toBe(true);
  });
});

describe('collectDependencies', () => {
  it('package.json を npm として読む', () => {
    const deps = collectDependencies(
      [
        {
          path: 'package.json',
          content: JSON.stringify({
            dependencies: { express: '^4.18.2' },
            devDependencies: { vitest: '^2.1.8' },
          }),
        },
      ],
      [],
    );
    expect(deps).toContainEqual({
      name: 'express',
      version: '^4.18.2',
      ecosystem: 'npm',
      dev: false,
      manifest: 'package.json',
    });
    expect(deps.find((d) => d.name === 'vitest')?.dev).toBe(true);
  });

  it('requirements.txt を PyPI として読む', () => {
    const deps = collectDependencies(
      [
        {
          path: 'requirements.txt',
          content: ['# コメント', '-r base.txt', 'Flask==2.3.2', 'requests>=2.31.0', 'uvicorn[standard]==0.30.0'].join('\n'),
        },
      ],
      [],
    );
    expect(deps.map((d) => d.name)).toEqual(['Flask', 'requests', 'uvicorn']);
    expect(deps.every((d) => d.ecosystem === 'PyPI')).toBe(true);
    expect(deps.find((d) => d.name === 'Flask')?.version).toBe('2.3.2');
  });

  it('go.mod を Go として読む', () => {
    const deps = collectDependencies(
      [
        {
          path: 'go.mod',
          content: [
            'module example.com/app',
            'go 1.22',
            'require (',
            '\tgithub.com/gin-gonic/gin v1.9.1',
            '\tgolang.org/x/crypto v0.17.0 // indirect',
            ')',
            'require github.com/gorilla/mux v1.8.0',
          ].join('\n'),
        },
      ],
      [],
    );
    expect(deps.map((d) => d.name)).toEqual(
      expect.arrayContaining([
        'github.com/gin-gonic/gin',
        'golang.org/x/crypto',
        'github.com/gorilla/mux',
      ]),
    );
    expect(deps.every((d) => d.ecosystem === 'Go')).toBe(true);
  });

  it('pyproject.toml の PEP621 と Poetry 双方を読む', () => {
    const pep621 = collectDependencies(
      [
        {
          path: 'pyproject.toml',
          content: ['[project]', 'name = "app"', 'dependencies = [', '  "django>=4.2",', '  "celery",', ']'].join('\n'),
        },
      ],
      [],
    );
    expect(pep621.map((d) => d.name)).toEqual(['celery', 'django']);

    const poetry = collectDependencies(
      [
        {
          path: 'pyproject.toml',
          content: [
            '[tool.poetry.dependencies]',
            'python = "^3.11"',
            'flask = "^3.0"',
            '[tool.poetry.group.dev.dependencies]',
            'pytest = "^8.0"',
          ].join('\n'),
        },
      ],
      [],
    );
    expect(poetry.find((d) => d.name === 'flask')?.version).toBe('^3.0');
    expect(poetry.find((d) => d.name === 'pytest')?.dev).toBe(true);
    // python 自体は依存として扱わない
    expect(poetry.find((d) => d.name === 'python')).toBeUndefined();
  });

  it('壊れた JSON は警告にして例外にしない', () => {
    const warnings: string[] = [];
    expect(() =>
      collectDependencies([{ path: 'package.json', content: '{ 壊れている' }], warnings),
    ).not.toThrow();
    expect(warnings).toHaveLength(1);
  });

  it('依存名として妥当でない文字列を除外する（マニフェストは未信頼入力）', () => {
    const warnings: string[] = [];
    const deps = collectDependencies(
      [
        {
          path: 'package.json',
          content: JSON.stringify({
            dependencies: {
              '<img src=x onerror=alert(1)>': '1.0.0',
              'evil`pkg`': '1.0.0',
              'name with space': '1.0.0',
              express: '^4.18.2',
            },
          }),
        },
      ],
      warnings,
    );
    expect(deps.map((d) => d.name)).toEqual(['express']);
    expect(warnings).toHaveLength(1);
    // 警告に不正な名前そのものを持ち込まない
    expect(warnings[0]!).not.toContain('<img');
    expect(warnings[0]!).toContain('package.json');
  });

  it('各エコシステムの正当な名前は除外しない', () => {
    const warnings: string[] = [];
    const deps = collectDependencies(
      [
        {
          path: 'package.json',
          content: JSON.stringify({ dependencies: { '@scope/pkg': '1.0.0' } }),
        },
        { path: 'go.mod', content: 'require github.com/gin-gonic/gin v1.9.1' },
        {
          path: 'pom.xml',
          content:
            '<dependency><groupId>org.springframework.boot</groupId>' +
            '<artifactId>spring-boot-starter-web</artifactId><version>3.2.0</version></dependency>',
        },
      ],
      warnings,
    );
    expect(deps.map((d) => d.name).sort()).toEqual([
      '@scope/pkg',
      'github.com/gin-gonic/gin',
      'org.springframework.boot:spring-boot-starter-web',
    ]);
    expect(warnings).toEqual([]);
  });
});

describe('detectFrameworks', () => {
  it('依存名からフレームワークを推定する', () => {
    const frameworks = detectFrameworks(
      [
        { name: 'express', version: '^4.18.2', ecosystem: 'npm', dev: false, manifest: 'package.json' },
        { name: 'django', version: '4.2', ecosystem: 'PyPI', dev: false, manifest: 'requirements.txt' },
        {
          name: 'github.com/gin-gonic/gin',
          version: 'v1.9.1',
          ecosystem: 'Go',
          dev: false,
          manifest: 'go.mod',
        },
        {
          name: 'org.springframework.boot:spring-boot-starter-web',
          version: '3.2.0',
          ecosystem: 'Maven',
          dev: false,
          manifest: 'pom.xml',
        },
      ],
      [],
      [],
    );
    const names = frameworks.map((f) => f.name);
    expect(names).toEqual(expect.arrayContaining(['Express', 'Django', 'Gin', 'Spring Boot']));
    expect(frameworks.find((f) => f.name === 'Express')?.version).toBe('^4.18.2');
    expect(frameworks.find((f) => f.name === 'Express')?.evidence).toContain('package.json');
  });

  it('規約ファイルからも推定する', () => {
    const frameworks = detectFrameworks([], ['web/next.config.js', 'api/manage.py'], []);
    expect(frameworks.map((f) => f.name)).toEqual(expect.arrayContaining(['Next.js', 'Django']));
  });
});

describe('detectEntryPoints', () => {
  it('Express のルートをメソッド付きで検出する', () => {
    const entries = entryPointsOf(
      src('src/routes.ts', 'typescript', [
        "app.get('/users/:id', handler);",
        "router.post('/login', loginHandler);",
        "const m = map.get('key');",
      ]),
    );
    const routes = entries.filter((e) => e.kind === 'http-route');
    expect(routes.map((r) => r.identifier)).toEqual(['/users/:id', '/login']);
    expect(routes[0]?.metadata?.['method']).toBe('GET');
    expect(routes[1]?.metadata?.['method']).toBe('POST');
  });

  it('Flask / FastAPI のデコレータを検出する', () => {
    const entries = entryPointsOf(
      src('app/views.py', 'python', [
        "@app.route('/search', methods=['GET', 'POST'])",
        'def search():',
        '    return 1',
      ]),
    );
    const route = entries.find((e) => e.kind === 'http-route');
    expect(route?.identifier).toBe('/search');
    expect(route?.metadata?.['method']).toBe('GET,POST');
  });

  it('Django の URLconf を検出する', () => {
    const entries = entryPointsOf(
      src('app/urls.py', 'python', ["path('admin/', admin.site.urls),"]),
    );
    expect(entries.some((e) => e.identifier === 'admin/')).toBe(true);
  });

  it('Spring のマッピングを検出する', () => {
    const entries = entryPointsOf(
      src('Controller.java', 'java', ['@GetMapping("/api/users")', 'public List<User> list() {}']),
    );
    const route = entries.find((e) => e.kind === 'http-route');
    expect(route?.identifier).toBe('/api/users');
    expect(route?.metadata?.['framework']).toBe('spring');
  });

  it('Go の main 関数と HandleFunc を検出する', () => {
    const entries = entryPointsOf(
      src('main.go', 'go', ['func main() {', '\thttp.HandleFunc("/health", ok)', '}']),
    );
    expect(entries.some((e) => e.kind === 'main')).toBe(true);
    expect(entries.some((e) => e.kind === 'http-route' && e.identifier === '/health')).toBe(true);
  });

  it('Next.js のファイル規約からルートを推定する', () => {
    const entries = entryPointsOf(
      src('pages/api/login.ts', 'typescript', ['export default function handler(req, res) {}']),
    );
    expect(entries.some((e) => e.identifier === '/api/login')).toBe(true);
  });

  it('入口が無いライブラリでは公開シンボルを export として扱う', () => {
    const entries = entryPointsOf(
      src('src/index.ts', 'typescript', ['export function publicApi() {', '  return 1;', '}']),
    );
    expect(entries).toEqual([
      expect.objectContaining({ kind: 'export', identifier: 'publicApi' }),
    ]);
  });

  it('複数ファイルでも main はそのファイルのものだけを拾う', () => {
    // シンボル表はファイル単位で索引化してある（source ループ内の全走査を廃止）。
    // 索引化しても、他ファイルの main が混ざらないこと
    const sources = [
      src('cmd/a/main.go', 'go', ['func main() {', '\tstart()', '}']),
      src('cmd/b/main.go', 'go', ['func main() {', '\tstop()', '}']),
      src('internal/util.go', 'go', ['func helper() {', '\treturn', '}']),
    ];
    const table = buildSymbolTable(sources, []);
    const entries = detectEntryPoints(sources, table, []);

    const mains = entries.filter((e) => e.kind === 'main');
    expect(mains.map((m) => m.file)).toEqual(['cmd/a/main.go', 'cmd/b/main.go']);
    for (const m of mains) {
      expect(m.symbolId).toBe(`${m.file}:main`);
    }
  });

  it('他言語のルールは適用されない', () => {
    // ルールを言語別に事前振り分けしても、対象言語の判定は変わらないこと
    const entries = entryPointsOf(
      src('app/views.py', 'python', ["app.get('/users', handler)"]),
    );
    expect(entries.some((e) => e.identifier === '/users')).toBe(false);
  });
});
