import { describe, expect, it } from 'vitest';
import { maskSource } from './mask.js';
import { buildSymbolTable, type AnalyzableSource } from './symbols.js';
import { detectTrustBoundaries } from './trust.js';

function analyze(path: string, language: string, lines: string[]) {
  const src: AnalyzableSource = {
    path,
    language,
    masked: maskSource(lines.join('\n'), language),
  };
  const table = buildSymbolTable([src], []);
  return detectTrustBoundaries([src], table, []);
}

function categories(boundaries: ReturnType<typeof detectTrustBoundaries>, type: 'source' | 'sink') {
  return boundaries.filter((b) => b.type === type).map((b) => b.category);
}

describe('detectTrustBoundaries (JavaScript / TypeScript)', () => {
  const boundaries = analyze('src/routes.ts', 'typescript', [
    "app.get('/user', (req, res) => {", //                 1
    '  const id = req.query.id;', //                       2
    '  const name = req.body.name;', //                    3
    "  db.query('SELECT * FROM users WHERE id=' + id);", // 4
    "  exec('ls ' + name);", //                            5
    '  res.send(el.innerHTML);', //                        6
    '});', //                                              7
  ]);

  it('リクエスト由来の値を source として拾う', () => {
    const sources = boundaries.filter((b) => b.type === 'source');
    expect(sources.map((s) => s.line)).toEqual(expect.arrayContaining([2, 3]));
    expect(categories(boundaries, 'source')).toContain('user-input');
  });

  it('SQL・コマンド実行・HTML出力を sink として分類する', () => {
    const sinks = categories(boundaries, 'sink');
    expect(sinks).toContain('sql');
    expect(sinks).toContain('command-exec');
    expect(sinks).toContain('html-output');
  });

  it('所属シンボルIDを付与する', () => {
    expect(boundaries.every((b) => typeof b.symbolId === 'string' && b.symbolId !== '')).toBe(true);
  });

  it('process.env と process.argv を区別して拾う', () => {
    const envBoundaries = analyze('src/config.ts', 'typescript', [
      'const key = process.env.API_KEY;',
      'const arg = process.argv[2];',
    ]);
    expect(categories(envBoundaries, 'source')).toContain('env');
    expect(categories(envBoundaries, 'source')).toContain('cli-arg');
  });

  it('コメント内の記述は検出しない', () => {
    const commented = analyze('src/note.ts', 'typescript', [
      '// exec(userInput) は危険という説明',
      '/* req.query.id もここでは説明 */',
      'const safe = 1;',
    ]);
    expect(commented).toHaveLength(0);
  });
});

describe('detectTrustBoundaries (Python)', () => {
  const boundaries = analyze('app/views.py', 'python', [
    'def handler(request):', //                            1
    "    name = request.args.get('name')", //              2
    "    os.system('echo ' + name)", //                    3
    '    cursor.execute(sql)', //                          4
    '    data = pickle.loads(payload)', //                 5
    "    path = open(os.path.join(base, name))", //        6
  ]);

  it('Flask/Django のリクエストを source として拾う', () => {
    expect(boundaries.some((b) => b.type === 'source' && b.line === 2)).toBe(true);
  });

  it('コマンド実行・SQL・デシリアライズ・パス結合を sink にする', () => {
    const sinks = categories(boundaries, 'sink');
    expect(sinks).toContain('command-exec');
    expect(sinks).toContain('sql');
    expect(sinks).toContain('deserialization');
    expect(sinks).toContain('file-path');
  });
});

describe('detectTrustBoundaries (Go / Java / PHP / Ruby)', () => {
  it('Go のリクエスト値と exec.Command を検出する', () => {
    const boundaries = analyze('main.go', 'go', [
      'func handle(w http.ResponseWriter, r *http.Request) {',
      '\tname := r.FormValue("name")',
      '\tout, _ := exec.Command("sh", "-c", name).Output()',
      '\tos.Getenv("HOME")',
      '}',
    ]);
    expect(categories(boundaries, 'source')).toContain('user-input');
    expect(categories(boundaries, 'source')).toContain('env');
    expect(categories(boundaries, 'sink')).toContain('command-exec');
  });

  it('Java の getParameter と Runtime.exec を検出する', () => {
    const boundaries = analyze('Servlet.java', 'java', [
      'public class Servlet {',
      '  public void doGet(HttpServletRequest request) {',
      '    String q = request.getParameter("q");',
      '    Runtime.getRuntime().exec(q);',
      '  }',
      '}',
    ]);
    expect(categories(boundaries, 'source')).toContain('user-input');
    expect(categories(boundaries, 'sink')).toContain('command-exec');
  });

  it('PHP のスーパーグローバルと shell_exec を検出する', () => {
    const boundaries = analyze('index.php', 'php', [
      '<?php',
      '$name = $_GET["name"];',
      'shell_exec("ls " . $name);',
      'unserialize($_POST["data"]);',
    ]);
    expect(categories(boundaries, 'source')).toContain('user-input');
    expect(categories(boundaries, 'sink')).toContain('command-exec');
    expect(categories(boundaries, 'sink')).toContain('deserialization');
  });

  it('Ruby の params と system を検出する', () => {
    const boundaries = analyze('app.rb', 'ruby', [
      'def show',
      '  name = params[:name]',
      '  system("echo #{name}")',
      'end',
    ]);
    expect(categories(boundaries, 'source')).toContain('user-input');
    expect(categories(boundaries, 'sink')).toContain('command-exec');
  });
});

describe('ハードコードされた秘密の検出', () => {
  it('リテラルの資格情報を source として拾う', () => {
    const boundaries = analyze('src/config.ts', 'typescript', [
      'const apiKey = "sk-9f8a7b6c5d4e3f2a";',
      'const dbPassword = "s3cr3t-p4ssw0rd";',
    ]);
    expect(categories(boundaries, 'source').filter((c) => c === 'secret')).toHaveLength(2);
  });

  it('環境変数やプレースホルダは秘密として扱わない', () => {
    const boundaries = analyze('src/config.ts', 'typescript', [
      'const apiKey = process.env.API_KEY;',
      'const token = "your-token-here";',
      'const secret = "changeme";',
    ]);
    expect(categories(boundaries, 'source')).not.toContain('secret');
  });
});

describe('言語ごとのルール振り分け', () => {
  it('言語非依存ルール（secret）はどの言語でも適用される', () => {
    // ルールを言語別バケットに事前振り分けしても、languages: null のルールは
    // 全バケットに含まれるので言語に依らず拾えること
    const cases: [string, string, string][] = [
      ['main.go', 'go', 'const apiKey = "sk-9f8a7b6c5d4e3f2a"'],
      ['app/settings.py', 'python', 'API_TOKEN = "tok-9f8a7b6c5d4e3f2a"'],
      ['index.php', 'php', '$dbPassword = "s3cr3t-p4ssw0rd";'],
      ['App.java', 'java', 'String clientSecret = "abcdefgh12345678";'],
      ['app.rb', 'ruby', 'ACCESS_KEY = "AKIAIOSFODNN7EXAMPLX"'],
    ];

    for (const [path, language, line] of cases) {
      expect(categories(analyze(path, language, [line]), 'source')).toContain('secret');
    }
  });

  it('他言語のルールは適用されない', () => {
    // PHP のスーパーグローバルは TypeScript ファイルでは拾わない
    expect(analyze('src/a.ts', 'typescript', ['const x = $_GET["a"];'])).toHaveLength(0);
    // process.env（JS 専用）は Python ファイルでは拾わない
    expect(analyze('app/a.py', 'python', ['x = process.env.KEY'])).toHaveLength(0);
  });

  it('どのルールにも属さない言語でも言語非依存ルールだけは動く', () => {
    const boundaries = analyze('main.rs', 'rust', [
      'let api_key = "sk-9f8a7b6c5d4e3f2a";',
      'let x = req.query.id;',
    ]);
    expect(categories(boundaries, 'source')).toEqual(['secret']);
  });

  it('同じ行に複数のマッチがあってもプレースホルダ判定は一貫する', () => {
    // 行内の1回評価に変えても、行単位の判定である以上結果は変わらない
    const suppressed = analyze('src/config.ts', 'typescript', [
      'const a = "your-token-here"; const b = "your-secret-here";',
    ]);
    expect(categories(suppressed, 'source')).not.toContain('secret');

    const kept = analyze('src/config.ts', 'typescript', [
      'const token = "tok-9f8a7b6c5d4e"; const secret = "s3cr3t-p4ssw0rd";',
    ]);
    expect(categories(kept, 'source').filter((c) => c === 'secret').length).toBeGreaterThan(0);
  });
});

describe('頑健性', () => {
  it('空ファイルでも例外を投げない', () => {
    expect(() => analyze('empty.ts', 'typescript', [''])).not.toThrow();
    expect(analyze('empty.ts', 'typescript', [''])).toEqual([]);
  });
});
