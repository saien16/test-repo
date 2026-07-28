/**
 * 信頼境界（source / sink）の検出。
 *
 * ②のLLM分析はここで挙がった地点を手掛かりに「汚染された入力が危険な
 * 操作に到達するか」を判断するため、コンテキスト収集の中で最も出力品質に
 * 効く部分である。言語ごとに実際によく使われる API を列挙する。
 *
 *  source: 攻撃者が内容を左右できる値の出所（HTTPリクエスト、CLI引数、環境変数…）
 *          加えて、外部へ漏れると危険な機微データの出所（ハードコードされた秘密）
 *  sink  : 汚染された値が届くと危険な操作（SQL、コマンド実行、HTML出力、パス結合…）
 */

import type { SymbolTable, TrustBoundary } from '../types/context.js';
import { SymbolLocator, type AnalyzableSource } from './symbols.js';

/** 1ファイルあたりの検出上限 */
const MAX_PER_FILE = 400;
/** expression の最大長 */
const MAX_EXPRESSION = 160;

interface BoundaryRule {
  type: TrustBoundary['type'];
  category: string;
  /** 適用言語。null なら全言語 */
  languages: readonly string[] | null;
  re: RegExp;
}

const JS = ['typescript', 'javascript', 'vue', 'svelte'];
const PY = ['python'];
const GO = ['go'];
const JAVA = ['java'];
const RB = ['ruby', 'erb'];
const PHP = ['php'];

/**
 * 検出ルール。すべて `g` フラグ付きで書くこと。
 */
const RULES: readonly BoundaryRule[] = [
  // ============================================================
  // JavaScript / TypeScript
  // ============================================================
  {
    type: 'source',
    category: 'user-input',
    languages: JS,
    re: /\b(?:req|request|ctx|context|c|event)\s*\.\s*(?:query|body|params|param|headers|header|cookies|files|rawBody|queryStringParameters|pathParameters|multiValueQueryStringParameters)\b/g,
  },
  {
    type: 'source',
    category: 'user-input',
    languages: JS,
    re: /\b(?:req|request)\s*\.\s*(?:get|header|param)\s*\(/g,
  },
  {
    type: 'source',
    category: 'user-input',
    languages: JS,
    re: /\b(?:searchParams|url\.searchParams)\s*\.\s*(?:get|getAll|has)\s*\(/g,
  },
  {
    type: 'source',
    category: 'user-input',
    languages: JS,
    re: /\b(?:window\s*\.\s*)?(?:location\s*\.\s*(?:search|hash|href|pathname)|document\s*\.\s*(?:referrer|cookie|URL))\b/g,
  },
  {
    type: 'source',
    category: 'user-input',
    languages: JS,
    re: /\b(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(/g,
  },
  {
    type: 'source',
    category: 'cli-arg',
    languages: JS,
    re: /\bprocess\s*\.\s*argv\b/g,
  },
  {
    type: 'source',
    category: 'env',
    languages: JS,
    re: /\bprocess\s*\.\s*env\b/g,
  },
  {
    // `regex.exec(...)` のような無関係な呼び出しを拾わないよう、レシーバ付きは
    // child_process とその別名に限定する。
    type: 'sink',
    category: 'command-exec',
    languages: JS,
    re: /\b(?:child_process|childProcess|cp|proc)\s*\.\s*(?:execSync|execFileSync|spawnSync|execFile|exec|spawn|fork)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'command-exec',
    languages: JS,
    re: /(?:^|[^.\w$])(?:execSync|execFileSync|spawnSync|execFile|exec|spawn)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'code-eval',
    languages: JS,
    re: /\b(?:eval\s*\(|new\s+Function\s*\(|vm\s*\.\s*run\w*\s*\(|Function\s*\(\s*['"`])/g,
  },
  {
    type: 'sink',
    category: 'sql',
    languages: JS,
    re: /\.\s*(?:query|execute|executeSql|raw|queryRaw|queryRawUnsafe|executeRawUnsafe|createQueryBuilder)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'nosql',
    languages: JS,
    re: /\.\s*(?:find|findOne|findOneAndUpdate|updateOne|deleteOne|aggregate)\s*\(\s*\{/g,
  },
  {
    type: 'sink',
    category: 'html-output',
    languages: JS,
    re: /\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|insertAdjacentHTML|document\s*\.\s*write(?:ln)?|v-html)\b/g,
  },
  {
    type: 'sink',
    category: 'file-path',
    languages: JS,
    re: /\b(?:path\s*\.\s*(?:join|resolve|normalize)|fs\s*\.\s*(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|createReadStream|createWriteStream|unlink|rm|readdir)\w*|sendFile|createReadStream)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'network',
    languages: JS,
    re: /\b(?:fetch|axios(?:\s*\.\s*\w+)?|got|superagent|https?\s*\.\s*(?:get|request))\s*\(/g,
  },
  {
    type: 'sink',
    category: 'deserialization',
    languages: JS,
    re: /\b(?:yaml\s*\.\s*load|unserialize|deserialize|JSON\s*\.\s*parse)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'redirect',
    languages: JS,
    re: /\b(?:res|response)\s*\.\s*redirect\s*\(|\blocation\s*\.\s*(?:href|assign|replace)\s*(?:=|\()/g,
  },
  {
    type: 'sink',
    category: 'crypto',
    languages: JS,
    re: /\b(?:createHash\s*\(\s*['"`](?:md5|sha1)['"`]|createCipher\s*\(|Math\s*\.\s*random\s*\(|createDecipher\s*\()/g,
  },
  {
    type: 'sink',
    category: 'template',
    languages: JS,
    re: /\b(?:res|response)\s*\.\s*render\s*\(|\bhandlebars\s*\.\s*compile\s*\(/g,
  },

  // ============================================================
  // Python
  // ============================================================
  {
    type: 'source',
    category: 'user-input',
    languages: PY,
    re: /\brequest\s*\.\s*(?:args|form|json|values|data|files|cookies|headers|GET|POST|body|META|COOKIES|FILES|query_params|stream)\b/g,
  },
  {
    type: 'source',
    category: 'user-input',
    languages: PY,
    re: /\b(?:input|raw_input)\s*\(/g,
  },
  {
    type: 'source',
    category: 'cli-arg',
    languages: PY,
    re: /\bsys\s*\.\s*argv\b/g,
  },
  {
    type: 'source',
    category: 'env',
    languages: PY,
    re: /\bos\s*\.\s*(?:environ\b|getenv\s*\()/g,
  },
  {
    type: 'sink',
    category: 'command-exec',
    languages: PY,
    re: /\b(?:os\s*\.\s*(?:system|popen|execv?p?e?|spawn\w*)|subprocess\s*\.\s*(?:run|call|check_call|check_output|Popen|getoutput)|commands\s*\.\s*getoutput)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'code-eval',
    languages: PY,
    re: /(?:^|[^.\w])(?:eval|exec|compile)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'sql',
    languages: PY,
    re: /\.\s*(?:execute|executemany|executescript|raw|extra)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'file-path',
    languages: PY,
    re: /\b(?:open|os\s*\.\s*path\s*\.\s*join|os\s*\.\s*(?:remove|unlink|rename|mkdir|listdir)|send_file|send_from_directory|shutil\s*\.\s*\w+|pathlib\s*\.\s*Path)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'html-output',
    languages: PY,
    re: /\b(?:render_template_string|mark_safe|Markup|format_html)\s*\(|\|\s*safe\b/g,
  },
  {
    type: 'sink',
    category: 'deserialization',
    languages: PY,
    re: /\b(?:pickle|cPickle|dill|marshal|jsonpickle)\s*\.\s*loads?\s*\(|\byaml\s*\.\s*(?:load|unsafe_load|full_load)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'network',
    languages: PY,
    re: /\b(?:requests\s*\.\s*(?:get|post|put|patch|delete|head|request)|urllib\s*\.\s*request\s*\.\s*urlopen|urlopen|httpx\s*\.\s*\w+|aiohttp\s*\.\s*\w+)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'crypto',
    languages: PY,
    re: /\b(?:hashlib\s*\.\s*(?:md5|sha1)|random\s*\.\s*(?:random|randint|choice)|Crypto\s*\.\s*Cipher\s*\.\s*DES)\s*[(.]/g,
  },
  {
    type: 'sink',
    category: 'redirect',
    languages: PY,
    re: /\b(?:redirect|HttpResponseRedirect)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'xml',
    languages: PY,
    re: /\b(?:etree\s*\.\s*(?:parse|fromstring)|xmlrpc|minidom\s*\.\s*parse\w*)\s*\(/g,
  },

  // ============================================================
  // Go
  // ============================================================
  {
    type: 'source',
    category: 'user-input',
    languages: GO,
    re: /\b\w+\s*\.\s*(?:FormValue|PostFormValue|URL\s*\.\s*Query|ParseForm|ParseMultipartForm|MultipartForm|PostForm)\s*(?:\(|\b)/g,
  },
  {
    type: 'source',
    category: 'user-input',
    languages: GO,
    re: /\b\w+\s*\.\s*(?:Body\b|Header\s*\.\s*Get\s*\(|Cookie\s*\(|Param\s*\(|Query\s*\(|QueryParam\s*\(|ShouldBind\w*\s*\(|BindJSON\s*\()/g,
  },
  {
    type: 'source',
    category: 'user-input',
    languages: GO,
    re: /\bmux\s*\.\s*Vars\s*\(/g,
  },
  {
    type: 'source',
    category: 'env',
    languages: GO,
    re: /\bos\s*\.\s*(?:Getenv|LookupEnv)\s*\(/g,
  },
  {
    type: 'source',
    category: 'cli-arg',
    languages: GO,
    re: /\bos\s*\.\s*Args\b/g,
  },
  {
    type: 'sink',
    category: 'command-exec',
    languages: GO,
    re: /\b(?:exec\s*\.\s*Command(?:Context)?|syscall\s*\.\s*Exec)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'sql',
    languages: GO,
    re: /\.\s*(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Raw|Where)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'file-path',
    languages: GO,
    re: /\b(?:os\s*\.\s*(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove\w*)|ioutil\s*\.\s*(?:ReadFile|WriteFile)|filepath\s*\.\s*Join|http\s*\.\s*ServeFile)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'html-output',
    languages: GO,
    re: /\b(?:template\s*\.\s*(?:HTML|JS|URL)|fmt\s*\.\s*Fprintf?\s*\(\s*w\b)/g,
  },
  {
    type: 'sink',
    category: 'network',
    languages: GO,
    re: /\bhttp\s*\.\s*(?:Get|Post|PostForm|Head|NewRequest)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'crypto',
    languages: GO,
    re: /\b(?:md5\s*\.\s*(?:New|Sum)|sha1\s*\.\s*(?:New|Sum)|rand\s*\.\s*(?:Intn|Int|Float64)|des\s*\.\s*NewCipher)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'deserialization',
    languages: GO,
    re: /\b(?:gob\s*\.\s*NewDecoder|yaml\s*\.\s*Unmarshal)\s*\(/g,
  },

  // ============================================================
  // Java
  // ============================================================
  {
    type: 'source',
    category: 'user-input',
    languages: JAVA,
    re: /\b\w*[Rr]equest\s*\.\s*(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getCookies|getQueryString|getInputStream|getReader|getPathInfo|getRequestURI)\s*\(/g,
  },
  {
    type: 'source',
    category: 'user-input',
    languages: JAVA,
    re: /@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|QueryParam|FormParam|HeaderParam)\b/g,
  },
  {
    type: 'source',
    category: 'env',
    languages: JAVA,
    re: /\bSystem\s*\.\s*(?:getenv|getProperty)\s*\(/g,
  },
  {
    type: 'source',
    category: 'cli-arg',
    languages: JAVA,
    re: /\bargs\s*\[\s*\d*\s*\w*\s*\]/g,
  },
  {
    type: 'sink',
    category: 'command-exec',
    languages: JAVA,
    re: /\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'sql',
    languages: JAVA,
    re: /\.\s*(?:createQuery|createNativeQuery|createSQLQuery|executeQuery|executeUpdate|prepareStatement|prepareCall)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'file-path',
    languages: JAVA,
    re: /\b(?:new\s+File|new\s+FileInputStream|new\s+FileOutputStream|Paths\s*\.\s*get|Files\s*\.\s*(?:readAllBytes|readString|write|newInputStream|delete))\s*\(/g,
  },
  {
    type: 'sink',
    category: 'html-output',
    languages: JAVA,
    re: /\.\s*getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write)\s*\(|\.\s*getOutputStream\s*\(\s*\)/g,
  },
  {
    type: 'sink',
    category: 'deserialization',
    languages: JAVA,
    re: /\b(?:new\s+ObjectInputStream|readObject\s*\(|XMLDecoder|XStream|SnakeYAML|new\s+Yaml)\b/g,
  },
  {
    type: 'sink',
    category: 'network',
    languages: JAVA,
    re: /\b(?:new\s+URL|HttpURLConnection|RestTemplate|HttpClient\s*\.\s*newHttpClient|WebClient)\b/g,
  },
  {
    type: 'sink',
    category: 'crypto',
    languages: JAVA,
    re: /\b(?:MessageDigest\s*\.\s*getInstance\s*\(\s*"(?:MD5|SHA-?1)"|Cipher\s*\.\s*getInstance\s*\(\s*"(?:DES|RC4|AES\/ECB)|new\s+Random\s*\()/g,
  },
  {
    type: 'sink',
    category: 'redirect',
    languages: JAVA,
    re: /\.\s*sendRedirect\s*\(/g,
  },
  {
    type: 'sink',
    category: 'xml',
    languages: JAVA,
    re: /\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\b/g,
  },

  // ============================================================
  // Ruby
  // ============================================================
  {
    type: 'source',
    category: 'user-input',
    languages: RB,
    re: /\b(?:params\s*\[|request\s*\.\s*(?:body|params|headers|env|query_string|raw_post)|cookies\s*\[)/g,
  },
  {
    type: 'source',
    category: 'env',
    languages: RB,
    re: /\bENV\s*\[|\bENV\s*\.\s*fetch\s*\(/g,
  },
  {
    type: 'source',
    category: 'cli-arg',
    languages: RB,
    re: /\bARGV\b|\bgets\b/g,
  },
  {
    type: 'sink',
    category: 'command-exec',
    languages: RB,
    re: /\b(?:system|exec|spawn)\s*\(|\bIO\s*\.\s*popen\s*\(|\bOpen3\s*\.\s*\w+\s*\(|%x[({[]/g,
  },
  {
    type: 'sink',
    category: 'code-eval',
    languages: RB,
    re: /\b(?:eval|instance_eval|class_eval|module_eval|send|public_send)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'sql',
    languages: RB,
    re: /\.\s*(?:find_by_sql|execute|where|order|group|select|joins)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'file-path',
    languages: RB,
    re: /\b(?:File\s*\.\s*(?:open|read|write|join|delete|new)|IO\s*\.\s*read|send_file|Dir\s*\.\s*glob)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'html-output',
    languages: RB,
    re: /\b(?:raw\s*\(|html_safe\b|render\s+inline\s*:)/g,
  },
  {
    type: 'sink',
    category: 'deserialization',
    languages: RB,
    re: /\b(?:Marshal\s*\.\s*load|YAML\s*\.\s*(?:load|unsafe_load)|Psych\s*\.\s*load)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'redirect',
    languages: RB,
    re: /\bredirect_to\b/g,
  },

  // ============================================================
  // PHP
  // ============================================================
  {
    type: 'source',
    category: 'user-input',
    languages: PHP,
    re: /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|SESSION)\b/g,
  },
  {
    type: 'source',
    category: 'user-input',
    languages: PHP,
    re: /\bphp:\/\/input\b|\bfilter_input\s*\(/g,
  },
  {
    type: 'source',
    category: 'env',
    languages: PHP,
    re: /\bgetenv\s*\(|\$_ENV\b/g,
  },
  {
    type: 'sink',
    category: 'command-exec',
    languages: PHP,
    re: /\b(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'code-eval',
    languages: PHP,
    re: /\b(?:eval|assert|create_function|call_user_func(?:_array)?)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'sql',
    languages: PHP,
    re: /\b(?:mysql_query|mysqli_query|pg_query)\s*\(|->\s*(?:query|prepare|exec)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'file-path',
    languages: PHP,
    re: /\b(?:fopen|file_get_contents|file_put_contents|readfile|unlink|include|include_once|require|require_once|move_uploaded_file)\s*[(\s]/g,
  },
  {
    type: 'sink',
    category: 'html-output',
    languages: PHP,
    re: /\b(?:echo|print)\s+[^;]*\$/g,
  },
  {
    type: 'sink',
    category: 'deserialization',
    languages: PHP,
    re: /\bunserialize\s*\(/g,
  },
  {
    type: 'sink',
    category: 'network',
    languages: PHP,
    re: /\b(?:curl_exec|curl_setopt|fsockopen)\s*\(/g,
  },
  {
    type: 'sink',
    category: 'crypto',
    languages: PHP,
    re: /\b(?:md5|sha1|mt_rand|rand|crypt)\s*\(/g,
  },

  // ============================================================
  // 言語非依存
  // ============================================================
  {
    // ハードコードされた資格情報。漏洩すると危険な機微データの出所として source 扱いにする。
    type: 'source',
    category: 'secret',
    languages: null,
    // `dbPassword` のように接頭辞が付く変数名も拾えるようにしている
    re: /\b[\w.$-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*['"][^'"\s]{8,}['"]/gi,
  },
  {
    type: 'source',
    category: 'secret',
    languages: null,
    re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    // AWS アクセスキーID の形式
    type: 'source',
    category: 'secret',
    languages: null,
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
];

/**
 * 言語ごとの適用ルールをモジュール初期化時に1回だけ振り分ける。
 *
 * 行ごとに RULES 全件（82件）を回すと、JS ファイルなら実際に使う22件以外の
 * 60件まで毎行実行して捨てることになる。バケットは RULES の並び順のまま作るので
 * 検出順・上限による打ち切り位置は変わらない。
 * 言語非依存ルール（languages: null）は全バケットに含める。
 */
const LANGUAGE_AGNOSTIC_RULES: readonly BoundaryRule[] = RULES.filter(
  (r) => r.languages === null,
);

const RULES_BY_LANGUAGE: ReadonlyMap<string, readonly BoundaryRule[]> = (() => {
  const languages = new Set<string>();
  for (const rule of RULES) {
    for (const lang of rule.languages ?? []) languages.add(lang);
  }
  const map = new Map<string, BoundaryRule[]>();
  for (const lang of languages) map.set(lang, []);
  for (const rule of RULES) {
    for (const lang of rule.languages ?? languages) map.get(lang)?.push(rule);
  }
  return map;
})();

/** その言語に実際に適用されるルールだけを返す */
function rulesFor(language: string): readonly BoundaryRule[] {
  return RULES_BY_LANGUAGE.get(language) ?? LANGUAGE_AGNOSTIC_RULES;
}

/** 明らかにプレースホルダな値は秘密情報として扱わない */
const SECRET_PLACEHOLDER = /(?:example|changeme|placeholder|your[_-]?|xxx+|\*{3,}|<[^>]+>|process\.env|os\.environ|\$\{)/i;

function truncate(text: string): string {
  const trimmed = text.trim();
  return trimmed.length > MAX_EXPRESSION ? `${trimmed.slice(0, MAX_EXPRESSION)}…` : trimmed;
}

/**
 * 信頼境界を検出する。1ファイルの失敗が全体を止めないよう例外は握り潰す。
 */
export function detectTrustBoundaries(
  sources: readonly AnalyzableSource[],
  table: SymbolTable,
  warnings: string[],
): TrustBoundary[] {
  const locator = new SymbolLocator(table);
  const results: TrustBoundary[] = [];

  for (const source of sources) {
    try {
      const seen = new Set<string>();
      const lines = source.masked.noComment;
      const rules = rulesFor(source.language);
      let count = 0;

      for (let i = 0; i < lines.length && count < MAX_PER_FILE; i++) {
        const line = lines[i] ?? '';
        if (line.trim() === '') continue;
        // プレースホルダ判定は行単位で不変。マッチごとに同じ行を再検査しないよう、
        // 最初に必要になった時点で1回だけ評価してこの行の間だけ持ち回す
        // （secret ルールに当たらない行では評価自体を行わない）。
        let placeholderCache: boolean | undefined;
        const isPlaceholderLine = (): boolean =>
          (placeholderCache ??= SECRET_PLACEHOLDER.test(line));

        for (const rule of rules) {
          rule.re.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = rule.re.exec(line)) !== null) {
            const raw = match[0];
            if (raw === '') {
              rule.re.lastIndex++;
              continue;
            }
            if (rule.category === 'secret' && isPlaceholderLine()) continue;

            const expression = truncate(raw);
            const key = `${rule.type}|${rule.category}|${i}|${expression}`;
            if (seen.has(key)) continue;
            seen.add(key);

            results.push({
              type: rule.type,
              category: rule.category,
              expression,
              file: source.path,
              line: i + 1,
              symbolId: locator.locate(source.path, i + 1),
            });
            count++;
            if (count >= MAX_PER_FILE) break;
          }
          if (count >= MAX_PER_FILE) break;
        }
      }

      if (count >= MAX_PER_FILE) {
        warnings.push(`信頼境界の検出数が上限に達しました: ${source.path}`);
      }
    } catch (err) {
      warnings.push(`信頼境界の検出に失敗しました: ${source.path} (${String(err)})`);
    }
  }

  results.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  return results;
}
