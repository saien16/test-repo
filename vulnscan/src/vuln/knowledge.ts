/**
 * CWE / OWASP Top 10 の知識ベース。
 * 外部ネットワークに依存せずオフラインで参照できるよう、主要な項目をハードコードしている。
 *
 * 二層構造:
 *   1. 手作りオーバーレイ（{@link CWE_KB}、70件）
 *      日本語名・日本語説明・OWASP Top 10 2021 マッピングを持つ。常に優先される。
 *      MITRE のカタログには OWASP Top Ten 2007/2004 の対応しか無く 2021 が無いため、
 *      この手作りマッピングのほうが価値が高い。
 *   2. MITRE CWE カタログ（`./catalog.js`、959件）
 *      オーバーレイに無い CWE の英語名・説明・親子関係を補う。
 *
 * OWASP 2021 のカテゴリはオーバーレイにしか無いので、カタログ側の CWE には
 * 親を辿って（{@link cweAncestors}）オーバーレイを持つ祖先のカテゴリを継承させる。
 * 継承したものは推測なので、{@link owaspForCwe} は `inherited` フラグで区別する。
 */

import { cweAncestors, lookupCwe as lookupCatalogCwe, type CweEntry as CweCatalogEntry } from './catalog.js';

/** OWASP Top 10 2021 のカテゴリ識別子 */
export type OwaspCategoryId =
  | 'A01:2021-Broken Access Control'
  | 'A02:2021-Cryptographic Failures'
  | 'A03:2021-Injection'
  | 'A04:2021-Insecure Design'
  | 'A05:2021-Security Misconfiguration'
  | 'A06:2021-Vulnerable and Outdated Components'
  | 'A07:2021-Identification and Authentication Failures'
  | 'A08:2021-Software and Data Integrity Failures'
  | 'A09:2021-Security Logging and Monitoring Failures'
  | 'A10:2021-Server-Side Request Forgery (SSRF)';

/** OWASP Top 10 2021 のカテゴリ → 公式解説ページ URL */
export const OWASP_TOP10_URLS: Record<string, string> = {
  A01: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
  A02: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  A03: 'https://owasp.org/Top10/A03_2021-Injection/',
  A04: 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
  A05: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  A06: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  A07: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
  A08: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
  A09: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
  A10: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
};

export interface CweEntry {
  /** 日本語の名称 */
  name: string;
  /** 英語の正式名称 */
  englishName: string;
  /** 日本語の概要説明 */
  description: string;
  /** 対応する OWASP Top 10 2021 カテゴリ */
  owasp: OwaspCategoryId;
}

/**
 * CWE ID → 知識エントリ。
 * OWASP カテゴリの対応は OWASP Top 10 2021 の公式 CWE マッピングに従う。
 */
export const CWE_KB: Record<string, CweEntry> = {
  'CWE-16': {
    name: '設定',
    englishName: 'Configuration',
    description: 'セキュリティに影響する設定値が安全でない既定値のまま利用されている。',
    owasp: 'A05:2021-Security Misconfiguration',
  },
  'CWE-20': {
    name: '不適切な入力検証',
    englishName: 'Improper Input Validation',
    description: '入力が想定した形式・範囲であることを検証せずに処理している。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-22': {
    name: 'パストラバーサル',
    englishName: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    description:
      '外部入力をファイルパスに連結しており、`../` 等で意図しないディレクトリのファイルを読み書きできる。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-23': {
    name: '相対パストラバーサル',
    englishName: 'Relative Path Traversal',
    description: '相対パス指定により制限されたディレクトリの外部にアクセスできる。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-74': {
    name: '下流コンポーネントへの特殊要素の不適切な無害化（インジェクション）',
    englishName: 'Improper Neutralization of Special Elements in Output Used by a Downstream Component',
    description: '外部入力を下流のインタプリタへ渡す際に無害化しておらず、命令を注入できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-77': {
    name: 'コマンドインジェクション',
    englishName: "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    description: '外部入力がコマンド文字列に混入し、任意のコマンドを実行できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-78': {
    name: 'OSコマンドインジェクション',
    englishName: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    description:
      'シェル経由でコマンドを実行する際に外部入力を無害化しておらず、任意のOSコマンドを実行できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-79': {
    name: 'クロスサイトスクリプティング (XSS)',
    englishName: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    description:
      '外部入力をエスケープせずにHTMLへ出力しており、被害者のブラウザで任意のスクリプトが実行される。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-80': {
    name: 'HTMLタグの不完全な無害化',
    englishName: 'Improper Neutralization of Script-Related HTML Tags in a Web Page',
    description: 'スクリプト関連のHTMLタグの無害化が不完全で、XSS に至る。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-88': {
    name: '引数インジェクション',
    englishName: 'Improper Neutralization of Argument Delimiters in a Command',
    description: '外部入力がコマンド引数の区切りとして解釈され、想定外のオプションを注入できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-89': {
    name: 'SQLインジェクション',
    englishName: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    description:
      '外部入力を文字列連結でSQLに埋め込んでおり、任意のSQLを実行してデータの窃取・改ざんができる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-90': {
    name: 'LDAPインジェクション',
    englishName: "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
    description: '外部入力がLDAPクエリに混入し、検索条件を改変できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-91': {
    name: 'XMLインジェクション',
    englishName: 'XML Injection (aka Blind XPath Injection)',
    description: '外部入力がXML文書やXPath式に混入し、構造を改変できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-94': {
    name: 'コード生成の不適切な制御（コードインジェクション）',
    englishName: "Improper Control of Generation of Code ('Code Injection')",
    description: '外部入力がコードとして評価され、任意のコードを実行できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-95': {
    name: 'evalインジェクション',
    englishName: "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    description: 'eval 等の動的評価関数に外部入力が渡っており、任意のコードを実行できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-113': {
    name: 'HTTPヘッダインジェクション / レスポンス分割',
    englishName: "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
    description: '外部入力の改行を無害化せずHTTPヘッダに出力しており、レスポンスを分割できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-116': {
    name: '不適切なエンコーディング・エスケープ',
    englishName: 'Improper Encoding or Escaping of Output',
    description: '出力先の文脈に応じたエンコード処理を行っていない。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-117': {
    name: 'ログ出力の不適切な無害化（ログインジェクション）',
    englishName: 'Improper Output Neutralization for Logs',
    description: '外部入力をそのままログに出力しており、ログの偽装・改ざんが可能。',
    owasp: 'A09:2021-Security Logging and Monitoring Failures',
  },
  'CWE-200': {
    name: '認可されていない主体への情報露出',
    englishName: 'Exposure of Sensitive Information to an Unauthorized Actor',
    description: '権限のない相手に機密情報が露出している。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-209': {
    name: 'エラーメッセージによる情報露出',
    englishName: 'Generation of Error Message Containing Sensitive Information',
    description: 'スタックトレースや内部情報を含むエラーを外部に返している。',
    owasp: 'A04:2021-Insecure Design',
  },
  'CWE-259': {
    name: 'ハードコードされたパスワード',
    englishName: 'Use of Hard-coded Password',
    description: 'ソースコードにパスワードが直接埋め込まれている。',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-269': {
    name: '不適切な権限管理',
    englishName: 'Improper Privilege Management',
    description: '権限の付与・剥奪が適切に行われず、権限昇格を許す。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-284': {
    name: '不適切なアクセス制御',
    englishName: 'Improper Access Control',
    description: 'リソースへのアクセス制御が不十分または欠落している。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-285': {
    name: '不適切な認可',
    englishName: 'Improper Authorization',
    description: '操作の実行前に権限確認を行っていない、または確認が不正確。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-287': {
    name: '不適切な認証',
    englishName: 'Improper Authentication',
    description: '主体の同一性確認が不十分で、なりすましが可能。',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-295': {
    name: '不適切な証明書検証',
    englishName: 'Improper Certificate Validation',
    description: 'TLS証明書の検証を無効化・省略しており、中間者攻撃を受ける。',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-306': {
    name: '重要な機能に対する認証の欠如',
    englishName: 'Missing Authentication for Critical Function',
    description: '重要な操作が認証なしで実行できる。',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-307': {
    name: '認証試行の制限不備',
    englishName: 'Improper Restriction of Excessive Authentication Attempts',
    description: '総当たり攻撃に対するレート制限やロックアウトがない。',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-311': {
    name: '機密データの暗号化の欠如',
    englishName: 'Missing Encryption of Sensitive Data',
    description: '機密情報が暗号化されずに保存・送信されている。',
    owasp: 'A02:2021-Cryptographic Failures',
  },
  'CWE-319': {
    name: '機密情報の平文送信',
    englishName: 'Cleartext Transmission of Sensitive Information',
    description: 'HTTP など暗号化されていない経路で機密情報を送信している。',
    owasp: 'A02:2021-Cryptographic Failures',
  },
  'CWE-326': {
    name: '不十分な暗号強度',
    englishName: 'Inadequate Encryption Strength',
    description: '鍵長やパラメータが現在の安全基準を満たしていない。',
    owasp: 'A02:2021-Cryptographic Failures',
  },
  'CWE-327': {
    name: '破られた・危険な暗号アルゴリズムの使用',
    englishName: 'Use of a Broken or Risky Cryptographic Algorithm',
    description: 'DES/RC4/ECB モードなど、安全でない暗号アルゴリズムを使用している。',
    owasp: 'A02:2021-Cryptographic Failures',
  },
  'CWE-328': {
    name: '可逆・脆弱なハッシュの使用',
    englishName: 'Use of Weak Hash',
    description: 'MD5/SHA-1 など衝突耐性のないハッシュや、ソルトなしのパスワードハッシュを使用している。',
    owasp: 'A02:2021-Cryptographic Failures',
  },
  'CWE-330': {
    name: '不十分にランダムな値の使用',
    englishName: 'Use of Insufficiently Random Values',
    description: '予測可能な乱数をセキュリティ用途に使用している。',
    owasp: 'A02:2021-Cryptographic Failures',
  },
  'CWE-331': {
    name: 'エントロピー不足',
    englishName: 'Insufficient Entropy',
    description: '生成される値のエントロピーが不足しており推測されうる。',
    owasp: 'A02:2021-Cryptographic Failures',
  },
  'CWE-338': {
    name: '暗号学的に脆弱なPRNGの使用',
    englishName: 'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)',
    description: 'Math.random() 等の非暗号学的乱数をトークン生成に使用している。',
    owasp: 'A02:2021-Cryptographic Failures',
  },
  'CWE-345': {
    name: 'データの真正性の検証不足',
    englishName: 'Insufficient Verification of Data Authenticity',
    description: '受信したデータの出所・完全性を検証していない。',
    owasp: 'A08:2021-Software and Data Integrity Failures',
  },
  'CWE-347': {
    name: '暗号署名の検証不備',
    englishName: 'Improper Verification of Cryptographic Signature',
    description: 'JWT の alg:none 受理など、署名検証が不十分。',
    owasp: 'A08:2021-Software and Data Integrity Failures',
  },
  'CWE-352': {
    name: 'クロスサイトリクエストフォージェリ (CSRF)',
    englishName: 'Cross-Site Request Forgery (CSRF)',
    description: 'リクエストの出所を検証しておらず、ログイン中の利用者に意図しない操作をさせられる。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-359': {
    name: '個人情報の露出',
    englishName: 'Exposure of Private Personal Information to an Unauthorized Actor',
    description: '個人情報が権限のない相手に露出している。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-384': {
    name: 'セッション固定',
    englishName: 'Session Fixation',
    description: '認証時にセッションIDを再生成しておらず、攻撃者が用意したIDを固定できる。',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-400': {
    name: '制御されないリソース消費',
    englishName: 'Uncontrolled Resource Consumption',
    description: '入力サイズや処理回数に上限がなく、サービス不能を引き起こせる。',
    owasp: 'A04:2021-Insecure Design',
  },
  'CWE-434': {
    name: '危険なタイプのファイルの無制限アップロード',
    englishName: 'Unrestricted Upload of File with Dangerous Type',
    description: '実行可能なファイルのアップロードを制限しておらず、リモートコード実行に至りうる。',
    owasp: 'A04:2021-Insecure Design',
  },
  'CWE-494': {
    name: '完全性チェックなしのコードダウンロード',
    englishName: 'Download of Code Without Integrity Check',
    description: '外部から取得したコードを検証せずに実行している。',
    owasp: 'A08:2021-Software and Data Integrity Failures',
  },
  'CWE-502': {
    name: '信頼できないデータの逆シリアル化',
    englishName: 'Deserialization of Untrusted Data',
    description:
      '外部から受け取ったシリアライズデータを検証せず復元しており、ガジェットチェーンにより任意コード実行に至りうる。',
    owasp: 'A08:2021-Software and Data Integrity Failures',
  },
  'CWE-521': {
    name: '脆弱なパスワード要件',
    englishName: 'Weak Password Requirements',
    description: 'パスワードの複雑さ・長さの要件が不十分。',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-522': {
    name: '不十分に保護された資格情報',
    englishName: 'Insufficiently Protected Credentials',
    description: '資格情報が平文や弱いハッシュで保存・送信されている。',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-532': {
    name: 'ログファイルへの機密情報の挿入',
    englishName: 'Insertion of Sensitive Information into Log File',
    description: 'パスワードやトークンをログに出力している。',
    owasp: 'A09:2021-Security Logging and Monitoring Failures',
  },
  'CWE-601': {
    name: 'オープンリダイレクト',
    englishName: "URL Redirection to Untrusted Site ('Open Redirect')",
    description: '外部入力のURLへ検証なしにリダイレクトしており、フィッシングに悪用できる。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-611': {
    name: 'XML外部エンティティ参照の不適切な制限 (XXE)',
    englishName: 'Improper Restriction of XML External Entity Reference',
    description: '外部エンティティの解決を無効化しておらず、ファイル読み出しやSSRFに至る。',
    owasp: 'A05:2021-Security Misconfiguration',
  },
  'CWE-613': {
    name: '不十分なセッション期限',
    englishName: 'Insufficient Session Expiration',
    description: 'セッションが失効せず、盗まれた資格情報が長期間有効になる。',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-614': {
    name: 'Secure属性のないHTTPS Cookie',
    englishName: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
    description: 'Secure 属性がないため Cookie が平文経路で送信されうる。',
    owasp: 'A05:2021-Security Misconfiguration',
  },
  'CWE-639': {
    name: 'ユーザ制御可能なキーによる認可回避 (IDOR)',
    englishName: 'Authorization Bypass Through User-Controlled Key',
    description: '識別子を差し替えるだけで他人のリソースにアクセスできる。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-643': {
    name: 'XPathインジェクション',
    englishName: "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
    description: '外部入力がXPath式に混入し、検索条件を改変できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-732': {
    name: '重要リソースの不適切な権限割り当て',
    englishName: 'Incorrect Permission Assignment for Critical Resource',
    description: 'ファイルやディレクトリに過剰な権限が与えられている。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-778': {
    name: '不十分なログ記録',
    englishName: 'Insufficient Logging',
    description: 'セキュリティ上重要なイベントが記録されておらず、検知・追跡ができない。',
    owasp: 'A09:2021-Security Logging and Monitoring Failures',
  },
  'CWE-798': {
    name: 'ハードコードされた資格情報の使用',
    englishName: 'Use of Hard-coded Credentials',
    description: 'APIキーやパスワードがソースコードに埋め込まれている。',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-829': {
    name: '信頼できない制御領域からの機能の取り込み',
    englishName: 'Inclusion of Functionality from Untrusted Control Sphere',
    description: '外部ホストのスクリプト等を検証せずに読み込んでいる。',
    owasp: 'A08:2021-Software and Data Integrity Failures',
  },
  'CWE-862': {
    name: '認可の欠落',
    englishName: 'Missing Authorization',
    description: '操作前に認可チェックを行っていない。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-863': {
    name: '不正な認可',
    englishName: 'Incorrect Authorization',
    description: '認可チェックは存在するが判定が誤っており回避できる。',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-915': {
    name: '動的に決定される属性の不適切な変更（マスアサインメント）',
    englishName: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
    description: 'リクエストのプロパティをそのままオブジェクトへ割り当て、権限フラグ等を改変できる。',
    owasp: 'A08:2021-Software and Data Integrity Failures',
  },
  'CWE-917': {
    name: '式言語インジェクション',
    englishName: "Improper Neutralization of Special Elements used in an Expression Language Statement",
    description: 'テンプレート式に外部入力が混入し、任意コード実行に至る。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-918': {
    name: 'サーバサイドリクエストフォージェリ (SSRF)',
    englishName: 'Server-Side Request Forgery (SSRF)',
    description:
      '外部入力のURLへサーバが要求を送るため、内部ネットワークやクラウドメタデータへ到達できる。',
    owasp: 'A10:2021-Server-Side Request Forgery (SSRF)',
  },
  'CWE-937': {
    name: '既知の脆弱性を持つコンポーネントの使用',
    englishName: 'Using Components with Known Vulnerabilities',
    description: '既知の脆弱性が公表されているライブラリに依存している。',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
  },
  'CWE-943': {
    name: 'データクエリ論理における特殊要素の不適切な無害化',
    englishName: 'Improper Neutralization of Special Elements in Data Query Logic',
    description: 'NoSQL 等のクエリ構造に外部入力が混入し、条件を改変できる。',
    owasp: 'A03:2021-Injection',
  },
  'CWE-1004': {
    name: 'HttpOnly属性のない機密Cookie',
    englishName: 'Sensitive Cookie Without HttpOnly Flag',
    description: 'HttpOnly が無いため XSS により Cookie を窃取されうる。',
    owasp: 'A05:2021-Security Misconfiguration',
  },
  'CWE-1021': {
    name: 'レンダリングされたUI層の不適切な制限（クリックジャッキング）',
    englishName: 'Improper Restriction of Rendered UI Layers or Frames',
    description: 'フレーム埋め込みを制限しておらず、UIを重ねた誘導操作が可能。',
    owasp: 'A04:2021-Insecure Design',
  },
  'CWE-1333': {
    name: '非効率な正規表現の複雑性 (ReDoS)',
    englishName: 'Inefficient Regular Expression Complexity',
    description: 'バックトラッキングが爆発する正規表現に外部入力を与えられ、サービス不能に陥る。',
    owasp: 'A04:2021-Insecure Design',
  },
  'CWE-1395': {
    name: '脆弱なサードパーティコンポーネントへの依存',
    englishName: 'Dependency on Vulnerable Third-Party Component',
    description: '既知の脆弱性を含むバージョンの依存パッケージを使用している。',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
  },
};

/**
 * CWE ID から手作りオーバーレイの知識エントリを引く（未知なら undefined）。
 *
 * 注: 「日本語名と OWASP 2021 カテゴリを持つ curated な 70 件か？」の判定に
 * 使われている箇所があるため（`osv.ts` の CWE 選択など）、
 * ここではカタログへのフォールバックを行わない。
 * カタログを含めた統合ビューが欲しい場合は {@link lookupCweInfo} を使うこと。
 */
export function lookupCwe(cweId: string): CweEntry | undefined {
  return CWE_KB[cweId];
}

/** CWE の公式定義ページ URL */
export function cweUrl(cweId: string): string | null {
  const m = /^CWE-(\d+)$/.exec(cweId);
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : null;
}

/** 'A03:2021-Injection' 等のカテゴリ文字列から OWASP 解説ページ URL を得る */
export function owaspUrl(category: string | undefined | null): string | null {
  if (!category) return null;
  const m = /^(A\d{2})/.exec(category.trim());
  const key = m?.[1];
  return key ? (OWASP_TOP10_URLS[key] ?? null) : null;
}

/**
 * Finding に付与する参考リンクを構築する。
 * CWE 定義ページ・OWASP Top 10 解説ページ・追加リンク（アドバイザリ等）を重複なく返す。
 */
export function buildReferences(
  cweId: string | null,
  category: string | undefined,
  extra: string[] = [],
): string[] {
  const refs: string[] = [];
  const push = (url: string | null | undefined): void => {
    if (url && !refs.includes(url)) refs.push(url);
  };

  if (cweId) push(cweUrl(cweId));
  // OWASP カテゴリの確度の高い順:
  //   1. 手作り知識ベースの直接対応
  //   2. 呼び出し側が持っているカテゴリ（LLM 申告 / 依存スキャンの既定値）
  //   3. CWE の親を辿って手作り知識ベースを持つ祖先から継承したもの（推測）
  const inherited = cweId ? owaspForCwe(cweId) : null;
  const direct = inherited && !inherited.inherited ? inherited.category : undefined;
  push(owaspUrl(direct ?? category ?? inherited?.category));
  for (const url of extra) push(url);
  return refs;
}

/* ------------------------------------------------------------------ *
 * MITRE CWE カタログ（959件）との統合
 * ------------------------------------------------------------------ */

/** 'cwe-89' / '89' / 'CWE-89' を 'CWE-89' に揃える。数値が取れなければ null */
function toCweId(raw: string | undefined | null): string | null {
  if (!raw) return null;
  const m = /(\d+)/.exec(String(raw));
  return m ? `CWE-${m[1]}` : null;
}

/** 情報の出所。事実（MITRE）と手作りの解釈を混同しないための印。 */
export type CweInfoSource = 'curated' | 'catalog' | 'curated+catalog';

/** 手作りオーバーレイと MITRE カタログを重ね合わせた CWE 情報 */
export interface CweInfo {
  /** 'CWE-89' 形式に正規化した ID */
  id: string;
  /** 表示名。手作り日本語名があればそれ、無ければ MITRE の英語名 */
  name: string;
  /** MITRE の英語正式名称（カタログにも手作りにも無ければ null） */
  englishName: string | null;
  /** 説明。手作り日本語説明があればそれ、無ければ MITRE の英語説明 */
  description: string;
  /** OWASP Top 10 2021 カテゴリ（手作り、または祖先から継承。無ければ null） */
  owasp: OwaspCategoryId | null;
  /** owasp が祖先からの継承（＝推測）なら true */
  owaspInherited: boolean;
  /** 継承元の CWE ID（継承していなければ null） */
  owaspVia: string | null;
  /** どこ由来の情報か */
  source: CweInfoSource;
  /** MITRE カタログの生エントリ（無ければ null） */
  catalog: CweCatalogEntry | null;
}

/**
 * OWASP Top 10 2021 のカテゴリを決める。
 *
 * 1. 手作りオーバーレイに直接の対応があればそれを返す（`inherited: false` ＝ 事実に近い）
 * 2. 無ければ親を辿り、最初に見つかったオーバーレイ持ちの祖先のカテゴリを継承する
 *    （`inherited: true` ＝ 推測。レポートではこの区別を落とさないこと）
 * 3. どちらも当たらなければ null
 */
export function owaspForCwe(
  cweId: string,
): { category: OwaspCategoryId; inherited: boolean; via: string | null } | null {
  const id = toCweId(cweId);
  if (id === null) return null;

  const direct = CWE_KB[id];
  if (direct) return { category: direct.owasp, inherited: false, via: null };

  for (const ancestor of cweAncestors(id)) {
    const hit = CWE_KB[ancestor.id];
    if (hit) return { category: hit.owasp, inherited: true, via: ancestor.id };
  }
  return null;
}

/**
 * 手作りオーバーレイ（優先）と MITRE カタログ（フォールバック）を
 * 重ね合わせた CWE 情報を返す。どちらにも無ければ null。
 */
export function lookupCweInfo(cweId: string): CweInfo | null {
  const id = toCweId(cweId);
  if (id === null) return null;

  const curated = CWE_KB[id];
  const catalog = lookupCatalogCwe(id);
  if (!curated && !catalog) return null;

  const owasp = owaspForCwe(id);
  const source: CweInfoSource = curated
    ? catalog
      ? 'curated+catalog'
      : 'curated'
    : 'catalog';

  return {
    id,
    name: curated?.name ?? catalog?.name ?? id,
    englishName: curated?.englishName ?? catalog?.name ?? null,
    description: curated?.description ?? catalog?.description ?? '',
    owasp: owasp?.category ?? null,
    owaspInherited: owasp?.inherited ?? false,
    owaspVia: owasp?.via ?? null,
    source,
    catalog,
  };
}

/**
 * 知識ベースのカバレッジ集計（レポートで「どこまで裏が取れているか」を示すため）。
 * curated は手作り70件、inherited は祖先から OWASP を継承できた件数。
 */
export function knowledgeCoverage(catalogIds: string[]): {
  curated: number;
  owaspDirect: number;
  owaspInherited: number;
  owaspNone: number;
} {
  let owaspDirect = 0;
  let owaspInherited = 0;
  let owaspNone = 0;
  for (const id of catalogIds) {
    const hit = owaspForCwe(id);
    if (!hit) owaspNone++;
    else if (hit.inherited) owaspInherited++;
    else owaspDirect++;
  }
  return {
    curated: Object.keys(CWE_KB).length,
    owaspDirect,
    owaspInherited,
    owaspNone,
  };
}
