/** Web出力レンズ: XSS / CSRF / セキュリティヘッダ欠落 */

import { composeSystemPrompt } from './common.js';
import type { Lens } from './types.js';

const SECTION = `## このレンズの観点: Web出力とブラウザ側の防御
サーバが返す内容と、それをブラウザがどう解釈するかを見ます。

- **XSS (CWE-79)**
  外部由来の値がエスケープされずにHTML・属性・JavaScript文脈・URL属性へ出力されるケース。
  dangerouslySetInnerHTML / innerHTML / document.write / v-html、
  テンプレートエンジンの生出力（|safe、triple-mustache など）、
  href や src に入る javascript: スキーム、JSONをscriptタグに直接埋め込む、など。
  テンプレートエンジンの自動エスケープが効いている出力は対象外です。
  出力される文脈（HTML本文か、属性値か、スクリプト内か）によって必要な無害化が違うので、
  どの文脈かを reasoning に書いてください。
- **CSRF (CWE-352)**
  状態を変更するエンドポイントに、CSRFトークン検証や SameSite クッキー、
  カスタムヘッダ要求などの対策が無いケース。
  クッキーではなく Authorization ヘッダのみで認証しているAPIは通常対象外です。
  フレームワークのCSRFミドルウェアが全体に効いているなら問題ありません。
  明示的に無効化されている箇所（csrf.exempt など）は注目に値します。
- **セキュリティヘッダ・クッキー属性の欠落 (CWE-693, CWE-1004, CWE-614)**
  Content-Security-Policy、X-Content-Type-Options、HSTS の欠落や、
  クッキーの HttpOnly / Secure / SameSite が設定されていないケース。
  これらは単体では影響が限定的なので、深刻度は控えめに見積もり、
  他の脆弱性を悪用しやすくする要因として扱ってください。
  なお、ヘッダ設定を担当していないコードで「ヘッダが無い」と指摘しないでください。
- **クリックジャッキング・CORSの緩すぎる設定**（Access-Control-Allow-Origin の反射＋credentials 許可など）
  も同じ観点で扱います。`;

export const webOutputLens: Lens = {
  id: 'web-output',
  title: 'Web出力',
  systemPrompt: composeSystemPrompt(SECTION),
};
