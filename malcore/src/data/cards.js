/* data/cards.js — マルこれ 攻撃手法カード（装備技）
   docs/MALCORE_SKILLS.md の技ロスターを装備技として実装。
   ・gauge: 主に削るゲージ（緩和の噛み合いにも使う）
   ・cia:   ダメージ配分（基礎攻撃力）。複数ゲージ技はここで表現
   ・cost:  装備技の発動コスト（情報/技術/資源）
   ・special: 'ignoreH'=ハードニング無視（ゼロデイ）
   ・defense: 防御官の対策解説（攻撃＝防御学習の原則）
   ※挙動の抽象表現。実コード・悪用手順は含まない。 */
const CARDS = [
  // 🔵 機密性(C)
  { id: 'sqli', name: 'SQL・インジェクション', en: 'SQL Injection', gauge: 'C',
    cia: { C: 70 }, type: '窃取', tactic: 'OWASP A03', gen: 0, cost: { info: 10 }, special: null,
    desc: '入力の隙からDBへ問い合わせを注入し、情報を吸い出す。',
    defense: 'プレースホルダ(プリペアドステートメント)と入力検証で遮断する。' },
  { id: 'xss', name: 'クロスサイト・スクリプティング', en: 'XSS', gauge: 'C',
    cia: { C: 50 }, type: '窃取', tactic: 'OWASP A03', gen: 0, cost: { info: 5 }, special: null,
    desc: 'ページにスクリプトを紛れ込ませ、セッションを奪う。',
    defense: '出力エンコードとCSPでスクリプト実行を封じる。' },
  { id: 'traversal', name: 'ディレクトリ・トラバーサル', en: 'Directory Traversal', gauge: 'C',
    cia: { C: 55 }, type: '窃取', tactic: 'OWASP A01', gen: 0, cost: { info: 5 }, special: null,
    desc: '範囲外のパスを辿り、機密ファイルを読み出す。',
    defense: 'パス正規化と最小権限、公開ディレクトリの限定。' },
  { id: 'kerberoast', name: 'ケルベロースティング', en: 'Kerberoasting', gauge: 'C',
    cia: { C: 75 }, type: '認証', tactic: 'ATT&CK Credential Access', gen: 2, cost: { info: 10, tech: 5 }, special: null,
    desc: 'サービスチケットを要求し、資格情報をオフラインで解く。',
    defense: '強い鍵とサービスアカウント監査、異常検知。' },
  // 🟢 完全性(I)
  { id: 'csrf', name: 'クロスサイト・リクエスト・フォージェリ', en: 'CSRF', gauge: 'I',
    cia: { I: 55 }, type: '改ざん', tactic: 'OWASP', gen: 0, cost: { tech: 5 }, special: null,
    desc: '正規ユーザーになりすました操作を強制する。',
    defense: 'CSRFトークンとSameSite Cookieで正規性を担保。' },
  { id: 'deserialize', name: 'インセキュア・デシリアライゼーション', en: 'Insecure Deserialization', gauge: 'I',
    cia: { I: 70 }, type: '改ざん', tactic: 'OWASP A08', gen: 2, cost: { tech: 10 }, special: null,
    desc: '信頼できないデータの復元を悪用し、処理を歪める。',
    defense: '署名検証と型の許可リスト、復元対象の限定。' },
  { id: 'webshell', name: 'ウェブシェル・インプラント', en: 'Web Shell', gauge: 'I',
    cia: { I: 50, C: 20 }, type: '改ざん', tactic: 'ATT&CK Persistence', gen: 1, cost: { tech: 5, info: 5 }, special: null,
    desc: '改ざん拠点を植え付け、遠隔から操作する。',
    defense: 'WAFと整合性監視、書き込み権限の最小化。' },
  { id: 'ikatako', name: 'イカタコ上書き', en: 'File-Overwrite Wiper (Ika-Tako/Harada, 2007–10)', gauge: 'I',
    cia: { I: 70, C: 10 }, type: '破壊', tactic: 'ATT&CK Impact (Data Destruction)', gen: 1, cost: { res: 5 }, special: null, icon: 'ikatako',
    desc: 'ファイルをイカ・タコの画像で上書きし、完全性を破壊する（日本の上書き型ウイルス）。暗号化ではなく“塗りつぶし”。',
    defense: 'バックアップと実行制限、Winny等の経路遮断。' },
  // 🟡 可用性(A)
  { id: 'slowloris', name: 'スローロリス', en: 'Slowloris', gauge: 'A',
    cia: { A: 65 }, type: '過負荷', tactic: 'DoS', gen: 1, cost: { res: 5 }, special: null,
    desc: '接続を小出しに保持し続け、枠を枯渇させる。',
    defense: '接続タイムアウトとリバースプロキシで吸収。' },
  { id: 'amplification', name: 'リフレクション・アンプリフィケーション', en: 'Amplification DDoS', gauge: 'A',
    cia: { A: 85 }, type: '過負荷', tactic: 'DDoS', gen: 2, cost: { res: 10 }, special: null,
    desc: '増幅応答を踏み台に集中させ、回線を溢れさせる。',
    defense: 'レート制限と送信元検証(BCP38)、上流での吸収。' },
  { id: 'gpcode', name: 'GpCode暗号化', en: 'GpCode / Cryptoviral Extortion (2004–08)', gauge: 'A',
    cia: { I: 55, A: 65 }, type: '破壊', tactic: 'ATT&CK Impact', gen: 1, cost: { res: 10, tech: 5 }, special: null,
    desc: '2000年代の暗号化トロイの祖。ファイルを暗号化し、完全性と可用性を同時に奪う（後のランサムの原型）。',
    defense: 'オフラインバックアップと復旧手順、横展開の遮断。鍵管理の監視。' },
  // ⚙️ 特殊・最上位
  { id: 'zeroday', name: 'ゼロデイ・エクスプロイト', en: 'Zero-Day Exploit', gauge: 'C',
    cia: { C: 80 }, type: '貫通', tactic: 'ATT&CK Initial Access', gen: 3, cost: { info: 30, tech: 30 }, special: 'ignoreH',
    desc: '未知の脆弱性を突く。ハードニングを無視して通す最上位レア。',
    defense: '多層防御と異常検知。単一対策に頼らない設計で被害を限定。' },
];

function cardById(id) { return CARDS.find(c => c.id === id) || null; }

if (typeof globalThis !== 'undefined') { globalThis.CARDS = CARDS; globalThis.cardById = cardById; }
