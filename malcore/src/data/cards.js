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
  { id: 'phishing', name: 'スピアフィッシング', en: 'Spear Phishing', gauge: 'C',
    cia: { C: 40 }, type: '窃取', tactic: 'ATT&CK Initial Access', gen: 0, cost: { info: 5 }, special: null,
    desc: '標的を狙った偽メールで認証情報や足場を得る、初期アクセスの王道。',
    defense: '添付サンドボックスとMFA、利用者教育で入口を絞る。' },
  { id: 'password_spray', name: 'パスワードスプレー', en: 'Password Spraying', gauge: 'C',
    cia: { C: 45 }, type: '認証', tactic: 'ATT&CK Credential Access', gen: 1, cost: { info: 8 }, special: null,
    desc: '弱いパスワードを多数アカウントへ横断的に試行する。',
    defense: 'アカウントロックアウトとMFA、パスワードポリシー強化。' },
  { id: 'ssrf', name: 'サーバサイド・リクエスト・フォージェリ', en: 'SSRF', gauge: 'C',
    cia: { C: 55 }, type: '窃取', tactic: 'OWASP A10', gen: 2, cost: { tech: 8 }, special: null,
    desc: 'サーバに内部資産へリクエストさせ、到達できない情報へ届く。',
    defense: 'egress制限とメタデータ保護、宛先の許可リスト化。' },
  { id: 'c2_beacon', name: 'C2ビーコン', en: 'C2 Beaconing', gauge: 'C',
    cia: { C: 35 }, type: '窃取', tactic: 'ATT&CK Command & Control', gen: 2, cost: { info: 6 }, special: null,
    desc: '静かな間隔で外部へ通信し、少しずつ持ち出す低ノイズ持ち出し。',
    defense: 'ビーコン間隔検知とDNS異常監視、egressの可視化。' },
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
  { id: 'dns_poison', name: 'DNSキャッシュポイズニング', en: 'DNS Cache Poisoning', gauge: 'I',
    cia: { I: 60 }, type: '改ざん', tactic: 'ATT&CK Impact', gen: 1, cost: { tech: 8 }, special: null,
    desc: '名前解決を書き換え、通信の宛先ごと偽装する。',
    defense: 'DNSSECと解決結果の検証、キャッシュの保護。' },
  { id: 'golden_ticket', name: 'ゴールデンチケット', en: 'Golden Ticket', gauge: 'I',
    cia: { I: 75, C: 20 }, type: '認証', tactic: 'ATT&CK Credential Access', gen: 2, cost: { tech: 15, info: 10 }, special: null,
    desc: '認証基盤の鍵を握り、正規に見える万能チケットを発行する。',
    defense: 'KRBTGTの定期更新と特権分離、異常なチケット発行の監視。' },
  { id: 'supplychain', name: 'サプライチェーン汚染', en: 'Supply-Chain Compromise', gauge: 'I',
    cia: { I: 60, C: 40 }, type: '貫通', tactic: 'ATT&CK Initial Access', gen: 3, cost: { tech: 15, info: 10 }, special: 'ignoreH',
    desc: '信頼された配布物を汚染し、多層防御を信頼ごと通過する上位技。',
    defense: '署名検証とSBOM、ビルド供給元の完全性監視。' },
  { id: 'ikatako', name: 'イカタコ上書き', en: 'File-Overwrite Wiper (Ika-Tako/Harada, 2007–10)', gauge: 'I',
    cia: { I: 70, C: 10 }, type: '破壊', tactic: 'ATT&CK Impact (Data Destruction)', gen: 1, cost: { res: 5 }, special: null, icon: 'ikatako',
    desc: 'ファイルをイカ・タコの画像で上書きし、完全性を破壊する（日本の上書き型ウイルス）。暗号化ではなく“塗りつぶし”。',
    defense: 'バックアップと実行制限、Winny等の経路遮断。' },
  // 🟡 可用性(A)
  { id: 'slowloris', name: 'スローロリス', en: 'Slowloris', gauge: 'A',
    cia: { A: 65 }, type: '過負荷', tactic: 'DoS', gen: 1, cost: { res: 5 }, special: null,
    desc: '接続を小出しに保持し続け、枠を枯渇させる。',
    defense: '接続タイムアウトとリバースプロキシで吸収。' },
  { id: 'forkbomb', name: 'フォークボム', en: 'Fork Bomb', gauge: 'A',
    cia: { A: 55 }, type: '過負荷', tactic: 'ATT&CK Impact', gen: 0, cost: { res: 5 }, special: null,
    desc: 'プロセスを自己増殖させ、計算資源を食い尽くす。',
    defense: 'ulimit/cgroupsでプロセス数を制限し、資源を隔離。' },
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

/* 図鑑の段階開示(intel)。L0=一言(初心者)／L1=defense(既存)／L2=技術詳細(習熟で解錠)／L3=参考名。
   ※抽象・分類のみ（ATT&CK T番号/OWASPカテゴリは分類であって手順ではない）。実CVE/IP/手順は載せない。 */
const CARD_INTEL = {
  sqli: { L0: '入力欄からDBに命令を"注射"して中身を吸い出す', notable: '2000年代以降のWeb侵害の定番。OWASP Top10の常連。', real: '入力を文字列連結でクエリに混ぜるのが根本原因。', refs: ['OWASP Cheat Sheet: SQL Injection Prevention', 'MITRE ATT&CK T1190'] },
  xss: { L0: 'ページに他人のスクリプトを紛れ込ませる', notable: 'Samworm(2005)がMySpaceを1日で席巻した古典。', real: '出力時のエスケープ漏れが原因。CSPで多層防御。', refs: ['OWASP Cheat Sheet: Cross Site Scripting Prevention'] },
  traversal: { L0: '「../」で見えないはずのファイルまで辿る', notable: 'Webサーバ黎明期から続く定番の設定ミス系。', real: 'パス正規化と公開範囲の限定で塞ぐ。', refs: ['OWASP: Path Traversal', 'MITRE ATT&CK T1083'] },
  kerberoast: { L0: '認証チケットを貰ってオフラインで解読', notable: 'AD内部侵害の定番。管理者が最も嫌う手口。', real: 'サービスアカウントの弱い鍵が狙われる。', refs: ['MITRE ATT&CK T1558.003'] },
  phishing: { L0: '偽メールで入口(認証情報や足場)を得る', notable: '侵害の最多起点。ほぼ全APTの第一歩。', real: '技術より"人"を狙う。教育とMFAが効く。', refs: ['MITRE ATT&CK T1566'] },
  password_spray: { L0: '弱いパスワードを大量アカウントに広く試す', notable: 'ロックアウト回避のため"広く浅く"試すのが特徴。', real: 'MFAとロックアウトで大半が無力化。', refs: ['MITRE ATT&CK T1110.003'] },
  ssrf: { L0: 'サーバに内部へリクエストさせて到達する', notable: 'クラウドのメタデータ窃取で一躍有名に。', real: 'egress制限と宛先許可リストで封じる。', refs: ['OWASP Top10 A10:2021 (SSRF)'] },
  c2_beacon: { L0: '静かな間隔で外部と通信し少しずつ運ぶ', notable: '低く遅く(low & slow)がAPTの美学。', real: '通信の周期性やDNS異常で炙り出す。', refs: ['MITRE ATT&CK T1071'] },
  csrf: { L0: '正規ユーザーになりすまして操作を強制', notable: '"ワンクリック詐欺"の技術版。SameSiteで大幅減。', real: 'トークンとSameSite Cookieで正規性を担保。', refs: ['OWASP Cheat Sheet: CSRF Prevention'] },
  deserialize: { L0: '信頼できないデータの復元を悪用', notable: 'Java/PHP等で重大RCEを何度も生んだ地雷。', real: '型の許可リストと署名検証で限定。', refs: ['OWASP Top10 A08:2021', 'MITRE ATT&CK T1190'] },
  webshell: { L0: '改ざん拠点を植えて遠隔操作の足場に', notable: 'サーバ侵害後の"住み着き"の定番。', real: '書込権限の最小化と整合性監視で検知。', refs: ['MITRE ATT&CK T1505.003'] },
  dns_poison: { L0: '名前解決を書き換え宛先ごと偽装', notable: 'Kaminsky脆弱性(2008)でDNSSEC普及が加速。', real: 'DNSSECと解決結果の検証で防ぐ。', refs: ['MITRE ATT&CK T1565'] },
  golden_ticket: { L0: '認証基盤の鍵を握り万能チケットを発行', notable: 'ドメイン完全掌握の象徴。復旧が非常に困難。', real: 'KRBTGT定期更新と特権分離が要。', refs: ['MITRE ATT&CK T1558.001'] },
  supplychain: { L0: '信頼される配布物を汚染し多層防御を通過', notable: 'SolarWinds(2020)で世界が震撼した手口。', real: '署名検証とSBOM、ビルド供給元の完全性監視。', refs: ['MITRE ATT&CK T1195'] },
  ikatako: { L0: 'ファイルをイカ・タコ画像で塗り潰す', notable: '日本の"原田/イカタコウイルス"(2007–10)。作者は器物損壊で摘発。', real: '暗号化ではなく"上書き"破壊。BKと実行制限が要。', refs: ['ATT&CK Impact: Data Destruction'] },
  slowloris: { L0: '接続を小出しに保ち枠を枯らす', notable: '少ない帯域で落とせる"上品な"DoSの代表。', real: 'タイムアウトとリバースプロキシで吸収。', refs: ['MITRE ATT&CK T1499'] },
  forkbomb: { L0: 'プロセスを自己増殖させ資源を食い尽くす', notable: '":(){ :|:& };:"の一行で有名な古典。', real: 'ulimit/cgroupsでプロセス数を制限。', refs: ['ATT&CK Impact: Resource Exhaustion'] },
  amplification: { L0: '増幅応答を踏み台に集中させ回線を溢れさす', notable: 'DNS/NTP/memcachedで史上最大級のDDoSを記録。', real: 'レート制限と送信元検証(BCP38)、上流吸収。', refs: ['MITRE ATT&CK T1498.002'] },
  gpcode: { L0: 'ファイルを暗号化して人質にする', notable: 'GpCode(2004–08)は現代ランサムの原型。', real: 'オフラインBKと復旧手順、鍵管理の監視。', refs: ['ATT&CK Impact: Data Encrypted for Impact'] },
  zeroday: { L0: '誰も知らない穴を突く。防御が間に合わない', notable: '最高値で取引される攻撃資源。国家級が備蓄。', real: '単一対策に頼らない多層防御と異常検知で被害限定。', refs: ['MITRE ATT&CK T1190'] },
};
CARDS.forEach(c => { c.intel = CARD_INTEL[c.id] || {}; });

function cardById(id) { return CARDS.find(c => c.id === id) || null; }

if (typeof globalThis !== 'undefined') { globalThis.CARDS = CARDS; globalThis.cardById = cardById; }
