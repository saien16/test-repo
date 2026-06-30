/* data/enemies.js — マルこれ ステージ定義（5ステージ）
   全ステージ共通トポロジ: 外部 → 踏み台(社員PC) →[境界FW]→ 本命
   ステージごとに CIA/H/V/本体防御/対策/監査・診断/EDR/制限ターン/勝利閾値 が変化。
   数値は docs/MALCORE_BALANCE.md / STAGE_MODEL.md / DEFENSE_MODEL.md 準拠（草案）。 */

// 共通の踏み台ノード
const PC_NODE = {
  name: '社員PC（踏み台）', kind: '踏み台', hostFW: true,
  desc: 'スピアフィッシングで初期侵害できる。ボット化で足場を固められる。',
};
// 標準の境界FW（ゲート）。剥がすと全ゲージの防御力が低下し経路が開く。
function fw(def) {
  return { id: 'fw', name: '境界FW', gate: true, between: ['pc', 'db'],
    def: def || { C: 0.10, I: 0.15, A: 0.20 }, detect: {},
    evade: { info: 15 }, breakable: true,
    desc: '踏み台と本命を分離。回避(情報)か破壊(装置破壊ロール)で経路を開く。剥がすと防御力が低下。' };
}

const STAGES = [
  { // 1) 入門
    id: 'machi', name: 'マチ町工業', gen: 0, turnLimit: 6,
    intro: '中小の町工場。防御は薄い入門ステージ。パッチもバックアップも甘い。まずは攻略の流れを掴め。',
    path: ['outside', 'pc', 'db'],
    nodes: {
      pc: PC_NODE,
      db: { name: '基幹サーバ（本命）', kind: '本命', C: 90, I: 90, A: 90, H: 25, V: 60,
        baseDef: { C: 0.06, I: 0.06, A: 0.06 }, desc: '防御が薄い。素直に攻略できる。' },
    },
    defenses: [
      { id: 'fw', name: 'ルータACL', gate: true, between: ['pc', 'db'], def: { C: 0.06, I: 0.08, A: 0.10 },
        detect: {}, evade: { info: 10 }, breakable: true, desc: '簡易な境界制御。回避(情報10)か破壊で通れる。' },
    ],
    audit: { hardenUp: 10 }, diag: { warnThreshold: 80, vulnDown: 10 }, edr: false, win: { ratio: 0.25 },
    blue: { alert: 50, react: 0.7 }, // 潜伏しやすい(発覚度50まで動かない)・反応も鈍い
  },
  { // 2) 金融（機密性が厚い）
    id: 'zenith', name: 'ゼニス銀行', gen: 1, turnLimit: 8,
    intro: '世代1・2段の金融系。機密性(🔵)が厚く、プロキシ/DLPで監視。8ターン以内に本命「勘定系DB」を攻略せよ。',
    path: ['outside', 'pc', 'db'],
    nodes: {
      pc: PC_NODE,
      db: { name: '勘定系DB（本命）', kind: '本命', C: 160, I: 100, A: 100, H: 55, V: 35,
        baseDef: { C: 0.14, I: 0.12, A: 0.12 }, desc: '機密性が厚い。対策を剥がして本体防御だけにしてから抜け。' },
    },
    defenses: [
      fw(),
      { id: 'dlp', name: 'プロキシ/DLP', gate: false, watch: 'C', def: { C: 0.30 }, detect: { C: 0.8 },
        evade: { info: 10 }, breakable: false, desc: '機密性の持ち出しを監視。回避で機密性の防御力と検知を下げる。' },
    ],
    audit: { hardenUp: 15 }, diag: { warnThreshold: 60, vulnDown: 15 }, edr: false, win: { ratio: 0.20 },
    blue: { alert: 42, react: 1.0 },
  },
  { // 3) インフラOT（可用性が厚い）
    id: 'power', name: '電力公社', gen: 2, turnLimit: 9,
    intro: '世代2のインフラOT環境。可用性(🟡)が厚く、IPSが可用性攻撃を監視。ネットワーク分離で横展開が重い。',
    path: ['outside', 'pc', 'db'],
    nodes: {
      pc: PC_NODE,
      db: { name: '制御サーバ（本命）', kind: '本命', C: 120, I: 120, A: 180, H: 60, V: 30,
        baseDef: { C: 0.12, I: 0.12, A: 0.16 }, desc: '可用性が厚い。MyDoom/Blaster等の可用性火力が要る。' },
    },
    defenses: [
      fw(),
      { id: 'ips', name: 'IPS', gate: false, watch: 'A', def: { A: 0.22 }, detect: { A: 0.7 },
        evade: { info: 10 }, breakable: true, desc: '可用性攻撃を検査・遮断。回避/破壊で可用性の防御力と検知を下げる。' },
    ],
    audit: { hardenUp: 15 }, diag: { warnThreshold: 55, vulnDown: 15 }, edr: false, win: { ratio: 0.20 },
    blue: { alert: 40, react: 1.15 },
  },
  { // 4) サプライチェーン（完全性が厚い・EDR）
    id: 'cyber', name: 'サイバネ重工', gen: 2, turnLimit: 9,
    intro: '世代2のサプライチェーン汚染。完全性(🟢)が厚く整合性監視＋EDR稼働。世代0マルウェアは検知されやすい。',
    path: ['outside', 'pc', 'db'],
    nodes: {
      pc: PC_NODE,
      db: { name: '設計DB（本命）', kind: '本命', C: 150, I: 170, A: 120, H: 65, V: 28,
        baseDef: { C: 0.14, I: 0.16, A: 0.12 }, desc: '完全性が厚い。EDR稼働で全行動が目立つ。短期決戦を。' },
    },
    defenses: [
      fw(),
      { id: 'fim', name: '整合性監視', gate: false, watch: 'I', def: { I: 0.24 }, detect: { I: 0.7 },
        evade: { tech: 10 }, breakable: false, desc: '完全性の改ざんを監視。回避(技術)で完全性の防御力と検知を下げる。' },
    ],
    audit: { hardenUp: 15 }, diag: { warnThreshold: 50, vulnDown: 15 }, edr: true, win: { ratio: 0.18 },
    blue: { alert: 36, react: 1.25 },
  },
  { // 5) 政府APT（全ゲージ厚い・ゼロトラスト）
    id: 'nsho', name: 'N省', gen: 2, turnLimit: 10,
    intro: '政府APT級。全ゲージが厚くゼロトラスト＋EDR＋DLP。監査が速く、長居は即発覚。世代進化と短期決戦が必須。',
    path: ['outside', 'pc', 'db'],
    nodes: {
      pc: PC_NODE,
      db: { name: '中枢DB（本命）', kind: '本命', C: 200, I: 180, A: 180, H: 80, V: 20,
        baseDef: { C: 0.15, I: 0.14, A: 0.14 }, desc: 'ゼロトラスト。全ゲージ厚く、対策を剥がしてもなお硬い。最終ボス。' },
    },
    defenses: [
      fw({ C: 0.12, I: 0.18, A: 0.22 }),
      { id: 'dlp', name: 'プロキシ/DLP', gate: false, watch: 'C', def: { C: 0.28 }, detect: { C: 0.8 },
        evade: { info: 15 }, breakable: false, desc: '機密性の持ち出しを監視。回避で機密性の防御力と検知を下げる。' },
      { id: 'edr', name: 'EDR', gate: false, def: { C: 0.08, I: 0.08, A: 0.08 }, detect: { all: 0.5 },
        evade: { tech: 15 }, breakable: false, desc: '振る舞い検知。全ゲージにわずかな防御＋全行動の検知を底上げ。回避で検知が下がる。' },
    ],
    audit: { hardenUp: 12 }, diag: { warnThreshold: 45, vulnDown: 15 }, edr: false, win: { ratio: 0.24 },
    blue: { alert: 30, react: 1.5 }, // 政府APT: すぐ気づき頻繁に動く
  },
];

const STAGE_ZENITH = STAGES[1]; // 後方互換（テスト/既定）

if (typeof globalThis !== 'undefined') { globalThis.STAGES = STAGES; globalThis.STAGE_ZENITH = STAGE_ZENITH; }
