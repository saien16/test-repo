/* data/enemies.js — マルこれ ステージ定義（MVP: ゼニス銀行）
   数値は docs/MALCORE_BALANCE.md §6 / docs/MALCORE_STAGE_MODEL.md 準拠。
   経路: 外部 → 踏み台(社員PC) →[境界FW]→ 本命(勘定系DB) */
const STAGE_ZENITH = {
  id: 'zenith', name: 'ゼニス銀行', gen: 1, turnLimit: 8,
  intro: '世代1・2段の金融系。機密性(🔵)が厚い。8ターン以内に本命「勘定系DB」を攻略せよ。長引けばブルーチームの封じ込めが間に合い敗北だ。',
  path: ['outside', 'pc', 'db'],
  nodes: {
    pc: {
      name: '社員PC（踏み台）', kind: '踏み台', hostFW: true,
      desc: 'フィッシングで初期侵害できる。ボット化で足場を固めると可用性火力が伸びる。',
    },
    db: {
      name: '勘定系DB（本命）', kind: '本命',
      C: 160, I: 100, A: 100, H: 55, V: 35,
      mit: { C: 0.30, I: 0, A: 0 }, // プロキシ/DLPで機密性の持ち出しを緩和
      desc: '本命。機密性が厚く、ハードニング高め・脆弱性低めで通りにくい。カットインで崩せ。',
    },
  },
  device: {
    name: '境界FW', between: ['pc', 'db'],
    desc: '踏み台と本命を分離。回避(情報レベル消費)か破壊(装置破壊ロール)で経路を開く。',
  },
  audit: { every: 4, hardenUp: 15 },   // システム監査: 一定ターン毎にH↑
  diag: { warnThreshold: 60, vulnDown: 15 }, // セキュリティ診断: 警戒度が閾値超えでV↓
  win: { ratio: 0.30 }, // 本命CIA合計が初期の30%以下で勝利
};

if (typeof globalThis !== 'undefined') { globalThis.STAGE_ZENITH = STAGE_ZENITH; }
