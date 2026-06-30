/* data/enemies.js — マルこれ ステージ定義（MVP: ゼニス銀行）
   数値は docs/MALCORE_BALANCE.md / docs/MALCORE_STAGE_MODEL.md / DEFENSE_MODEL.md 準拠。
   経路: 外部 → 踏み台(社員PC) →[境界FW]→ 本命(勘定系DB)

   ■防御力モデル
   ・本命の各ゲージは「本体防御力 baseDef」を持つ（対策を剥がしても残る）。
   ・defenses（対策）は def でゲージ別に防御力を上乗せし、detect で検知を上げる。
   ・対策は回避(evade)/破壊(break)で無効化でき、無効化すると寄与が消えて防御力が一気に低下。 */
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
      baseDef: { C: 0.14, I: 0.12, A: 0.12 }, // サーバ自身の防御力（対策を剥がしても残る）
      desc: '本命。機密性が厚く、ハードニング高め・脆弱性低めで通りにくい。対策を剥がして本体防御だけにしてから抜け。',
    },
  },
  // 対策（フィールド/ホスト）。回避/破壊で無効化すると防御力が一気に低下する。
  defenses: [
    {
      id: 'fw', name: '境界FW', gate: true, between: ['pc', 'db'],
      def: { C: 0.10, I: 0.15, A: 0.20 }, detect: {},
      evade: { info: 15 }, breakable: true,
      desc: '踏み台と本命を分離。回避(情報15)か破壊(装置破壊ロール)で経路を開く。剥がすと全ゲージの防御力が低下。',
    },
    {
      id: 'dlp', name: 'プロキシ/DLP', gate: false, watch: 'C',
      def: { C: 0.30 }, detect: { C: 0.8 },
      evade: { info: 10 }, breakable: false,
      desc: '機密性の持ち出しを監視。回避(情報10)で機密性の防御力を下げ、検知もしにくくなる。',
    },
  ],
  audit: { every: 4, hardenUp: 15 },         // システム監査: 一定ターン毎にH↑
  diag: { warnThreshold: 60, vulnDown: 15 }, // セキュリティ診断: 警戒度が閾値超えでV↓
  edr: false,                                // 振る舞い検知(EDR)。世代が上がると true（検知係数+）
  win: { ratio: 0.20 },                      // 本命CIA合計が初期の20%以下で勝利
};

if (typeof globalThis !== 'undefined') { globalThis.STAGE_ZENITH = STAGE_ZENITH; }
