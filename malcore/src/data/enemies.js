/* data/enemies.js — マルこれ ステージ定義（7ステージ・可変段数）
   経路は可変長: ['outside', n1, n2, ..., boss]。各内部ノードを侵害/横展開で進む。
   段数(=outside以外のノード数): ステージ1-3=2段 / 4-7=3段。各内部ホップにゲート(FW/WAF)。
   ゲートは脆弱性スキャン→エクスプロイト or 貫通で侵攻（横展開連打ではなく脆弱性攻略）。
   ゲート(FW/WAF: gate:true, between:[a,b])はその区間の横展開を塞ぐ。剥がすと防御力低下。
   数値は docs/MALCORE_*.md 準拠（草案）。 */

const PC = { name: '社員PC（踏み台）', kind: 'pc' };
// 境界FW（区間ゲート）
function fwGate(a, b, def, opt) {
  return Object.assign({ id: 'fw_' + a + '_' + b, name: '境界FW', gate: true, between: [a, b],
    def: def || { C: 0.10, I: 0.12, A: 0.16 }, detect: {}, evade: { info: 12 }, breakable: true,
    desc: a + '→' + b + ' を分離するFW。回避(情報)か破壊で経路を開く。剥がすと防御力低下。' }, opt || {});
}
function wafGate(a, b) {
  return { id: 'waf_' + a + '_' + b, name: 'WAF', gate: true, between: [a, b],
    def: { C: 0.10, I: 0.14, A: 0.06 }, detect: { I: 0.4 }, evade: { tech: 12 }, breakable: true,
    desc: 'Web境界のWAF。正規リクエスト偽装で回避、または破壊で通す。' };
}
// 監視系(非ゲート)
const DLP = { id: 'dlp', name: 'プロキシ/DLP', gate: false, watch: 'C', def: { C: 0.28 }, detect: { C: 0.8 },
  evade: { info: 12 }, breakable: false, desc: '機密性の持ち出しを監視。回避で機密性の防御力と検知を下げる。' };
const IPS = { id: 'ips', name: 'IPS', gate: false, watch: 'A', def: { A: 0.22 }, detect: { A: 0.7 },
  evade: { info: 12 }, breakable: true, desc: '可用性攻撃を検査。回避/破壊で可用性の防御力と検知を下げる。' };
const FIM = { id: 'fim', name: '整合性監視', gate: false, watch: 'I', def: { I: 0.24 }, detect: { I: 0.7 },
  evade: { tech: 12 }, breakable: false, desc: '完全性の改ざんを監視。回避で完全性の防御力と検知を下げる。' };
const EDR = { id: 'edr', name: 'EDR', gate: false, def: { C: 0.06, I: 0.06, A: 0.06 }, detect: { all: 0.5 },
  evade: { tech: 14 }, breakable: false, desc: '振る舞い検知。全ゲージに薄い防御＋全行動の検知を底上げ。回避で検知が下がる。' };

const STAGES = [
  { // 1) 2段 入門（踏み台→本命）
    id: 'machi', name: 'マチ町工業', gen: 0, turnLimit: 6,
    intro: '中小の町工場。2段(踏み台→基幹サーバ)。FWは簡易ACLのみ。入門ステージ。',
    path: ['outside', 'pc', 'db'],
    nodes: { pc: PC,
      db: { name: '基幹サーバ（本命）', kind: 'db', C: 90, I: 90, A: 90, H: 25, V: 60, baseDef: { C: 0.06, I: 0.06, A: 0.06 }, desc: '防御が薄い。素直に攻略できる。' } },
    defenses: [fwGate('pc', 'db', { C: 0.06, I: 0.08, A: 0.10 }, { name: 'ルータACL', evade: { info: 8 } })],
    audit: { hardenUp: 10 }, diag: { warnThreshold: 80, vulnDown: 10 }, edr: false, win: { ratio: 0.25 },
    blue: { alert: 50, react: 0.7 },
  },
  { // 2) 2段 金融(機密厚)
    id: 'zenith', name: 'ゼニス銀行', gen: 1, turnLimit: 7,
    intro: '金融系。2段(踏み台→勘定系DB)。境界FWの先、機密性(🔵)が厚くDLPで監視。',
    path: ['outside', 'pc', 'db'],
    nodes: { pc: PC,
      db: { name: '勘定系DB（本命）', kind: 'db', C: 160, I: 100, A: 100, H: 55, V: 35, baseDef: { C: 0.14, I: 0.12, A: 0.12 }, desc: '機密性が厚い。対策を剥がしてから抜け。' } },
    defenses: [fwGate('pc', 'db'), Object.assign({}, DLP)],
    audit: { hardenUp: 15 }, diag: { warnThreshold: 60, vulnDown: 15 }, edr: false, win: { ratio: 0.20 },
    blue: { alert: 42, react: 1.0 },
  },
  { // 3) 2段 インフラ(可用厚)
    id: 'power', name: '電力公社', gen: 2, turnLimit: 8,
    intro: 'インフラOT。2段(踏み台→制御サーバ)。境界FWの先、可用性(🟡)が厚くIPSが監視。',
    path: ['outside', 'pc', 'db'],
    nodes: { pc: PC,
      db: { name: '制御サーバ（本命）', kind: 'db', C: 120, I: 120, A: 180, H: 60, V: 30, baseDef: { C: 0.12, I: 0.12, A: 0.16 }, desc: '可用性が厚い。MyDoom/Blaster等が要る。' } },
    defenses: [fwGate('pc', 'db'), Object.assign({}, IPS)],
    audit: { hardenUp: 15 }, diag: { warnThreshold: 55, vulnDown: 15 }, edr: false, win: { ratio: 0.20 },
    blue: { alert: 40, react: 1.15 },
  },
  { // 4) 3段 サプライチェーン(完全厚・EDR)
    id: 'cyber', name: 'サイバネ重工', gen: 2, turnLimit: 10,
    intro: 'サプライチェーン。3段(踏み台→設計LAN→設計DB)。各段のFWを脆弱性で抜く。完全性(🟢)厚＋EDR稼働。',
    path: ['outside', 'pc', 'srv', 'db'],
    nodes: { pc: PC, srv: { name: '設計LAN', kind: 'srv' },
      db: { name: '設計DB（本命）', kind: 'db', C: 150, I: 170, A: 120, H: 65, V: 28, baseDef: { C: 0.14, I: 0.16, A: 0.12 }, desc: '完全性が厚い。EDRで全行動が目立つ。短期決戦を。' } },
    defenses: [fwGate('pc', 'srv'), fwGate('srv', 'db'), Object.assign({}, FIM)],
    audit: { hardenUp: 15 }, diag: { warnThreshold: 50, vulnDown: 15 }, edr: true, win: { ratio: 0.18 },
    blue: { alert: 38, react: 1.2 },
  },
  { // 5) 3段 医療(機密厚・WAF) NEW
    id: 'medi', name: 'メディテック製薬', gen: 2, turnLimit: 9,
    intro: '医療/個人情報。3段(踏み台→院内サーバ→患者DB)。入口WAF＋機密監視が厚い。',
    path: ['outside', 'pc', 'srv', 'db'],
    nodes: { pc: PC, srv: { name: '院内サーバ', kind: 'srv' },
      db: { name: '患者DB（本命）', kind: 'db', C: 180, I: 130, A: 110, H: 62, V: 30, baseDef: { C: 0.15, I: 0.13, A: 0.11 }, desc: '個人情報の宝庫。機密性が非常に厚い。' } },
    defenses: [wafGate('pc', 'srv'), fwGate('srv', 'db'), Object.assign({}, DLP)],
    audit: { hardenUp: 15 }, diag: { warnThreshold: 52, vulnDown: 15 }, edr: false, win: { ratio: 0.18 },
    blue: { alert: 38, react: 1.2 },
  },
  { // 6) 3段 政府APT(全厚・FW二重)
    id: 'nsho', name: 'X省', gen: 2, turnLimit: 11,
    intro: '政府APT級。3段(踏み台→内部LAN→中枢DB)。全ゲージ厚くFW二重＋EDR。',
    path: ['outside', 'pc', 'srv', 'db'],
    nodes: { pc: PC, srv: { name: '内部LAN', kind: 'srv' },
      db: { name: '中枢DB（本命）', kind: 'db', C: 180, I: 170, A: 160, H: 75, V: 22, baseDef: { C: 0.15, I: 0.14, A: 0.14 }, desc: 'ゼロトラスト。全ゲージ厚い。' } },
    defenses: [fwGate('pc', 'srv'), fwGate('srv', 'db', { C: 0.12, I: 0.16, A: 0.18 }), Object.assign({}, DLP), Object.assign({}, EDR)],
    audit: { hardenUp: 13 }, diag: { warnThreshold: 45, vulnDown: 15 }, edr: false, win: { ratio: 0.22 },
    blue: { alert: 32, react: 1.4 },
  },
  { // 7) 3段 最終ボス(2000年代の集大成)
    id: 'clearing', name: '国際金融クリアリング機構', gen: 2, turnLimit: 12,
    intro: '2000年代の集大成。3段(踏み台→DMZ→機密決済サーバ)。入口WAF＋境界FW＋全監視のゼロトラスト要塞。各機器を脆弱性で抜く。',
    path: ['outside', 'pc', 'dmz', 'db'],
    nodes: { pc: PC, dmz: { name: 'DMZサーバ', kind: 'srv' },
      db: { name: '機密決済サーバ（本命）', kind: 'db', C: 200, I: 190, A: 180, H: 80, V: 20, baseDef: { C: 0.16, I: 0.15, A: 0.15 }, desc: '最終目標。全ゲージ厚く多層防御。世代進化と編成と脆弱性攻略の総力戦。' } },
    defenses: [wafGate('pc', 'dmz'), fwGate('dmz', 'db', { C: 0.12, I: 0.16, A: 0.18 }), Object.assign({}, DLP), Object.assign({}, IPS)],
    audit: { hardenUp: 12 }, diag: { warnThreshold: 42, vulnDown: 15 }, edr: true, win: { ratio: 0.28 },
    blue: { alert: 34, react: 1.35 },
  },
];

// 制圧報酬: ステージ毎に本命サーバから溢れ出す 情報/技術/リソース(メモリ・GPU等)。
// テーマ: 機密(C)厚→情報多め / 完全(I)厚→技術多め / 可用(A)厚→リソース多め。
const STAGE_REWARDS = {
  machi: { info: 20, tech: 12, res: 15 },
  zenith: { info: 36, tech: 16, res: 18 },   // 金融=機密→情報
  power: { info: 24, tech: 18, res: 36 },    // インフラ=可用→リソース
  cyber: { info: 32, tech: 34, res: 26 },    // 完全→技術
  medi: { info: 48, tech: 24, res: 22 },     // 医療=機密→情報
  nsho: { info: 52, tech: 44, res: 44 },     // 全厚→全体的に多い
  clearing: { info: 74, tech: 58, res: 64 }, // 最終ボス=最大
};
STAGES.forEach(s => { s.reward = STAGE_REWARDS[s.id] || { info: 20, tech: 12, res: 15 }; });

const STAGE_ZENITH = STAGES[1]; // 後方互換（テスト/既定）

if (typeof globalThis !== 'undefined') { globalThis.STAGES = STAGES; globalThis.STAGE_ZENITH = STAGE_ZENITH; }
