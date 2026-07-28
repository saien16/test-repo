/**
 * アーキテクチャ図に脆弱性ヒートマップを重ね合わせる可視化。
 *
 * ■ なぜ「行列」ではなく「構成図」なのか
 *
 * 構成要素 × 弱点カテゴリの行列は、どのセルが熱いかは分かるが
 * 「その構成要素がどこに繋がっているか」が分からない。
 * 攻撃者は行列のセルを攻撃するのではなく、公開された入口から入って
 * 信頼境界をまたいで奥へ進む。したがって主役はトポロジ（構成要素とデータフロー）で、
 * リスクの熱はその上に重ねる。行列は補助として図の下に併置する。
 *
 * ■ 視覚的符号化の約束（凡例で必ず説明する）
 *
 *   塗りの濃さ  = 実測リスク（事実）        … 検出された Finding 由来
 *   破線の輪郭  = 想定リスク（推測）        … CWEカタログとスタック構成由来
 *   ハッチング＋▲ = 死角（実測低 × 想定高）  … 「安全」ではなく「見えていない」
 *
 * 単純な赤〜緑グラデーションは使わない。緑は「安全」と読まれてしまうが、
 * このツールが本当に言えるのは「実測が無い」ことだけであって、
 * 「安全である」ことではないため。塗りが薄い＝事実が無い、それだけを意味する。
 *
 * ■ 決定性
 *
 * レイアウトは入力の順序のみから決まる。乱数・時刻・ハッシュ順は一切使わない。
 * 座標は 1/10 px に丸めて文字列化するため、同じ入力なら常に同じ SVG になる。
 */

import type {
  ArchitectureComponent,
  ArchitectureModel,
  ComponentDataFlow,
  ComponentKind,
  DeploymentStack,
  Exposure,
} from '../../types/architecture.js';
import type { Claim, Provenance } from '../../types/evidence.js';
import { provenanceLabel } from '../../types/evidence.js';
import type { BlindSpot, HeatmapCell, VulnerabilityHeatmap } from '../../types/heatmap.js';
import { escapeHtml, displayWidth, truncate } from '../text.js';

// ---------------------------------------------------------------------------
// 表示用ラベル
// ---------------------------------------------------------------------------

/** 露出度＝層。上ほど攻撃者に近い */
const LAYER_ORDER: readonly Exposure[] = ['public-internet', 'internal', 'local', 'unknown'];

const LAYER_LABEL: Record<Exposure, string> = {
  'public-internet': '公開層 — インターネットから直接到達',
  internal: '内部層 — 社内ネットワーク／VPC 内からのみ',
  local: 'ローカル層 — 同一ホスト・同一プロセスからのみ',
  unknown: '露出度 不明 — 推定できなかった構成要素',
};

/** 構成要素の種別。色に頼らないよう、ノード上に短いラベルとして出す */
const KIND_LABEL: Record<ComponentKind, string> = {
  'web-frontend': 'WEB',
  'api-service': 'API',
  database: 'DB',
  cache: 'CACHE',
  'message-queue': 'QUEUE',
  'object-storage': 'STORE',
  'auth-provider': 'AUTH',
  'background-worker': 'WORKER',
  gateway: 'GW',
  cdn: 'CDN',
  'external-api': 'EXT',
  cli: 'CLI',
  unknown: '?',
};

const CAUSE_ORDER: readonly BlindSpot['likelyCause'][] = [
  'not-scanned',
  'no-matching-lens',
  'genuinely-absent',
  'unknown',
];

const CAUSE_LABEL: Record<BlindSpot['likelyCause'], string> = {
  'not-scanned': '走査していない（除外設定・レンズ未有効）',
  'no-matching-lens': '該当カテゴリを見るレンズが無い',
  'genuinely-absent': '該当する実装自体が無さそう',
  unknown: '原因を切り分けられていない',
};

/** 原因ごとの「この空白をどう読むべきか」 */
const CAUSE_READING: Record<BlindSpot['likelyCause'], string> = {
  'not-scanned': '検出ゼロは安全の根拠にならない。走査範囲を広げて再確認すること。',
  'no-matching-lens': 'このカテゴリは今回そもそも見ていない。手動レビューか別ツールで補うこと。',
  'genuinely-absent': '実装が無いため出ていない可能性が高い。ただし推定であり保証ではない。',
  unknown: '安全なのか見えていないのか判断できない。まず原因の切り分けから。',
};

const DEPLOYMENT_FIELDS: readonly { key: keyof DeploymentStack; label: string }[] = [
  { key: 'runtime', label: 'ランタイム' },
  { key: 'containerization', label: 'コンテナ化' },
  { key: 'platform', label: '実行基盤' },
  { key: 'cloudProvider', label: 'クラウド' },
  { key: 'cicd', label: 'CI/CD' },
  { key: 'ingress', label: '受け口 (ingress)' },
  { key: 'secretsManagement', label: '秘密情報の管理' },
  { key: 'iac', label: 'インフラのコード化' },
];

const STYLE_LABEL: Record<string, string> = {
  monolith: 'モノリス',
  microservices: 'マイクロサービス',
  serverless: 'サーバレス',
  'spa-with-api': 'SPA + API',
  'static-site': '静的サイト',
  'cli-tool': 'CLI ツール',
  library: 'ライブラリ',
  'batch-job': 'バッチジョブ',
  unknown: '不明',
};

// ---------------------------------------------------------------------------
// レイアウト定数（すべて固定値。可変要素はノード数だけ）
// ---------------------------------------------------------------------------

const PAD_X = 20;
const PAD_TOP = 10;
const PAD_BOTTOM = 14;
const NODE_W = 168;
const NODE_H = 92;
const HGAP = 26;
const ROW_GAP = 18;
/** 1 層あたりの最大列数。これを超えたら層内で折り返す */
const MAX_COLS = 4;
/** 層ラベルの高さ */
const LABEL_H = 24;
/** 同一層内のデータフローを逃がす帯（ノードの下） */
const DIP_H = 34;
/** 層と層の間。層をまたぐフローと信頼境界の破線がここに入る */
const BAND_GAP = 78;
const MIN_CONTENT_W = 640;

/** 小数第1位まで。浮動小数の揺れを出さないための丸め */
function n(value: number): string {
  return (Math.round(value * 10) / 10).toString();
}

// ---------------------------------------------------------------------------
// リスク値 → 視覚レベル
// ---------------------------------------------------------------------------

/**
 * 0..100 相当の値を 0〜4 の離散レベルへ落とす。
 * 連続グラデーションにしないのは、微差を意味のある差として読ませないため。
 */
function heatLevel(value: number, scale: number): number {
  if (!Number.isFinite(value) || value <= 0) return 0;
  const ratio = value / Math.max(1, scale);
  if (ratio < 0.25) return 1;
  if (ratio < 0.5) return 2;
  if (ratio < 0.75) return 3;
  return 4;
}

/** 想定リスクは輪郭で表すため、段階を粗く（0〜3）する */
function inferLevel(value: number, scale: number): number {
  if (!Number.isFinite(value) || value <= 0) return 0;
  const ratio = value / Math.max(1, scale);
  if (ratio < 0.34) return 1;
  if (ratio < 0.67) return 2;
  return 3;
}

// ---------------------------------------------------------------------------
// SVG の小道具
// ---------------------------------------------------------------------------

/** SVG テキスト。中身は必ずエスケープする（構成要素名は未信頼入力） */
function svgText(
  x: number,
  y: number,
  text: string,
  className: string,
  anchor: 'start' | 'middle' | 'end' = 'start',
): string {
  return `<text x="${n(x)}" y="${n(y)}" class="${className}" text-anchor="${anchor}">${escapeHtml(text)}</text>`;
}

/**
 * 線の上に置く小さなラベル。読めるよう背景の板を敷く。
 * 幅は displayWidth（全角=2）から見積もる。決定的な計算。
 */
function svgTagLabel(cx: number, cy: number, text: string, className: string): string {
  const w = displayWidth(text) * 5.4 + 10;
  return [
    `<rect x="${n(cx - w / 2)}" y="${n(cy - 9)}" width="${n(w)}" height="18" rx="4" class="gm-tag-bg"/>`,
    svgText(cx, cy + 4, text, className, 'middle'),
  ].join('');
}

// ---------------------------------------------------------------------------
// レイアウト計算
// ---------------------------------------------------------------------------

interface NodeBox {
  component: ArchitectureComponent;
  x: number;
  y: number;
  observed: number;
  inferred: number;
  blindCount: number;
}

interface LayerBox {
  exposure: Exposure;
  top: number;
  height: number;
  nodes: NodeBox[];
}

interface Layout {
  width: number;
  height: number;
  layers: LayerBox[];
  boxById: Map<string, NodeBox>;
  observedScale: number;
  inferredScale: number;
}

function layerOf(component: ArchitectureComponent): Exposure {
  const value = component.exposure.value;
  return LAYER_ORDER.includes(value) ? value : 'unknown';
}

function computeLayout(architecture: ArchitectureModel, heatmap: VulnerabilityHeatmap): Layout {
  const blindByComponent = new Map<string, number>();
  for (const spot of heatmap.blindSpots) {
    blindByComponent.set(spot.componentId, (blindByComponent.get(spot.componentId) ?? 0) + 1);
  }

  // 露出度ごとに、architecture.components の順序を保って振り分ける（決定的）
  const grouped = new Map<Exposure, ArchitectureComponent[]>();
  for (const component of architecture.components) {
    const key = layerOf(component);
    const list = grouped.get(key);
    if (list) list.push(component);
    else grouped.set(key, [component]);
  }

  let observedScale = 100;
  let inferredScale = 100;
  for (const component of architecture.components) {
    const totals = heatmap.componentTotals[component.id];
    if (!totals) continue;
    observedScale = Math.max(observedScale, totals.observed);
    inferredScale = Math.max(inferredScale, totals.inferred);
  }

  // 図の横幅は「最も混み合う行」で決まる
  let maxRowW = MIN_CONTENT_W;
  for (const exposure of LAYER_ORDER) {
    const members = grouped.get(exposure);
    if (!members || members.length === 0) continue;
    const cols = Math.min(members.length, MAX_COLS);
    maxRowW = Math.max(maxRowW, cols * NODE_W + (cols - 1) * HGAP);
  }
  const contentW = maxRowW;
  const width = contentW + PAD_X * 2;

  const layers: LayerBox[] = [];
  const boxById = new Map<string, NodeBox>();
  let cursorY = PAD_TOP;

  for (const exposure of LAYER_ORDER) {
    const members = grouped.get(exposure);
    if (!members || members.length === 0) continue;

    const cols = Math.min(members.length, MAX_COLS);
    const rows = Math.ceil(members.length / cols);
    const nodes: NodeBox[] = [];

    for (let r = 0; r < rows; r++) {
      const slice = members.slice(r * cols, r * cols + cols);
      const rowW = slice.length * NODE_W + (slice.length - 1) * HGAP;
      const startX = PAD_X + (contentW - rowW) / 2;
      const y = cursorY + LABEL_H + r * (NODE_H + ROW_GAP);
      slice.forEach((component, i) => {
        const totals = heatmap.componentTotals[component.id];
        const box: NodeBox = {
          component,
          x: startX + i * (NODE_W + HGAP),
          y,
          observed: totals?.observed ?? 0,
          inferred: totals?.inferred ?? 0,
          blindCount: blindByComponent.get(component.id) ?? 0,
        };
        nodes.push(box);
        boxById.set(component.id, box);
      });
    }

    const height = LABEL_H + rows * NODE_H + (rows - 1) * ROW_GAP + DIP_H;
    layers.push({ exposure, top: cursorY, height, nodes });
    cursorY += height + BAND_GAP;
  }

  const height = Math.max(PAD_TOP + PAD_BOTTOM, cursorY - BAND_GAP + PAD_BOTTOM);
  return { width, height, layers, boxById, observedScale, inferredScale };
}

// ---------------------------------------------------------------------------
// SVG 描画
// ---------------------------------------------------------------------------

function renderDefs(): string {
  return [
    '<defs>',
    // 死角のハッチング。色覚に依存しないパターン記号
    '<pattern id="gm-hatch" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">',
    '<line x1="0" y1="0" x2="0" y2="8" class="gm-hatch-line"/>',
    '</pattern>',
    '<marker id="gm-arrow" viewBox="0 0 8 8" refX="7.5" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">',
    '<path d="M0,0 L8,4 L0,8 Z" class="gm-arrow-head"/>',
    '</marker>',
    '<marker id="gm-arrow-cross" viewBox="0 0 8 8" refX="7.5" refY="4" markerWidth="8" markerHeight="8" orient="auto-start-reverse">',
    '<path d="M0,0 L8,4 L0,8 Z" class="gm-arrow-head-cross"/>',
    '</marker>',
    '</defs>',
  ].join('');
}

function renderLayerBand(layer: LayerBox, width: number): string {
  const out: string[] = [];
  out.push(
    `<rect x="${n(PAD_X - 8)}" y="${n(layer.top)}" width="${n(width - (PAD_X - 8) * 2)}" ` +
      `height="${n(layer.height)}" rx="12" class="gm-band"/>`,
  );
  out.push(svgText(PAD_X, layer.top + 16, LAYER_LABEL[layer.exposure], 'gm-band-label'));
  return out.join('');
}

/** 層と層の間に引く信頼境界の破線 */
function renderTrustBoundary(y: number, width: number): string {
  return [
    `<line x1="${n(PAD_X - 8)}" y1="${n(y)}" x2="${n(width - PAD_X + 8)}" y2="${n(y)}" class="gm-boundary"/>`,
    svgTagLabel(PAD_X + 54, y, '信頼境界', 'gm-boundary-label'),
  ].join('');
}

function renderNode(box: NodeBox, layout: Layout): string {
  const c = box.component;
  const hLevel = heatLevel(box.observed, layout.observedScale);
  const iLevel = inferLevel(box.inferred, layout.inferredScale);
  const isBlind = box.blindCount > 0;

  const out: string[] = [];
  out.push(`<g class="gm-node">`);
  // マウスオーバー・支援技術向けの完全なテキスト（切り詰め前の値）
  out.push(
    `<title>${escapeHtml(
      `${c.name} / ${c.technology.value} — 実測リスク ${Math.round(box.observed)}・想定リスク ${Math.round(
        box.inferred,
      )}${isBlind ? `・死角 ${box.blindCount} 件` : ''}`,
    )}</title>`,
  );

  // 想定リスク（推測）＝ 外側の破線ハロー
  if (iLevel > 0) {
    out.push(
      `<rect x="${n(box.x - 5)}" y="${n(box.y - 5)}" width="${n(NODE_W + 10)}" height="${n(NODE_H + 10)}" ` +
        `rx="14" class="gm-halo gm-infer-${iLevel}"/>`,
    );
  }
  // 実測リスク（事実）＝ 塗りの濃さ
  out.push(
    `<rect x="${n(box.x)}" y="${n(box.y)}" width="${n(NODE_W)}" height="${n(NODE_H)}" rx="10" class="gm-node-base"/>`,
  );
  out.push(
    `<rect x="${n(box.x)}" y="${n(box.y)}" width="${n(NODE_W)}" height="${n(NODE_H)}" rx="10" ` +
      `class="gm-node-fill gm-heat-${hLevel}"/>`,
  );
  // 死角＝ハッチング＋二重の縁取り。塗り・輪郭とは独立した第3の記号
  if (isBlind) {
    out.push(
      `<rect x="${n(box.x)}" y="${n(box.y)}" width="${n(NODE_W)}" height="${n(NODE_H)}" rx="10" class="gm-node-hatch"/>`,
    );
    out.push(
      `<rect x="${n(box.x)}" y="${n(box.y)}" width="${n(NODE_W)}" height="${n(NODE_H)}" rx="10" class="gm-node-blind"/>`,
    );
  }
  out.push(
    `<rect x="${n(box.x)}" y="${n(box.y)}" width="${n(NODE_W)}" height="${n(NODE_H)}" rx="10" class="gm-node-edge"/>`,
  );

  // 種別バッジ（色ではなく文字で種別を示す）
  const kind = KIND_LABEL[c.kind] ?? '?';
  const kindW = displayWidth(kind) * 5.6 + 12;
  out.push(
    `<rect x="${n(box.x + 10)}" y="${n(box.y + 10)}" width="${n(kindW)}" height="16" rx="4" class="gm-kind-bg"/>`,
  );
  out.push(svgText(box.x + 10 + kindW / 2, box.y + 22, kind, 'gm-kind', 'middle'));

  out.push(svgText(box.x + 10, box.y + 44, truncate(c.name, 26), 'gm-node-name'));
  out.push(svgText(box.x + 10, box.y + 60, truncate(c.technology.value, 28), 'gm-node-tech'));
  out.push(
    svgText(
      box.x + 10,
      box.y + 78,
      `実測 ${String(Math.round(box.observed)).padStart(3, ' ')} / 想定 ${String(Math.round(box.inferred)).padStart(3, ' ')}`,
      'gm-node-num',
    ),
  );
  if (isBlind) {
    out.push(svgText(box.x + NODE_W - 10, box.y + 78, `▲ 死角 ${box.blindCount}`, 'gm-node-blind-tag', 'end'));
  }
  out.push('</g>');
  return out.join('');
}

/** データフロー1本ぶんのパスと注記 */
function renderFlow(flow: ComponentDataFlow, layout: Layout): string {
  const from = layout.boxById.get(flow.fromId);
  const to = layout.boxById.get(flow.toId);
  if (!from || !to || from === to) return '';

  const crosses = flow.crossesTrustBoundary.value === true;
  const cls = crosses ? 'gm-flow gm-flow-cross' : 'gm-flow';
  const marker = crosses ? 'gm-arrow-cross' : 'gm-arrow';

  const fromCx = from.x + NODE_W / 2;
  const toCx = to.x + NODE_W / 2;
  const dy = to.y - from.y;

  let d: string;
  let labelX: number;
  let labelY: number;

  if (Math.abs(dy) > 10) {
    // 層（または層内の行）をまたぐ ＝ 縦方向の接続
    const goingDown = dy > 0;
    const y1 = goingDown ? from.y + NODE_H : from.y;
    const y2 = goingDown ? to.y : to.y + NODE_H;
    const mid = (y1 + y2) / 2;
    d = `M ${n(fromCx)} ${n(y1)} C ${n(fromCx)} ${n(mid)}, ${n(toCx)} ${n(mid)}, ${n(toCx)} ${n(y2)}`;
    labelX = (fromCx + toCx) / 2;
    // 注記は中点ちょうどではなく手前に置く。層の中点には信頼境界の破線が走っているため
    labelY = y1 + (y2 - y1) * 0.33;
  } else {
    // 同一行 ＝ ノードの下の帯を通して迂回させる（他ノードを貫かない）
    const bottom = from.y + NODE_H;
    const dip = bottom + DIP_H - 12;
    d = `M ${n(fromCx)} ${n(bottom)} C ${n(fromCx)} ${n(dip)}, ${n(toCx)} ${n(dip)}, ${n(toCx)} ${n(to.y + NODE_H)}`;
    labelX = (fromCx + toCx) / 2;
    labelY = dip - 2;
  }

  const protocol = flow.protocol.value === '' ? '?' : flow.protocol.value;
  const label = crosses ? `⚠ 境界越え ${protocol}` : protocol;
  return (
    `<path d="${d}" class="${cls}" marker-end="url(#${marker})"/>` +
    svgTagLabel(labelX, labelY, truncate(label, 26), crosses ? 'gm-flow-label-cross' : 'gm-flow-label')
  );
}

function renderSvg(architecture: ArchitectureModel, layout: Layout): string {
  const parts: string[] = [];
  parts.push(
    `<svg class="gm-svg" viewBox="0 0 ${n(layout.width)} ${n(layout.height)}" ` +
      `width="${n(layout.width)}" height="${n(layout.height)}" role="img" ` +
      `aria-label="アーキテクチャ構成図に脆弱性リスクを重ねた図" ` +
      `style="width:${n(layout.width)}px;min-width:${n(Math.min(layout.width, 620))}px;max-width:100%;height:auto">`,
  );
  parts.push(renderDefs());

  // 1. 層の帯
  for (const layer of layout.layers) parts.push(renderLayerBand(layer, layout.width));
  // 2. 信頼境界の破線（層と層の間）
  for (let i = 0; i < layout.layers.length - 1; i++) {
    const current = layout.layers[i];
    if (!current) continue;
    parts.push(renderTrustBoundary(current.top + current.height + BAND_GAP / 2, layout.width));
  }
  // 3. データフロー（ノードの下に敷く）
  for (const flow of architecture.dataFlows) parts.push(renderFlow(flow, layout));
  // 4. ノード（熱を重ねる本体）
  for (const layer of layout.layers) {
    for (const box of layer.nodes) parts.push(renderNode(box, layout));
  }

  parts.push('</svg>');
  return parts.join('\n');
}

// ---------------------------------------------------------------------------
// 凡例
// ---------------------------------------------------------------------------

/**
 * 凡例。この図の生命線。
 * 「何が事実で何が推測か」をここで言い切れていなければ、この可視化は失敗である。
 */
function renderLegend(layout: Layout): string {
  const heatSwatches = [0, 1, 2, 3, 4]
    .map(
      (level, i) =>
        `<rect x="${n(6 + i * 34)}" y="6" width="28" height="20" rx="4" class="gm-node-base"/>` +
        `<rect x="${n(6 + i * 34)}" y="6" width="28" height="20" rx="4" class="gm-node-fill gm-heat-${level}"/>` +
        `<rect x="${n(6 + i * 34)}" y="6" width="28" height="20" rx="4" class="gm-node-edge"/>`,
    )
    .join('');

  const inferSwatches = [1, 2, 3]
    .map(
      (level, i) =>
        `<rect x="${n(8 + i * 46)}" y="8" width="34" height="16" rx="5" class="gm-halo gm-infer-${level}"/>`,
    )
    .join('');

  const box = (title: string, svg: string, w: number, h: number, desc: string): string =>
    `<div class="gm-legend-item">` +
    `<div class="gm-legend-title">${escapeHtml(title)}</div>` +
    `<svg class="gm-svg gm-legend-svg" viewBox="0 0 ${n(w)} ${n(h)}" width="${n(w)}" height="${n(h)}" aria-hidden="true">${renderDefs()}${svg}</svg>` +
    `<p class="gm-legend-desc">${desc}</p>` +
    `</div>`;

  return [
    '<h4>凡例 — 何が事実で、何が推測か</h4>',
    '<div class="gm-legend">',
    box(
      '塗りの濃さ ＝ 実測リスク（事実）',
      heatSwatches + svgText(6, 42, '無 →→→→ 濃', 'gm-legend-tick'),
      178,
      50,
      '検出された Finding の CVSS と件数から算出した値。' +
        `この図では最大 <span class="gm-num">${Math.round(layout.observedScale)}</span> を最濃としています。` +
        '<strong>薄い＝安全ではありません。</strong>「事実としての検出が無い」という意味しか持ちません。',
    ),
    box(
      '破線の輪郭 ＝ 想定リスク（推測）',
      inferSwatches + svgText(8, 42, '弱 →→ 強', 'gm-legend-tick'),
      178,
      50,
      'CWE カタログと露出度・技術スタックから導いた推測値。' +
        `最大 <span class="gm-num">${Math.round(layout.inferredScale)}</span> を最強の輪郭としています。` +
        '事実ではないため、塗りとは別の視覚言語（輪郭の太さと破線の粗さ）に分けています。',
    ),
    box(
      'ハッチング＋▲ ＝ 死角',
      `<rect x="6" y="6" width="96" height="28" rx="6" class="gm-node-base"/>` +
        `<rect x="6" y="6" width="96" height="28" rx="6" class="gm-node-fill gm-heat-1"/>` +
        `<rect x="6" y="6" width="96" height="28" rx="6" class="gm-node-hatch"/>` +
        `<rect x="6" y="6" width="96" height="28" rx="6" class="gm-node-blind"/>` +
        svgText(112, 25, '▲ 死角 n', 'gm-node-blind-tag'),
      178,
      50,
      '実測が低いのに想定が高い箇所。<strong>「安全だから出ていない」のか「見ていないから出ていない」のか</strong>が' +
        '未確定であることを示します。図の下の一覧で原因ごとに分類しています。',
    ),
    box(
      '線 ＝ データフロー',
      `<path d="M 8 30 C 40 30, 48 12, 84 12" class="gm-flow" marker-end="url(#gm-arrow)"/>` +
        `<path d="M 8 44 C 40 44, 48 40, 84 40" class="gm-flow gm-flow-cross" marker-end="url(#gm-arrow-cross)"/>` +
        svgText(92, 16, '通常', 'gm-legend-tick') +
        svgText(92, 44, '⚠ 信頼境界を越える', 'gm-legend-tick'),
      178,
      50,
      '太い線は信頼境界をまたぐ経路です。攻撃者が層を越えて奥へ進む経路であり、' +
        '同じ弱点でも境界を越える線の上にあるほうが危険です。',
    ),
    '</div>',
    '<p class="gm-note">色だけに情報を載せていません。濃さ・輪郭の太さ・パターン・数値ラベルが同じ情報を重複して伝えます。</p>',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// 図の下に添える情報
// ---------------------------------------------------------------------------

/** Claim の出所を人が読める形へ */
function provenanceDetail(provenance: Provenance): string {
  switch (provenance.kind) {
    case 'observed':
      return provenance.citations
        .map((c) => `<code>${escapeHtml(c.file)}${c.line === undefined ? '' : `:${c.line}`}</code>`)
        .join(', ');
    case 'inferred': {
      const alternatives =
        provenance.alternatives && provenance.alternatives.length > 0
          ? `<br><span class="gm-alt">対立仮説: ${provenance.alternatives.map((a) => escapeHtml(a)).join(' / ')}</span>`
          : '';
      return `${escapeHtml(provenance.reasoning)}${alternatives}`;
    }
    case 'assumed':
      return escapeHtml(provenance.reasoning);
  }
}

function claimBadge(claim: Claim<unknown>): string {
  const kind = claim.provenance.kind;
  return `<span class="gm-prov gm-prov-${kind}">${escapeHtml(provenanceLabel(claim.provenance))}</span>`;
}

function table(head: string[], rows: string[][], className = ''): string {
  const thead = head.map((h) => `<th scope="col">${h}</th>`).join('');
  const tbody = rows.map((row) => `<tr>${row.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('\n');
  return [
    '<div class="table-scroll" tabindex="0">',
    `<table class="${className}">`,
    `<thead><tr>${thead}</tr></thead>`,
    `<tbody>\n${tbody}\n</tbody>`,
    '</table>',
    '</div>',
  ].join('\n');
}

/** 推測依存度。1 に近いほど話半分に読むべき、という意味を文章で伝える */
function renderInferenceRatio(heatmap: VulnerabilityHeatmap): string {
  const raw = Number.isFinite(heatmap.inferenceRatio) ? heatmap.inferenceRatio : 0;
  const ratio = Math.max(0, Math.min(1, raw));
  const pct = Math.round(ratio * 100);
  let verdict: string;
  if (ratio < 0.25) {
    verdict = 'この図の大半は実際の検出に裏付けられています。ほぼそのまま読んで構いません。';
  } else if (ratio < 0.5) {
    verdict = '実測が優勢ですが、推測も無視できない割合です。断定的な結論は避けてください。';
  } else if (ratio < 0.75) {
    verdict = '推測のほうが多い状態です。この図は「仮説」であり「診断結果」ではありません。';
  } else {
    verdict = 'ほぼ推測でできています。話半分に読み、必ず手動での確認を挟んでください。';
  }
  return [
    '<h3>推測依存度</h3>',
    '<div class="card gm-ratio">',
    `<div class="gm-ratio-head"><span class="gm-num gm-ratio-value">${ratio.toFixed(2)}</span>` +
      `<span class="gm-ratio-unit">/ 1.00（${pct}% が推測）</span></div>`,
    `<div class="gm-ratio-bar" role="img" aria-label="推測依存度 ${pct}パーセント">` +
      `<span class="gm-ratio-fill" style="width:${pct}%"></span></div>`,
    `<div class="gm-ratio-scale"><span>0.00 実測のみ</span><span>1.00 推測のみ</span></div>`,
    `<p>${escapeHtml(verdict)}</p>`,
    '</div>',
  ].join('\n');
}

/** 死角一覧。原因ごとに分けることで「安全」と「未確認」を混同させない */
function renderBlindSpots(heatmap: VulnerabilityHeatmap): string {
  const out = ['<h3>死角 — 検出ゼロの空白をどう読むか</h3>'];
  if (heatmap.blindSpots.length === 0) {
    out.push(
      '<p>死角として記録された箇所はありません。ただしこれは「死角を検出しなかった」' +
        'という意味であり、死角が存在しないことの証明ではありません。</p>',
    );
    return out.join('\n');
  }

  const nameOf = new Map(heatmap.categories.map((c) => [c.id, c.name]));
  out.push(
    '<p>以下は<strong>検出が無いのに想定リスクが高い</strong>箇所です。' +
      '「安全だから出ていない」のか「見ていないから出ていない」のかを区別するため、' +
      '推定される原因ごとに分類しています。</p>',
  );

  // likelyCause ごとに分類。各グループ内は想定リスクの高い順（同値ならID順）で決定的に並べる
  for (const cause of CAUSE_ORDER) {
    const group = heatmap.blindSpots
      .filter((s) => s.likelyCause === cause)
      .sort(
        (a, b) =>
          b.inferredRisk - a.inferredRisk ||
          a.componentId.localeCompare(b.componentId) ||
          a.categoryId.localeCompare(b.categoryId),
      );
    if (group.length === 0) continue;

    out.push(`<div class="gm-cause gm-cause-${cause}">`);
    out.push(
      `<h4 class="gm-cause-head">${escapeHtml(CAUSE_LABEL[cause])} <span class="gm-num">(${group.length} 件)</span></h4>`,
    );
    out.push(`<p class="gm-cause-reading">${escapeHtml(CAUSE_READING[cause])}</p>`);
    out.push(
      table(
        ['構成要素', '弱点カテゴリ', '想定リスク', 'そう判断した理由', '確認すべきこと'],
        group.map((s) => [
          `<code>${escapeHtml(s.componentId)}</code>`,
          escapeHtml(nameOf.get(s.categoryId) ?? s.categoryId),
          `<span class="gm-num">${Math.round(s.inferredRisk)}</span>`,
          escapeHtml(s.reasoning),
          escapeHtml(s.recommendedAction),
        ]),
        'gm-table',
      ),
    );
    out.push('</div>');
  }
  return out.join('\n');
}

/** 補助の行列。主役は上の構成図で、こちらはセル単位の裏取り用 */
function renderMatrix(architecture: ArchitectureModel, heatmap: VulnerabilityHeatmap, layout: Layout): string {
  if (heatmap.categories.length === 0) return '';

  const cellAt = new Map<string, HeatmapCell>();
  for (const cell of heatmap.cells) cellAt.set(`${cell.componentId} ${cell.categoryId}`, cell);
  const nameOfComponent = new Map(architecture.components.map((c) => [c.id, c.name]));

  const componentIds =
    heatmap.componentIds.length > 0 ? heatmap.componentIds : architecture.components.map((c) => c.id);

  const basisMark: Record<string, string> = {
    both: '●',
    'observed-only': '◐',
    'inferred-only': '△',
    none: '·',
  };

  const rows = componentIds.map((componentId) => {
    const cells = heatmap.categories.map((category) => {
      const cell = cellAt.get(`${componentId} ${category.id}`);
      if (!cell) return '<span class="gm-cell gm-heat-0">·</span>';
      const level = heatLevel(cell.observedRisk, 100);
      const mark = basisMark[cell.basis] ?? '·';
      const title = `${category.name}: 実測 ${Math.round(cell.observedRisk)} / 想定 ${Math.round(cell.inferredRisk.value)}（${provenanceLabel(cell.inferredRisk.provenance)}）`;
      return (
        `<span class="gm-cell gm-heat-${level}" title="${escapeHtml(title)}">` +
        `${mark}<span class="gm-num">${Math.round(cell.observedRisk)}</span></span>`
      );
    });
    return [
      `${escapeHtml(nameOfComponent.get(componentId) ?? componentId)}`,
      ...cells,
    ];
  });

  return [
    '<details class="gm-matrix">',
    '<summary>補助: 構成要素 × 弱点カテゴリの行列（セル単位の裏取り用）</summary>',
    '<p class="gm-note">記号 ● 実測と想定の双方あり ／ ◐ 実測のみ（想定外の発見） ／ △ 想定のみ＝死角候補 ／ · どちらも無し。' +
      `背景の濃さは実測リスク（0〜100 の絶対値。上の図の相対スケール ${Math.round(layout.observedScale)} とは別）。</p>`,
    table(
      ['構成要素', ...heatmap.categories.map((c) => escapeHtml(c.name))],
      rows,
      'gm-table gm-matrix-table',
    ),
    '</details>',
  ].join('\n');
}

function renderDeployment(architecture: ArchitectureModel): string {
  const d = architecture.deployment;
  const rows = DEPLOYMENT_FIELDS.map(({ key, label }) => {
    const claim = d[key] as Claim<string> | undefined;
    if (!claim) return [escapeHtml(label), '<code>-</code>', '-', '-'];
    return [
      escapeHtml(label),
      `<code>${escapeHtml(String(claim.value))}</code>`,
      claimBadge(claim),
      provenanceDetail(claim.provenance),
    ];
  });

  const e = architecture.evidence;
  const confidence =
    e.meanInferredConfidence === null ? '—' : `${Math.round(e.meanInferredConfidence * 100)}%`;

  const out = ['<h3>デプロイメントスタック</h3>'];
  out.push(
    '<p>各項目に出所を付けています。<strong>「事実」はコード中の引用がある項目、' +
      '「推測」は根拠から導いた項目、「仮定」は根拠なしの既定値</strong>です。</p>',
  );
  out.push(
    '<p class="gm-note">この推定全体の内訳: ' +
      `事実 <span class="gm-num">${e.observed}</span> 件 / ` +
      `推測 <span class="gm-num">${e.inferred}</span> 件（平均確信度 <span class="gm-num">${confidence}</span>） / ` +
      `仮定 <span class="gm-num">${e.assumed}</span> 件</p>`,
  );
  out.push(table(['項目', '推定値', '出所', '根拠'], rows, 'gm-table'));

  if (architecture.inspectedManifests.length > 0) {
    out.push(
      '<p class="gm-note">参照した設定ファイル: ' +
        architecture.inspectedManifests.map((m) => `<code>${escapeHtml(m)}</code>`).join(', ') +
        '</p>',
    );
  }
  return out.join('\n');
}

/** 推定できなかったこと。隠さずに出す */
function renderGaps(architecture: ArchitectureModel): string {
  if (architecture.gaps.length === 0) return '';
  return [
    '<h3>推定できなかったこと</h3>',
    '<p>以下は今回のスキャンでは判断がつかなかった項目です。' +
      '図に描かれていないことは「無い」ことを意味しません。</p>',
    `<ul class="gm-gaps">${architecture.gaps.map((g) => `<li>${escapeHtml(g)}</li>`).join('')}</ul>`,
  ].join('\n');
}

// ---------------------------------------------------------------------------
// エントリポイント
// ---------------------------------------------------------------------------

/**
 * アーキテクチャ図＋ヒートマップのセクションを描画する。
 * architecture / heatmap のどちらかが無ければ空文字を返す（既存レポートを壊さない）。
 */
export function renderArchitectureMap(
  architecture: ArchitectureModel | undefined,
  heatmap: VulnerabilityHeatmap | undefined,
): string {
  if (!architecture || !heatmap) return '';
  if (architecture.components.length === 0) return '';

  const layout = computeLayout(architecture, heatmap);
  const styleLabel = STYLE_LABEL[architecture.style.value] ?? architecture.style.value;

  const out: string[] = [];
  out.push('<h2 id="archmap">アーキテクチャ × リスクヒートマップ</h2>');
  out.push(
    `<p>推定したアーキテクチャ様式: <strong>${escapeHtml(styleLabel)}</strong> ${claimBadge(architecture.style)}。` +
      `構成要素 <span class="gm-num">${architecture.components.length}</span> 件 / ` +
      `データフロー <span class="gm-num">${architecture.dataFlows.length}</span> 本。</p>`,
  );
  out.push(
    '<p>上ほど攻撃者に近い層です。ノードの見た目は「実測（事実）」と「想定（推測）」を' +
      '別々に符号化しています。読み方は図の下の凡例を必ず確認してください。</p>',
  );
  out.push('<div class="gm-figure" tabindex="0">');
  out.push(renderSvg(architecture, layout));
  out.push('</div>');
  out.push('<div class="card gm-legend-card">');
  out.push(renderLegend(layout));
  out.push('</div>');
  out.push(renderMatrix(architecture, heatmap, layout));
  out.push(renderBlindSpots(heatmap));
  out.push(renderInferenceRatio(heatmap));
  out.push(renderDeployment(architecture));
  out.push(renderGaps(architecture));

  return out.filter((s) => s !== '').join('\n');
}

/**
 * このセクション専用の CSS。html.ts の STYLE へ連結して使う。
 * 意味色（--gm-heat 系）はアクセント色 --accent とは別系統に取る。
 */
export const ARCHITECTURE_MAP_STYLE = `
:root {
  /* 意味色: 危険度。アクセント(青)とは別系統に取り、装飾と混同させない */
  --gm-heat: #a3103c;
  --gm-infer: #6d28d9;
  --gm-blind: #b45309;
  --gm-line: #7c8797;
  --gm-band: rgba(0, 0, 0, 0.035);
}
@media (prefers-color-scheme: dark) {
  :root {
    --gm-heat: #ff5d87;
    --gm-infer: #b79bff;
    --gm-blind: #f0a53a;
    --gm-line: #78838f;
    --gm-band: rgba(255, 255, 255, 0.04);
  }
}
.gm-figure {
  overflow-x: auto; -webkit-overflow-scrolling: touch; max-width: 100%;
  border: 1px solid var(--border); border-radius: 10px;
  background: var(--surface); padding: 8px; margin: 16px 0;
}
.gm-svg { color: var(--text); display: block; }
.gm-band { fill: var(--gm-band); stroke: var(--border); stroke-width: 1; stroke-dasharray: 2 4; }
.gm-band-label { fill: var(--text-dim); font-size: 11.5px; font-weight: 700; }
.gm-boundary { stroke: var(--gm-blind); stroke-width: 2; stroke-dasharray: 10 6; opacity: 0.85; }
.gm-boundary-label { fill: var(--gm-blind); font-size: 10.5px; font-weight: 700; }
.gm-tag-bg { fill: var(--surface); stroke: var(--border); stroke-width: 1; opacity: 0.95; }

/* ノード本体。塗り＝実測（事実） */
.gm-node-base { fill: var(--surface-2); }
.gm-node-fill { stroke: none; fill: var(--gm-heat); }
.gm-node-edge { fill: none; stroke: var(--border); stroke-width: 1.2; }
.gm-heat-0 { fill-opacity: 0; }
.gm-heat-1 { fill-opacity: 0.12; }
.gm-heat-2 { fill-opacity: 0.30; }
.gm-heat-3 { fill-opacity: 0.52; }
.gm-heat-4 { fill-opacity: 0.78; }

/* 輪郭＝想定（推測）。破線であること自体が「推測」の合図 */
.gm-halo { fill: none; stroke: var(--gm-infer); }
.gm-infer-1 { stroke-width: 1.2; stroke-dasharray: 3 3; opacity: 0.7; }
.gm-infer-2 { stroke-width: 2.4; stroke-dasharray: 6 3; opacity: 0.85; }
.gm-infer-3 { stroke-width: 3.6; stroke-dasharray: 9 3; opacity: 1; }

/* 死角＝ハッチング＋縁取り。塗り・輪郭とは独立した第3の記号 */
.gm-node-hatch { fill: url(#gm-hatch); stroke: none; }
.gm-hatch-line { stroke: var(--gm-blind); stroke-width: 2.5; opacity: 0.4; }
.gm-node-blind { fill: none; stroke: var(--gm-blind); stroke-width: 2.4; stroke-dasharray: 1 0; }
.gm-node-blind-tag { fill: var(--gm-blind); font-size: 10.5px; font-weight: 700; }

.gm-kind-bg { fill: var(--surface); stroke: var(--border); stroke-width: 1; }
.gm-kind { fill: var(--text-dim); font-size: 9.5px; font-weight: 700; letter-spacing: 0.04em; }
.gm-node-name { fill: currentColor; font-size: 13px; font-weight: 700; }
.gm-node-tech { fill: var(--text-dim); font-size: 11px; }
.gm-node-num {
  fill: currentColor; font-size: 11.5px; font-weight: 600;
  font-variant-numeric: tabular-nums; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

/* データフロー。信頼境界をまたぐ線は太さで強調する（色だけに頼らない） */
.gm-flow { fill: none; stroke: var(--gm-line); stroke-width: 1.5; }
.gm-flow-cross { stroke: var(--gm-heat); stroke-width: 3.2; }
.gm-arrow-head { fill: var(--gm-line); }
.gm-arrow-head-cross { fill: var(--gm-heat); }
.gm-flow-label { fill: var(--text-dim); font-size: 10.5px; }
.gm-flow-label-cross { fill: var(--gm-heat); font-size: 10.5px; font-weight: 700; }
.gm-legend-tick { fill: var(--text-dim); font-size: 10.5px; }

.gm-legend {
  display: grid; gap: 14px; margin: 8px 0 4px;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
}
.gm-legend-item {
  border: 1px solid var(--border); border-radius: 8px;
  padding: 10px 12px; background: var(--surface-2);
}
.gm-legend-title { font-weight: 700; font-size: 0.9rem; margin-bottom: 6px; }
.gm-legend-svg { max-width: 100%; height: auto; margin-bottom: 4px; }
.gm-legend-desc { font-size: 0.82rem; color: var(--text-dim); margin: 0; line-height: 1.7; }
.gm-note { font-size: 0.82rem; color: var(--text-dim); }
.gm-num { font-variant-numeric: tabular-nums; }

.gm-ratio-head { display: flex; align-items: baseline; gap: 8px; }
.gm-ratio-value { font-size: 2rem; font-weight: 700; }
.gm-ratio-unit { color: var(--text-dim); font-size: 0.85rem; }
.gm-ratio-bar {
  height: 12px; border-radius: 6px; background: var(--surface-2);
  border: 1px solid var(--border); overflow: hidden; margin: 8px 0 4px;
}
.gm-ratio-fill { display: block; height: 100%; background: var(--gm-infer); }
.gm-ratio-scale {
  display: flex; justify-content: space-between;
  font-size: 0.75rem; color: var(--text-dim); font-variant-numeric: tabular-nums;
}
.gm-cause { margin: 20px 0; border-left: 4px solid var(--gm-blind); padding-left: 14px; }
.gm-cause-genuinely-absent { border-left-color: var(--border); }
.gm-cause-head { margin: 0 0 4px; color: var(--text); font-size: 0.98rem; }
.gm-cause-reading { font-size: 0.85rem; color: var(--text-dim); margin: 0 0 8px; }
.gm-table td, .gm-table th { font-size: 0.84rem; }
/*
 * 行列セルの熱。color-mix 未対応の環境では背景が付かないだけで壊れない
 * （記号と数値が同じ情報を持っているため、色が落ちても読める）。
 */
.gm-matrix-table .gm-cell {
  display: inline-flex; align-items: center; gap: 4px; min-width: 46px;
  padding: 1px 6px; border-radius: 4px; background-color: transparent;
  border: 1px solid var(--border);
  font-variant-numeric: tabular-nums; font-size: 0.8rem;
}
.gm-matrix-table .gm-heat-0 { color: var(--text-dim); border-color: transparent; }
.gm-matrix-table .gm-heat-1 { background-color: color-mix(in srgb, var(--gm-heat) 12%, transparent); }
.gm-matrix-table .gm-heat-2 { background-color: color-mix(in srgb, var(--gm-heat) 30%, transparent); }
.gm-matrix-table .gm-heat-3 { background-color: color-mix(in srgb, var(--gm-heat) 52%, transparent); }
.gm-matrix-table .gm-heat-4 { background-color: color-mix(in srgb, var(--gm-heat) 78%, transparent); }
.gm-prov {
  display: inline-block; padding: 0 8px; border-radius: 999px;
  font-size: 0.72rem; font-weight: 700; white-space: nowrap; border: 1px solid var(--border);
}
.gm-prov-observed { border-color: var(--ok); color: var(--ok); }
.gm-prov-inferred { border-style: dashed; border-color: var(--gm-infer); color: var(--gm-infer); }
.gm-prov-assumed { border-style: dotted; border-color: var(--gm-blind); color: var(--gm-blind); }
.gm-alt { color: var(--text-dim); font-size: 0.8rem; }
.gm-gaps li { margin: 4px 0; }
@media (max-width: 600px) {
  .gm-legend { grid-template-columns: 1fr; }
}
`;
