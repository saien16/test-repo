/**
 * アーキテクチャ図＋ヒートマップ可視化のテスト。
 *
 * 検証の主眼は「見た目が綺麗か」ではなく、
 *   - 情報が無いときに黙ること（既存レポートを壊さない）
 *   - 未信頼入力が漏れないこと
 *   - 同じ入力で同じ図が出ること（決定的レイアウト）
 *   - 事実／推測／死角の区別が出力に残ること
 * の4点である。
 */

import { describe, expect, it } from 'vitest';
import { assumed, inferred, observed } from '../types/evidence.js';
import type { AnalyzedReport, ScanResult } from '../types/report.js';
import { analyzeMechanically } from './analyze.js';
import {
  makeArchitecture,
  makeContext,
  makeFinding,
  makeHeatmap,
  makeResult,
} from './fixtures.js';
import { renderArchitectureMap } from './formatters/architecture-map.js';
import { renderHtml } from './formatters/html.js';
import { buildFallbackNarrative } from './narrative.js';

function analyzedOf(result: ScanResult): AnalyzedReport {
  const m = analyzeMechanically(result);
  const n = buildFallbackNarrative(
    {
      context: result.context,
      summary: result.summary,
      ranked: m.ranked,
      chains: result.chains,
      actions: m.actions,
      hasBaseline: m.hasBaseline,
      errors: result.errors,
    },
    m.keyFindings,
  );
  const report: AnalyzedReport = {
    executiveSummary: n.executiveSummary,
    keyFindings: n.keyFindings,
    prioritizedActions: m.actions,
    riskNarrative: n.riskNarrative,
    summary: result.summary,
  };
  if (n.trendNarrative) report.trendNarrative = n.trendNarrative;
  return report;
}

const fullResult = (): ScanResult =>
  makeResult({
    context: makeContext(),
    findings: [makeFinding({ id: 'f-1' })],
    architecture: makeArchitecture(),
    heatmap: makeHeatmap(),
  });

describe('renderArchitectureMap — 情報が無い場合', () => {
  it('architecture も heatmap も無ければ空文字を返す', () => {
    expect(renderArchitectureMap(undefined, undefined)).toBe('');
  });

  it('architecture だけでは描かない（熱を重ねる元が無いため）', () => {
    expect(renderArchitectureMap(makeArchitecture(), undefined)).toBe('');
  });

  it('heatmap だけでは描かない（トポロジが無いため）', () => {
    expect(renderArchitectureMap(undefined, makeHeatmap())).toBe('');
  });

  it('構成要素が0件なら描かない', () => {
    const empty = makeArchitecture({ components: [], dataFlows: [] });
    expect(renderArchitectureMap(empty, makeHeatmap())).toBe('');
  });
});

describe('renderHtml — セクションの有無で既存レポートを壊さない', () => {
  it('architecture / heatmap が無いHTMLにはセクションも目次項目も出ない', () => {
    const result = makeResult({ context: makeContext(), findings: [makeFinding({ id: 'f-1' })] });
    const html = renderHtml(result, analyzedOf(result), { verbose: false });

    expect(html).not.toContain('id="archmap"');
    expect(html).not.toContain('href="#archmap"');
    // CSS は常に入るが、図そのものは出ない
    expect(html).not.toContain('<div class="gm-figure"');
    expect(html).not.toContain('<svg');
    // 既存の骨格は従来どおり
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('id="executive"');
    expect(html).toContain('id="actions"');
    expect(html).toContain('id="findings"');
  });

  it('両方あればセクションと目次項目が出る', () => {
    const result = fullResult();
    const html = renderHtml(result, analyzedOf(result), { verbose: false });

    expect(html).toContain('id="archmap"');
    expect(html).toContain('href="#archmap"');
    expect(html).toContain('<svg');
    // 既存セクションは失われない
    expect(html).toContain('id="executive"');
    expect(html).toContain('id="actions"');
  });

  it('片方だけ渡されても描画されない', () => {
    const onlyArch = makeResult({ architecture: makeArchitecture() });
    expect(renderHtml(onlyArch, analyzedOf(onlyArch), { verbose: false })).not.toContain('id="archmap"');

    const onlyHeat = makeResult({ heatmap: makeHeatmap() });
    expect(renderHtml(onlyHeat, analyzedOf(onlyHeat), { verbose: false })).not.toContain('id="archmap"');
  });
});

describe('アーキテクチャ図としての体裁', () => {
  const html = renderArchitectureMap(makeArchitecture(), makeHeatmap());

  it('Canvas ではなく SVG で描かれ、viewBox を持つ', () => {
    expect(html).toContain('<svg');
    expect(html).toContain('viewBox="0 0 ');
    expect(html).not.toContain('<canvas');
  });

  it('露出度ごとの層が描かれる', () => {
    expect(html).toContain('公開層');
    expect(html).toContain('内部層');
    expect(html).toContain('ローカル層');
  });

  it('構成要素がノードとして描かれる', () => {
    expect(html).toContain('API サーバ (Express)');
    expect(html).toContain('PostgreSQL');
    expect(html).toContain('Web フロントエンド');
  });

  it('データフローがパスとして描かれ、プロトコルが注記される', () => {
    expect(html).toContain('<path d="M ');
    expect(html).toContain('SQL');
    expect(html).toContain('HTTP');
  });

  it('信頼境界をまたぐフローが強調され、境界の破線が引かれる', () => {
    expect(html).toContain('gm-flow-cross');
    expect(html).toContain('境界越え');
    expect(html).toContain('gm-boundary');
    expect(html).toContain('信頼境界');
  });

  it('レスポンシブに縮小できる（max-width と横スクロールコンテナ）', () => {
    expect(html).toContain('max-width:100%');
    expect(html).toContain('class="gm-figure"');
  });

  it('数値の並ぶ箇所に tabular-nums が効くクラスが付く', () => {
    expect(html).toContain('gm-num');
  });
});

describe('事実／推測／死角の符号化', () => {
  const html = renderArchitectureMap(makeArchitecture(), makeHeatmap());

  it('実測は塗り、想定は輪郭として別のクラスで符号化される', () => {
    expect(html).toMatch(/gm-node-fill gm-heat-\d/);
    expect(html).toMatch(/gm-halo gm-infer-\d/);
  });

  it('実測が高い構成要素ほど濃い塗りになる（api > web）', () => {
    // componentTotals: api=152 / web=12 → api のほうが高いレベルになる
    const apiLevel = /API サーバ[\s\S]*?/.test(html);
    expect(apiLevel).toBe(true);
    expect(html).toContain('gm-heat-4');
    expect(html).toContain('gm-heat-1');
  });

  it('死角のある構成要素にはハッチングと警告記号が付く', () => {
    expect(html).toContain('gm-node-hatch');
    expect(html).toContain('gm-node-blind');
    expect(html).toContain('▲ 死角');
  });

  it('ノードに実測値と想定値が数値としても出る（色だけに頼らない）', () => {
    expect(html).toContain('実測');
    expect(html).toContain('想定');
  });

  it('凡例が出力に含まれ、塗り＝事実・輪郭＝推測の対応を説明している', () => {
    expect(html).toContain('凡例');
    expect(html).toContain('塗りの濃さ ＝ 実測リスク（事実）');
    expect(html).toContain('破線の輪郭 ＝ 想定リスク（推測）');
    expect(html).toContain('ハッチング＋▲ ＝ 死角');
    // 「薄い＝安全」と読ませない注意書き
    expect(html).toContain('薄い＝安全ではありません');
    expect(html).toContain('色だけに情報を載せていません');
  });
});

describe('死角一覧', () => {
  const html = renderArchitectureMap(makeArchitecture(), makeHeatmap());

  it('likelyCause ごとに分類して表示される', () => {
    expect(html).toContain('gm-cause-not-scanned');
    expect(html).toContain('gm-cause-no-matching-lens');
    expect(html).toContain('gm-cause-genuinely-absent');
    expect(html).toContain('gm-cause-unknown');
    expect(html).toContain('走査していない（除外設定・レンズ未有効）');
    expect(html).toContain('該当カテゴリを見るレンズが無い');
    expect(html).toContain('該当する実装自体が無さそう');
    expect(html).toContain('原因を切り分けられていない');
  });

  it('「安全だから出ていない」と「見ていないから出ていない」を区別する文言がある', () => {
    expect(html).toContain('見ていないから出ていない');
    expect(html).toContain('検出ゼロは安全の根拠にならない');
  });

  it('原因が1種類だけならその分類だけが出る', () => {
    const heatmap = makeHeatmap({
      blindSpots: [
        {
          componentId: 'db',
          categoryId: 'authz',
          inferredRisk: 70,
          reasoning: 'レンズ未対応',
          likelyCause: 'no-matching-lens',
          recommendedAction: '手動確認',
        },
      ],
    });
    const only = renderArchitectureMap(makeArchitecture(), heatmap);
    expect(only).toContain('gm-cause-no-matching-lens');
    expect(only).not.toContain('gm-cause-not-scanned');
    expect(only).not.toContain('gm-cause-genuinely-absent');
  });

  it('死角が0件でも「死角が無い証明ではない」と明示する', () => {
    const none = renderArchitectureMap(makeArchitecture(), makeHeatmap({ blindSpots: [] }));
    expect(none).toContain('死角が存在しないことの証明ではありません');
  });
});

describe('推測依存度', () => {
  it('値と「話半分に読むべき」旨が出る', () => {
    const html = renderArchitectureMap(makeArchitecture(), makeHeatmap({ inferenceRatio: 0.9 }));
    expect(html).toContain('推測依存度');
    expect(html).toContain('0.90');
    expect(html).toContain('話半分に読み');
  });

  it('実測中心なら表現が変わる', () => {
    const html = renderArchitectureMap(makeArchitecture(), makeHeatmap({ inferenceRatio: 0.1 }));
    expect(html).toContain('0.10');
    expect(html).toContain('実際の検出に裏付けられています');
  });

  it('範囲外の値でも 0..1 に丸めて壊れない', () => {
    const html = renderArchitectureMap(makeArchitecture(), makeHeatmap({ inferenceRatio: 5 }));
    expect(html).toContain('1.00');
    expect(html).not.toContain('width:500%');
  });
});

describe('デプロイスタックと gaps', () => {
  const html = renderArchitectureMap(makeArchitecture(), makeHeatmap());

  it('provenanceLabel によるラベルが付く', () => {
    expect(html).toContain('デプロイメントスタック');
    expect(html).toContain('事実');
    expect(html).toMatch(/推測\(確信度 \d+%\)/);
    expect(html).toContain('仮定');
  });

  it('各項目の値と根拠が出る', () => {
    expect(html).toContain('Node.js 20');
    expect(html).toContain('github-actions');
    expect(html).toContain('task-definition.json があるため ECS と推測。');
    expect(html).toContain('対立仮説');
  });

  it('推定できなかった項目（gaps）を隠さない', () => {
    expect(html).toContain('推定できなかったこと');
    expect(html).toContain('ロードバランサ／WAF の有無を判断できなかった');
  });
});

describe('エスケープ（構成要素名はスキャン対象由来＝未信頼入力）', () => {
  const hostile = () => {
    const base = makeArchitecture();
    const first = base.components[0];
    if (!first) throw new Error('fixture broken');
    return makeArchitecture({
      style: inferred('monolith', {
        confidence: 0.5,
        inferredBy: 'llm',
        reasoning: '</p><script>alert("reasoning")</script>',
      }),
      components: [
        {
          ...first,
          id: 'evil',
          name: '<script>alert("name")</script>',
          technology: observed('"><img src=x onerror=alert(1)>', [
            { file: '<script>alert("cite")</script>.json', line: 1 },
          ]),
        },
        {
          ...first,
          id: 'evil2',
          name: '</title><script>alert("name2")</script>',
          exposure: assumed('internal', 'x'),
        },
      ],
      dataFlows: [
        {
          fromId: 'evil',
          toId: 'evil2',
          protocol: assumed('</text><script>alert("proto")</script>', 'x'),
          crossesTrustBoundary: assumed(true, 'x'),
        },
      ],
      gaps: ['<script>alert("gap")</script>'],
      inspectedManifests: ['<script>alert("manifest")</script>'],
    });
  };

  it('SVG内・HTML内ともに生タグが残らない', () => {
    const heatmap = makeHeatmap({
      componentIds: ['evil'],
      blindSpots: [
        {
          componentId: '<script>alert("cid")</script>',
          categoryId: 'injection',
          inferredRisk: 80,
          reasoning: '<script>alert("reason")</script>',
          likelyCause: 'not-scanned',
          recommendedAction: '<script>alert("action")</script>',
        },
      ],
      categories: [{ id: 'injection', name: '<script>alert("cat")</script>', cweIds: [] }],
      componentTotals: { evil: { observed: 40, inferred: 90 } },
    });
    const html = renderArchitectureMap(hostile(), heatmap);

    // タグとして解釈されうる形が一切残っていないこと
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<img/i);
    // SVG の <text>/<title> を閉じて抜け出す形も潰れていること
    expect(html).toContain('&lt;/title&gt;&lt;script&gt;');
    expect(html).toContain('&lt;/text&gt;');
    expect(html).toContain('&lt;script&gt;');
    // 属性値を抜け出せる引用符も実体参照になっていること
    expect(html).toContain('&quot;&gt;&lt;img src=x onerror=alert(1)&gt;');
  });

  it('エスケープはHTML全体に通しても保たれる', () => {
    const result = makeResult({
      architecture: hostile(),
      heatmap: makeHeatmap({ componentTotals: { evil: { observed: 1, inferred: 1 } } }),
    });
    const html = renderHtml(result, analyzedOf(result), { verbose: false });
    expect(html).not.toContain('<script>alert(');
  });
});

describe('決定的レイアウト', () => {
  it('同じ入力なら完全に同じ出力になる', () => {
    const a = renderArchitectureMap(makeArchitecture(), makeHeatmap());
    const b = renderArchitectureMap(makeArchitecture(), makeHeatmap());
    expect(a).toBe(b);
  });

  it('別インスタンスの同値な入力でも一致する（参照に依存しない）', () => {
    const arch1 = makeArchitecture();
    const arch2 = JSON.parse(JSON.stringify(arch1)) as ReturnType<typeof makeArchitecture>;
    const heat1 = makeHeatmap();
    const heat2 = JSON.parse(JSON.stringify(heat1)) as ReturnType<typeof makeHeatmap>;
    expect(renderArchitectureMap(arch2, heat2)).toBe(renderArchitectureMap(arch1, heat1));
  });

  it('座標に乱数由来の長い小数が現れない（1/10 px に丸めている）', () => {
    const html = renderArchitectureMap(makeArchitecture(), makeHeatmap());
    const coords = html.match(/(?:x|y|x1|y1|x2|y2|width|height)="[\d.]+"/g) ?? [];
    expect(coords.length).toBeGreaterThan(0);
    for (const c of coords) {
      const value = c.split('"')[1] ?? '';
      const decimals = value.includes('.') ? value.split('.')[1] ?? '' : '';
      expect(decimals.length).toBeLessThanOrEqual(1);
    }
  });

  it('構成要素の並び順が変われば図も変わる（順序を保持している証拠）', () => {
    const base = makeArchitecture();
    const reversed = makeArchitecture({ components: [...base.components].reverse() });
    expect(renderArchitectureMap(reversed, makeHeatmap())).not.toBe(
      renderArchitectureMap(base, makeHeatmap()),
    );
  });
});

describe('堅牢性', () => {
  it('componentTotals に無い構成要素は 0 として扱い落ちない', () => {
    const html = renderArchitectureMap(makeArchitecture(), makeHeatmap({ componentTotals: {} }));
    expect(html).toContain('gm-heat-0');
    expect(html).toContain('API サーバ (Express)');
  });

  it('存在しない構成要素を指すデータフローは黙って捨てる', () => {
    const arch = makeArchitecture({
      dataFlows: [
        {
          fromId: 'api',
          toId: 'nonexistent',
          protocol: assumed('HTTP', 'x'),
          crossesTrustBoundary: assumed(false, 'x'),
        },
      ],
    });
    const html = renderArchitectureMap(arch, makeHeatmap());
    expect(html).toContain('<svg');
    expect(html).not.toContain('nonexistent');
  });

  it('カテゴリが0件でも補助行列を出さずに図は描ける', () => {
    const html = renderArchitectureMap(
      makeArchitecture(),
      makeHeatmap({ categories: [], cells: [] }),
    );
    expect(html).toContain('<svg');
    expect(html).not.toContain('gm-matrix-table');
  });

  it('露出度が不明な構成要素も専用の層に落ちる', () => {
    const arch = makeArchitecture({
      components: [
        {
          ...(makeArchitecture().components[0] as NonNullable<
            ReturnType<typeof makeArchitecture>['components'][number]
          >),
          id: 'mystery',
          name: '正体不明のサービス',
          exposure: assumed('unknown', '判断材料なし'),
        },
      ],
      dataFlows: [],
    });
    const html = renderArchitectureMap(arch, makeHeatmap());
    expect(html).toContain('露出度 不明');
    expect(html).toContain('正体不明のサービス');
  });

  it('層をまたぐ構成要素が多くても折り返して描ける', () => {
    const many = Array.from({ length: 9 }, (_, i) => {
      const base = makeArchitecture().components[1];
      if (!base) throw new Error('fixture broken');
      return { ...base, id: `svc-${i}`, name: `サービス ${i}` };
    });
    const html = renderArchitectureMap(
      makeArchitecture({ components: many, dataFlows: [] }),
      makeHeatmap({ componentTotals: {} }),
    );
    expect(html).toContain('サービス 8');
    expect(html).toContain('<svg');
  });
});

describe('補助の行列（主役はあくまで構成図）', () => {
  const html = renderArchitectureMap(makeArchitecture(), makeHeatmap());

  it('行列は details で折りたたまれ、補助であることが明示される', () => {
    expect(html).toContain('<details class="gm-matrix">');
    expect(html).toContain('補助:');
    // 構成図が先、行列が後
    expect(html.indexOf('<svg')).toBeLessThan(html.indexOf('gm-matrix'));
  });

  it('basis が記号で区別される', () => {
    expect(html).toContain('●');
    expect(html).toContain('◐');
    expect(html).toContain('△');
  });
});
