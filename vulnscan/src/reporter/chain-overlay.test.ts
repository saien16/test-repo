/**
 * 構成図への攻撃チェーンの重ね合わせ。
 *
 * ヒートマップは「どこが危ないか」を面で示すが、チェーンは
 * 「どこから入って、どこを通って、何に届くか」という順序を持つ。
 * ここで固定したいのは次の3点:
 *   - 経路の順序が step 順に解決されること（面の情報から順序を作り直せている）
 *   - 図に引けなかった経路を黙って捨てないこと
 *   - 同じ入力からは同じ図が出ること（決定的）
 */

import { describe, expect, it } from 'vitest';
import { inferred } from '../types/evidence.js';
import type { HeatmapCell, VulnerabilityHeatmap } from '../types/heatmap.js';
import { makeArchitecture, makeChain, makeHeatmap } from './fixtures.js';
import { renderArchitectureMap } from './formatters/architecture-map.js';

/** 指定の finding を指定の構成要素へ載せたセルを作る */
function cell(componentId: string, categoryId: string, findingIds: string[]): HeatmapCell {
  return {
    componentId,
    categoryId,
    observedRisk: findingIds.length > 0 ? 70 : 0,
    findingIds,
    chainIds: findingIds.length > 0 ? ['ch-1'] : [],
    inferredRisk: inferred(40, { confidence: 0.5, inferredBy: 'catalog', reasoning: 'test' }),
    basis: findingIds.length > 0 ? 'both' : 'none',
  };
}

/** f-1 を api、f-2 を db に置く（＝2構成要素をまたぐ経路になる） */
function spanningHeatmap(): VulnerabilityHeatmap {
  const base = makeHeatmap();
  return {
    ...base,
    cells: [
      cell('api', 'injection', ['f-1']),
      cell('db', 'authz', ['f-2']),
      cell('web', 'crypto', []),
    ],
  };
}

describe('攻撃チェーンの重ね合わせ', () => {
  it('構成要素をまたぐ経路は線として引かれる', () => {
    const html = renderArchitectureMap(makeArchitecture(), spanningHeatmap(), [makeChain()]);
    expect(html).toContain('gm-chain-core');
    expect(html).toContain('gm-chain-casing');
    // 通過順の番号が 1, 2 と振られる
    expect(html).toContain('gm-chain-dot-label');
    expect(html).toContain('図に重ねた攻撃経路');
    expect(html).toContain('SQLインジェクション経由で認証情報を奪取し横展開');
  });

  it('矢先マーカーを定義し、経路に適用する（向きを線だけに頼らない）', () => {
    const html = renderArchitectureMap(makeArchitecture(), spanningHeatmap(), [makeChain()]);
    // データフロー用の gm-arrow とは別IDであること（同じIDだと後勝ちで衝突する）
    expect(html).toContain('id="gm-chain-arrow"');
    expect(html).toContain('marker-end="url(#gm-chain-arrow)"');
  });

  it('チョークポイントの構成要素に印を付ける', () => {
    const html = renderArchitectureMap(makeArchitecture(), spanningHeatmap(), [makeChain()]);
    expect(html).toContain('gm-choke-ring');
    expect(html).toContain('チョークポイント');
  });

  it('経路は最前面（ノードより後ろに出力）に引く', () => {
    const html = renderArchitectureMap(makeArchitecture(), spanningHeatmap(), [makeChain()]);
    // 塗りに隠れないよう、ノードより後に描かれていること
    expect(html.indexOf('gm-node-fill')).toBeLessThan(html.indexOf('gm-chain-core'));
  });

  it('1つの構成要素に収まる経路は引かず、理由つきで一覧に残す', () => {
    // 既定フィクスチャは f-1 も f-2 も api にあるため1点に潰れる
    const html = renderArchitectureMap(makeArchitecture(), makeHeatmap(), [makeChain()]);
    // 凡例ではなく、図中の経路グループが無いことで判定する
    expect(html).not.toContain('class="gm-chain gm-chain-0"');
    expect(html).toContain('図には引けていません');
  });

  it('上限を超えた経路は省略し、省略した事実を書く', () => {
    const chains = [0, 1, 2, 3, 4].map((i) =>
      makeChain({ id: `ch-${i}`, title: `経路${i}`, priorityScore: 90 - i }),
    );
    const html = renderArchitectureMap(makeArchitecture(), spanningHeatmap(), chains);
    expect(html).toContain('省略しています');
  });

  it('優先度の高い経路から描く', () => {
    const low = makeChain({ id: 'ch-low', title: '低優先の経路', priorityScore: 10 });
    const high = makeChain({ id: 'ch-high', title: '高優先の経路', priorityScore: 99 });
    const html = renderArchitectureMap(makeArchitecture(), spanningHeatmap(), [low, high]);
    expect(html.indexOf('高優先の経路')).toBeLessThan(html.indexOf('低優先の経路'));
  });

  it('チェーンを渡さなければ従来どおりの図（節ごと出ない）', () => {
    const html = renderArchitectureMap(makeArchitecture(), spanningHeatmap());
    expect(html).not.toContain('class="gm-chain gm-chain-0"');
    expect(html).not.toContain('図に重ねた攻撃経路');
    // 図に出ていない記号を凡例で説明しない
    expect(html).not.toContain('番号つきの線 ＝ 攻撃経路');
    // 図そのものは従来どおり出る
    expect(html).toContain('gm-svg');
  });

  it('同じ入力からは同じ図が出る（決定的）', () => {
    const args = [makeArchitecture(), spanningHeatmap(), [makeChain()]] as const;
    expect(renderArchitectureMap(...args)).toBe(renderArchitectureMap(...args));
  });

  it('存在しない構成要素を指すステップがあっても壊れない', () => {
    const base = makeHeatmap();
    const heat: VulnerabilityHeatmap = {
      ...base,
      cells: [cell('api', 'injection', ['f-1']), cell('存在しない', 'authz', ['f-2'])],
    };
    const html = renderArchitectureMap(makeArchitecture(), heat, [makeChain()]);
    expect(html).toContain('gm-svg');
    expect(html).not.toContain('NaN');
  });
});
