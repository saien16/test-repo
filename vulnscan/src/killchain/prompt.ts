/**
 * キルチェーン推論用のプロンプト構築。
 *
 * system は候補グループによらず不変にしてプロンプトキャッシュを効かせ、
 * 可変部分（Finding 詳細・呼び出しパス）はすべて user 側に置く。
 */

import type { ScanContext, TrustBoundary } from '../types/context.js';
import type { Finding } from '../types/finding.js';
import { ATTACK_TACTICS, KILL_CHAIN_PHASES, TECHNIQUE_CATALOG } from './attack-mapping.js';
import type { CandidateGroup } from './grouping.js';
import { normalizePath } from './reachability.js';

const MAX_EVIDENCE_CHARS = 600;
const MAX_FLOW_STEPS = 8;
const MAX_PATH_NODES = 12;
const MAX_TRUST_BOUNDARIES = 20;

function truncate(text: string, limit: number): string {
  const s = String(text ?? '').trim();
  return s.length <= limit ? s : `${s.slice(0, limit)}…（以下省略）`;
}

/** 候補グループによらず不変な system プロンプト（キャッシュ対象） */
export function buildSystemPrompt(): string {
  const techniques = Object.values(TECHNIQUE_CATALOG)
    .map((t) => `- ${t.id}: ${t.name} (${t.tactic})`)
    .join('\n');

  return [
    'あなたは攻撃シナリオ分析とレッドチームの専門家です。',
    '静的解析で検出された複数の脆弱性(Finding)が与えられます。',
    'それらが「単独の指摘」ではなく「一連の攻撃として繋がるか」を判定し、',
    'source(侵入点) → 中間ステップ(権限昇格・資格情報奪取・横展開) → sink(最終影響)',
    'という攻撃シナリオを構築してください。',
    '',
    '# 判断基準',
    '- 提示された「到達可能性の根拠（呼び出しパス）」を最重視すること。',
    '  呼び出しパスが示されていない Finding を連鎖の必須ステップに置く場合は、',
    '  preconditions にその不確実性を明記すること。',
    '- 無理に連鎖させないこと。繋がらないと判断したら chainViable=false か空配列を返す。',
    '- 1グループから複数の異なるシナリオが成立する場合は最大3件まで返してよい。',
    '- steps は攻撃の時系列順に並べること。',
    '- findingId には提示された id のみを使うこと。存在しない id を作らないこと。',
    '  Finding に紐づかない推論ステップ（例: 奪取した資格情報での横展開）は findingId を null にする。',
    '',
    '# キルチェーン段階（killChainPhase）',
    KILL_CHAIN_PHASES.map((p) => `- ${p}`).join('\n'),
    '',
    '# ATT&CK 戦術（attackTactic）',
    ATTACK_TACTICS.map((t) => `- ${t}`).join('\n'),
    '',
    '# ATT&CK テクニック（attackTechnique に使う候補）',
    '以下から最も適切なものを選ぶこと。該当が無ければ実在する別のIDを使ってよいが、',
    '自信が無ければ null にすること（後段でCWE対応表から補完される）。',
    techniques,
    '',
    '# 出力',
    '- すべての自然言語フィールドは日本語で書くこと。',
    '- 実際の攻撃コード（エクスプロイト）は書かないこと。防御側が理解できる抽象度に留めること。',
  ].join('\n');
}

function formatFinding(finding: Finding, repoRoot?: string): string {
  const loc = finding.location;
  const lines: string[] = [
    `## ${finding.id}`,
    `- タイトル: ${finding.title}`,
    `- CWE / カテゴリ: ${finding.cwe} / ${finding.category}`,
    `- 深刻度: ${finding.severity} (CVSS ${finding.cvss?.baseScore ?? '不明'} ${finding.cvss?.vector ?? ''})`,
    `- 確信度: ${finding.confidence}`,
    `- 位置: ${normalizePath(loc?.file ?? '不明', repoRoot)}:${loc?.startLine ?? '?'}-${loc?.endLine ?? '?'}`,
    `- レンズ: ${finding.lens}`,
  ];
  if (finding.cve !== undefined) lines.push(`- CVE: ${finding.cve}`);
  if (finding.affectedPackage !== undefined) {
    const p = finding.affectedPackage;
    lines.push(
      `- 依存パッケージ: ${p.name}@${p.version} (${p.ecosystem})` +
        (p.fixedVersion !== undefined ? ` 修正版 ${p.fixedVersion}` : ''),
    );
  }
  lines.push(`- 理由: ${truncate(finding.reasoning, 400)}`);
  lines.push(`- 修正方針: ${truncate(finding.remediation, 240)}`);
  lines.push(`- 該当コード:\n\`\`\`\n${truncate(finding.evidence, MAX_EVIDENCE_CHARS)}\n\`\`\``);

  const flow = Array.isArray(finding.dataFlow) ? finding.dataFlow.slice(0, MAX_FLOW_STEPS) : [];
  if (flow.length > 0) {
    lines.push('- データフロー:');
    for (const s of flow) {
      lines.push(
        `  - [${s.role}] ${normalizePath(s.file, repoRoot)}:${s.line} ${truncate(s.description, 120)}`,
      );
    }
  } else {
    lines.push('- データフロー: 未証明（source→sink の根拠なし）');
  }
  return lines.join('\n');
}

function formatReachability(group: CandidateGroup): string {
  const lines: string[] = [];
  for (const e of group.evidence) {
    if (e.reachable) {
      const path = e.path.slice(0, MAX_PATH_NODES);
      const suffix = e.path.length > MAX_PATH_NODES ? ' → …' : '';
      lines.push(
        `- ${e.findingId}: 到達可能（${e.depth}ホップ, 経路確信度 ${e.minEdgeConfidence.toFixed(2)}）\n` +
          `  経路: ${path.join(' → ')}${suffix}`,
      );
    } else if (e.sameFileOnly) {
      lines.push(
        `- ${e.findingId}: 呼び出しグラフ上は未接続。ただしエントリポイントと同一ファイル（弱い根拠）`,
      );
    } else {
      lines.push(`- ${e.findingId}: 呼び出しグラフ上は到達性を証明できていない`);
    }
  }
  return lines.join('\n');
}

function formatTrustBoundaries(group: CandidateGroup, ctx: ScanContext): string {
  const files = new Set<string>();
  for (const e of group.evidence) {
    const sym = e.symbolId;
    if (sym !== null) {
      const idx = sym.lastIndexOf(':');
      if (idx > 0) files.add(normalizePath(sym.slice(0, idx), ctx.repoRoot));
    }
  }
  if (group.entryPoint !== null) files.add(normalizePath(group.entryPoint.file, ctx.repoRoot));

  const related: TrustBoundary[] = (ctx.trustBoundaries ?? []).filter((b) =>
    files.has(normalizePath(b.file, ctx.repoRoot)),
  );
  if (related.length === 0) return '（関連する信頼境界の記録なし）';
  return related
    .slice(0, MAX_TRUST_BOUNDARIES)
    .map(
      (b) =>
        `- [${b.type}/${b.category}] ${normalizePath(b.file, ctx.repoRoot)}:${b.line} ${b.expression}`,
    )
    .join('\n');
}

/** 候補グループ 1 件分の user プロンプト */
export function buildUserPrompt(
  group: CandidateGroup,
  findings: readonly Finding[],
  ctx: ScanContext,
): string {
  const repoRoot = ctx?.repoRoot;
  const byId = new Map(findings.map((f) => [f.id, f]));
  const members = group.findingIds
    .map((id) => byId.get(id))
    .filter((f): f is Finding => f !== undefined);

  const ep = group.entryPoint;
  const epLines =
    ep === null
      ? '（エントリポイントを特定できていない。データフローの連結のみが根拠）'
      : [
          `- 種別: ${ep.kind}`,
          `- 識別子: ${ep.identifier}`,
          `- 位置: ${normalizePath(ep.file, repoRoot)}:${ep.line}`,
          ep.metadata === undefined
            ? null
            : `- 補足: ${Object.entries(ep.metadata)
                .map(([k, v]) => `${k}=${v}`)
                .join(', ')}`,
        ]
          .filter((l): l is string => l !== null)
          .join('\n');

  const frameworks = (ctx?.frameworks ?? []).map((f) => f.name).join(', ') || '不明';
  const languages = (ctx?.languages ?? []).map((l) => l.name).join(', ') || '不明';

  const kindLabel: Record<CandidateGroup['kind'], string> = {
    'entry-point': '同一エントリポイントから到達可能な Finding 群',
    'data-flow': 'データフローが繋がる Finding 群',
    standalone: '単独で致命的な Finding（連鎖を待たず成立しうる）',
  };

  return [
    '# 対象リポジトリ',
    `- 言語: ${languages}`,
    `- フレームワーク: ${frameworks}`,
    '',
    '# 候補グループ',
    `- 種別: ${kindLabel[group.kind]}`,
    `- 露出度（機械算出 0..1）: ${group.exposure.toFixed(2)}`,
    `- 到達性証明済みの割合: ${(group.reachabilityRatio * 100).toFixed(0)}%`,
    '',
    '# エントリポイント',
    epLines,
    '',
    '# 到達可能性の根拠（呼び出しグラフ上の経路）',
    formatReachability(group),
    '',
    '# 信頼境界（source / sink）',
    formatTrustBoundaries(group, ctx),
    '',
    '# Finding 一覧',
    `使用可能な findingId: ${members.map((f) => f.id).join(', ')}`,
    '',
    members.map((f) => formatFinding(f, repoRoot)).join('\n\n'),
    '',
    '# 指示',
    'これらが一連の攻撃として繋がるかを判定し、繋がるならシナリオを構築してください。',
    'entryPoint には上記のエントリポイント識別子をそのまま使ってください。',
  ].join('\n');
}
