/**
 * 事実収集の取りまとめ。
 *
 * 探索 → 種別ごとのパーサ呼び出し → FactSet 化。
 * 個々のパーサは例外を投げない設計だが、未信頼リポジトリを相手にするため
 * ここでも try/catch で囲み、失敗はすべて warnings に落とす。
 */

import type { ScanContext } from '../types/context.js';
import {
  looksLikeKubernetes,
  parseCompose,
  parseDockerfile,
  parseHelmChart,
  parseKubernetes,
} from './containers.js';
import { discoverManifests, type LoadedManifest, type RepoFileSystem } from './discover.js';
import {
  citationFor,
  emptyOutput,
  type FactSet,
  mergeOutput,
  type ParseOutput,
} from './facts.js';
import {
  looksLikeCloudFormation,
  parseCiWorkflow,
  parseCloudFormation,
  parseNetlify,
  parsePaasManifest,
  parseProcfile,
  parsePulumi,
  parseServerless,
  parseTerraform,
  parseVercel,
} from './platforms.js';
import {
  signalsFromDependencies,
  signalsFromEntryPoints,
  signalsFromEnvironment,
} from './signals.js';

/** package.json / go.mod からランタイムの手掛かりを拾う */
export function parsePackageManifest(path: string, content: string): ParseOutput {
  const out = emptyOutput();
  const base = path.toLowerCase();

  if (base.endsWith('package.json')) {
    try {
      const json: unknown = JSON.parse(content);
      if (typeof json === 'object' && json !== null) {
        const record = json as Record<string, unknown>;
        const engines = record['engines'];
        if (typeof engines === 'object' && engines !== null) {
          const node = (engines as Record<string, unknown>)['node'];
          if (typeof node === 'string') {
            out.facts.push({
              kind: 'platform.manifest',
              value: `Node.js ${node}`,
              citation: citationFor(path, content, node),
              detail: { field: 'engines.node', runtime: `Node.js ${node}` },
            });
          }
        }
        const scripts = record['scripts'];
        if (typeof scripts === 'object' && scripts !== null) {
          const start = (scripts as Record<string, unknown>)['start'];
          if (typeof start === 'string') {
            out.facts.push({
              kind: 'platform.process',
              value: `npm start: ${start}`,
              citation: citationFor(path, content, start),
              detail: { kind: 'npm-script' },
            });
          }
        }
        if (typeof record['bin'] === 'object' || typeof record['bin'] === 'string') {
          out.facts.push({
            kind: 'platform.process',
            value: 'package.json の bin 定義',
            citation: citationFor(path, content, '"bin"'),
            detail: { kind: 'npm-bin' },
          });
        }
      }
    } catch (err) {
      out.warnings.push(`package.json を解釈できませんでした: ${path} (${String(err)})`);
    }
    return out;
  }

  if (base.endsWith('go.mod')) {
    const m = /^go\s+(\d+\.\d+(?:\.\d+)?)/m.exec(content);
    if (m !== null) {
      out.facts.push({
        kind: 'platform.manifest',
        value: `Go ${m[1] ?? ''}`,
        citation: citationFor(path, content, m[0]),
        detail: { field: 'go.mod', runtime: `Go ${m[1] ?? ''}` },
      });
    }
  }
  return out;
}

/** 1 マニフェストを種別に応じて解析する。解析しなかった場合は null */
function parseManifest(manifest: LoadedManifest): ParseOutput | null {
  const { path, content, type } = manifest;
  switch (type) {
    case 'dockerfile':
      return parseDockerfile(path, content);
    case 'compose':
      return parseCompose(path, content);
    case 'helm-chart':
      return parseHelmChart(path, content);
    case 'serverless':
      return parseServerless(path, content);
    case 'vercel':
      return parseVercel(path, content);
    case 'netlify':
      return parseNetlify(path, content);
    case 'procfile':
      return parseProcfile(path, content);
    case 'paas-candidate':
      return parsePaasManifest(path, content);
    case 'terraform':
      return parseTerraform(path, content);
    case 'pulumi':
      return parsePulumi(path, content);
    case 'github-workflow':
      return parseCiWorkflow(path, content, 'github-actions');
    case 'gitlab-ci':
      return parseCiWorkflow(path, content, 'gitlab-ci');
    case 'circleci':
      return parseCiWorkflow(path, content, 'circleci');
    case 'jenkins':
      return parseCiWorkflow(path, content, 'jenkins');
    case 'package-manifest':
      return parsePackageManifest(path, content);
    case 'dotenv':
      // 中身の値は秘密情報なので読まない。存在だけを事実にする
      return {
        facts: [
          {
            kind: 'secrets.mechanism',
            value: 'env-file',
            citation: { file: path },
          },
        ],
        services: [],
        warnings: [],
      };
    case 'cloudformation-candidate':
      if (looksLikeCloudFormation(content)) return parseCloudFormation(path, content);
      if (looksLikeKubernetes(content)) return parseKubernetes(path, content);
      return null;
    case 'kubernetes-candidate':
      if (looksLikeKubernetes(content)) return parseKubernetes(path, content);
      if (looksLikeCloudFormation(content)) return parseCloudFormation(path, content);
      return null;
    default:
      return null;
  }
}

export interface CollectResult extends FactSet {
  /** 引用の実在検証に使う既知パス集合 */
  knownPaths: Set<string>;
  /** 読み込み済みファイルの内容 */
  contents: Map<string, string>;
}

/** ヒューリスティックな事実収集を一括で行う */
export async function collectFacts(
  ctx: ScanContext,
  fs: RepoFileSystem,
): Promise<CollectResult> {
  const accumulated = emptyOutput();
  const inspected: string[] = [];

  const discovery = await discoverManifests(ctx, fs);
  accumulated.warnings.push(...discovery.warnings);

  for (const manifest of discovery.manifests) {
    let output: ParseOutput | null = null;
    try {
      output = parseManifest(manifest);
    } catch (err) {
      // パーサ自体の想定外の失敗もスキャンを止めない
      accumulated.warnings.push(
        `設定ファイルの解析に失敗しました: ${manifest.path} (${String(err)})`,
      );
      continue;
    }
    if (output === null) continue;
    mergeOutput(accumulated, output);
    inspected.push(manifest.path);
  }

  try {
    mergeOutput(accumulated, signalsFromDependencies(ctx, discovery.contents));
  } catch (err) {
    accumulated.warnings.push(`依存関係からのシグナル収集に失敗しました: ${String(err)}`);
  }

  try {
    mergeOutput(accumulated, signalsFromEntryPoints(ctx));
  } catch (err) {
    accumulated.warnings.push(`エントリポイントの取り込みに失敗しました: ${String(err)}`);
  }

  try {
    mergeOutput(accumulated, await signalsFromEnvironment(ctx, fs, discovery.contents));
  } catch (err) {
    accumulated.warnings.push(`環境変数の走査に失敗しました: ${String(err)}`);
  }

  return {
    facts: accumulated.facts,
    services: accumulated.services,
    inspected,
    warnings: accumulated.warnings,
    knownPaths: discovery.knownPaths,
    contents: discovery.contents,
  };
}
