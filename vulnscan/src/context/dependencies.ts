/**
 * 依存関係の抽出。
 *
 * ecosystem 名は OSV.dev の表記に合わせる（'npm', 'PyPI', 'Go', 'Maven',
 * 'RubyGems', 'Packagist', 'crates.io'）。後段で脆弱性DBに問い合わせる際、
 * ここの表記がそのままキーになる。
 */

import type { Dependency } from '../types/context.js';
import type { ManifestFile } from './walk.js';

/** バージョン指定を正規化する（前後の空白と引用符を落とす） */
function cleanVersion(version: string | undefined): string {
  if (!version) return '*';
  const trimmed = version.trim().replace(/^['"]|['"]$/g, '').trim();
  return trimmed === '' ? '*' : trimmed;
}

function isDevManifest(path: string): boolean {
  return /(?:^|\/)(?:dev|test|requirements-(?:dev|test))|(?:-dev|-test)\.txt$/.test(path);
}

/** package.json → npm */
function parsePackageJson(manifest: ManifestFile, warnings: string[]): Dependency[] {
  const out: Dependency[] = [];
  let json: unknown;
  try {
    json = JSON.parse(manifest.content);
  } catch (err) {
    warnings.push(`package.json を解釈できませんでした: ${manifest.path} (${String(err)})`);
    return out;
  }
  if (typeof json !== 'object' || json === null) return out;

  const sections: Array<[string, boolean]> = [
    ['dependencies', false],
    ['devDependencies', true],
    ['optionalDependencies', false],
    ['peerDependencies', false],
  ];

  for (const [section, dev] of sections) {
    const value = (json as Record<string, unknown>)[section];
    if (typeof value !== 'object' || value === null) continue;
    for (const [name, version] of Object.entries(value as Record<string, unknown>)) {
      out.push({
        name,
        version: cleanVersion(typeof version === 'string' ? version : undefined),
        ecosystem: 'npm',
        dev,
        manifest: manifest.path,
      });
    }
  }
  return out;
}

/** requirements.txt → PyPI */
function parseRequirements(manifest: ManifestFile): Dependency[] {
  const out: Dependency[] = [];
  const dev = isDevManifest(manifest.path);

  for (const rawLine of manifest.content.split(/\r?\n/)) {
    const line = rawLine.split('#')[0]?.trim() ?? '';
    if (line === '') continue;
    // -r other.txt / -e . / --index-url ... はパッケージではない
    if (line.startsWith('-')) continue;
    // 環境マーカー（`; python_version < "3.9"`）を落とす
    const spec = line.split(';')[0]?.trim() ?? '';
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(spec);
    if (!match?.[1]) continue;
    const version = (match[2] ?? '').replace(/^[=<>!~^\s]+/, '').trim();
    out.push({
      name: match[1],
      version: version === '' ? '*' : version,
      ecosystem: 'PyPI',
      dev,
      manifest: manifest.path,
    });
  }
  return out;
}

/**
 * pyproject.toml → PyPI
 * 完全な TOML パーサは持ち込まず、依存宣言に使われる形だけを読む。
 */
function parsePyproject(manifest: ManifestFile): Dependency[] {
  const out: Dependency[] = [];
  let section = '';
  let inArray = false;
  let arrayDev = false;

  const pushSpec = (spec: string, dev: boolean): void => {
    const cleaned = spec.replace(/^['"]|['",]+$/g, '').split(';')[0]?.trim() ?? '';
    if (cleaned === '') return;
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(cleaned);
    if (!match?.[1]) return;
    out.push({
      name: match[1],
      version: (match[2] ?? '').replace(/^[=<>!~^\s]+/, '').trim() || '*',
      ecosystem: 'PyPI',
      dev,
      manifest: manifest.path,
    });
  };

  for (const rawLine of manifest.content.split(/\r?\n/)) {
    const line = rawLine.split('#')[0]?.trim() ?? '';
    if (line === '') continue;

    if (inArray) {
      if (line.startsWith(']')) {
        inArray = false;
        continue;
      }
      for (const item of line.split(',')) pushSpec(item, arrayDev);
      continue;
    }

    const sectionMatch = /^\[([^\]]+)\]$/.exec(line);
    if (sectionMatch?.[1]) {
      section = sectionMatch[1];
      continue;
    }

    // PEP 621: dependencies = ["flask>=2.0", ...]
    const arrayStart = /^(dependencies|[\w.-]+)\s*=\s*\[(.*)$/.exec(line);
    if (arrayStart && (section === 'project' || section === 'project.optional-dependencies')) {
      const dev = section === 'project.optional-dependencies';
      const rest = arrayStart[2] ?? '';
      if (rest.includes(']')) {
        for (const item of rest.slice(0, rest.indexOf(']')).split(',')) pushSpec(item, dev);
      } else {
        inArray = true;
        arrayDev = dev;
        for (const item of rest.split(',')) pushSpec(item, dev);
      }
      continue;
    }

    // Poetry: flask = "^2.0" / flask = { version = "^2.0" }
    if (section.startsWith('tool.poetry') && section.includes('dependencies')) {
      const dev = /dev|test/.test(section);
      const kv = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+)$/.exec(line);
      if (kv?.[1] && kv[1].toLowerCase() !== 'python') {
        const rawValue = kv[2] ?? '';
        const versionInObject = /version\s*=\s*"([^"]*)"/.exec(rawValue);
        out.push({
          name: kv[1],
          version: cleanVersion(versionInObject?.[1] ?? rawValue),
          ecosystem: 'PyPI',
          dev,
          manifest: manifest.path,
        });
      }
    }
  }
  return out;
}

/** go.mod → Go */
function parseGoMod(manifest: ManifestFile): Dependency[] {
  const out: Dependency[] = [];
  let inRequireBlock = false;

  for (const rawLine of manifest.content.split(/\r?\n/)) {
    const line = rawLine.split('//')[0]?.trim() ?? '';
    if (line === '') continue;

    if (inRequireBlock) {
      if (line === ')') {
        inRequireBlock = false;
        continue;
      }
      const match = /^(\S+)\s+(\S+)/.exec(line);
      if (match?.[1] && match[2]) {
        out.push({
          name: match[1],
          version: match[2],
          ecosystem: 'Go',
          dev: false,
          manifest: manifest.path,
        });
      }
      continue;
    }

    if (/^require\s*\($/.test(line)) {
      inRequireBlock = true;
      continue;
    }
    const single = /^require\s+(\S+)\s+(\S+)/.exec(line);
    if (single?.[1] && single[2]) {
      out.push({
        name: single[1],
        version: single[2],
        ecosystem: 'Go',
        dev: false,
        manifest: manifest.path,
      });
    }
  }
  return out;
}

/** pom.xml → Maven（name は `groupId:artifactId`） */
function parsePomXml(manifest: ManifestFile): Dependency[] {
  const out: Dependency[] = [];
  const blocks = manifest.content.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? [];

  for (const block of blocks) {
    const group = /<groupId>([^<]+)<\/groupId>/.exec(block)?.[1]?.trim();
    const artifact = /<artifactId>([^<]+)<\/artifactId>/.exec(block)?.[1]?.trim();
    const version = /<version>([^<]+)<\/version>/.exec(block)?.[1]?.trim();
    const scope = /<scope>([^<]+)<\/scope>/.exec(block)?.[1]?.trim();
    if (!group || !artifact) continue;
    out.push({
      name: `${group}:${artifact}`,
      version: cleanVersion(version),
      ecosystem: 'Maven',
      dev: scope === 'test' || scope === 'provided',
      manifest: manifest.path,
    });
  }
  return out;
}

/** Gemfile → RubyGems */
function parseGemfile(manifest: ManifestFile): Dependency[] {
  const out: Dependency[] = [];
  let devDepth = 0;

  for (const rawLine of manifest.content.split(/\r?\n/)) {
    const line = rawLine.split('#')[0]?.trim() ?? '';
    if (line === '') continue;

    if (/^group\s+.*\b(?:development|test)\b.*\bdo\b/.test(line)) {
      devDepth++;
      continue;
    }
    if (devDepth > 0 && /^end\b/.test(line)) {
      devDepth--;
      continue;
    }

    const match = /^gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/.exec(line);
    if (match?.[1]) {
      out.push({
        name: match[1],
        version: cleanVersion(match[2]),
        ecosystem: 'RubyGems',
        dev: devDepth > 0,
        manifest: manifest.path,
      });
    }
  }
  return out;
}

/** composer.json → Packagist */
function parseComposerJson(manifest: ManifestFile, warnings: string[]): Dependency[] {
  const out: Dependency[] = [];
  let json: unknown;
  try {
    json = JSON.parse(manifest.content);
  } catch (err) {
    warnings.push(`composer.json を解釈できませんでした: ${manifest.path} (${String(err)})`);
    return out;
  }
  if (typeof json !== 'object' || json === null) return out;

  for (const [section, dev] of [
    ['require', false],
    ['require-dev', true],
  ] as Array<[string, boolean]>) {
    const value = (json as Record<string, unknown>)[section];
    if (typeof value !== 'object' || value === null) continue;
    for (const [name, version] of Object.entries(value as Record<string, unknown>)) {
      if (name === 'php' || name.startsWith('ext-')) continue;
      out.push({
        name,
        version: cleanVersion(typeof version === 'string' ? version : undefined),
        ecosystem: 'Packagist',
        dev,
        manifest: manifest.path,
      });
    }
  }
  return out;
}

/** Cargo.toml → crates.io / Pipfile → PyPI（どちらも TOML の単純なセクション） */
function parseTomlSections(
  manifest: ManifestFile,
  ecosystem: string,
  sectionIsDev: (section: string) => boolean | null,
): Dependency[] {
  const out: Dependency[] = [];
  let section = '';

  for (const rawLine of manifest.content.split(/\r?\n/)) {
    const line = rawLine.split('#')[0]?.trim() ?? '';
    if (line === '') continue;

    const sectionMatch = /^\[([^\]]+)\]$/.exec(line);
    if (sectionMatch?.[1]) {
      section = sectionMatch[1];
      continue;
    }

    const dev = sectionIsDev(section);
    if (dev === null) continue;

    const kv = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+)$/.exec(line);
    if (!kv?.[1]) continue;
    const rawValue = kv[2] ?? '';
    const versionInObject = /version\s*=\s*"([^"]*)"/.exec(rawValue);
    out.push({
      name: kv[1],
      version: cleanVersion(versionInObject?.[1] ?? rawValue),
      ecosystem,
      dev,
      manifest: manifest.path,
    });
  }
  return out;
}

/**
 * 全マニフェストから依存関係を抽出する。個々の解釈失敗は warnings に積む。
 */
export function collectDependencies(
  manifests: readonly ManifestFile[],
  warnings: string[],
): Dependency[] {
  const out: Dependency[] = [];

  for (const manifest of manifests) {
    const base = manifest.path.slice(manifest.path.lastIndexOf('/') + 1).toLowerCase();
    try {
      if (base === 'package.json') out.push(...parsePackageJson(manifest, warnings));
      else if (/^requirements[\w.-]*\.txt$/.test(base)) out.push(...parseRequirements(manifest));
      else if (base === 'pyproject.toml') out.push(...parsePyproject(manifest));
      else if (base === 'go.mod') out.push(...parseGoMod(manifest));
      else if (base === 'pom.xml') out.push(...parsePomXml(manifest));
      else if (base === 'gemfile') out.push(...parseGemfile(manifest));
      else if (base === 'composer.json') out.push(...parseComposerJson(manifest, warnings));
      else if (base === 'cargo.toml') {
        out.push(
          ...parseTomlSections(manifest, 'crates.io', (section) => {
            if (section === 'dependencies') return false;
            if (section === 'dev-dependencies' || section === 'build-dependencies') return true;
            return null;
          }),
        );
      } else if (base === 'pipfile') {
        out.push(
          ...parseTomlSections(manifest, 'PyPI', (section) => {
            if (section === 'packages') return false;
            if (section === 'dev-packages') return true;
            return null;
          }),
        );
      }
    } catch (err) {
      warnings.push(`依存関係の抽出に失敗しました: ${manifest.path} (${String(err)})`);
    }
  }

  // 同一マニフェスト内の重複を除去（dev 宣言が両方にある場合は本番側を優先）
  const byKey = new Map<string, Dependency>();
  for (const dep of out) {
    const key = `${dep.ecosystem}|${dep.name}|${dep.manifest}`;
    const existing = byKey.get(key);
    if (!existing || (existing.dev && !dep.dev)) byKey.set(key, dep);
  }

  return [...byKey.values()].sort(
    (a, b) => a.ecosystem.localeCompare(b.ecosystem) || a.name.localeCompare(b.name),
  );
}
