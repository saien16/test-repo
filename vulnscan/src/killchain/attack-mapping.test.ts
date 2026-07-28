import { describe, expect, it } from 'vitest';
import {
  ATTACK_TACTICS,
  CWE_TECHNIQUE_MAP,
  KILL_CHAIN_PHASES,
  LENS_TECHNIQUE_MAP,
  OWASP_TECHNIQUE_MAP,
  TACTIC_DEFAULT_PHASE,
  TECHNIQUE_CATALOG,
  isValidPhase,
  isValidTactic,
  lookupTechnique,
  mapFindingToTechnique,
  normalizeCwe,
  normalizeTechniqueId,
  reconcileStep,
  reconcileSteps,
  type RawChainStep,
} from './attack-mapping.js';

describe('normalizeCwe', () => {
  it('表記ゆれを CWE-<n> に揃える', () => {
    expect(normalizeCwe('CWE-89')).toBe('CWE-89');
    expect(normalizeCwe('cwe89')).toBe('CWE-89');
    expect(normalizeCwe('CWE_089')).toBe('CWE-89');
    expect(normalizeCwe('918')).toBe('CWE-918');
  });

  it('数字が無ければ null', () => {
    expect(normalizeCwe('unknown')).toBeNull();
    expect(normalizeCwe(undefined)).toBeNull();
  });
});

describe('normalizeTechniqueId', () => {
  it('大小文字とサブテクニックを扱う', () => {
    expect(normalizeTechniqueId('t1190')).toBe('T1190');
    expect(normalizeTechniqueId('T1552.005')).toBe('T1552.005');
    expect(normalizeTechniqueId('T1190 - Exploit Public-Facing Application')).toBe('T1190');
  });

  it('不正な形式は null', () => {
    expect(normalizeTechniqueId('1190')).toBeNull();
    expect(normalizeTechniqueId('TA0001')).toBeNull();
    expect(normalizeTechniqueId('')).toBeNull();
    expect(normalizeTechniqueId(null)).toBeNull();
  });
});

describe('lookupTechnique', () => {
  it('カタログにあるIDを引ける', () => {
    expect(lookupTechnique('T1190')?.tactic).toBe('initial-access');
    expect(lookupTechnique('T1059')?.tactic).toBe('execution');
  });

  it('カタログに無いサブテクニックは親に縮退しつつIDを保つ', () => {
    const info = lookupTechnique('T1059.003');
    expect(info?.id).toBe('T1059.003');
    expect(info?.tactic).toBe('execution');
  });

  it('存在しないIDは null（幻覚とみなす）', () => {
    expect(lookupTechnique('T9999')).toBeNull();
  });
});

describe('mapFindingToTechnique', () => {
  it('CWE から引く', () => {
    expect(mapFindingToTechnique({ cwe: 'CWE-78' })?.id).toBe('T1059.004');
    expect(mapFindingToTechnique({ cwe: 'CWE-918' })?.id).toBe('T1552.005');
    expect(mapFindingToTechnique({ cwe: 'CWE-798' })?.id).toBe('T1552.001');
  });

  it('CWE が未知なら OWASP カテゴリにフォールバックする', () => {
    expect(mapFindingToTechnique({ cwe: 'CWE-9999', category: 'A03:2021-Injection' })?.id).toBe(
      'T1190',
    );
  });

  it('カテゴリも無ければレンズにフォールバックする', () => {
    expect(mapFindingToTechnique({ cwe: 'CWE-9999', lens: 'dependency' })?.id).toBe('T1195.001');
  });

  it('手掛かりが無ければ null', () => {
    expect(mapFindingToTechnique({})).toBeNull();
    expect(mapFindingToTechnique(null)).toBeNull();
  });
});

describe('対応表の整合性', () => {
  it('CWE 対応表の値はすべてカタログで解決できる', () => {
    for (const [cwe, id] of Object.entries(CWE_TECHNIQUE_MAP)) {
      expect(lookupTechnique(id), `${cwe} → ${id}`).not.toBeNull();
    }
  });

  it('OWASP / レンズ対応表の値もカタログで解決できる', () => {
    for (const id of Object.values(OWASP_TECHNIQUE_MAP)) expect(lookupTechnique(id)).not.toBeNull();
    for (const id of Object.values(LENS_TECHNIQUE_MAP)) expect(lookupTechnique(id)).not.toBeNull();
  });

  it('カタログの戦術・段階は型の許す値のみ', () => {
    for (const info of Object.values(TECHNIQUE_CATALOG)) {
      expect(ATTACK_TACTICS).toContain(info.tactic);
      expect(KILL_CHAIN_PHASES).toContain(info.phase);
      expect(normalizeTechniqueId(info.id)).toBe(info.id);
    }
  });

  it('全戦術に既定のキルチェーン段階がある', () => {
    for (const t of ATTACK_TACTICS) {
      expect(KILL_CHAIN_PHASES).toContain(TACTIC_DEFAULT_PHASE[t]);
    }
  });
});

describe('isValidPhase / isValidTactic', () => {
  it('型に定義された値のみ通す', () => {
    expect(isValidPhase('exploitation')).toBe(true);
    expect(isValidPhase('pwning')).toBe(false);
    expect(isValidTactic('credential-access')).toBe(true);
    expect(isValidTactic('resource-development')).toBe(false);
  });
});

describe('reconcileStep', () => {
  const finding = { id: 'F1', cwe: 'CWE-918', category: 'A10:2021-SSRF', lens: 'deserialization-ssrf' as const };

  it('妥当な出力はそのまま通す', () => {
    const raw: RawChainStep = {
      findingId: 'F1',
      killChainPhase: 'exploitation',
      attackTactic: 'credential-access',
      attackTechnique: 'T1552.005',
      description: 'メタデータAPIから資格情報を取得する',
      preconditions: ['SSRF が外部宛先を制限していない'],
    };
    const { step, corrections } = reconcileStep(raw, finding, 2);
    expect(step.attackTechnique).toBe('T1552.005');
    expect(step.attackTactic).toBe('credential-access');
    expect(step.killChainPhase).toBe('exploitation');
    expect(step.order).toBe(2);
    expect(corrections).toEqual([]);
  });

  it('幻覚のテクニックIDを CWE 対応表で置き換える', () => {
    const { step, corrections } = reconcileStep(
      { attackTechnique: 'T9999', attackTactic: 'credential-access', killChainPhase: 'exploitation', description: 'x' },
      finding,
      1,
    );
    expect(step.attackTechnique).toBe('T1552.005');
    expect(corrections.join()).toContain('T9999');
  });

  it('不正な戦術をテクニックの正準値で補正する', () => {
    const { step, corrections } = reconcileStep(
      { attackTechnique: 'T1059', attackTactic: 'pwnage', killChainPhase: 'exploitation', description: 'x' },
      null,
      1,
    );
    expect(step.attackTactic).toBe('execution');
    expect(corrections.join()).toContain('pwnage');
  });

  it('不正なキルチェーン段階を戦術から補完する', () => {
    const { step } = reconcileStep(
      { attackTactic: 'persistence', killChainPhase: 'なんとか段階', attackTechnique: null, description: 'x' },
      null,
      1,
    );
    expect(step.killChainPhase).toBe(TACTIC_DEFAULT_PHASE.persistence);
  });

  it('手掛かりが全く無い先頭ステップは initial-access になる', () => {
    const { step } = reconcileStep({}, null, 1);
    expect(step.attackTactic).toBe('initial-access');
    expect(step.attackTechnique).toBeUndefined();
    expect(step.description).not.toBe('');
  });

  it('空文字や null の前提条件を落とす', () => {
    const { step } = reconcileStep(
      { preconditions: ['ok', '', null, '  '], attackTactic: 'execution', killChainPhase: 'exploitation' },
      null,
      1,
    );
    expect(step.preconditions).toEqual(['ok']);
  });
});

describe('reconcileSteps', () => {
  const findings = new Map([
    ['F1', { id: 'F1', cwe: 'CWE-918' }],
    ['F2', { id: 'F2', cwe: 'CWE-78' }],
  ]);

  it('存在しない findingId を null に落とす', () => {
    const { steps, corrections } = reconcileSteps(
      [
        { findingId: 'F1', attackTactic: 'credential-access', killChainPhase: 'exploitation', description: 'a' },
        { findingId: 'DOES-NOT-EXIST', attackTactic: 'execution', killChainPhase: 'exploitation', description: 'b' },
      ],
      findings,
    );
    expect(steps[0]?.findingId).toBe('F1');
    expect(steps[1]?.findingId).toBeNull();
    expect(corrections.join()).toContain('DOES-NOT-EXIST');
  });

  it('order を 1 から振り直す', () => {
    const { steps } = reconcileSteps(
      [
        { findingId: 'F2', attackTactic: 'execution', killChainPhase: 'exploitation', description: 'a' },
        { findingId: 'F1', attackTactic: 'credential-access', killChainPhase: 'exploitation', description: 'b' },
      ],
      findings,
    );
    expect(steps.map((s) => s.order)).toEqual([1, 2]);
  });

  it('同一 Finding × 同一テクニックの重複ステップを除去する', () => {
    const dup: RawChainStep = {
      findingId: 'F1',
      attackTactic: 'credential-access',
      killChainPhase: 'exploitation',
      attackTechnique: 'T1552.005',
      description: 'a',
    };
    const { steps, corrections } = reconcileSteps([dup, { ...dup }], findings);
    expect(steps).toHaveLength(1);
    expect(corrections.join()).toContain('重複');
  });

  it('findingId が null のステップは重複除去の対象外（推論ステップは複数あってよい）', () => {
    const s: RawChainStep = {
      findingId: null,
      attackTactic: 'lateral-movement',
      killChainPhase: 'exploitation',
      attackTechnique: 'T1021',
      description: 'a',
    };
    const { steps } = reconcileSteps([s, { ...s }], findings);
    expect(steps).toHaveLength(2);
  });

  it('空入力なら空出力', () => {
    expect(reconcileSteps([], findings).steps).toEqual([]);
  });
});
