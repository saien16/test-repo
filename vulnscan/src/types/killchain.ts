/**
 * ④ キルチェーン分析のデータモデル。
 */

/** サイバーキルチェーン段階 */
export type KillChainPhase =
  | 'reconnaissance'
  | 'weaponization'
  | 'delivery'
  | 'exploitation'
  | 'installation'
  | 'command-and-control'
  | 'actions-on-objectives';

/** MITRE ATT&CK 戦術 */
export type AttackTactic =
  | 'initial-access'
  | 'execution'
  | 'persistence'
  | 'privilege-escalation'
  | 'defense-evasion'
  | 'credential-access'
  | 'discovery'
  | 'lateral-movement'
  | 'collection'
  | 'exfiltration'
  | 'impact';

export interface ChainStep {
  order: number;
  /** 関連する Finding の id。単独Findingに紐づかない推論ステップなら null */
  findingId: string | null;
  killChainPhase: KillChainPhase;
  attackTactic: AttackTactic;
  /** MITRE ATT&CK テクニックID 例: 'T1190' */
  attackTechnique?: string;
  /** このステップで攻撃者が何を達成するか */
  description: string;
  /** 成立の前提条件 */
  preconditions: string[];
}

export interface AttackChain {
  id: string;
  /** 例: 'SSRF経由でクラウド資格情報を奪取し横展開' */
  title: string;
  /** 攻撃の起点（エントリポイント識別子） */
  entryPoint: string;
  steps: ChainStep[];
  /** 最終的なビジネス影響 */
  impact: string;
  likelihood: 'high' | 'medium' | 'low';
  /** 連鎖を考慮した総合優先度 0..100 */
  priorityScore: number;
  /** 連鎖を断ち切るのに最も効果的な対策 */
  chokePoint: {
    findingId: string;
    rationale: string;
  } | null;
  /** LLMの推論根拠 */
  reasoning: string;
}
