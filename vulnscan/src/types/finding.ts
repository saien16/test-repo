/**
 * ② ソースコード分析 と ③ 脆弱性情報管理 のデータモデル。
 */

import type { Severity } from './context.js';

export type { Severity };

/** source → sink へのデータフロー1ステップ */
export interface DataFlowStep {
  file: string;
  line: number;
  /** 該当コード片 */
  code: string;
  /** このステップの役割 */
  role: 'source' | 'propagation' | 'sanitizer' | 'sink';
  description: string;
}

/** 分析レンズ（観点）の識別子 */
export type LensId =
  | 'injection'
  | 'authz'
  | 'crypto-secrets'
  | 'deserialization-ssrf'
  | 'web-output'
  | 'dependency';

/** ②の生出力。LLMが構造化出力で返す形。 */
export interface RawFinding {
  /** 例: 'CWE-89' */
  cwe: string;
  /** OWASP Top 10 カテゴリ 例: 'A03:2021-Injection' */
  category: string;
  title: string;
  severity: Severity;
  /** 自己検証後の確信度 0..1 */
  confidence: number;
  location: {
    file: string;
    startLine: number;
    endLine: number;
  };
  /** 該当コード抜粋 */
  evidence: string;
  /** source→sink の根拠。空配列なら到達性未証明 */
  dataFlow: DataFlowStep[];
  /** なぜ脆弱か */
  reasoning: string;
  /** 修正方針 */
  remediation: string;
  /** どのレンズが検出したか */
  lens: LensId;
}

/** CVSS v3.0/v3.1 基本評価基準のメトリクス */
export interface Cvss3Metrics {
  /** Attack Vector: Network / Adjacent / Local / Physical */
  AV: 'N' | 'A' | 'L' | 'P';
  /** Attack Complexity: Low / High */
  AC: 'L' | 'H';
  /** Privileges Required: None / Low / High */
  PR: 'N' | 'L' | 'H';
  /** User Interaction: None / Required */
  UI: 'N' | 'R';
  /** Scope: Unchanged / Changed */
  S: 'U' | 'C';
  /** Confidentiality Impact: High / Low / None */
  C: 'H' | 'L' | 'N';
  /** Integrity Impact */
  I: 'H' | 'L' | 'N';
  /** Availability Impact */
  A: 'H' | 'L' | 'N';
}

export interface Cvss3Result {
  /** 0.0 - 10.0 */
  baseScore: number;
  /** スコアから導かれる深刻度 */
  baseSeverity: 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
  /** 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' */
  vector: string;
  metrics: Cvss3Metrics;
  version: '3.0' | '3.1';
  /** 内訳（説明用） */
  breakdown: {
    impactSubScore: number;
    exploitabilitySubScore: number;
  };
}

export type TriageStatus = 'open' | 'confirmed' | 'false-positive' | 'accepted' | 'fixed';

/** ベースライン差分での状態 */
export type DiffStatus = 'new' | 'persistent' | 'fixed';

/** ③で正規化された最終的な Finding */
export interface Finding extends RawFinding {
  /** 安定した一意ID（fingerprint 由来） */
  id: string;
  /** 位置とCWEから算出する再現可能な指紋。ベースライン照合に使う */
  fingerprint: string;
  /** 依存脆弱性の場合の CVE ID */
  cve?: string;
  /** 該当する依存パッケージ（依存由来のFindingのみ） */
  affectedPackage?: {
    name: string;
    version: string;
    ecosystem: string;
    fixedVersion?: string;
  };
  cvss: Cvss3Result;
  status: TriageStatus;
  diffStatus: DiffStatus;
  firstSeen: string;
  lastSeen: string;
  /** 統合された重複Findingのfingerprint一覧 */
  mergedFrom: string[];
  /** 参考リンク（CWE/OWASP/アドバイザリ） */
  references: string[];
}
