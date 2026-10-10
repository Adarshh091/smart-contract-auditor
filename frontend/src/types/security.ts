// ─── Security Finding & Detection Types ─────────────────────────────────────

import type { SourceLocation, ASTAnalysisResult } from "./ast";
import type { VulnerabilityCategory, VulnerabilityPlan } from "./vulnerability";
import type { SemanticResult } from "./semantic";

export type VulnerabilityClassification = "CONFIRMED" | "POTENTIAL" | "NOT_VULNERABLE";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "informational";

export type FindingConfidence = "high" | "medium" | "low";

export interface SecurityFinding {
  id: string;
  vulnerabilityType: VulnerabilityCategory;
  title: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  classification: VulnerabilityClassification;
  contractName: string;
  functionName: string;
  location?: SourceLocation;
  evidence: string[];
  reason: string;
  recommendation: string;
  codeSnippet?: string;
}

export interface DetectionSummary {
  totalFindings: number;
  confirmedCount: number;
  potentialCount: number;
  notVulnerableCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
}

export interface SecurityAnalysisResult {
  findings: SecurityFinding[];
  summary: DetectionSummary;
  analyzedAt: number;
}

/**
 * Context provided to every vulnerability detector engine module.
 *
 * `solidityVersion` is the resolved lower-bound version string (e.g. "0.4.19"
 * or "0.8.20") extracted from the pragma statement.  Detectors use it to
 * choose the correct analysis model (e.g. overflow behaviour differs between
 * pre-0.8 and >=0.8 Solidity).  When absent, detectors must be conservative.
 */
export interface DetectionContext {
  ast: ASTAnalysisResult;
  plan?: VulnerabilityPlan;
  semantic?: SemanticResult;
  /** Resolved pragma lower-bound, e.g. "0.4.19" or "0.8.20". Optional. */
  solidityVersion?: string;
  /** Optional raw or pre-parsed Slither findings/output for correlation */
  slitherFindings?: unknown;
}

/**
 * Pluggable interface for individual vulnerability detectors.
 * Enables easy addition of Access Control, Overflow, Delegatecall, etc.
 */
export interface VulnerabilityDetector {
  category: VulnerabilityCategory;
  name: string;
  description: string;
  detect(ctx: DetectionContext): SecurityFinding[];
}
