// ─── Dynamic Analysis & Foundry Runner Types ─────────────────────────────────────
//
// Structured representation of Foundry dynamic execution results.
//
// Invariants:
//   1. Dynamic results are SUPPORTING evidence only.
//   2. Never replace deterministic AST findings automatically.
//   3. If Foundry (forge) is unavailable, gracefully fall back with status "UNAVAILABLE".
//   4. Do NOT claim vulnerabilities if tests cannot run.

import type { SourceLocation } from "./ast";

export type DynamicAnalysisStatus = "VERIFIED" | "NOT_REPRODUCED" | "UNAVAILABLE" | "ERROR";

export interface DynamicTestCaseResult {
  id: string;
  testName: string;
  contractName: string;
  functionName: string;
  status: DynamicAnalysisStatus;
  passed: boolean;
  revertReason?: string;
  executionEvidence: string[];
  location?: SourceLocation;
  durationMs?: number;
}

export interface DynamicAnalysisSummary {
  totalTests: number;
  verifiedCount: number;
  notReproducedCount: number;
  errorCount: number;
}

export interface DynamicAnalysisResult {
  available: boolean;
  status: DynamicAnalysisStatus;
  reason?: string;
  results: DynamicTestCaseResult[];
  summary: DynamicAnalysisSummary;
  analyzedAt: number;
}

export interface FoundryRunnerOptions {
  timeoutMs?: number;
  solidityVersion?: string;
  workspaceDir?: string;
}
