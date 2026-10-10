// ─── PoC / Exploit Verification Types ─────────────────────────────────────────
//
// Structured representation of deterministic PoC / Exploit Verification scenarios.
//
// Design Invariants:
//   1. VERIFIED requires actual successful runtime reproduction from Foundry test.
//   2. PoC generation alone NEVER marks a finding as VERIFIED.
//   3. PoC failure or unavailability NEVER removes or downgrades static findings.
//   4. Minimal and deterministic test generation for verification.

import type { SourceLocation } from "./ast";
import type { VulnerabilityCategory } from "./vulnerability";
import type { DynamicAnalysisStatus } from "./dynamic";

export interface PocScenario {
  id: string;
  vulnerabilityType: VulnerabilityCategory;
  contractName: string;
  functionName: string;
  testName: string;
  testCode: string;
  location?: SourceLocation;
}

export interface PocVerificationResult {
  vulnerabilityType: VulnerabilityCategory;
  contractName: string;
  functionName: string;
  verificationStatus: DynamicAnalysisStatus;
  testName: string;
  executionEvidence: string[];
  failureReason?: string;
  sourceLocation?: SourceLocation;
  findingId?: string;
}

export interface PocVerificationReport {
  available: boolean;
  overallStatus: DynamicAnalysisStatus;
  verifications: PocVerificationResult[];
  summary: {
    totalFindingsEvaluated: number;
    verifiedCount: number;
    notReproducedCount: number;
    unavailableCount: number;
    errorCount: number;
  };
  generatedAt: number;
}
