// ─── Taint & Data-Flow Analysis Types ─────────────────────────────────────────
//
// Structured representation of Taint Sources, Taint Sinks, Propagation Steps,
// and Taint Flow Paths derived from ASTAnalysisResult and ContractCFGResult.
//
// Design Invariant:
//   Taint analysis provides supporting evidence ONLY.
//   It NEVER automatically converts signals into confirmed vulnerabilities
//   or alters existing detector findings.

import type { SourceLocation } from "./ast";

export type TaintSourceType =
  | "parameter"
  | "msg.sender"
  | "msg.value"
  | "tx.origin"
  | "block.timestamp"
  | "block.number"
  | "external-return";

export interface TaintSource {
  id: string;
  type: TaintSourceType;
  contractName: string;
  functionName: string;
  name: string;
  expression: string;
  location?: SourceLocation;
}

export type TaintSinkType =
  | "delegatecall-target"
  | "low-level-call-target"
  | "low-level-call-value"
  | "selfdestruct-recipient"
  | "ether-transfer-recipient"
  | "ether-transfer-value"
  | "privileged-state-change"
  | "sensitive-condition";

export interface TaintSink {
  id: string;
  type: TaintSinkType;
  contractName: string;
  functionName: string;
  expression: string;
  targetOrVar: string;
  location?: SourceLocation;
}

export interface TaintFlowStep {
  from: string;
  to: string;
  expression: string;
  location?: SourceLocation;
}

export interface TaintPath {
  id: string;
  source: TaintSource;
  sink: TaintSink;
  steps: TaintFlowStep[];
  isTainted: boolean;
  confidence: "high" | "medium" | "low";
}

export interface TaintAnalysisSummary {
  totalSources: number;
  totalSinks: number;
  totalTaintedPaths: number;
}

export interface TaintAnalysisResult {
  sources: TaintSource[];
  sinks: TaintSink[];
  paths: TaintPath[];
  summary: TaintAnalysisSummary;
}
