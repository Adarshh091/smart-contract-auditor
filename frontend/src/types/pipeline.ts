// ─── Pipeline Stage Types ──────────────────────────────────────────────────────
// Each stage is self-contained. Add new stages here as the auditor grows.

export type PipelineStageId =
  | "upload"        // Stage 1: .sol file upload & code preview
  | "compiler"      // Stage 2: Solidity version detect + compiler select (next)
  | "compile"       // Stage 3: Compile
  | "ast"           // Stage 4: AST + Call Graph
  | "analysis"      // Stage 5: Purpose / Semantic Analysis
  | "security"      // Stage 6: Context-Aware Vulnerability Analysis
  | "findings";     // Stage 7: Verified Final Findings

export type PipelineStageStatus = "pending" | "active" | "complete" | "error";

export interface PipelineStage {
  id: PipelineStageId;
  label: string;
  description: string;
  status: PipelineStageStatus;
}

// ─── Solidity File ─────────────────────────────────────────────────────────────

export interface SolidityFile {
  name: string;
  size: number;        // bytes
  lastModified: number;
  source: string;      // raw Solidity source code
}

// ─── Compiler Info (Stage 2 output) ───────────────────────────────────────────

export interface CompilerInfo {
  /** Raw pragma constraint string, e.g. "^0.8.20" */
  detectedConstraint: string;
  /** "exact" | "caret" | "tilde" | "range" | "unknown" */
  constraintKind: string;
  /** Selected compiler version, e.g. "0.8.20" */
  selectedVersion: string;
  /** Human-readable reason for this choice */
  selectionReason: string;
  /** true when the selected compiler fully satisfies the pragma */
  isCompatible: boolean;
}

// ─── Pipeline State ────────────────────────────────────────────────────────────

// Re-export from canonical locations so consumers only import from types/pipeline.
export type { CompilationResult } from "../utils/solidity-compiler";
export type { ASTAnalysisResult } from "./ast";
export type { SemanticResult } from "./semantic";
export type { VulnerabilityPlan } from "./vulnerability";
export type { SecurityFinding, SecurityAnalysisResult } from "./security";

export interface PipelineState {
  currentStage: PipelineStageId;
  stages: PipelineStage[];
  solidityFile: SolidityFile | null;
  /** Populated after Stage 2 completes */
  compilerInfo: CompilerInfo | null;
  /** Populated after Stage 3 completes */
  compilationResult: import("../utils/solidity-compiler").CompilationResult | null;
  /** Populated after Stage 4 completes */
  astAnalysis: import("./ast").ASTAnalysisResult | null;
  /** Populated after Stage 5 completes */
  semanticResult: import("./semantic").SemanticResult | null;
  /** Populated after Stage 6 completes */
  vulnerabilityPlan: import("./vulnerability").VulnerabilityPlan | null;
  /** Populated after Security Analysis runs */
  securityAnalysis: import("./security").SecurityAnalysisResult | null;
}

// ─── Default pipeline stages ──────────────────────────────────────────────────

export const DEFAULT_PIPELINE_STAGES: PipelineStage[] = [
  {
    id: "upload",
    label: "Upload",
    description: ".sol File Upload",
    status: "active",
  },
  {
    id: "compiler",
    label: "Compiler",
    description: "Version Detection",
    status: "pending",
  },
  {
    id: "compile",
    label: "Compile",
    description: "Build & Artifacts",
    status: "pending",
  },
  {
    id: "ast",
    label: "AST",
    description: "AST Analysis",
    status: "pending",
  },
  {
    id: "analysis",
    label: "Semantic",
    description: "Semantic Audit",
    status: "pending",
  },
  {
    id: "security",
    label: "Security",
    description: "Vulnerability Checks",
    status: "pending",
  },
  {
    id: "findings",
    label: "Findings",
    description: "Final Verified Results",
    status: "pending",
  },
];
