// ─── ML Analyzer Stub for Hosted Version ──────────────────────────────────────
//
// In the hosted edition, local CodeBERT / Python ML inference is completely disabled.
// Static AST / Security detectors remain 100% authoritative.

import type { SecurityFinding } from "../types/security";
import type { VulnerabilityCategory } from "../types/vulnerability";
import type { MLAnalysisResult, MLLabel } from "../types/ml";

export const DEFAULT_MODEL_PATH = "";

export function getModelPath(): string {
  return "";
}

export function mapCategoryToMLLabel(_category: VulnerabilityCategory): MLLabel | null {
  return null;
}

export function mapMLLabelToCategory(_label: string): VulnerabilityCategory | null {
  return null;
}

export function checkMLModelAvailability(): boolean {
  return false;
}

export function runMLInference(
  _sourceCode: string,
  _customRunner?: (source: string) => MLAnalysisResult,
  _modelPathOverride?: string
): MLAnalysisResult {
  return {
    predictions: [],
    modelName: "Disabled (Hosted)",
    available: false,
    error: "Local ML analysis is disabled in hosted environment",
  };
}

export async function runMLInferenceAsync(
  _sourceCode: string,
  _customRunner?: (source: string) => MLAnalysisResult | Promise<MLAnalysisResult>,
  _modelPathOverride?: string
): Promise<MLAnalysisResult> {
  return runMLInference(_sourceCode);
}

export function correlateMLWithFindings(
  findings: SecurityFinding[],
  _mlResult: MLAnalysisResult
): SecurityFinding[] {
  return findings;
}
