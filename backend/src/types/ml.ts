// ─── Machine Learning Security Signal Types ─────────────────────────────────────
//
// Structured representation of CodeBERT multi-label ML classifier predictions.
//
// Invariants:
//   1. ML output is a SECONDARY SUPPORTING SIGNAL only.
//   2. ML prediction alone MUST NEVER create CONFIRMED, CRITICAL, or HIGH findings.
//   3. AST/deterministic detectors remain authoritative.
//   4. If model is unavailable, return available: false with empty predictions.

export const CODEBERT_ML_LABELS = [
  "block_number_dependency",
  "dangerous_delegatecall",
  "ether_frozen",
  "ether_strict_equality",
  "integer_overflow",
  "reentrancy",
  "timestamp_dependency",
  "unchecked_call",
  "safe",
] as const;

export type MLLabel = (typeof CODEBERT_ML_LABELS)[number];

export interface MLPrediction {
  label: string;
  score: number;
  predicted: boolean;
}

export interface MLAnalysisResult {
  predictions: MLPrediction[];
  modelName: string;
  available: boolean;
  device?: string;
  error?: string;
}
