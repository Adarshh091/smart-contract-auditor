import type { SourceLocation } from "./ast";
import type { FindingSeverity, FindingConfidence } from "./security";
import type { VulnerabilityCategory } from "./vulnerability";

export interface SlitherElement {
  type: string; // "contract" | "function" | "node" | "variable"
  name?: string;
  source_mapping?: {
    start?: number;
    length?: number;
    lines?: number[];
    filename_relative?: string;
    filename_absolute?: string;
  };
  type_specific_fields?: {
    parent?: {
      type: string;
      name: string;
    };
  };
}

export interface RawSlitherFinding {
  check: string;
  impact?: string;
  confidence?: string;
  description?: string;
  elements?: SlitherElement[];
  first_markdown_element?: string;
}

export interface RawSlitherOutput {
  success?: boolean;
  error?: string;
  results?: {
    detectors?: RawSlitherFinding[];
  };
}

export interface SlitherFinding {
  id?: string;
  check: string;
  vulnerabilityType: VulnerabilityCategory;
  contractName: string;
  functionName: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  location?: SourceLocation;
  lines?: number[];
  raw?: unknown;
}
