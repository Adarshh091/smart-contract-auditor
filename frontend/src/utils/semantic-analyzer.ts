// ─── Semantic Analysis Engine for Hosted Version (Gemini API Integration) ──────
//
// Pure TypeScript module that:
//  1. Builds a compact structured summary of the contract from ASTAnalysisResult
//  2. Calls the backend Gemini proxy endpoint (/api/semantic-analyze)
//  3. Validates and returns the parsed SemanticResult
//
// Server-side environment variable GEMINI_API_KEY is used by the backend proxy.
// No API keys are exposed to client-side code.

import type { ASTAnalysisResult } from "../types/ast";
import type { SemanticResult } from "../types/semantic";
import { SEMANTIC_RESULT_REQUIRED_KEYS } from "../types/semantic";

export interface SemanticAnalysisError {
  type: "missing-key" | "connection" | "invalid-response" | "validation" | "timeout";
  message: string;
  detail?: string;
}

export interface SemanticAnalysisSuccess {
  ok: true;
  result: SemanticResult;
  model: string;
  durationMs: number;
}

export interface SemanticAnalysisFailure {
  ok: false;
  error: SemanticAnalysisError;
}

export type SemanticAnalysisOutcome = SemanticAnalysisSuccess | SemanticAnalysisFailure;

// ─── Compact Contract Summary Builder ────────────────────────────────────────

interface ContractSummary {
  name: string;
  kind: string;
  bases: string[];
  functions: FunctionSummary[];
  stateVariables: string[];
  events: string[];
  modifiers: string[];
  externalCalls: string[];
  etherTransfers: string[];
  controlStatements: string[];
}

interface FunctionSummary {
  signature: string;
  visibility: string;
  mutability: string;
  modifiers: string[];
  hasExternalCalls: boolean;
  hasEtherTransfer: boolean;
}

export function buildContractSummary(ast: ASTAnalysisResult): ContractSummary[] {
  return ast.contracts.map((contract) => {
    const fns: FunctionSummary[] = contract.functions.map((fn) => ({
      signature: fn.signature,
      visibility: fn.visibility,
      mutability: fn.stateMutability,
      modifiers: fn.modifiers,
      hasExternalCalls: fn.externalCalls.length > 0,
      hasEtherTransfer: fn.etherTransfers.length > 0,
    }));

    const stateVarDescriptions = contract.stateVariables.map(
      (v) => `${v.visibility} ${v.type} ${v.name}${v.mutability !== "mutable" ? ` (${v.mutability})` : ""}`
    );

    const eventSignatures = contract.events.map((e) => e.signature);

    const modifierNames = contract.modifiers.map(
      (m) => `${m.name}(${m.parameters.map((p) => p.type).join(",")})`
    );

    const externalCallDescriptions = contract.externalCalls.map(
      (c) => `${c.callType}: ${c.rawExpression.slice(0, 80)}`
    );

    const etherTransferDescriptions = contract.etherTransfers.map(
      (t) => `${t.transferType} to ${t.recipient} amount ${t.amount}`
    );

    const controlDescriptions = contract.controlStatements.map(
      (cs) => `${cs.kind}${cs.condition ? `(${cs.condition.slice(0, 60)})` : ""}`
    );

    return {
      name: contract.name,
      kind: contract.kind,
      bases: contract.bases,
      functions: fns,
      stateVariables: stateVarDescriptions,
      events: eventSignatures,
      modifiers: modifierNames,
      externalCalls: externalCallDescriptions,
      etherTransfers: etherTransferDescriptions,
      controlStatements: controlDescriptions,
    };
  });
}

export function serializeContractSummary(summaries: ContractSummary[]): string {
  const lines: string[] = [];

  for (const c of summaries) {
    lines.push(`## Contract: ${c.name} (${c.kind})`);

    if (c.bases.length > 0) {
      lines.push(`Inherits: ${c.bases.join(", ")}`);
    }

    if (c.stateVariables.length > 0) {
      lines.push("\n### State Variables:");
      c.stateVariables.forEach((v) => lines.push(`  - ${v}`));
    }

    if (c.events.length > 0) {
      lines.push("\n### Events:");
      c.events.forEach((e) => lines.push(`  - ${e}`));
    }

    if (c.modifiers.length > 0) {
      lines.push("\n### Modifiers:");
      c.modifiers.forEach((m) => lines.push(`  - ${m}`));
    }

    if (c.functions.length > 0) {
      lines.push("\n### Functions:");
      c.functions.forEach((fn) => {
        let desc = `  - [${fn.visibility}][${fn.mutability}] ${fn.signature}`;
        if (fn.modifiers.length > 0) desc += ` — modifiers: ${fn.modifiers.join(", ")}`;
        if (fn.hasExternalCalls) desc += " [has external calls]";
        if (fn.hasEtherTransfer) desc += " [transfers ETH]";
        lines.push(desc);
      });
    }

    if (c.externalCalls.length > 0) {
      lines.push("\n### External Calls:");
      c.externalCalls.forEach((ec) => lines.push(`  - ${ec}`));
    }

    if (c.etherTransfers.length > 0) {
      lines.push("\n### ETH Transfers:");
      c.etherTransfers.forEach((et) => lines.push(`  - ${et}`));
    }

    if (c.controlStatements.length > 0) {
      lines.push("\n### Access / Validation Checks (require/assert/revert):");
      c.controlStatements.slice(0, 20).forEach((cs) => lines.push(`  - ${cs}`));
      if (c.controlStatements.length > 20) {
        lines.push(`  ... and ${c.controlStatements.length - 20} more`);
      }
    }

    lines.push("");
  }

  return lines.join("\n");
}

// ─── Prompt Builder ───────────────────────────────────────────────────────────

export function buildPrompt(contractText: string): string {
  return `You are a Solidity smart contract security researcher.
Analyze the following structured summary of a Solidity smart contract and determine its purpose and category.

IMPORTANT RULES:
- Respond ONLY with a valid JSON object. No markdown formatting, no backticks, no explanations, no text before or after the JSON.
- Use EXACTLY these JSON keys.
- "confidence" must be a number between 0.0 and 1.0.
- All other values are strings or arrays of strings.

EXPECTED JSON STRUCTURE:
{
  "purpose": "<one or two sentence description of what this contract does>",
  "category": "<one of: Token, NFT, Marketplace, Auction, DAO, Lending, Staking, Escrow, Payment, Governance, Wallet, Proxy/Upgradeable, Lottery, Other>",
  "confidence": <0.0 to 1.0>,
  "assets": ["<asset 1>", "..."],
  "mainFunctions": ["<function signature or name>", "..."],
  "criticalOperations": ["<operation>", "..."],
  "accessControl": ["<mechanism>", "..."],
  "externalInteractions": ["<interaction>", "..."],
  "financialOperations": ["<operation>", "..."],
  "securityCriticalAreas": ["<area>", "..."]
}

CONTRACT SUMMARY:
${contractText}

Respond with the JSON object only:`;
}

// ─── JSON Extraction & Healing ──────────────────────────────────────────────

export function extractJSON(text: string): string {
  let trimmed = text.trim();

  // Extract from markdown code block ```json ... ``` or ``` ... ```
  const codeBlock = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (codeBlock && codeBlock[1]) {
    trimmed = codeBlock[1].trim();
  } else {
    // Try to find the first { ... } block
    const start = trimmed.indexOf("{");
    const end = trimmed.lastIndexOf("}");
    if (start !== -1 && end !== -1 && end > start) {
      trimmed = trimmed.slice(start, end + 1);
    } else if (start !== -1) {
      trimmed = trimmed.slice(start);
    }
  }

  // Trailing commas cleanup
  trimmed = trimmed.replace(/,\s*([}\]])/g, "$1");

  // Attempt to close unclosed JSON structures
  if (!trimmed.endsWith("}")) {
    const quoteCount = (trimmed.match(/"/g) || []).length;
    if (quoteCount % 2 !== 0) {
      trimmed += '"';
    }
    const openBrackets = (trimmed.match(/\[/g) || []).length - (trimmed.match(/\]/g) || []).length;
    for (let i = 0; i < openBrackets; i++) {
      trimmed += "]";
    }
    const openBraces = (trimmed.match(/\{/g) || []).length - (trimmed.match(/\}/g) || []).length;
    for (let i = 0; i < openBraces; i++) {
      trimmed += "}";
    }
    trimmed = trimmed.replace(/,\s*([}\]])/g, "$1");
  }

  return trimmed;
}

// ─── JSON Validation ──────────────────────────────────────────────────────────

export function validateSemanticResult(raw: unknown): SemanticResult {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("Response is not a JSON object.");
  }

  const obj = raw as Record<string, unknown>;

  const missing = SEMANTIC_RESULT_REQUIRED_KEYS.filter((k) => !(k in obj));
  if (missing.length > 0) {
    throw new Error(`Response is missing required keys: ${missing.join(", ")}`);
  }

  if (typeof obj.purpose !== "string" || obj.purpose.trim() === "") {
    throw new Error('"purpose" must be a non-empty string.');
  }
  if (typeof obj.category !== "string" || obj.category.trim() === "") {
    throw new Error('"category" must be a non-empty string.');
  }

  let confNum = typeof obj.confidence === "number" ? obj.confidence : parseFloat(String(obj.confidence));
  if (isNaN(confNum) || confNum < 0 || confNum > 1) {
    confNum = 0.85; // Fallback default confidence
  }
  obj.confidence = confNum;

  const arrayKeys: (keyof SemanticResult)[] = [
    "assets",
    "mainFunctions",
    "criticalOperations",
    "accessControl",
    "externalInteractions",
    "financialOperations",
    "securityCriticalAreas",
  ];

  for (const key of arrayKeys) {
    if (!Array.isArray(obj[key])) {
      if (typeof obj[key] === "string") {
        obj[key] = (obj[key] as string)
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
      } else {
        obj[key] = [];
      }
    }
    obj[key] = (obj[key] as unknown[]).map(String);
  }

  return obj as unknown as SemanticResult;
}

// ─── Client API Runner ────────────────────────────────────────────────────────

/**
 * Executes Stage 5 semantic analysis via server-side Gemini backend endpoint (/api/semantic-analyze).
 * Accepts optional fetchFn for dependency injection in testing.
 */
export async function runSemanticAnalysis(
  ast: ASTAnalysisResult,
  options?: { fetchFn?: typeof fetch; endpoint?: string }
): Promise<SemanticAnalysisOutcome> {
  const customFetch = options?.fetchFn ?? fetch;
  const endpoint = options?.endpoint ?? "/api/semantic-analyze";
  const startMs = Date.now();

  const summaries = buildContractSummary(ast);
  const contractText = serializeContractSummary(summaries);
  const prompt = buildPrompt(contractText);

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60_000); // 60s timeout

    let res: Response;
    try {
      res = await customFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt, contractText }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    if (!res.ok) {
      const errData = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      return {
        ok: false,
        error: {
          type: res.status === 401 ? "missing-key" : "connection",
          message: errData.error || `Server returned HTTP ${res.status}`,
          detail: errData.detail || undefined,
        },
      };
    }

    const payload = await res.json();
    if (!payload.ok) {
      return {
        ok: false,
        error: {
          type: payload.errorType || "connection",
          message: payload.error || "Gemini semantic analysis request failed.",
          detail: payload.detail || undefined,
        },
      };
    }

    const rawText = payload.text || "";
    const extracted = extractJSON(rawText);
    const parsed = JSON.parse(extracted);
    const result = validateSemanticResult(parsed);

    return {
      ok: true,
      result,
      model: payload.model || "Gemini 3.8 Flash",
      durationMs: Date.now() - startMs,
    };
  } catch (err: any) {
    const isTimeout = err instanceof DOMException && err.name === "AbortError";
    return {
      ok: false,
      error: {
        type: isTimeout ? "timeout" : "connection",
        message: isTimeout
          ? "Gemini API request timed out."
          : `Failed to connect to semantic analysis service: ${err.message || String(err)}`,
        detail: String(err),
      },
    };
  }
}
