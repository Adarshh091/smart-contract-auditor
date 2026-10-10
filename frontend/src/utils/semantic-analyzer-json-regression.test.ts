// ─── Semantic Analyzer Gemini Integration Regression Tests ──────────────────
//
// Tests the new Gemini-backed runSemanticAnalysis via the fetchFn injection API.
// No real Gemini API calls are made; mock fetch responses simulate backend behavior.

import { describe, it, expect } from "vitest";
import {
  runSemanticAnalysis,
  extractJSON,
  buildContractSummary,
  serializeContractSummary,
  buildPrompt,
  validateSemanticResult,
} from "./semantic-analyzer";
import { detectSecurityVulnerabilities } from "./security-detector";
import type { ASTAnalysisResult, ASTContract, ASTFunction, ASTOperation } from "../types/ast";

const EMPTY_OPS: ASTOperation[] = [];
const BASE_LOC = { file: "Test.sol", line: 10, column: 1, start: 100, length: 200, end: 300 };

function makeAST(): ASTAnalysisResult {
  const fn: ASTFunction = {
    id: 1,
    name: "withdraw",
    contractName: "TestVault",
    kind: "function",
    visibility: "public",
    stateMutability: "nonpayable",
    isVirtual: false,
    isOverride: false,
    modifiers: [],
    parameters: [],
    returnParameters: [],
    signature: "withdraw()",
    location: BASE_LOC,
    codeSnippet: `
      function withdraw() public {
        uint amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
      }
    `,
    externalCalls: [
      {
        id: "c1",
        contractName: "TestVault",
        functionName: "withdraw",
        target: "msg.sender",
        method: "call",
        callType: "low-level-call",
        value: "amount",
        arguments: [],
        rawExpression: 'msg.sender.call{value: amount}("")',
        location: BASE_LOC,
      },
    ],
    etherTransfers: [],
    controlStatements: [],
    operations: EMPTY_OPS,
  };

  const contract: ASTContract = {
    id: 1,
    name: "TestVault",
    kind: "contract",
    isAbstract: false,
    sourceFile: "Test.sol",
    bases: [],
    functions: [fn],
    stateVariables: [
      {
        id: 10,
        name: "balances",
        contractName: "TestVault",
        type: "mapping(address => uint256)",
        visibility: "public",
        mutability: "mutable",
        location: BASE_LOC,
      },
    ],
    modifiers: [],
    events: [],
    structs: [],
    enums: [],
    externalCalls: fn.externalCalls,
    etherTransfers: [],
    controlStatements: [],
    location: BASE_LOC,
  };

  return {
    contracts: [contract],
    functions: [fn],
    stateVariables: contract.stateVariables,
    modifiers: [],
    events: [],
    structs: [],
    enums: [],
    inheritance: [],
    externalCalls: fn.externalCalls,
    etherTransfers: [],
    controlStatements: [],
    summary: {
      totalContracts: 1,
      totalFunctions: 1,
      totalStateVariables: 1,
      totalModifiers: 0,
      totalEvents: 0,
      totalStructs: 0,
      totalEnums: 0,
      totalExternalCalls: 1,
      totalEtherTransfers: 0,
      totalControlStatements: 0,
      publicOrExternalFunctions: 1,
      internalOrPrivateFunctions: 0,
      payableFunctions: 0,
      viewOrPureFunctions: 0,
    },
    rawAst: {},
  };
}

const VALID_SEMANTIC_JSON = JSON.stringify({
  purpose: "A vault contract for user deposits and withdrawals.",
  category: "Wallet",
  confidence: 0.95,
  assets: ["ETH"],
  mainFunctions: ["withdraw()"],
  criticalOperations: ["ETH transfer"],
  accessControl: ["none"],
  externalInteractions: ["msg.sender"],
  financialOperations: ["withdraw"],
  securityCriticalAreas: ["reentrancy"],
});

// ─── Helper: mock backend response ───────────────────────────────────────────

function mockBackendOk(text: string) {
  return async () =>
    new Response(JSON.stringify({ ok: true, text, model: "gemini-3.8-flash" }), { status: 200 });
}

function mockBackendError(errorType: string, message: string) {
  return async () =>
    new Response(JSON.stringify({ ok: false, errorType, error: message }), { status: 200 });
}

function mockHttpError(status: number) {
  return async () =>
    new Response(JSON.stringify({ error: `HTTP ${status}` }), { status });
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("Semantic Analyzer — Gemini Integration", () => {
  it("1. Valid Gemini JSON response → success", async () => {
    const outcome = await runSemanticAnalysis(makeAST(), {
      fetchFn: mockBackendOk(VALID_SEMANTIC_JSON) as typeof fetch,
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.result.category).toBe("Wallet");
      expect(outcome.result.confidence).toBe(0.95);
      expect(outcome.model).toBe("gemini-3.8-flash");
    }
  });

  it("2. Markdown-wrapped JSON → extracted and parsed successfully", async () => {
    const wrapped = "```json\n" + VALID_SEMANTIC_JSON + "\n```";
    const outcome = await runSemanticAnalysis(makeAST(), {
      fetchFn: mockBackendOk(wrapped) as typeof fetch,
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.result.category).toBe("Wallet");
    }
  });

  it("3. Truncated JSON → safely extracted/healed via extractJSON", () => {
    const truncated = `{"purpose":"A vault contract","category":"Wallet","confidence":0.9,"assets":["ETH"],"mainFunctions":["withdraw()"],"criticalOperations":[],"accessControl":[],"externalInteractions":[],"financialOperations":[],"securityCriticalAreas":[]`;
    const extracted = extractJSON(truncated);
    expect(extracted.endsWith("}")).toBe(true);
    const parsed = JSON.parse(extracted);
    expect(parsed.category).toBe("Wallet");
  });

  it("4. Backend returns missing-key error → failure outcome", async () => {
    const outcome = await runSemanticAnalysis(makeAST(), {
      fetchFn: mockBackendError("missing-key", "GEMINI_API_KEY not configured") as typeof fetch,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok === false) {
      expect(outcome.error.type).toBe("missing-key");
      expect(outcome.error.message).toContain("GEMINI_API_KEY");
    }
  });

  it("5. Backend returns HTTP 500 → connection failure", async () => {
    const outcome = await runSemanticAnalysis(makeAST(), {
      fetchFn: mockHttpError(500) as typeof fetch,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok === false) {
      expect(outcome.error.type).toBe("connection");
    }
  });

  it("6. Backend returns invalid JSON text → validation fails gracefully", async () => {
    const outcome = await runSemanticAnalysis(makeAST(), {
      fetchFn: mockBackendOk("{ NOT JSON AT ALL }") as typeof fetch,
    });
    expect(outcome.ok).toBe(false);
  });

  it("7. Security analysis still runs when semantic analysis fails or is unavailable", () => {
    const ast = makeAST();
    const result = detectSecurityVulnerabilities(ast, undefined, undefined);
    const confirmed = result.findings.filter(
      (f) => f.vulnerabilityType === "Reentrancy" && f.classification === "CONFIRMED"
    );
    expect(confirmed.length).toBe(1);
    expect(confirmed[0].functionName).toBe("withdraw");
  });

  it("8. buildContractSummary produces correct structure", () => {
    const summaries = buildContractSummary(makeAST());
    expect(summaries.length).toBe(1);
    expect(summaries[0].name).toBe("TestVault");
    expect(summaries[0].functions.length).toBe(1);
    expect(summaries[0].functions[0].hasExternalCalls).toBe(true);
  });

  it("9. buildPrompt contains CONTRACT SUMMARY section", () => {
    const prompt = buildPrompt("## Contract: TestVault (contract)");
    expect(prompt).toContain("CONTRACT SUMMARY");
    expect(prompt).toContain("TestVault");
    expect(prompt).toContain("Respond with the JSON object only:");
  });

  it("10. validateSemanticResult accepts valid object", () => {
    const parsed = JSON.parse(VALID_SEMANTIC_JSON);
    const result = validateSemanticResult(parsed);
    expect(result.category).toBe("Wallet");
    expect(result.confidence).toBeCloseTo(0.95);
  });
});
