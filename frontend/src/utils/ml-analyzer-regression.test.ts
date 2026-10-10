import { describe, it, expect } from "vitest";
import {
  runMLInference,
  runMLInferenceAsync,
  checkMLModelAvailability,
  correlateMLWithFindings,
  getModelPath,
} from "./ml-analyzer";
import { detectSecurityVulnerabilities } from "./security-detector";
import type { ASTAnalysisResult, ASTContract, SourceLocation } from "../types/ast";
import type { SecurityFinding } from "../types/security";
import type { MLAnalysisResult } from "../types/ml";

const BASE_LOC: SourceLocation = {
  file: "Test.sol",
  line: 10,
  column: 1,
  endLine: 20,
  start: 100,
  length: 100,
  end: 200,
};

function makeMinimalAST(contractName: string): ASTAnalysisResult {
  const contract: ASTContract = {
    id: 1,
    name: contractName,
    kind: "contract",
    isAbstract: false,
    sourceFile: "Test.sol",
    bases: [],
    functions: [],
    stateVariables: [],
    modifiers: [],
    events: [],
    structs: [],
    enums: [],
    externalCalls: [],
    etherTransfers: [],
    controlStatements: [],
    location: BASE_LOC,
  };
  return {
    contracts: [contract],
    functions: [],
    stateVariables: [],
    modifiers: [],
    events: [],
    structs: [],
    enums: [],
    inheritance: [],
    externalCalls: [],
    etherTransfers: [],
    controlStatements: [],
    summary: {
      totalContracts: 1,
      totalFunctions: 0,
      totalStateVariables: 0,
      totalModifiers: 0,
      totalEvents: 0,
      totalStructs: 0,
      totalEnums: 0,
      totalExternalCalls: 0,
      totalEtherTransfers: 0,
      totalControlStatements: 0,
      publicOrExternalFunctions: 0,
      internalOrPrivateFunctions: 0,
      payableFunctions: 0,
      viewOrPureFunctions: 0,
    },
    rawAst: {},
  };
}

function makeFinding(
  category: SecurityFinding["vulnerabilityType"],
  contractName: string = "Vault",
  functionName: string = "withdraw"
): SecurityFinding {
  return {
    id: `finding-${category}-${contractName}-${functionName}`,
    vulnerabilityType: category,
    title: `${category} vulnerability`,
    severity: "high",
    confidence: "medium",
    classification: "CONFIRMED",
    contractName,
    functionName,
    location: BASE_LOC,
    evidence: ["AST evidence confirmed"],
    reason: "Deterministic check failed",
    recommendation: "Fix vulnerability",
  };
}

describe("CodeBERT ML Classifier Adapter (Hosted Stub)", () => {
  it("1. Model path configuration check", () => {
    const configuredPath = getModelPath();
    expect(configuredPath).toBe("");
  });

  it("2. Model directory loading check returns false in hosted version", () => {
    const isAvailable = checkMLModelAvailability();
    expect(isAvailable).toBe(false);
  });

  it("3. ML Inference returns disabled state in hosted version", async () => {
    const res = await runMLInferenceAsync("contract Vault {}");
    expect(res.available).toBe(false);
    expect(res.predictions.length).toBe(0);
    expect(res.error).toContain("disabled in hosted environment");
  });

  it("4. ML unavailable fallback", () => {
    const res = runMLInference("contract Vault {}");
    expect(res.available).toBe(false);
    expect(res.predictions.length).toBe(0);
    expect(res.error).toContain("disabled in hosted environment");
  });

  it("5. ML correlate findings returns findings unmodified when ML unavailable", () => {
    const finding = makeFinding("Reentrancy", "Vault", "withdraw");
    const mlResult: MLAnalysisResult = {
      predictions: [],
      modelName: "Disabled (Hosted)",
      available: false,
    };

    const correlated = correlateMLWithFindings([finding], mlResult);
    expect(correlated.length).toBe(1);
    expect(correlated[0].confidence).toBe("medium");
  });

  it("6. Existing benchmark contract findings remain unchanged", () => {
    const ast = makeMinimalAST("Vault");
    const beforeRes = detectSecurityVulnerabilities(ast);
    const mlRes = runMLInference("contract Vault {}");
    const correlatedFindings = correlateMLWithFindings(beforeRes.findings, mlRes);

    expect(mlRes.available).toBe(false);
    expect(correlatedFindings.length).toBe(beforeRes.findings.length);
    expect(beforeRes.summary.confirmedCount).toBe(0);
  });
});
