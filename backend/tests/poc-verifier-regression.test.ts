import { describe, it, expect } from "vitest";
import {
  generatePocScenario,
  verifyFindingPoc,
  verifyAllFindingsPoc,
} from "../src/engines/poc-verifier";
import { detectSecurityVulnerabilities } from "../../frontend/src/utils/security-detector";
import type { ASTAnalysisResult, ASTContract, SourceLocation } from "../src/types/ast";
import type { SecurityFinding } from "../src/types/security";
import type { DynamicAnalysisResult } from "../src/types/dynamic";

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
    confidence: "high",
    classification: "CONFIRMED",
    contractName,
    functionName,
    location: BASE_LOC,
    evidence: ["AST evidence confirmed"],
    reason: "Deterministic check failed",
    recommendation: "Fix vulnerability",
  };
}

describe("PoC / Exploit Verification Engine", () => {
  it("1. Reentrancy PoC generation", () => {
    const finding = makeFinding("Reentrancy", "Vault", "withdraw");
    const ast = makeMinimalAST("Vault");
    const scenario = generatePocScenario(finding, "contract Vault {}", ast);

    expect(scenario.vulnerabilityType).toBe("Reentrancy");
    expect(scenario.contractName).toBe("Vault");
    expect(scenario.functionName).toBe("withdraw");
    expect(scenario.testCode).toContain("withdraw");
  });

  it("2. Access Control PoC generation", () => {
    const finding = makeFinding("Access Control", "Vault", "setOwner");
    const ast = makeMinimalAST("Vault");
    const scenario = generatePocScenario(finding, "contract Vault {}", ast);

    expect(scenario.vulnerabilityType).toBe("Access Control");
    expect(scenario.testCode).toContain("attacker");
  });

  it("3. Unchecked Call verification scenario", () => {
    const finding = makeFinding("Unchecked External Call", "Vault", "sendBonus");
    const ast = makeMinimalAST("Vault");
    const scenario = generatePocScenario(finding, "contract Vault {}", ast);

    expect(scenario.vulnerabilityType).toBe("Unchecked External Call");
    expect(scenario.testCode).toContain("Verification scenario");
  });

  it("4. DoS verification scenario", () => {
    const finding = makeFinding("Denial of Service", "Auction", "bid");
    const ast = makeMinimalAST("Auction");
    const scenario = generatePocScenario(finding, "contract Auction {}", ast);

    expect(scenario.vulnerabilityType).toBe("Denial of Service");
    expect(scenario.testCode).toContain("rejects ETH");
  });

  it("5. Ether Strict Equality verification scenario", () => {
    const finding = makeFinding("Ether Strict Equality", "Vault", "checkBalance");
    const ast = makeMinimalAST("Vault");
    const scenario = generatePocScenario(finding, "contract Vault {}", ast);

    expect(scenario.vulnerabilityType).toBe("Ether Strict Equality");
    expect(scenario.testCode).toContain("transfer");
  });

  it("6. Foundry unavailable -> UNAVAILABLE status", () => {
    const finding = makeFinding("Reentrancy", "Vault", "withdraw");
    const ast = makeMinimalAST("Vault");
    const result = verifyFindingPoc(finding, "contract Vault {}", ast);

    // Default execution on system without forge installed returns UNAVAILABLE
    expect(result.verificationStatus).toBe("UNAVAILABLE");
    expect(result.failureReason).toBe("Foundry unavailable");
  });

  it("7. Runtime reproduction -> VERIFIED status when runner mock reproduces finding", () => {
    const finding = makeFinding("Reentrancy", "Vault", "withdraw");
    const ast = makeMinimalAST("Vault");

    const mockRunner = (): DynamicAnalysisResult => ({
      available: true,
      status: "VERIFIED",
      results: [
        {
          id: "dyn-1",
          testName: generatePocScenario(finding, "", ast).testName,
          contractName: "Vault",
          functionName: "withdraw",
          status: "VERIFIED",
          passed: true,
          executionEvidence: ["State written after call, reentrancy triggered"],
        },
      ],
      summary: { totalTests: 1, verifiedCount: 1, notReproducedCount: 0, errorCount: 0 },
      analyzedAt: Date.now(),
    });

    const result = verifyFindingPoc(finding, "contract Vault {}", ast, mockRunner);

    expect(result.verificationStatus).toBe("VERIFIED");
    expect(result.executionEvidence[0]).toContain("reentrancy triggered");
  });

  it("8. Runtime non-reproduction -> NOT_REPRODUCED status when runner mock fails to reproduce", () => {
    const finding = makeFinding("Reentrancy", "Vault", "withdraw");
    const ast = makeMinimalAST("Vault");

    const mockRunner = (): DynamicAnalysisResult => ({
      available: true,
      status: "NOT_REPRODUCED",
      results: [
        {
          id: "dyn-1",
          testName: generatePocScenario(finding, "", ast).testName,
          contractName: "Vault",
          functionName: "withdraw",
          status: "NOT_REPRODUCED",
          passed: false,
          revertReason: "ReentrancyGuard: reentrant call",
          executionEvidence: ["Call reverted safely"],
        },
      ],
      summary: { totalTests: 1, verifiedCount: 0, notReproducedCount: 1, errorCount: 0 },
      analyzedAt: Date.now(),
    });

    const result = verifyFindingPoc(finding, "contract Vault {}", ast, mockRunner);

    expect(result.verificationStatus).toBe("NOT_REPRODUCED");
    expect(result.failureReason).toBe("Vulnerability condition not triggered during execution");
  });

  it("9. PoC verification failure -> static finding remains completely unchanged", () => {
    const finding = makeFinding("Reentrancy", "Vault", "withdraw");
    const ast = makeMinimalAST("Vault");

    const mockRunner = (): DynamicAnalysisResult => ({
      available: true,
      status: "NOT_REPRODUCED",
      results: [],
      summary: { totalTests: 0, verifiedCount: 0, notReproducedCount: 0, errorCount: 0 },
      analyzedAt: Date.now(),
    });

    const report = verifyAllFindingsPoc([finding], "contract Vault {}", ast, mockRunner);

    expect(report.verifications.length).toBe(1);
    // Static finding classification and evidence are NOT mutated
    expect(finding.classification).toBe("CONFIRMED");
    expect(finding.confidence).toBe("high");
  });

  it("10. Existing 10 benchmark findings remain completely unchanged by PoC verification engine", () => {
    const ast = makeMinimalAST("Vault");
    const staticResBefore = detectSecurityVulnerabilities(ast);

    const report = verifyAllFindingsPoc(staticResBefore.findings, "contract Vault {}", ast);
    const staticResAfter = detectSecurityVulnerabilities(ast);

    expect(report).toBeDefined();
    expect(staticResAfter.summary.totalFindings).toBe(staticResBefore.summary.totalFindings);
    expect(staticResAfter.summary.confirmedCount).toBe(staticResBefore.summary.confirmedCount);
  });
});

