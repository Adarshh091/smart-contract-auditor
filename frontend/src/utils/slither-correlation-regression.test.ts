import { describe, it, expect } from "vitest";
import { detectSecurityVulnerabilities } from "./security-detector";
import { correlateSlitherWithAST, parseSlitherFindings, isSlitherASTMatch } from "./slither-correlator";
import type { ASTAnalysisResult, ASTContract, ASTFunction } from "../types/ast";
import type { SecurityFinding } from "../types/security";

const BASE_LOC = { file: "Vault.sol", line: 20, column: 1, start: 200, length: 100, end: 300 };

const mockWithdrawFunc: ASTFunction = {
  id: 1,
  name: "withdraw",
  contractName: "Vault",
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
  externalCalls: [
    {
      id: "call1",
      contractName: "Vault",
      functionName: "withdraw",
      target: "msg.sender",
      method: "call",
      callType: "low-level-call",
      arguments: [],
      rawExpression: "msg.sender.call{value: amount}(\"\")",
      location: BASE_LOC,
    },
  ],
  etherTransfers: [
    {
      id: "transfer1",
      contractName: "Vault",
      functionName: "withdraw",
      recipient: "msg.sender",
      amount: "amount",
      transferType: "call-value",
      rawExpression: "msg.sender.call{value: amount}(\"\")",
      location: BASE_LOC,
    },
  ],
  controlStatements: [],
  operations: [],
};

const mockVaultContract: ASTContract = {
  id: 1,
  name: "Vault",
  kind: "contract",
  isAbstract: false,
  sourceFile: "Vault.sol",
  bases: [],
  functions: [mockWithdrawFunc],
  stateVariables: [
    {
      id: 2,
      name: "balances",
      contractName: "Vault",
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
  externalCalls: mockWithdrawFunc.externalCalls,
  etherTransfers: mockWithdrawFunc.etherTransfers,
  controlStatements: [],
  location: BASE_LOC,
};

const mockAst: ASTAnalysisResult = {
  contracts: [mockVaultContract],
  functions: [mockWithdrawFunc],
  stateVariables: mockVaultContract.stateVariables,
  modifiers: [],
  events: [],
  structs: [],
  enums: [],
  inheritance: [],
  externalCalls: mockVaultContract.externalCalls,
  etherTransfers: mockVaultContract.etherTransfers,
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
    totalEtherTransfers: 1,
    totalControlStatements: 0,
    publicOrExternalFunctions: 1,
    internalOrPrivateFunctions: 0,
    payableFunctions: 0,
    viewOrPureFunctions: 0,
  },
  rawAst: {},
};

describe("Slither + AST Result Correlation Engine", () => {
  it("1. Matching Slither + AST finding -> one merged finding with elevated confidence", () => {
    const astResult = detectSecurityVulnerabilities(mockAst);
    const initialConfirmedCount = astResult.summary.confirmedCount;
    expect(initialConfirmedCount).toBeGreaterThan(0);

    const slitherInput = [
      {
        check: "reentrancy-eth",
        impact: "High",
        confidence: "High",
        description: "State variables written after external call in Vault.withdraw",
        elements: [
          { type: "contract", name: "Vault" },
          { type: "function", name: "withdraw" },
        ],
      },
    ];

    const correlatedResult = detectSecurityVulnerabilities(mockAst, undefined, undefined, undefined, slitherInput);

    // ONE finding, not two
    const reentrancyFindings = correlatedResult.findings.filter(
      (f) => f.contractName === "Vault" && f.functionName === "withdraw" && f.vulnerabilityType === "Reentrancy"
    );
    expect(reentrancyFindings.length).toBe(1);

    const merged = reentrancyFindings[0];
    expect(merged.confidence).toBe("high");
    expect(merged.evidence.some((e) => e.includes("Correlation: Supported by both Slither and AST"))).toBe(true);
    expect(merged.evidence.some((e) => e.includes("reentrancy-eth"))).toBe(true);
  });

  it("2. AST-only finding -> preserved without downgrade", () => {
    const astResult = detectSecurityVulnerabilities(mockAst);
    const originalFinding = astResult.findings[0];

    // Slither returns empty/unrelated findings
    const slitherInput = [
      {
        check: "arbitrary-send-eth",
        contractName: "OtherContract",
        functionName: "foo",
        description: "Unrelated finding",
      },
    ];

    const correlatedResult = detectSecurityVulnerabilities(mockAst, undefined, undefined, undefined, slitherInput);

    const preserved = correlatedResult.findings.find(
      (f) => f.contractName === originalFinding.contractName && f.vulnerabilityType === originalFinding.vulnerabilityType
    );

    expect(preserved).toBeDefined();
    expect(preserved?.classification).toBe(originalFinding.classification);
  });

  it("3. Slither-only finding -> NOT automatically confirmed (kept as POTENTIAL signal)", () => {
    const slitherInput = [
      {
        check: "timestamp",
        impact: "Medium",
        confidence: "High",
        description: "Dependence on block.timestamp in Vault.withdraw",
        elements: [
          { type: "contract", name: "Vault" },
          { type: "function", name: "withdraw" },
        ],
      },
    ];

    const correlatedResult = detectSecurityVulnerabilities(mockAst, undefined, undefined, undefined, slitherInput);

    const slitherFinding = correlatedResult.findings.find(
      (f) => f.vulnerabilityType === "Timestamp Dependency"
    );

    expect(slitherFinding).toBeDefined();
    expect(slitherFinding?.classification).toBe("POTENTIAL");
    expect(slitherFinding?.classification).not.toBe("CONFIRMED");
    expect(slitherFinding?.evidence.some((e) => e.includes("Unverified Slither signal"))).toBe(true);
  });

  it("4. Duplicate suppression -> ensures no duplicate cards for same contract/func/type", () => {
    const astResult = detectSecurityVulnerabilities(mockAst);
    const slitherInput = [
      {
        check: "reentrancy-eth",
        contractName: "Vault",
        functionName: "withdraw",
        description: "Slither finding 1",
      },
      {
        check: "reentrancy-no-eth",
        contractName: "Vault",
        functionName: "withdraw",
        description: "Slither finding 2",
      },
    ];

    const correlatedResult = detectSecurityVulnerabilities(mockAst, undefined, undefined, undefined, slitherInput);

    const reentrancyCardCount = correlatedResult.findings.filter(
      (f) => f.contractName === "Vault" && f.functionName === "withdraw" && f.vulnerabilityType === "Reentrancy"
    ).length;

    expect(reentrancyCardCount).toBe(1);
  });

  it("5. Slither failure -> AST pipeline still works gracefully", () => {
    const astResult = detectSecurityVulnerabilities(mockAst);

    const badInputs = [
      "invalid-json-string",
      { success: false, error: "Compiler mismatch: solc 0.8.20 not found" },
      null,
      undefined,
      12345,
      { throwOnAccess: true },
    ];

    for (const badInput of badInputs) {
      expect(() => {
        const res = detectSecurityVulnerabilities(mockAst, undefined, undefined, undefined, badInput);
        expect(res.findings.length).toBe(astResult.findings.length);
      }).not.toThrow();
    }
  });

  it("6. Source location and function matching between Slither and AST", () => {
    const astFinding: SecurityFinding = {
      id: "f1",
      vulnerabilityType: "Reentrancy",
      title: "Reentrancy",
      severity: "high",
      confidence: "medium",
      classification: "CONFIRMED",
      contractName: "Vault",
      functionName: "withdraw",
      location: { file: "Vault.sol", line: 25, column: 1, endLine: 30, start: 100, length: 50, end: 150 },
      evidence: ["State written after call"],
      reason: "Reentrancy vulnerability detected",
      recommendation: "Use CEI",
    };

    const slitherMatch = parseSlitherFindings([
      {
        check: "reentrancy-eth",
        contractName: "Vault",
        functionName: "withdraw",
        description: "Reentrancy in Vault.withdraw",
        lines: [27],
      },
    ])[0];

    expect(isSlitherASTMatch(astFinding, slitherMatch, mockAst)).toBe(true);
  });
});
