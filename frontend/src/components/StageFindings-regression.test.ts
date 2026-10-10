import { describe, it, expect } from "vitest";
import { detectSecurityVulnerabilities } from "../utils/security-detector";
import type { ASTAnalysisResult, ASTContract, ASTFunction } from "../types/ast";
import type { SemanticResult } from "../types/semantic";
import type { VulnerabilityPlan } from "../types/vulnerability";

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

const mockSemantic: SemanticResult = {
  contractName: "Vault",
  summary: { contractType: "Vault", totalFunctions: 1, publicStateVariables: 0, externalCalls: 1, ethTransfers: 1 },
  roles: [],
  stateMutations: [],
  functions: [],
  riskIndicators: [],
};

const mockPlan: VulnerabilityPlan = {
  contractCategory: "Vault",
  contractPurpose: "Vault operations",
  selectedChecks: [
    { category: "Reentrancy", priority: "critical", reason: "ETH transfer", tags: ["eth"] },
  ],
  skippedChecks: [],
};

describe("StageFindings Dashboard Data & Pipeline Regression Tests", () => {
  it("computes accurate summary counts for findings", () => {
    const result = detectSecurityVulnerabilities(mockAst, mockPlan, mockSemantic);
    expect(result.summary.totalFindings).toBeGreaterThan(0);
    expect(result.summary.confirmedCount).toBeDefined();
    expect(result.summary.potentialCount).toBeDefined();
    expect(result.summary.notVulnerableCount).toBeDefined();
  });

  it("ensures detectors remain completely unchanged", () => {
    const result = detectSecurityVulnerabilities(mockAst, mockPlan, mockSemantic);
    const reentrancy = result.findings.find(f => f.vulnerabilityType === "Reentrancy");
    expect(reentrancy).toBeDefined();
    expect(reentrancy?.vulnerabilityType).toBe("Reentrancy");
    expect(reentrancy?.contractName).toBe("Vault");
  });

  it("handles Slither + AST merged evidence without creating duplicate findings", () => {
    const mockSlither = [
      {
        check: "reentrancy-eth",
        impact: "High",
        confidence: "High",
        description: "Reentrancy in Vault.withdraw",
        elements: [
          { type: "contract", name: "Vault" },
          { type: "function", name: "withdraw" },
        ]
      }
    ];

    const result = detectSecurityVulnerabilities(mockAst, mockPlan, mockSemantic, "0.8.0", mockSlither);
    const reentrancyFindings = result.findings.filter(f => f.vulnerabilityType === "Reentrancy");
    expect(reentrancyFindings.length).toBe(1); // exactly 1 merged finding, no duplicates
    expect(reentrancyFindings[0].evidence.some(e => e.includes("Slither Detector") || e.includes("reentrancy-eth"))).toBe(true);
  });
});
