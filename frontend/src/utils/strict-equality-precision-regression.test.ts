// ─── Ether Strict Equality Precision Regression Tests ─────────────────────────
//
// Tests for Ether Strict Equality Detection Precision:
//  1. require(address(this).balance == target) in state-changing fn -> CONFIRMED
//  2. if(address(this).balance == target) in state-changing fn -> CONFIRMED
//  3. view-only equality helper (exactBalanceReached) -> NO confirmed vulnerability
//  4. selfdestruct without equality -> NO Ether Strict Equality finding or candidate
//  5. payable/transfer without equality -> NO Ether Strict Equality finding
//  6. StrictEqualityVulnerable.checkBalance() vs exactBalanceReached() benchmark rules

import { describe, it, expect } from "vitest";
import { detectSecurityVulnerabilities } from "./security-detector";
import { buildVulnerabilityPlan } from "./vulnerability-analyzer";
import type { ASTAnalysisResult, ASTContract, ASTFunction, ASTOperation } from "../types/ast";
import type { SemanticResult } from "../types/semantic";

const EMPTY_OPS: ASTOperation[] = [];
const BASE_LOC = { file: "Test.sol", line: 10, column: 1, start: 100, length: 200, end: 300 };

const DUMMY_SEMANTIC: SemanticResult = {
  purpose: "A smart contract",
  category: "Other",
  confidence: 0.8,
  assets: ["ETH"],
  mainFunctions: [],
  criticalOperations: [],
  accessControl: [],
  externalInteractions: [],
  financialOperations: [],
  securityCriticalAreas: [],
};

function makeAST(contracts: ASTContract[]): ASTAnalysisResult {
  return {
    contracts,
    functions: contracts.flatMap((c) => c.functions),
    stateVariables: contracts.flatMap((c) => c.stateVariables),
    modifiers: [],
    events: [],
    structs: [],
    enums: [],
    inheritance: [],
    externalCalls: contracts.flatMap((c) => c.externalCalls),
    etherTransfers: contracts.flatMap((c) => c.etherTransfers),
    controlStatements: [],
    summary: {
      totalContracts: contracts.length,
      totalFunctions: contracts.reduce((n, c) => n + c.functions.length, 0),
      totalStateVariables: contracts.reduce((n, c) => n + c.stateVariables.length, 0),
      totalModifiers: 0,
      totalEvents: 0,
      totalStructs: 0,
      totalEnums: 0,
      totalExternalCalls: contracts.reduce((n, c) => n + c.externalCalls.length, 0),
      totalEtherTransfers: contracts.reduce((n, c) => n + c.etherTransfers.length, 0),
      totalControlStatements: 0,
      publicOrExternalFunctions: contracts.reduce((n, c) => n + c.functions.length, 0),
      internalOrPrivateFunctions: 0,
      payableFunctions: 0,
      viewOrPureFunctions: 0,
    },
    rawAst: {},
  };
}

describe("Ether Strict Equality Precision Regression", () => {
  it("1. require(address(this).balance == target) in execution path -> CONFIRMED", () => {
    const fn: ASTFunction = {
      id: 1,
      name: "checkBalance",
      contractName: "StrictEqualityVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "checkBalance()",
      location: BASE_LOC,
      codeSnippet: `
        function checkBalance() public {
          require(address(this).balance == targetBalance, "Balance mismatch");
          isGoalReached = true;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 1,
      name: "StrictEqualityVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        { id: 10, name: "targetBalance", contractName: "StrictEqualityVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 11, name: "isGoalReached", contractName: "StrictEqualityVulnerable", type: "bool", visibility: "public", mutability: "mutable", location: BASE_LOC }
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      location: BASE_LOC,
    };

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const confirmed = res.findings.filter((f) => f.vulnerabilityType === "Ether Strict Equality" && f.classification === "CONFIRMED");
    expect(confirmed.length).toBe(1);
    expect(confirmed[0].functionName).toBe("checkBalance");
  });

  it("2. if(address(this).balance == target) in execution path -> CONFIRMED", () => {
    const fn: ASTFunction = {
      id: 2,
      name: "processIfEqual",
      contractName: "StrictEqualityIf",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "processIfEqual()",
      location: BASE_LOC,
      codeSnippet: `
        function processIfEqual() public {
          if (address(this).balance == 10 ether) {
            payoutWinner();
          }
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 2,
      name: "StrictEqualityIf",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [fn],
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

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const confirmed = res.findings.filter((f) => f.vulnerabilityType === "Ether Strict Equality" && f.classification === "CONFIRMED");
    expect(confirmed.length).toBe(1);
    expect(confirmed[0].functionName).toBe("processIfEqual");
  });

  it("3. view-only equality helper (exactBalanceReached) -> NO confirmed vulnerability", () => {
    const viewFn: ASTFunction = {
      id: 3,
      name: "exactBalanceReached",
      contractName: "StrictEqualityVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "view",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [{ name: "", type: "bool" }],
      signature: "exactBalanceReached()",
      location: BASE_LOC,
      codeSnippet: `
        function exactBalanceReached() public view returns (bool) {
          return address(this).balance == targetBalance;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 3,
      name: "StrictEqualityVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [viewFn],
      stateVariables: [
        { id: 30, name: "targetBalance", contractName: "StrictEqualityVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC }
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      location: BASE_LOC,
    };

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const confirmed = res.findings.filter((f) => f.vulnerabilityType === "Ether Strict Equality");
    expect(confirmed.length).toBe(0);
  });

  it("4. selfdestruct without equality -> NO Ether Strict Equality finding or candidate", () => {
    const destroyFn: ASTFunction = {
      id: 4,
      name: "destroyContract",
      contractName: "AccessControlVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "destroyContract()",
      location: BASE_LOC,
      codeSnippet: "function destroyContract() public { selfdestruct(payable(msg.sender)); }",
      externalCalls: [],
      etherTransfers: [
        { id: "e1", contractName: "AccessControlVulnerable", functionName: "destroyContract", recipient: "msg.sender", amount: "balance", transferType: "selfdestruct", rawExpression: "selfdestruct(payable(msg.sender))", location: BASE_LOC }
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 4,
      name: "AccessControlVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [destroyFn],
      stateVariables: [],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: [],
      etherTransfers: destroyFn.etherTransfers,
      controlStatements: [],
      location: BASE_LOC,
    };

    const ast = makeAST([contract]);

    // Check candidate selection in vulnerability plan
    const plan = buildVulnerabilityPlan(DUMMY_SEMANTIC, ast);
    const candidate = plan.selectedChecks.find((c) => c.category === "Ether Strict Equality");
    expect(candidate).toBeUndefined();

    // Check security detector findings
    const res = detectSecurityVulnerabilities(ast);
    const finding = res.findings.find((f) => f.vulnerabilityType === "Ether Strict Equality");
    expect(finding).toBeUndefined();
  });

  it("5. payable/transfer without equality -> NO Ether Strict Equality finding", () => {
    const revoceFn: ASTFunction = {
      id: 5,
      name: "Revoce",
      contractName: "NEW_YEARS_GIFT",
      kind: "function",
      visibility: "public",
      stateMutability: "payable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "Revoce()",
      location: BASE_LOC,
      codeSnippet: `
        function Revoce() public payable {
          require(msg.value >= 1 ether);
          payable(msg.sender).transfer(address(this).balance);
        }
      `,
      externalCalls: [
        { id: "c1", contractName: "NEW_YEARS_GIFT", functionName: "Revoce", target: "payable(msg.sender)", method: "transfer", callType: "transfer", arguments: ["address(this).balance"], rawExpression: "payable(msg.sender).transfer(address(this).balance)", location: BASE_LOC }
      ],
      etherTransfers: [
        { id: "e2", contractName: "NEW_YEARS_GIFT", functionName: "Revoce", recipient: "payable(msg.sender)", amount: "address(this).balance", transferType: "transfer", rawExpression: "payable(msg.sender).transfer(address(this).balance)", location: BASE_LOC }
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 5,
      name: "NEW_YEARS_GIFT",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [revoceFn],
      stateVariables: [],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: revoceFn.externalCalls,
      etherTransfers: revoceFn.etherTransfers,
      controlStatements: [],
      location: BASE_LOC,
    };

    const ast = makeAST([contract]);
    const res = detectSecurityVulnerabilities(ast);
    const finding = res.findings.find((f) => f.vulnerabilityType === "Ether Strict Equality");
    expect(finding).toBeUndefined();
  });
});
