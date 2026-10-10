// ─── Timestamp Dependency Precision Regression Tests ─────────────────────────
//
// Benchmark expectations:
// 1. claimReward() with require(block.timestamp >= deadline) -> POTENTIAL Timestamp Dependency
// 2. if(now > deadline) in state-changing fn -> POTENTIAL Timestamp Dependency
// 3. isExpired() view getter -> NO separate vulnerability finding
// 4. timeRemaining() view getter -> NO separate vulnerability finding
// 5. constructor initialization (deadline = now + 1 days) -> NO vulnerability finding
// 6. setDeadline(uint newDeadline) require(newDeadline > now) -> NO vulnerability finding

import { describe, it, expect } from "vitest";
import { detectSecurityVulnerabilities } from "./security-detector";
import type { ASTAnalysisResult, ASTContract, ASTFunction, ASTOperation } from "../types/ast";

const EMPTY_OPS: ASTOperation[] = [];
const BASE_LOC = { file: "Test.sol", line: 10, column: 1, start: 100, length: 200, end: 300 };

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

describe("Timestamp Dependency Precision Regression", () => {
  it("1. claimReward() require(block.timestamp >= deadline) -> POTENTIAL Timestamp Dependency", () => {
    const fn: ASTFunction = {
      id: 1,
      name: "claimReward",
      contractName: "TimestampVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "claimReward()",
      location: BASE_LOC,
      codeSnippet: `
        function claimReward() public {
          require(block.timestamp >= deadline, "Not ended");
          payable(msg.sender).transfer(1 ether);
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 1,
      name: "TimestampVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        { id: 10, name: "deadline", contractName: "TimestampVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC }
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
    const findings = res.findings.filter((f) => f.vulnerabilityType === "Timestamp Dependency");
    expect(findings.length).toBe(1);
    expect(findings[0].classification).toBe("POTENTIAL");
  });

  it("2. if(now > deadline) in state-changing fn -> POTENTIAL Timestamp Dependency", () => {
    const fn: ASTFunction = {
      id: 2,
      name: "finalize",
      contractName: "TimestampVulnerableIf",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "finalize()",
      location: BASE_LOC,
      codeSnippet: `
        function finalize() public {
          if (now > deadline) {
            ended = true;
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
      name: "TimestampVulnerableIf",
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
    const findings = res.findings.filter((f) => f.vulnerabilityType === "Timestamp Dependency");
    expect(findings.length).toBe(1);
  });

  it("3 & 4. view getters (isExpired, timeRemaining) -> NO separate vulnerability finding", () => {
    const isExpiredFn: ASTFunction = {
      id: 3,
      name: "isExpired",
      contractName: "TimestampVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "view",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [{ name: "", type: "bool" }],
      signature: "isExpired()",
      location: BASE_LOC,
      codeSnippet: `
        function isExpired() public view returns (bool) {
          return block.timestamp >= deadline;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const timeRemainingFn: ASTFunction = {
      id: 4,
      name: "timeRemaining",
      contractName: "TimestampVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "view",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [{ name: "", type: "uint256" }],
      signature: "timeRemaining()",
      location: BASE_LOC,
      codeSnippet: `
        function timeRemaining() public view returns (uint256) {
          if (block.timestamp >= deadline) return 0;
          return deadline - block.timestamp;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 3,
      name: "TimestampVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [isExpiredFn, timeRemainingFn],
      stateVariables: [
        { id: 30, name: "deadline", contractName: "TimestampVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC }
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
    const findings = res.findings.filter((f) => f.vulnerabilityType === "Timestamp Dependency");
    expect(findings.length).toBe(0);
  });

  it("5. constructor initialization (deadline = now + 1 days) -> NO Timestamp vulnerability", () => {
    const ctorFn: ASTFunction = {
      id: 5,
      name: "constructor",
      contractName: "TimestampVulnerable",
      kind: "constructor",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "constructor()",
      location: BASE_LOC,
      codeSnippet: `
        constructor() {
          deadline = now + 1 days;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 4,
      name: "TimestampVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [ctorFn],
      stateVariables: [
        { id: 40, name: "deadline", contractName: "TimestampVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC }
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
    const findings = res.findings.filter((f) => f.vulnerabilityType === "Timestamp Dependency");
    expect(findings.length).toBe(0);
  });

  it("6. setDeadline(newDeadline) require(newDeadline > now) -> NO Timestamp vulnerability", () => {
    const setDeadlineFn: ASTFunction = {
      id: 6,
      name: "setDeadline",
      contractName: "TimestampVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "newDeadline", type: "uint256" }],
      returnParameters: [],
      signature: "setDeadline(uint256)",
      location: BASE_LOC,
      codeSnippet: `
        function setDeadline(uint256 newDeadline) public {
          require(newDeadline > now, "Must be future");
          deadline = newDeadline;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 5,
      name: "TimestampVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [setDeadlineFn],
      stateVariables: [
        { id: 50, name: "deadline", contractName: "TimestampVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC }
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
    const findings = res.findings.filter((f) => f.vulnerabilityType === "Timestamp Dependency");
    expect(findings.length).toBe(0);
  });
});
