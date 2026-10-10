// ─── Block Number Dependency Precision Regression Tests ─────────────────────
//
// Benchmark expectations:
// 1. claimReward() with require(block.number >= startBlock) -> POTENTIAL Block Number Dependency
// 2. if(block.number > endBlock) in state-changing fn -> POTENTIAL Block Number Dependency
// 3. startRound() assignment (startBlock = block.number) -> NO vulnerability finding
// 4. isRoundActive() view getter -> NO separate vulnerability finding
// 5. blocksRemaining() view getter -> NO separate vulnerability finding
// 6. currentBlock() view helper -> NO vulnerability finding
// 7. constructor initialization -> NO vulnerability finding

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

describe("Block Number Dependency Precision Regression", () => {
  it("1. claimReward() require(block.number >= startBlock) -> POTENTIAL Block Number Dependency", () => {
    const fn: ASTFunction = {
      id: 1,
      name: "claimReward",
      contractName: "BlockNumberVulnerable",
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
          require(block.number >= startBlock, "Too early");
          require(block.number <= endBlock, "Too late");
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
      name: "BlockNumberVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        { id: 10, name: "startBlock", contractName: "BlockNumberVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 11, name: "endBlock", contractName: "BlockNumberVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC }
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
    const findings = res.findings.filter((f) => f.vulnerabilityType === "Block Number Dependency");
    expect(findings.length).toBe(1);
    expect(findings[0].classification).toBe("POTENTIAL");
  });

  it("2. if(block.number > endBlock) in state-changing fn -> POTENTIAL Block Number Dependency", () => {
    const fn: ASTFunction = {
      id: 2,
      name: "endRound",
      contractName: "BlockNumberVulnerableIf",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "endRound()",
      location: BASE_LOC,
      codeSnippet: `
        function endRound() public {
          if (block.number > endBlock) {
            roundEnded = true;
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
      name: "BlockNumberVulnerableIf",
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
    const findings = res.findings.filter((f) => f.vulnerabilityType === "Block Number Dependency");
    expect(findings.length).toBe(1);
    expect(findings[0].classification).toBe("POTENTIAL");
  });

  it("3. startRound() assignment (startBlock = block.number) -> NO vulnerability finding", () => {
    const fn: ASTFunction = {
      id: 3,
      name: "startRound",
      contractName: "BlockNumberVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "startRound()",
      location: BASE_LOC,
      codeSnippet: `
        function startRound() public {
          startBlock = block.number;
          endBlock = block.number + 100;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 3,
      name: "BlockNumberVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        { id: 30, name: "startBlock", contractName: "BlockNumberVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 31, name: "endBlock", contractName: "BlockNumberVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC }
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
    const findings = res.findings.filter((f) => f.vulnerabilityType === "Block Number Dependency");
    expect(findings.length).toBe(0);
  });

  it("4 & 5 & 6. view helpers (isRoundActive, blocksRemaining, currentBlock) -> NO vulnerability finding", () => {
    const isRoundActiveFn: ASTFunction = {
      id: 4,
      name: "isRoundActive",
      contractName: "BlockNumberVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "view",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [{ name: "", type: "bool" }],
      signature: "isRoundActive()",
      location: BASE_LOC,
      codeSnippet: `
        function isRoundActive() public view returns (bool) {
          return block.number >= startBlock && block.number <= endBlock;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const blocksRemainingFn: ASTFunction = {
      id: 5,
      name: "blocksRemaining",
      contractName: "BlockNumberVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "view",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [{ name: "", type: "uint256" }],
      signature: "blocksRemaining()",
      location: BASE_LOC,
      codeSnippet: `
        function blocksRemaining() public view returns (uint256) {
          if (block.number >= endBlock) return 0;
          return endBlock - block.number;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const currentBlockFn: ASTFunction = {
      id: 6,
      name: "currentBlock",
      contractName: "BlockNumberVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "view",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [{ name: "", type: "uint256" }],
      signature: "currentBlock()",
      location: BASE_LOC,
      codeSnippet: `
        function currentBlock() public view returns (uint256) {
          return block.number;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 4,
      name: "BlockNumberVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [isRoundActiveFn, blocksRemainingFn, currentBlockFn],
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
    const findings = res.findings.filter((f) => f.vulnerabilityType === "Block Number Dependency");
    expect(findings.length).toBe(0);
  });

  it("7. constructor initialization -> NO vulnerability finding", () => {
    const ctorFn: ASTFunction = {
      id: 7,
      name: "constructor",
      contractName: "BlockNumberVulnerable",
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
          startBlock = block.number;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 5,
      name: "BlockNumberVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [ctorFn],
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
    const findings = res.findings.filter((f) => f.vulnerabilityType === "Block Number Dependency");
    expect(findings.length).toBe(0);
  });
});
