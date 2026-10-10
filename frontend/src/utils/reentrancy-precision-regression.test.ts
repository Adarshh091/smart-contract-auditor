// ─── Reentrancy Precision Regression Tests ────────────────────────────────────
//
// Tests for Reentrancy Detection Precision:
//  1. Critical balance update after call -> CONFIRMED Reentrancy
//  2. Counter-only update after call (e.g. successfulTransfers) -> NOT CONFIRMED Reentrancy
//  3. CEI-safe withdrawal -> NOT CONFIRMED Reentrancy (NOT_VULNERABLE)
//  4. transfer/send with state after -> POTENTIAL Reentrancy (gas limit)
//  5. Reentrancy guard (nonReentrant / mutex) -> NOT_VULNERABLE
//  6. UncheckedExternalCall.sendPayment() & emergencyTransfer() -> NO CONFIRMED Reentrancy
//  7. NEW_YEARS_GIFT.Revoce() & SendReentrancyVulnerable -> POTENTIAL Reentrancy at most

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

describe("Reentrancy Precision Regression Tests", () => {
  it("1. Critical balance update after call -> CONFIRMED Reentrancy", () => {
    const fn: ASTFunction = {
      id: 1,
      name: "withdraw",
      contractName: "ReentrancyVulnerable",
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
          (bool success, ) = msg.sender.call{value: amount}("");
          require(success);
          balances[msg.sender] = 0;
        }
      `,
      externalCalls: [
        { id: "c1", contractName: "ReentrancyVulnerable", functionName: "withdraw", target: "msg.sender", method: "call", callType: "low-level-call", value: "amount", arguments: [], rawExpression: 'msg.sender.call{value: amount}("")', location: { ...BASE_LOC, line: 12 } }
      ],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 1,
      name: "ReentrancyVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        { id: 10, name: "balances", contractName: "ReentrancyVulnerable", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC }
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

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const confirmed = res.findings.filter((f) => f.vulnerabilityType === "Reentrancy" && f.classification === "CONFIRMED");
    expect(confirmed.length).toBe(1);
    expect(confirmed[0].functionName).toBe("withdraw");
  });

  it("2. Counter-only update after call (successfulTransfers) -> NOT CONFIRMED Reentrancy", () => {
    const fn: ASTFunction = {
      id: 2,
      name: "sendPayment",
      contractName: "UncheckedExternalCall",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "sendPayment()",
      location: BASE_LOC,
      codeSnippet: `
        function sendPayment() public {
          uint amount = balances[msg.sender];
          balances[msg.sender] = 0;
          (bool success, ) = recipient.call{value: amount}("");
          successfulTransfers += 1;
        }
      `,
      externalCalls: [
        { id: "c2", contractName: "UncheckedExternalCall", functionName: "sendPayment", target: "recipient", method: "call", callType: "low-level-call", value: "amount", arguments: [], rawExpression: 'recipient.call{value: amount}("")', location: { ...BASE_LOC, line: 14 } }
      ],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 2,
      name: "UncheckedExternalCall",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        { id: 20, name: "balances", contractName: "UncheckedExternalCall", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 21, name: "successfulTransfers", contractName: "UncheckedExternalCall", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC }
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

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const confirmed = res.findings.filter((f) => f.vulnerabilityType === "Reentrancy" && f.classification === "CONFIRMED");
    expect(confirmed.length).toBe(0);
  });

  it("3. CEI-safe withdrawal -> NOT CONFIRMED Reentrancy (NOT_VULNERABLE)", () => {
    const fn: ASTFunction = {
      id: 3,
      name: "withdraw",
      contractName: "ReentrancySafe",
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
          balances[msg.sender] = 0;
          (bool success, ) = msg.sender.call{value: amount}("");
          require(success);
        }
      `,
      externalCalls: [
        { id: "c3", contractName: "ReentrancySafe", functionName: "withdraw", target: "msg.sender", method: "call", callType: "low-level-call", value: "amount", arguments: [], rawExpression: 'msg.sender.call{value: amount}("")', location: { ...BASE_LOC, line: 14 } }
      ],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 3,
      name: "ReentrancySafe",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        { id: 30, name: "balances", contractName: "ReentrancySafe", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC }
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

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const confirmed = res.findings.filter((f) => f.vulnerabilityType === "Reentrancy" && f.classification === "CONFIRMED");
    expect(confirmed.length).toBe(0);
    const notVuln = res.findings.filter((f) => f.vulnerabilityType === "Reentrancy" && f.classification === "NOT_VULNERABLE");
    expect(notVuln.length).toBe(1);
  });

  it("4. transfer/send with state after -> POTENTIAL Reentrancy", () => {
    const fn: ASTFunction = {
      id: 4,
      name: "withdraw",
      contractName: "SendReentrancyVulnerable",
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
          bool ok = msg.sender.send(amount);
          require(ok);
          balances[msg.sender] = 0;
        }
      `,
      externalCalls: [
        { id: "c4", contractName: "SendReentrancyVulnerable", functionName: "withdraw", target: "msg.sender", method: "send", callType: "send", arguments: ["amount"], rawExpression: 'msg.sender.send(amount)', location: { ...BASE_LOC, line: 12 } }
      ],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 4,
      name: "SendReentrancyVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        { id: 40, name: "balances", contractName: "SendReentrancyVulnerable", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC }
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

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const confirmed = res.findings.filter((f) => f.vulnerabilityType === "Reentrancy" && f.classification === "CONFIRMED");
    expect(confirmed.length).toBe(0);
    const potential = res.findings.filter((f) => f.vulnerabilityType === "Reentrancy" && f.classification === "POTENTIAL");
    expect(potential.length).toBe(1);
  });

  it("5. Reentrancy guard -> NOT_VULNERABLE", () => {
    const fn: ASTFunction = {
      id: 5,
      name: "guardedWithdraw",
      contractName: "GuardedVault",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: ["nonReentrant"],
      parameters: [],
      returnParameters: [],
      signature: "guardedWithdraw()",
      location: BASE_LOC,
      codeSnippet: `
        function guardedWithdraw() public nonReentrant {
          uint amount = balances[msg.sender];
          (bool success, ) = msg.sender.call{value: amount}("");
          require(success);
          balances[msg.sender] = 0;
        }
      `,
      externalCalls: [
        { id: "c5", contractName: "GuardedVault", functionName: "guardedWithdraw", target: "msg.sender", method: "call", callType: "low-level-call", value: "amount", arguments: [], rawExpression: 'msg.sender.call{value: amount}("")', location: { ...BASE_LOC, line: 13 } }
      ],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 5,
      name: "GuardedVault",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        { id: 50, name: "balances", contractName: "GuardedVault", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC }
      ],
      modifiers: [
        { id: 500, name: "nonReentrant", contractName: "GuardedVault", parameters: [], location: BASE_LOC, invokedBy: ["guardedWithdraw()"] }
      ],
      events: [],
      structs: [],
      enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: [],
      controlStatements: [],
      location: BASE_LOC,
    };

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const notVuln = res.findings.filter((f) => f.vulnerabilityType === "Reentrancy" && f.classification === "NOT_VULNERABLE");
    expect(notVuln.length).toBe(1);
    expect(notVuln[0].reason).toContain("protected by a reentrancy guard");
  });
});
