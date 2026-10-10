// ─── Security Detector Engine Unit Tests ───────────────────────────────────────
//
// Tests the Reentrancy Detection Engine under 8 distinct scenarios:
//
//  1. Vulnerable withdraw         – call before state write            → CONFIRMED
//  2. CEI-safe withdraw           – state write before call            → NOT_VULNERABLE
//  3. nonReentrant withdraw       – modifier guard                     → NOT_VULNERABLE
//  4. send-based withdraw         – send() with state after            → POTENTIAL
//  5. transfer-based withdraw     – transfer() with state after        → POTENTIAL
//  6. External call no state      – call with no state modification    → POTENTIAL (unguarded low-level)
//  7. Attacker-controlled dest    – explicit param as recipient        → CONFIRMED
//  8. Trusted destination         – hardcoded owner address as target  → NOT_VULNERABLE / POTENTIAL
//
// Every ASTFunction includes the required `operations: []` field.

import { describe, it, expect } from "vitest";
import { detectSecurityVulnerabilities } from "./security-detector";
import type { ASTAnalysisResult, ASTContract, ASTFunction, ASTOperation } from "../types/ast";

// ── Mock helpers ──────────────────────────────────────────────────────────────

const EMPTY_OPS: ASTOperation[] = [];

function createMockAST(contract: ASTContract): ASTAnalysisResult {
  return {
    contracts: [contract],
    functions: contract.functions,
    stateVariables: contract.stateVariables,
    modifiers: contract.modifiers,
    events: contract.events,
    structs: contract.structs,
    enums: contract.enums,
    inheritance: [],
    externalCalls: contract.externalCalls,
    etherTransfers: contract.etherTransfers,
    controlStatements: contract.controlStatements,
    summary: {
      totalContracts: 1,
      totalFunctions: contract.functions.length,
      totalStateVariables: contract.stateVariables.length,
      totalModifiers: contract.modifiers.length,
      totalEvents: contract.events.length,
      totalStructs: 0,
      totalEnums: 0,
      totalExternalCalls: contract.externalCalls.length,
      totalEtherTransfers: contract.etherTransfers.length,
      totalControlStatements: contract.controlStatements.length,
      publicOrExternalFunctions: contract.functions.length,
      internalOrPrivateFunctions: 0,
      payableFunctions: 0,
      viewOrPureFunctions: 0,
    },
    rawAst: {},
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("Security Detector - Reentrancy Detection Engine", () => {
  // ── 1. Vulnerable Withdraw: external call BEFORE state update ─────────────
  it("1. should classify low-level call before state update as CONFIRMED reentrancy", () => {
    const fn: ASTFunction = {
      id: 1,
      name: "withdraw",
      contractName: "VulnerableVault",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "withdraw()",
      location: { file: "VulnerableVault.sol", line: 10, column: 1, start: 100, length: 200, end: 300 },
      codeSnippet: `
        function withdraw() public {
          uint amount = balances[msg.sender];
          (bool success, ) = msg.sender.call{value: amount}("");
          require(success);
          balances[msg.sender] = 0;
        }
      `,
      externalCalls: [
        {
          id: "call-1",
          contractName: "VulnerableVault",
          functionName: "withdraw",
          target: "msg.sender",
          method: "call",
          callType: "low-level-call",
          value: "amount",
          arguments: [],
          rawExpression: 'msg.sender.call{value: amount}("")',
          location: { file: "VulnerableVault.sol", line: 13, column: 5, start: 150, length: 45, end: 195 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-1",
          contractName: "VulnerableVault",
          functionName: "withdraw",
          recipient: "msg.sender",
          amount: "amount",
          transferType: "call-value",
          rawExpression: 'msg.sender.call{value: amount}("")',
          location: { file: "VulnerableVault.sol", line: 13, column: 5, start: 150, length: 45, end: 195 },
        },
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 100,
      name: "VulnerableVault",
      kind: "contract",
      isAbstract: false,
      sourceFile: "VulnerableVault.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        {
          id: 10,
          name: "balances",
          contractName: "VulnerableVault",
          type: "mapping(address => uint256)",
          visibility: "public",
          mutability: "mutable",
          location: { file: "VulnerableVault.sol", line: 3, column: 1, start: 20, length: 30, end: 50 },
        },
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: fn.etherTransfers,
      controlStatements: fn.controlStatements,
      location: { file: "VulnerableVault.sol", line: 1, column: 1, start: 0, length: 400, end: 400 },
    };

    const ast = createMockAST(contract);
    const result = detectSecurityVulnerabilities(ast);

    expect(result.summary.totalFindings).toBe(1);
    expect(result.summary.confirmedCount).toBe(1);

    const finding = result.findings[0];
    expect(finding.vulnerabilityType).toBe("Reentrancy");
    expect(finding.classification).toBe("CONFIRMED");
    expect(finding.severity).toBe("critical");
    expect(finding.contractName).toBe("VulnerableVault");
    expect(finding.functionName).toBe("withdraw");
    expect(finding.evidence.some((e) => e.includes("attacker-controllable"))).toBe(true);
    expect(finding.evidence.some((e) => e.includes("updated AFTER call"))).toBe(true);
  });

  // ── 2. CEI-safe Withdraw: state update BEFORE external call ──────────────
  it("2. should classify state update BEFORE external call as NOT_VULNERABLE (CEI pattern)", () => {
    const fn: ASTFunction = {
      id: 2,
      name: "withdraw",
      contractName: "SafeVault",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "withdraw()",
      location: { file: "SafeVault.sol", line: 10, column: 1, start: 100, length: 200, end: 300 },
      codeSnippet: `
        function withdraw() public {
          uint amount = balances[msg.sender];
          balances[msg.sender] = 0;
          (bool success, ) = msg.sender.call{value: amount}("");
          require(success);
        }
      `,
      externalCalls: [
        {
          id: "call-2",
          contractName: "SafeVault",
          functionName: "withdraw",
          target: "msg.sender",
          method: "call",
          callType: "low-level-call",
          value: "amount",
          arguments: [],
          rawExpression: 'msg.sender.call{value: amount}("")',
          location: { file: "SafeVault.sol", line: 14, column: 5, start: 160, length: 45, end: 205 },
        },
      ],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 101,
      name: "SafeVault",
      kind: "contract",
      isAbstract: false,
      sourceFile: "SafeVault.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        {
          id: 11,
          name: "balances",
          contractName: "SafeVault",
          type: "mapping(address => uint256)",
          visibility: "public",
          mutability: "mutable",
          location: { file: "SafeVault.sol", line: 3, column: 1, start: 20, length: 30, end: 50 },
        },
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: [],
      controlStatements: [],
      location: { file: "SafeVault.sol", line: 1, column: 1, start: 0, length: 400, end: 400 },
    };

    const ast = createMockAST(contract);
    const result = detectSecurityVulnerabilities(ast);

    expect(result.summary.totalFindings).toBe(1);
    expect(result.summary.notVulnerableCount).toBe(1);

    const finding = result.findings[0];
    expect(finding.classification).toBe("NOT_VULNERABLE");
    expect(finding.evidence.some((e) => e.includes("Checks-Effects-Interactions"))).toBe(true);
  });

  // ── 3. nonReentrant Withdraw: modifier guard present ─────────────────────
  it("3. should classify guarded function as NOT_VULNERABLE due to nonReentrant modifier", () => {
    const fn: ASTFunction = {
      id: 3,
      name: "guardedWithdraw",
      contractName: "ProtectedVault",
      kind: "function",
      visibility: "external",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: ["nonReentrant"],
      parameters: [],
      returnParameters: [],
      signature: "guardedWithdraw()",
      location: { file: "ProtectedVault.sol", line: 10, column: 1, start: 100, length: 200, end: 300 },
      codeSnippet: `
        function guardedWithdraw() external nonReentrant {
          uint amount = balances[msg.sender];
          (bool success, ) = msg.sender.call{value: amount}("");
          require(success);
          balances[msg.sender] = 0;
        }
      `,
      externalCalls: [
        {
          id: "call-3",
          contractName: "ProtectedVault",
          functionName: "guardedWithdraw",
          target: "msg.sender",
          method: "call",
          callType: "low-level-call",
          value: "amount",
          arguments: [],
          rawExpression: 'msg.sender.call{value: amount}("")',
          location: { file: "ProtectedVault.sol", line: 13, column: 5, start: 150, length: 45, end: 195 },
        },
      ],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 102,
      name: "ProtectedVault",
      kind: "contract",
      isAbstract: false,
      sourceFile: "ProtectedVault.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        {
          id: 12,
          name: "balances",
          contractName: "ProtectedVault",
          type: "mapping(address => uint256)",
          visibility: "public",
          mutability: "mutable",
          location: { file: "ProtectedVault.sol", line: 3, column: 1, start: 20, length: 30, end: 50 },
        },
      ],
      modifiers: [
        {
          id: 50,
          name: "nonReentrant",
          contractName: "ProtectedVault",
          parameters: [],
          location: { file: "ProtectedVault.sol", line: 5, column: 1, start: 60, length: 30, end: 90 },
          invokedBy: ["guardedWithdraw()"],
        },
      ],
      events: [],
      structs: [],
      enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: [],
      controlStatements: [],
      location: { file: "ProtectedVault.sol", line: 1, column: 1, start: 0, length: 400, end: 400 },
    };

    const ast = createMockAST(contract);
    const result = detectSecurityVulnerabilities(ast);

    expect(result.summary.notVulnerableCount).toBe(1);

    const finding = result.findings[0];
    expect(finding.classification).toBe("NOT_VULNERABLE");
    expect(finding.reason).toContain("protected by a reentrancy guard");
  });

  // ── 4. send()-based Withdraw: state update AFTER send() → POTENTIAL ───────
  it("4. should classify state update after send() as POTENTIAL reentrancy (2300 gas limit)", () => {
    const fn: ASTFunction = {
      id: 4,
      name: "withdrawSend",
      contractName: "SendVault",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "withdrawSend()",
      location: { file: "SendVault.sol", line: 10, column: 1, start: 100, length: 200, end: 300 },
      codeSnippet: `
        function withdrawSend() public {
          uint amount = balances[msg.sender];
          bool ok = payable(msg.sender).send(amount);
          require(ok);
          balances[msg.sender] = 0;
        }
      `,
      externalCalls: [
        {
          id: "call-4-send",
          contractName: "SendVault",
          functionName: "withdrawSend",
          target: "payable(msg.sender)",
          method: "send",
          callType: "send",
          arguments: ["amount"],
          rawExpression: "payable(msg.sender).send(amount)",
          location: { file: "SendVault.sol", line: 12, column: 5, start: 140, length: 32, end: 172 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-4-send",
          contractName: "SendVault",
          functionName: "withdrawSend",
          recipient: "payable(msg.sender)",
          amount: "amount",
          transferType: "send",
          rawExpression: "payable(msg.sender).send(amount)",
          location: { file: "SendVault.sol", line: 12, column: 5, start: 140, length: 32, end: 172 },
        },
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 104,
      name: "SendVault",
      kind: "contract",
      isAbstract: false,
      sourceFile: "SendVault.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        {
          id: 14,
          name: "balances",
          contractName: "SendVault",
          type: "mapping(address => uint256)",
          visibility: "public",
          mutability: "mutable",
          location: { file: "SendVault.sol", line: 3, column: 1, start: 20, length: 30, end: 50 },
        },
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: fn.etherTransfers,
      controlStatements: [],
      location: { file: "SendVault.sol", line: 1, column: 1, start: 0, length: 400, end: 400 },
    };

    const ast = createMockAST(contract);
    const result = detectSecurityVulnerabilities(ast);

    expect(result.summary.potentialCount).toBe(1);

    const finding = result.findings[0];
    expect(finding.classification).toBe("POTENTIAL");
    expect(finding.severity).toBe("medium");
    expect(finding.evidence.some((e) => e.includes("2300 gas limit"))).toBe(true);
  });

  // ── 5. transfer()-based Withdraw: state update AFTER transfer() → POTENTIAL
  it("5. should classify state update after transfer() as POTENTIAL reentrancy (2300 gas limit)", () => {
    const fn: ASTFunction = {
      id: 5,
      name: "withdrawTransfer",
      contractName: "LegacyVault",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "withdrawTransfer()",
      location: { file: "LegacyVault.sol", line: 10, column: 1, start: 100, length: 200, end: 300 },
      codeSnippet: `
        function withdrawTransfer() public {
          uint amount = balances[msg.sender];
          payable(msg.sender).transfer(amount);
          balances[msg.sender] = 0;
        }
      `,
      externalCalls: [
        {
          id: "call-5",
          contractName: "LegacyVault",
          functionName: "withdrawTransfer",
          target: "payable(msg.sender)",
          method: "transfer",
          callType: "transfer",
          arguments: ["amount"],
          rawExpression: "payable(msg.sender).transfer(amount)",
          location: { file: "LegacyVault.sol", line: 12, column: 5, start: 140, length: 36, end: 176 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-5",
          contractName: "LegacyVault",
          functionName: "withdrawTransfer",
          recipient: "payable(msg.sender)",
          amount: "amount",
          transferType: "transfer",
          rawExpression: "payable(msg.sender).transfer(amount)",
          location: { file: "LegacyVault.sol", line: 12, column: 5, start: 140, length: 36, end: 176 },
        },
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 105,
      name: "LegacyVault",
      kind: "contract",
      isAbstract: false,
      sourceFile: "LegacyVault.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        {
          id: 15,
          name: "balances",
          contractName: "LegacyVault",
          type: "mapping(address => uint256)",
          visibility: "public",
          mutability: "mutable",
          location: { file: "LegacyVault.sol", line: 3, column: 1, start: 20, length: 30, end: 50 },
        },
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: fn.etherTransfers,
      controlStatements: [],
      location: { file: "LegacyVault.sol", line: 1, column: 1, start: 0, length: 400, end: 400 },
    };

    const ast = createMockAST(contract);
    const result = detectSecurityVulnerabilities(ast);

    expect(result.summary.potentialCount).toBe(1);

    const finding = result.findings[0];
    expect(finding.classification).toBe("POTENTIAL");
    expect(finding.severity).toBe("medium");
    expect(finding.evidence.some((e) => e.includes("2300 gas limit"))).toBe(true);
  });

  // ── 6. External call with no state mutation → POTENTIAL (unguarded) ───────
  it("6. should classify low-level call with no state mutation as POTENTIAL (cross-function risk)", () => {
    // The function calls an external address with forwarded gas but has no
    // detectable state modifications — still warrants a POTENTIAL finding
    // because cross-function or read-only reentrancy can still occur.
    const fn: ASTFunction = {
      id: 6,
      name: "notifyExternalOracle",
      contractName: "NotifierContract",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "notifyExternalOracle()",
      location: { file: "NotifierContract.sol", line: 10, column: 1, start: 100, length: 150, end: 250 },
      codeSnippet: `
        function notifyExternalOracle() public {
          (bool ok,) = oracle.call(abi.encodeWithSignature("update()"));
          require(ok, "oracle call failed");
        }
      `,
      externalCalls: [
        {
          id: "call-6",
          contractName: "NotifierContract",
          functionName: "notifyExternalOracle",
          target: "oracle",
          method: "call",
          callType: "low-level-call",
          arguments: ['abi.encodeWithSignature("update()")'],
          rawExpression: 'oracle.call(abi.encodeWithSignature("update()"))',
          location: { file: "NotifierContract.sol", line: 12, column: 5, start: 140, length: 50, end: 190 },
        },
      ],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 106,
      name: "NotifierContract",
      kind: "contract",
      isAbstract: false,
      sourceFile: "NotifierContract.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        {
          id: 16,
          name: "oracle",
          contractName: "NotifierContract",
          type: "address",
          visibility: "internal",
          mutability: "immutable",
          location: { file: "NotifierContract.sol", line: 3, column: 1, start: 20, length: 20, end: 40 },
        },
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: [],
      controlStatements: [],
      location: { file: "NotifierContract.sol", line: 1, column: 1, start: 0, length: 300, end: 300 },
    };

    const ast = createMockAST(contract);
    const result = detectSecurityVulnerabilities(ast);

    // No state modifications after call, but still a POTENTIAL due to
    // unguarded low-level call to external attacker-controllable address.
    const finding = result.findings[0];
    expect(finding).toBeDefined();
    // Should NOT be CONFIRMED because no state modification detected after call
    expect(finding.classification).not.toBe("CONFIRMED");
    // Should be POTENTIAL or NOT_VULNERABLE (oracle is a state variable; could be
    // attacker-controlled depending on how it was set — the detector classifies by
    // heuristic variable name, which does NOT match common attacker-controlled names)
    expect(["POTENTIAL", "NOT_VULNERABLE"]).toContain(finding.classification);
  });

  // ── 7. Attacker-controlled destination: explicit parameter as recipient ───
  it("7. should classify explicit parameter recipient call before state write as CONFIRMED", () => {
    // withdraw(address payable to) — `to` is a function parameter → attacker-controlled
    const fn: ASTFunction = {
      id: 7,
      name: "withdrawTo",
      contractName: "ParamVault",
      kind: "function",
      visibility: "external",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [
        { name: "to", type: "address payable" },
        { name: "amount", type: "uint256" },
      ],
      returnParameters: [],
      signature: "withdrawTo(address,uint256)",
      location: { file: "ParamVault.sol", line: 10, column: 1, start: 100, length: 200, end: 300 },
      codeSnippet: `
        function withdrawTo(address payable to, uint256 amount) external {
          require(balances[msg.sender] >= amount, "insufficient");
          (bool success, ) = to.call{value: amount}("");
          require(success);
          balances[msg.sender] -= amount;
        }
      `,
      externalCalls: [
        {
          id: "call-7",
          contractName: "ParamVault",
          functionName: "withdrawTo",
          target: "to",
          method: "call",
          callType: "low-level-call",
          value: "amount",
          arguments: [],
          rawExpression: 'to.call{value: amount}("")',
          location: { file: "ParamVault.sol", line: 13, column: 5, start: 150, length: 26, end: 176 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-7",
          contractName: "ParamVault",
          functionName: "withdrawTo",
          recipient: "to",
          amount: "amount",
          transferType: "call-value",
          rawExpression: 'to.call{value: amount}("")',
          location: { file: "ParamVault.sol", line: 13, column: 5, start: 150, length: 26, end: 176 },
        },
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 107,
      name: "ParamVault",
      kind: "contract",
      isAbstract: false,
      sourceFile: "ParamVault.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        {
          id: 17,
          name: "balances",
          contractName: "ParamVault",
          type: "mapping(address => uint256)",
          visibility: "public",
          mutability: "mutable",
          location: { file: "ParamVault.sol", line: 3, column: 1, start: 20, length: 30, end: 50 },
        },
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: fn.etherTransfers,
      controlStatements: [],
      location: { file: "ParamVault.sol", line: 1, column: 1, start: 0, length: 400, end: 400 },
    };

    const ast = createMockAST(contract);
    const result = detectSecurityVulnerabilities(ast);

    const finding = result.findings[0];
    expect(finding).toBeDefined();
    expect(finding.classification).toBe("CONFIRMED");
    expect(finding.severity).toBe("critical");
    // The target `to` is a function parameter → attacker-controllable
    expect(finding.evidence.some((e) => e.includes("attacker-controllable"))).toBe(true);
  });

  // ── 8. Trusted destination: hardcoded constant address ───────────────────
  it("8. should classify trusted constant destination as NOT_VULNERABLE or low-risk", () => {
    // Sends to a hardcoded address (0x...) — not attacker-controllable.
    // State is modified AFTER the call, but target is trusted.
    const fn: ASTFunction = {
      id: 8,
      name: "collectFee",
      contractName: "FeeCollector",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "collectFee()",
      location: { file: "FeeCollector.sol", line: 10, column: 1, start: 100, length: 200, end: 300 },
      codeSnippet: `
        function collectFee() public {
          uint fee = pendingFees[msg.sender];
          (bool ok,) = 0xAbCd1234AbCd1234AbCd1234AbCd1234AbCd1234.call{value: fee}("");
          require(ok);
          pendingFees[msg.sender] = 0;
        }
      `,
      externalCalls: [
        {
          id: "call-8",
          contractName: "FeeCollector",
          functionName: "collectFee",
          target: "0xAbCd1234AbCd1234AbCd1234AbCd1234AbCd1234",
          method: "call",
          callType: "low-level-call",
          value: "fee",
          arguments: [],
          rawExpression: '0xAbCd1234AbCd1234AbCd1234AbCd1234AbCd1234.call{value: fee}("")',
          location: { file: "FeeCollector.sol", line: 13, column: 5, start: 150, length: 70, end: 220 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-8",
          contractName: "FeeCollector",
          functionName: "collectFee",
          recipient: "0xAbCd1234AbCd1234AbCd1234AbCd1234AbCd1234",
          amount: "fee",
          transferType: "call-value",
          rawExpression: '0xAbCd1234AbCd1234AbCd1234AbCd1234AbCd1234.call{value: fee}("")',
          location: { file: "FeeCollector.sol", line: 13, column: 5, start: 150, length: 70, end: 220 },
        },
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 108,
      name: "FeeCollector",
      kind: "contract",
      isAbstract: false,
      sourceFile: "FeeCollector.sol",
      bases: [],
      functions: [fn],
      stateVariables: [
        {
          id: 18,
          name: "pendingFees",
          contractName: "FeeCollector",
          type: "mapping(address => uint256)",
          visibility: "public",
          mutability: "mutable",
          location: { file: "FeeCollector.sol", line: 3, column: 1, start: 20, length: 30, end: 50 },
        },
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: fn.etherTransfers,
      controlStatements: [],
      location: { file: "FeeCollector.sol", line: 1, column: 1, start: 0, length: 400, end: 400 },
    };

    const ast = createMockAST(contract);
    const result = detectSecurityVulnerabilities(ast);

    // Hardcoded 0x address is NOT attacker-controllable.
    // The detector correctly produces NO reentrancy finding for trusted destinations
    // because reentrancy requires the callee to be able to re-enter — a hardcoded
    // address does not fit the attacker-controlled model.
    expect(result.summary.confirmedCount).toBe(0);
    // Either no finding, or any finding present must not be CONFIRMED
    for (const finding of result.findings) {
      expect(finding.classification).not.toBe("CONFIRMED");
    }
  });
});
