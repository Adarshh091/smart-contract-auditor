// ─── DoS Detector Regression Tests ────────────────────────────────────────────
//
// Benchmark expectations (from specification):
//
//  1. DosAuction.bid()      require(currentFrontrunner.send(currentBid))
//                           → CONFIRMED DoS
//  2. SecureAuction.bid()   no blocking send in require()
//                           → NO DoS
//  3. msg.sender.send(x)    self-affecting only
//                           → NO DoS (any classification)
//  4. msg.sender.transfer(x) self-affecting only
//                           → NO DoS (any classification)
//  5. treasury.transfer(x)  bare transfer to stored address, no require()
//                           → NO confirmed DoS
//  6. SendReentrancyVulnerable.withdraw()  msg.sender.send — not global DoS
//                           → NO confirmed global DoS
//  7. SendReentrancyVulnerable.payout()   msg.sender.transfer — not global DoS
//                           → NO confirmed global DoS
//  8. AccessControlVulnerable.emergencyWithdraw() msg.sender.transfer
//                           → NO confirmed DoS
//  9. AccessControlVulnerable.adminSweep() treasury.transfer
//                           → NO confirmed DoS
// 10. BlockNumberVulnerable.claimReward()  msg.sender.transfer exists
//                           → NO DoS merely because msg.sender.transfer() exists

import { describe, it, expect } from "vitest";
import { detectSecurityVulnerabilities } from "./security-detector";
import type { ASTAnalysisResult, ASTContract, ASTFunction, ASTOperation } from "../types/ast";

// ── Helpers ────────────────────────────────────────────────────────────────────

const EMPTY_OPS: ASTOperation[] = [];
const BASE_LOC = { file: "Test.sol", line: 10, column: 1, start: 100, length: 200, end: 300 };

function makeAST(contracts: ASTContract[]): ASTAnalysisResult {
  return {
    contracts,
    functions: contracts.flatMap(c => c.functions),
    stateVariables: contracts.flatMap(c => c.stateVariables),
    modifiers: [],
    events: [],
    structs: [],
    enums: [],
    inheritance: [],
    externalCalls: contracts.flatMap(c => c.externalCalls),
    etherTransfers: contracts.flatMap(c => c.etherTransfers),
    controlStatements: [],
    summary: {
      totalContracts: contracts.length,
      totalFunctions: contracts.reduce((n, c) => n + c.functions.length, 0),
      totalStateVariables: contracts.reduce((n, c) => n + c.stateVariables.length, 0),
      totalModifiers: 0, totalEvents: 0, totalStructs: 0, totalEnums: 0,
      totalExternalCalls: contracts.reduce((n, c) => n + c.externalCalls.length, 0),
      totalEtherTransfers: contracts.reduce((n, c) => n + c.etherTransfers.length, 0),
      totalControlStatements: 0,
      publicOrExternalFunctions: contracts.reduce((n, c) => n + c.functions.length, 0),
      internalOrPrivateFunctions: 0, payableFunctions: 0, viewOrPureFunctions: 0,
    },
    rawAst: {},
  };
}

// ── 1 + 2: DosAuction (CONFIRMED) and SecureAuction (NO DoS) ──────────────────

describe("DoS Regression — 1. DosAuction.bid() must be CONFIRMED DoS", () => {
  it("require(currentFrontrunner.send(currentBid)) → CONFIRMED DoS", () => {
    const dosBid: ASTFunction = {
      id: 1, name: "bid", contractName: "DosAuction", kind: "function",
      visibility: "public", stateMutability: "payable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "bid()",
      location: BASE_LOC,
      codeSnippet: `
        function bid() public payable {
          require(msg.value > currentBid);
          if (currentFrontrunner != address(0)) {
            require(currentFrontrunner.send(currentBid));
          }
          currentFrontrunner = msg.sender;
          currentBid = msg.value;
        }
      `,
      externalCalls: [
        {
          id: "c1", contractName: "DosAuction", functionName: "bid",
          target: "currentFrontrunner", method: "send", callType: "send",
          arguments: ["currentBid"], rawExpression: "currentFrontrunner.send(currentBid)",
          location: { ...BASE_LOC, line: 14 },
        },
      ],
      etherTransfers: [
        {
          id: "t1", contractName: "DosAuction", functionName: "bid",
          recipient: "currentFrontrunner", amount: "currentBid",
          transferType: "send", rawExpression: "currentFrontrunner.send(currentBid)",
          location: { ...BASE_LOC, line: 14 },
        },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };

    const dosAuction: ASTContract = {
      id: 1, name: "DosAuction", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [dosBid],
      stateVariables: [
        { id: 10, name: "currentFrontrunner", contractName: "DosAuction", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 11, name: "currentBid", contractName: "DosAuction", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: dosBid.externalCalls,
      etherTransfers: dosBid.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    };

    const result = detectSecurityVulnerabilities(makeAST([dosAuction]));
    const dosFind = result.findings.find(
      f => f.contractName === "DosAuction" && f.vulnerabilityType === "Denial of Service"
    );
    expect(dosFind).toBeDefined();
    expect(dosFind!.classification).toBe("CONFIRMED");
    expect(dosFind!.severity).toBe("high");
  });
});

describe("DoS Regression — 2. SecureAuction.bid() must have NO DoS", () => {
  it("bid() with pull-pattern refund mapping → no DoS finding", () => {
    const secBid: ASTFunction = {
      id: 2, name: "bid", contractName: "SecureAuction", kind: "function",
      visibility: "external", stateMutability: "payable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "bid()",
      location: BASE_LOC,
      codeSnippet: `
        function bid() external payable {
          require(msg.value > currentBid);
          if (currentFrontrunner != address(0)) {
            refunds[currentFrontrunner] += currentBid;
          }
          currentFrontrunner = msg.sender;
          currentBid = msg.value;
        }
      `,
      // No external calls that can block execution
      externalCalls: [], etherTransfers: [], controlStatements: [], operations: EMPTY_OPS,
    };

    const secAuction: ASTContract = {
      id: 2, name: "SecureAuction", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [secBid],
      stateVariables: [
        { id: 20, name: "currentFrontrunner", contractName: "SecureAuction", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 21, name: "currentBid", contractName: "SecureAuction", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 22, name: "refunds", contractName: "SecureAuction", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: [], etherTransfers: [], controlStatements: [], location: BASE_LOC,
    };

    const result = detectSecurityVulnerabilities(makeAST([secAuction]));
    const dosFind = result.findings.find(
      f => f.contractName === "SecureAuction" && f.vulnerabilityType === "Denial of Service"
    );
    expect(dosFind).toBeUndefined();
  });
});

// ── 3: msg.sender.send() must NOT be DoS ──────────────────────────────────────

describe("DoS Regression — 3. msg.sender.send(amount) must NOT be flagged as DoS", () => {
  it("bare msg.sender.send in withdraw() → no DoS finding", () => {
    const fn: ASTFunction = {
      id: 3, name: "withdraw", contractName: "WithdrawVault", kind: "function",
      visibility: "public", stateMutability: "nonpayable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "withdraw()",
      location: BASE_LOC,
      codeSnippet: `
        function withdraw() public {
          uint amount = balances[msg.sender];
          balances[msg.sender] = 0;
          msg.sender.send(amount);
        }
      `,
      externalCalls: [
        {
          id: "send-3", contractName: "WithdrawVault", functionName: "withdraw",
          target: "msg.sender", method: "send", callType: "send",
          arguments: ["amount"], rawExpression: "msg.sender.send(amount)",
          location: { ...BASE_LOC, line: 14 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-3", contractName: "WithdrawVault", functionName: "withdraw",
          recipient: "msg.sender", amount: "amount",
          transferType: "send", rawExpression: "msg.sender.send(amount)",
          location: { ...BASE_LOC, line: 14 },
        },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 3, name: "WithdrawVault", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [fn],
      stateVariables: [
        { id: 30, name: "balances", contractName: "WithdrawVault", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: fn.externalCalls, etherTransfers: fn.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    };

    const result = detectSecurityVulnerabilities(makeAST([contract]));
    // msg.sender.send() is a self-withdrawal — failure only affects the caller
    const dosFind = result.findings.find(f => f.vulnerabilityType === "Denial of Service");
    expect(dosFind).toBeUndefined();
  });
});

// ── 4: msg.sender.transfer() must NOT be DoS ──────────────────────────────────

describe("DoS Regression — 4. msg.sender.transfer(amount) must NOT be flagged as DoS", () => {
  it("msg.sender.transfer in claimReward() → no DoS finding", () => {
    const fn: ASTFunction = {
      id: 4, name: "claimReward", contractName: "BlockNumberVulnerable", kind: "function",
      visibility: "public", stateMutability: "nonpayable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "claimReward()",
      location: BASE_LOC,
      codeSnippet: `
        function claimReward() public {
          require(block.number > endBlock, "Too early");
          uint reward = rewards[msg.sender];
          rewards[msg.sender] = 0;
          payable(msg.sender).transfer(reward);
        }
      `,
      externalCalls: [
        {
          id: "trans-4", contractName: "BlockNumberVulnerable", functionName: "claimReward",
          target: "payable(msg.sender)", method: "transfer", callType: "transfer",
          arguments: ["reward"], rawExpression: "payable(msg.sender).transfer(reward)",
          location: { ...BASE_LOC, line: 15 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-4", contractName: "BlockNumberVulnerable", functionName: "claimReward",
          recipient: "payable(msg.sender)", amount: "reward",
          transferType: "transfer", rawExpression: "payable(msg.sender).transfer(reward)",
          location: { ...BASE_LOC, line: 15 },
        },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 4, name: "BlockNumberVulnerable", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [fn],
      stateVariables: [
        { id: 40, name: "rewards", contractName: "BlockNumberVulnerable", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 41, name: "endBlock", contractName: "BlockNumberVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: fn.externalCalls, etherTransfers: fn.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    };

    const result = detectSecurityVulnerabilities(makeAST([contract]));
    // msg.sender.transfer is self-withdrawal — NO DoS
    const dosFind = result.findings.find(f => f.vulnerabilityType === "Denial of Service");
    expect(dosFind).toBeUndefined();
  });
});

// ── 5: treasury.transfer(amount) must NOT be CONFIRMED DoS ────────────────────

describe("DoS Regression — 5. treasury.transfer(amount) must NOT be CONFIRMED DoS", () => {
  it("bare treasury.transfer outside require() → no confirmed DoS", () => {
    const fn: ASTFunction = {
      id: 5, name: "adminSweep", contractName: "AccessControlVulnerable", kind: "function",
      visibility: "public", stateMutability: "nonpayable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "adminSweep()",
      location: BASE_LOC,
      codeSnippet: `
        function adminSweep() public {
          require(msg.sender == owner);
          uint amount = address(this).balance;
          treasury.transfer(amount);
        }
      `,
      externalCalls: [
        {
          id: "trans-5", contractName: "AccessControlVulnerable", functionName: "adminSweep",
          target: "treasury", method: "transfer", callType: "transfer",
          arguments: ["amount"], rawExpression: "treasury.transfer(amount)",
          location: { ...BASE_LOC, line: 14 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-5", contractName: "AccessControlVulnerable", functionName: "adminSweep",
          recipient: "treasury", amount: "amount",
          transferType: "transfer", rawExpression: "treasury.transfer(amount)",
          location: { ...BASE_LOC, line: 14 },
        },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 5, name: "AccessControlVulnerable", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [fn],
      stateVariables: [
        { id: 50, name: "treasury", contractName: "AccessControlVulnerable", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 51, name: "owner", contractName: "AccessControlVulnerable", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: fn.externalCalls, etherTransfers: fn.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    };

    const result = detectSecurityVulnerabilities(makeAST([contract]));
    // treasury.transfer is a bare transfer (not inside require()) — not a confirmed DoS
    const dosFind = result.findings.find(
      f => f.vulnerabilityType === "Denial of Service" && f.classification === "CONFIRMED"
    );
    expect(dosFind).toBeUndefined();
  });
});

// ── 6: SendReentrancyVulnerable.withdraw() — msg.sender.send, NO global DoS ───

describe("DoS Regression — 6. SendReentrancyVulnerable.withdraw() must have NO confirmed global DoS", () => {
  it("msg.sender.send in withdraw() → no confirmed DoS", () => {
    const fn: ASTFunction = {
      id: 6, name: "withdraw", contractName: "SendReentrancyVulnerable", kind: "function",
      visibility: "public", stateMutability: "nonpayable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "withdraw()",
      location: BASE_LOC,
      codeSnippet: `
        function withdraw() public {
          uint amount = balances[msg.sender];
          bool ok = msg.sender.send(amount);
          require(ok, "Transfer failed");
          balances[msg.sender] = 0;
        }
      `,
      externalCalls: [
        {
          id: "send-6", contractName: "SendReentrancyVulnerable", functionName: "withdraw",
          target: "msg.sender", method: "send", callType: "send",
          arguments: ["amount"], rawExpression: "msg.sender.send(amount)",
          location: { ...BASE_LOC, line: 12 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-6", contractName: "SendReentrancyVulnerable", functionName: "withdraw",
          recipient: "msg.sender", amount: "amount",
          transferType: "send", rawExpression: "msg.sender.send(amount)",
          location: { ...BASE_LOC, line: 12 },
        },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 6, name: "SendReentrancyVulnerable", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [fn],
      stateVariables: [
        { id: 60, name: "balances", contractName: "SendReentrancyVulnerable", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: fn.externalCalls, etherTransfers: fn.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    };

    const result = detectSecurityVulnerabilities(makeAST([contract]));
    // msg.sender.send — self-affecting only, not a global DoS
    const confirmedDos = result.findings.find(
      f => f.vulnerabilityType === "Denial of Service" && f.classification === "CONFIRMED"
    );
    expect(confirmedDos).toBeUndefined();
  });
});

// ── 7: SendReentrancyVulnerable.payout() — msg.sender.transfer, NO global DoS ──

describe("DoS Regression — 7. SendReentrancyVulnerable.payout() must have NO confirmed global DoS", () => {
  it("msg.sender.transfer in payout() → no confirmed DoS", () => {
    const fn: ASTFunction = {
      id: 7, name: "payout", contractName: "SendReentrancyVulnerable", kind: "function",
      visibility: "public", stateMutability: "nonpayable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "payout()",
      location: BASE_LOC,
      codeSnippet: `
        function payout() public {
          uint amount = pendingPayouts[msg.sender];
          pendingPayouts[msg.sender] = 0;
          payable(msg.sender).transfer(amount);
        }
      `,
      externalCalls: [
        {
          id: "trans-7", contractName: "SendReentrancyVulnerable", functionName: "payout",
          target: "payable(msg.sender)", method: "transfer", callType: "transfer",
          arguments: ["amount"], rawExpression: "payable(msg.sender).transfer(amount)",
          location: { ...BASE_LOC, line: 13 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-7", contractName: "SendReentrancyVulnerable", functionName: "payout",
          recipient: "payable(msg.sender)", amount: "amount",
          transferType: "transfer", rawExpression: "payable(msg.sender).transfer(amount)",
          location: { ...BASE_LOC, line: 13 },
        },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 7, name: "SendReentrancyVulnerable", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [fn],
      stateVariables: [
        { id: 70, name: "pendingPayouts", contractName: "SendReentrancyVulnerable", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: fn.externalCalls, etherTransfers: fn.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    };

    const result = detectSecurityVulnerabilities(makeAST([contract]));
    // msg.sender.transfer — self-affecting, not a global DoS
    const confirmedDos = result.findings.find(
      f => f.vulnerabilityType === "Denial of Service" && f.classification === "CONFIRMED"
    );
    expect(confirmedDos).toBeUndefined();
  });
});

// ── 8: AccessControlVulnerable.emergencyWithdraw() — msg.sender.transfer NO DoS

describe("DoS Regression — 8. AccessControlVulnerable.emergencyWithdraw() must have NO confirmed DoS", () => {
  it("msg.sender.transfer in emergencyWithdraw() → no confirmed DoS", () => {
    const fn: ASTFunction = {
      id: 8, name: "emergencyWithdraw", contractName: "AccessControlVulnerable", kind: "function",
      visibility: "external", stateMutability: "nonpayable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "emergencyWithdraw()",
      location: BASE_LOC,
      codeSnippet: `
        function emergencyWithdraw() external {
          uint amount = stakes[msg.sender];
          stakes[msg.sender] = 0;
          payable(msg.sender).transfer(amount);
        }
      `,
      externalCalls: [
        {
          id: "trans-8", contractName: "AccessControlVulnerable", functionName: "emergencyWithdraw",
          target: "payable(msg.sender)", method: "transfer", callType: "transfer",
          arguments: ["amount"], rawExpression: "payable(msg.sender).transfer(amount)",
          location: { ...BASE_LOC, line: 13 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-8", contractName: "AccessControlVulnerable", functionName: "emergencyWithdraw",
          recipient: "payable(msg.sender)", amount: "amount",
          transferType: "transfer", rawExpression: "payable(msg.sender).transfer(amount)",
          location: { ...BASE_LOC, line: 13 },
        },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 8, name: "AccessControlVulnerable", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [fn],
      stateVariables: [
        { id: 80, name: "stakes", contractName: "AccessControlVulnerable", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: fn.externalCalls, etherTransfers: fn.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    };

    const result = detectSecurityVulnerabilities(makeAST([contract]));
    const confirmedDos = result.findings.find(
      f => f.vulnerabilityType === "Denial of Service" && f.classification === "CONFIRMED"
    );
    expect(confirmedDos).toBeUndefined();
  });
});

// ── 9 + 10 combined: All benchmark contracts except DosAuction → NO DoS ─────

describe("DoS Regression — 9 & 10. No false-positive DoS across full benchmark set", () => {
  it("combined: only DosAuction.bid() produces CONFIRMED DoS; all others produce none", () => {
    // Build a minimal version of each benchmark contract's relevant function
    const contracts: ASTContract[] = [];

    // DosAuction.bid — SHOULD have DoS
    const dosAuctionBid: ASTFunction = {
      id: 100, name: "bid", contractName: "DosAuction", kind: "function",
      visibility: "public", stateMutability: "payable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "bid()",
      location: BASE_LOC,
      codeSnippet: "require(currentFrontrunner.send(currentBid));",
      externalCalls: [
        { id: "c100", contractName: "DosAuction", functionName: "bid", target: "currentFrontrunner", method: "send", callType: "send", arguments: ["currentBid"], rawExpression: "currentFrontrunner.send(currentBid)", location: { ...BASE_LOC, line: 14 } },
      ],
      etherTransfers: [
        { id: "t100", contractName: "DosAuction", functionName: "bid", recipient: "currentFrontrunner", amount: "currentBid", transferType: "send", rawExpression: "currentFrontrunner.send(currentBid)", location: { ...BASE_LOC, line: 14 } },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };
    contracts.push({
      id: 100, name: "DosAuction", kind: "contract", isAbstract: false, sourceFile: "Test.sol",
      bases: [], functions: [dosAuctionBid],
      stateVariables: [
        { id: 1000, name: "currentFrontrunner", contractName: "DosAuction", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 1001, name: "currentBid", contractName: "DosAuction", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: dosAuctionBid.externalCalls, etherTransfers: dosAuctionBid.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    });

    // SecureAuction.bid — no external calls, no DoS
    const secAuctionBid: ASTFunction = {
      id: 101, name: "bid", contractName: "SecureAuction", kind: "function",
      visibility: "external", stateMutability: "payable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "bid()",
      location: BASE_LOC,
      codeSnippet: "refunds[currentFrontrunner] += currentBid;",
      externalCalls: [], etherTransfers: [], controlStatements: [], operations: EMPTY_OPS,
    };
    contracts.push({
      id: 101, name: "SecureAuction", kind: "contract", isAbstract: false, sourceFile: "Test.sol",
      bases: [], functions: [secAuctionBid],
      stateVariables: [
        { id: 1010, name: "currentFrontrunner", contractName: "SecureAuction", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 1011, name: "refunds", contractName: "SecureAuction", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: [], etherTransfers: [], controlStatements: [], location: BASE_LOC,
    });

    // AccessControlVulnerable.emergencyWithdraw — msg.sender.transfer, no DoS
    const acEmergency: ASTFunction = {
      id: 102, name: "emergencyWithdraw", contractName: "AccessControlVulnerable2", kind: "function",
      visibility: "external", stateMutability: "nonpayable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "emergencyWithdraw()",
      location: BASE_LOC,
      codeSnippet: "payable(msg.sender).transfer(amount);",
      externalCalls: [
        { id: "c102", contractName: "AccessControlVulnerable2", functionName: "emergencyWithdraw", target: "payable(msg.sender)", method: "transfer", callType: "transfer", arguments: ["amount"], rawExpression: "payable(msg.sender).transfer(amount)", location: { ...BASE_LOC, line: 13 } },
      ],
      etherTransfers: [
        { id: "t102", contractName: "AccessControlVulnerable2", functionName: "emergencyWithdraw", recipient: "payable(msg.sender)", amount: "amount", transferType: "transfer", rawExpression: "payable(msg.sender).transfer(amount)", location: { ...BASE_LOC, line: 13 } },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };
    contracts.push({
      id: 102, name: "AccessControlVulnerable2", kind: "contract", isAbstract: false, sourceFile: "Test.sol",
      bases: [], functions: [acEmergency],
      stateVariables: [
        { id: 1020, name: "stakes", contractName: "AccessControlVulnerable2", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: acEmergency.externalCalls, etherTransfers: acEmergency.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    });

    // AccessControlVulnerable.adminSweep — treasury.transfer (bare, not in require), no DoS
    const acSweep: ASTFunction = {
      id: 103, name: "adminSweep", contractName: "AccessControlVulnerable3", kind: "function",
      visibility: "public", stateMutability: "nonpayable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "adminSweep()",
      location: BASE_LOC,
      codeSnippet: "treasury.transfer(address(this).balance);",
      externalCalls: [
        { id: "c103", contractName: "AccessControlVulnerable3", functionName: "adminSweep", target: "treasury", method: "transfer", callType: "transfer", arguments: ["amount"], rawExpression: "treasury.transfer(amount)", location: { ...BASE_LOC, line: 14 } },
      ],
      etherTransfers: [
        { id: "t103", contractName: "AccessControlVulnerable3", functionName: "adminSweep", recipient: "treasury", amount: "amount", transferType: "transfer", rawExpression: "treasury.transfer(amount)", location: { ...BASE_LOC, line: 14 } },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };
    contracts.push({
      id: 103, name: "AccessControlVulnerable3", kind: "contract", isAbstract: false, sourceFile: "Test.sol",
      bases: [], functions: [acSweep],
      stateVariables: [
        { id: 1030, name: "treasury", contractName: "AccessControlVulnerable3", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: acSweep.externalCalls, etherTransfers: acSweep.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    });

    // BlockNumberVulnerable.claimReward — msg.sender.transfer, no DoS
    const bnClaim: ASTFunction = {
      id: 104, name: "claimReward", contractName: "BlockNumberVulnerable2", kind: "function",
      visibility: "public", stateMutability: "nonpayable",
      isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "claimReward()",
      location: BASE_LOC,
      codeSnippet: "payable(msg.sender).transfer(reward);",
      externalCalls: [
        { id: "c104", contractName: "BlockNumberVulnerable2", functionName: "claimReward", target: "payable(msg.sender)", method: "transfer", callType: "transfer", arguments: ["reward"], rawExpression: "payable(msg.sender).transfer(reward)", location: { ...BASE_LOC, line: 15 } },
      ],
      etherTransfers: [
        { id: "t104", contractName: "BlockNumberVulnerable2", functionName: "claimReward", recipient: "payable(msg.sender)", amount: "reward", transferType: "transfer", rawExpression: "payable(msg.sender).transfer(reward)", location: { ...BASE_LOC, line: 15 } },
      ],
      controlStatements: [], operations: EMPTY_OPS,
    };
    contracts.push({
      id: 104, name: "BlockNumberVulnerable2", kind: "contract", isAbstract: false, sourceFile: "Test.sol",
      bases: [], functions: [bnClaim],
      stateVariables: [
        { id: 1040, name: "rewards", contractName: "BlockNumberVulnerable2", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: bnClaim.externalCalls, etherTransfers: bnClaim.etherTransfers,
      controlStatements: [], location: BASE_LOC,
    });

    const result = detectSecurityVulnerabilities(makeAST(contracts));
    const dosFindings = result.findings.filter(f => f.vulnerabilityType === "Denial of Service");

    // Only DosAuction.bid() should be flagged
    expect(dosFindings.length).toBe(1);
    expect(dosFindings[0].contractName).toBe("DosAuction");
    expect(dosFindings[0].classification).toBe("CONFIRMED");

    // Verify none of the other contracts have DoS findings
    const nonDosContracts = ["SecureAuction", "AccessControlVulnerable2", "AccessControlVulnerable3", "BlockNumberVulnerable2"];
    for (const name of nonDosContracts) {
      const found = dosFindings.find(f => f.contractName === name);
      expect(found).toBeUndefined();
    }
  });
});
