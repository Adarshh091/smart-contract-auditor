// ─── Regression Tests: False Positive Fixes ───────────────────────────────────
//
// These tests guard against the specific false positives identified:
//
//  1. CEI withdraw()       → NO Reentrancy candidate in VulnerabilityPlan
//  2. payable auction bid() → NO Ether/Payment Logic candidate in VulnerabilityPlan
//  3. DosAuction           → DoS candidate REMAINS (require(addr.send(...)))
//  4. unchecked send()     → Unchecked External Call candidate REMAINS

import { describe, it, expect } from "vitest";
import { buildVulnerabilityPlan } from "./vulnerability-analyzer";
import type { ASTAnalysisResult, ASTContract, ASTFunction, ASTOperation } from "../types/ast";
import type { SemanticResult } from "../types/semantic";

// ── Shared helpers ────────────────────────────────────────────────────────────

const EMPTY_OPS: ASTOperation[] = [];

const BASE_LOC = { file: "Test.sol", line: 10, column: 1, start: 100, length: 200, end: 300 };

const AUCTION_SEMANTIC: SemanticResult = {
  purpose: "An English auction where users submit ETH bids",
  category: "Auction",
  confidence: 0.9,
  assets: ["ETH"],
  mainFunctions: ["bid", "withdraw"],
  criticalOperations: ["bid placement", "refund"],
  accessControl: [],
  externalInteractions: [],
  financialOperations: ["bid", "refund"],
  securityCriticalAreas: ["bidding logic", "refund handling"],
};

function makeAST(contract: ASTContract): ASTAnalysisResult {
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
      totalModifiers: 0, totalEvents: 0, totalStructs: 0, totalEnums: 0,
      totalExternalCalls: contract.externalCalls.length,
      totalEtherTransfers: contract.etherTransfers.length,
      totalControlStatements: contract.controlStatements.length,
      publicOrExternalFunctions: contract.functions.length,
      internalOrPrivateFunctions: 0, payableFunctions: 0, viewOrPureFunctions: 0,
    },
    rawAst: {},
  };
}

// ── Regression 1: CEI withdraw() → NO Reentrancy candidate ───────────────────

describe("Regression 1 — CEI withdraw() must NOT produce a Reentrancy candidate", () => {
  it("withdraw() with state cleared BEFORE send: no Reentrancy SelectedCheck", () => {
    // function withdraw() external {
    //   uint refund = refunds[msg.sender];
    //   refunds[msg.sender] = 0;       ← state update BEFORE call
    //   msg.sender.send(refund);       ← call comes after
    // }
    const fn: ASTFunction = {
      id: 1,
      name: "withdraw",
      contractName: "SecureAuction",
      kind: "function",
      visibility: "external",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "withdraw()",
      location: { file: "Test.sol", line: 10, column: 1, start: 100, length: 200, end: 300 },
      // State write (line 13) is BEFORE the send call (line 14)
      codeSnippet: `
        function withdraw() external {
          uint refund = refunds[msg.sender];
          refunds[msg.sender] = 0;
          msg.sender.send(refund);
        }
      `,
      externalCalls: [
        {
          id: "call-1",
          contractName: "SecureAuction",
          functionName: "withdraw",
          target: "msg.sender",
          method: "send",
          callType: "send",
          arguments: ["refund"],
          rawExpression: "msg.sender.send(refund)",
          // line 14 — AFTER the state write on line 13
          location: { file: "Test.sol", line: 14, column: 5, start: 180, length: 23, end: 203 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-1",
          contractName: "SecureAuction",
          functionName: "withdraw",
          recipient: "msg.sender",
          amount: "refund",
          transferType: "send",
          rawExpression: "msg.sender.send(refund)",
          location: { file: "Test.sol", line: 14, column: 5, start: 180, length: 23, end: 203 },
        },
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 1, name: "SecureAuction", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [fn],
      stateVariables: [
        {
          id: 10, name: "refunds", contractName: "SecureAuction",
          type: "mapping(address => uint256)", visibility: "public",
          mutability: "mutable", location: BASE_LOC,
        },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: fn.etherTransfers,
      controlStatements: [],
      location: BASE_LOC,
    };

    const plan = buildVulnerabilityPlan(AUCTION_SEMANTIC, makeAST(contract));

    // No Reentrancy candidate — CEI is satisfied
    const reentrancyCheck = plan.selectedChecks.find((c) => c.category === "Reentrancy");
    expect(reentrancyCheck).toBeUndefined();

    // Reentrancy should be in the skipped list with an explanatory reason
    const skipped = plan.skippedChecks.find((c) => c.category === "Reentrancy");
    expect(skipped).toBeDefined();
    // Reason must NOT say "no ETH transfers" — it must acknowledge CEI compliance
    expect(skipped!.reason).toContain("CEI");
  });
});

// ── Regression 2: payable auction bid() → NO Ether/Payment Logic candidate ───

describe("Regression 2 — payable bid() with proper tracking must NOT produce Ether/Payment Logic candidate", () => {
  it("bid() payable with balance-tracking mapping: no Ether/Payment Logic SelectedCheck", () => {
    // function bid() public payable {
    //   require(msg.value > highestBid, "Bid too low");
    //   bids[msg.sender] += msg.value;   ← tracking state
    //   highestBidder = msg.sender;
    //   highestBid = msg.value;
    // }
    const fn: ASTFunction = {
      id: 2,
      name: "bid",
      contractName: "AuctionWithTracking",
      kind: "function",
      visibility: "public",
      stateMutability: "payable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "bid()",
      location: BASE_LOC,
      codeSnippet: `
        function bid() public payable {
          require(msg.value > highestBid, "Bid too low");
          bids[msg.sender] += msg.value;
          highestBidder = msg.sender;
          highestBid = msg.value;
        }
      `,
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 2, name: "AuctionWithTracking", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [fn],
      stateVariables: [
        {
          id: 20, name: "highestBid", contractName: "AuctionWithTracking",
          type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC,
        },
        {
          id: 21, name: "highestBidder", contractName: "AuctionWithTracking",
          type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC,
        },
        // "bids" is a mapping(address => uint) — satisfies ETH tracking requirement
        {
          id: 22, name: "bids", contractName: "AuctionWithTracking",
          type: "mapping(address => uint256)", visibility: "public",
          mutability: "mutable", location: BASE_LOC,
        },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: [], etherTransfers: [], controlStatements: [],
      location: BASE_LOC,
    };

    const plan = buildVulnerabilityPlan(AUCTION_SEMANTIC, makeAST(contract));

    // No Ether/Payment Logic candidate — proper tracking exists
    const ethCheck = plan.selectedChecks.find((c) => c.category === "Ether/Payment Logic");
    expect(ethCheck).toBeUndefined();

    // It should appear in the skipped list
    const skipped = plan.skippedChecks.find((c) => c.category === "Ether/Payment Logic");
    expect(skipped).toBeDefined();
  });
});

// ── Regression 3: DosAuction → DoS candidate REMAINS ─────────────────────────

describe("Regression 3 — DosAuction bid() with require(addr.send(...)) must produce DoS candidate", () => {
  it("require(currentFrontrunner.send(currentBid)): DoS SelectedCheck present", () => {
    // function bid() public payable {
    //   require(msg.value > currentBid, "Bid too low");
    //   require(currentFrontrunner.send(currentBid), "Refund failed");  ← blocking send
    //   currentFrontrunner = msg.sender;
    //   currentBid = msg.value;
    // }
    const fn: ASTFunction = {
      id: 3,
      name: "bid",
      contractName: "DosAuction",
      kind: "function",
      visibility: "public",
      stateMutability: "payable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "bid()",
      location: BASE_LOC,
      codeSnippet: `
        function bid() public payable {
          require(msg.value > currentBid, "Bid too low");
          require(currentFrontrunner.send(currentBid), "Refund failed");
          currentFrontrunner = msg.sender;
          currentBid = msg.value;
        }
      `,
      externalCalls: [
        {
          id: "send-3",
          contractName: "DosAuction",
          functionName: "bid",
          target: "currentFrontrunner",
          method: "send",
          callType: "send",
          arguments: ["currentBid"],
          rawExpression: "currentFrontrunner.send(currentBid)",
          location: { file: "Test.sol", line: 14, column: 5, start: 180, length: 36, end: 216 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-3",
          contractName: "DosAuction",
          functionName: "bid",
          recipient: "currentFrontrunner",
          amount: "currentBid",
          transferType: "send",
          rawExpression: "currentFrontrunner.send(currentBid)",
          location: { file: "Test.sol", line: 14, column: 5, start: 180, length: 36, end: 216 },
        },
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 3, name: "DosAuction", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [fn],
      stateVariables: [
        {
          id: 30, name: "currentFrontrunner", contractName: "DosAuction",
          type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC,
        },
        {
          id: 31, name: "currentBid", contractName: "DosAuction",
          type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC,
        },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: fn.etherTransfers,
      controlStatements: [],
      location: BASE_LOC,
    };

    const plan = buildVulnerabilityPlan(AUCTION_SEMANTIC, makeAST(contract));

    // DoS must be a selected candidate
    const dosCheck = plan.selectedChecks.find((c) => c.category === "Denial of Service");
    expect(dosCheck).toBeDefined();
    expect(dosCheck!.reason).toContain("AST evidence");
    expect(dosCheck!.reason).toContain("bid");
  });
});

// ── Regression 4: unchecked send → Unchecked External Call REMAINS ────────────

describe("Regression 4 — unchecked send() must produce Unchecked External Call candidate", () => {
  it("msg.sender.send(refund) with no require(result): Unchecked External Call SelectedCheck present", () => {
    // function withdraw() external {
    //   uint refund = refunds[msg.sender];
    //   refunds[msg.sender] = 0;
    //   msg.sender.send(refund);   ← return value NOT checked
    // }
    const fn: ASTFunction = {
      id: 4,
      name: "withdraw",
      contractName: "SecureAuction",
      kind: "function",
      visibility: "external",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "withdraw()",
      location: { file: "Test.sol", line: 10, column: 1, start: 100, length: 200, end: 300 },
      codeSnippet: `
        function withdraw() external {
          uint refund = refunds[msg.sender];
          refunds[msg.sender] = 0;
          msg.sender.send(refund);
        }
      `,
      externalCalls: [
        {
          id: "send-4",
          contractName: "SecureAuction",
          functionName: "withdraw",
          target: "msg.sender",
          method: "send",
          callType: "send",
          arguments: ["refund"],
          rawExpression: "msg.sender.send(refund)",
          location: { file: "Test.sol", line: 14, column: 5, start: 180, length: 23, end: 203 },
        },
      ],
      etherTransfers: [
        {
          id: "eth-4",
          contractName: "SecureAuction",
          functionName: "withdraw",
          recipient: "msg.sender",
          amount: "refund",
          transferType: "send",
          rawExpression: "msg.sender.send(refund)",
          location: { file: "Test.sol", line: 14, column: 5, start: 180, length: 23, end: 203 },
        },
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 4, name: "SecureAuction", kind: "contract", isAbstract: false,
      sourceFile: "Test.sol", bases: [], functions: [fn],
      stateVariables: [
        {
          id: 40, name: "refunds", contractName: "SecureAuction",
          type: "mapping(address => uint256)", visibility: "public",
          mutability: "mutable", location: BASE_LOC,
        },
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: fn.externalCalls,
      etherTransfers: fn.etherTransfers,
      controlStatements: [],
      location: BASE_LOC,
    };

    const plan = buildVulnerabilityPlan(AUCTION_SEMANTIC, makeAST(contract));

    // Unchecked External Call must be a selected candidate
    const uncheckedCheck = plan.selectedChecks.find(
      (c) => c.category === "Unchecked External Call"
    );
    expect(uncheckedCheck).toBeDefined();
    expect(uncheckedCheck!.reason).toContain("AST evidence");
    expect(uncheckedCheck!.reason).toContain("msg.sender.send(refund)");
  });
});
