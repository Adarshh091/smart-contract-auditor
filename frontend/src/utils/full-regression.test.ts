import { describe, it, expect } from "vitest";
import { detectSecurityVulnerabilities } from "./security-detector";
import type { ASTAnalysisResult, ASTContract, ASTFunction, ASTOperation } from "../types/ast";
import { buildVulnerabilityPlan } from "./vulnerability-analyzer";
import type { SemanticResult } from "../types/semantic";

const EMPTY_OPS: ASTOperation[] = [];
const BASE_LOC = { file: "Test.sol", line: 10, column: 1, start: 100, length: 200, end: 300 };

describe("Mandatory Regression Fixture", () => {
  it("DosAuction and SecureAuction expected results", () => {
    // We will build the two contracts manually
    const dosBid: ASTFunction = {
      id: 1, name: "bid", contractName: "DosAuction", kind: "function", visibility: "public",
      stateMutability: "payable", isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "bid()", location: BASE_LOC,
      codeSnippet: `
        function bid() payable {
          require(msg.value > currentBid);
          if (currentFrontrunner != 0) {
            require(currentFrontrunner.send(currentBid));
          }
          currentFrontrunner = msg.sender;
          currentBid = msg.value;
        }
      `,
      externalCalls: [
        { id: "c1", contractName: "DosAuction", functionName: "bid", target: "currentFrontrunner", method: "send", callType: "send", arguments: ["currentBid"], rawExpression: "currentFrontrunner.send(currentBid)", location: BASE_LOC }
      ],
      etherTransfers: [
        { id: "t1", contractName: "DosAuction", functionName: "bid", recipient: "currentFrontrunner", amount: "currentBid", transferType: "send", rawExpression: "currentFrontrunner.send(currentBid)", location: BASE_LOC }
      ],
      controlStatements: [], operations: []
    };

    const dosAuction: ASTContract = {
      id: 1, name: "DosAuction", kind: "contract", isAbstract: false, sourceFile: "Test.sol",
      bases: [], functions: [dosBid],
      stateVariables: [
        { id: 10, name: "currentFrontrunner", contractName: "DosAuction", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 11, name: "currentBid", contractName: "DosAuction", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC }
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: dosBid.externalCalls, etherTransfers: dosBid.etherTransfers, controlStatements: [], location: BASE_LOC
    };

    const secBid: ASTFunction = {
      id: 2, name: "bid", contractName: "SecureAuction", kind: "function", visibility: "external",
      stateMutability: "payable", isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "bid()", location: BASE_LOC,
      codeSnippet: `
        function bid() payable external {
          require(msg.value > currentBid);
          if (currentFrontrunner != 0) {
            refunds[currentFrontrunner] += currentBid;
          }
          currentFrontrunner = msg.sender;
          currentBid = msg.value;
        }
      `,
      externalCalls: [], etherTransfers: [], controlStatements: [], operations: []
    };

    const secWithdraw: ASTFunction = {
      id: 3, name: "withdraw", contractName: "SecureAuction", kind: "function", visibility: "external",
      stateMutability: "nonpayable", isVirtual: false, isOverride: false, modifiers: [],
      parameters: [], returnParameters: [], signature: "withdraw()", location: BASE_LOC,
      codeSnippet: `
        function withdraw() external {
          uint refund = refunds[msg.sender];
          refunds[msg.sender] = 0;
          msg.sender.send(refund);
        }
      `,
      externalCalls: [
        { id: "c2", contractName: "SecureAuction", functionName: "withdraw", target: "msg.sender", method: "send", callType: "send", arguments: ["refund"], rawExpression: "msg.sender.send(refund)", location: { ...BASE_LOC, line: 15 } }
      ],
      etherTransfers: [
        { id: "t2", contractName: "SecureAuction", functionName: "withdraw", recipient: "msg.sender", amount: "refund", transferType: "send", rawExpression: "msg.sender.send(refund)", location: { ...BASE_LOC, line: 15 } }
      ],
      controlStatements: [], operations: []
    };

    const secAuction: ASTContract = {
      id: 2, name: "SecureAuction", kind: "contract", isAbstract: false, sourceFile: "Test.sol",
      bases: [], functions: [secBid, secWithdraw],
      stateVariables: [
        { id: 20, name: "currentFrontrunner", contractName: "SecureAuction", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 21, name: "currentBid", contractName: "SecureAuction", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 22, name: "refunds", contractName: "SecureAuction", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC }
      ],
      modifiers: [], events: [], structs: [], enums: [],
      externalCalls: secWithdraw.externalCalls, etherTransfers: secWithdraw.etherTransfers, controlStatements: [], location: BASE_LOC
    };

    const ast = {
      contracts: [dosAuction, secAuction],
      functions: [dosBid, secBid, secWithdraw],
      stateVariables: [...dosAuction.stateVariables, ...secAuction.stateVariables],
      modifiers: [], events: [], structs: [], enums: [], inheritance: [],
      externalCalls: [...dosAuction.externalCalls, ...secAuction.externalCalls],
      etherTransfers: [...dosAuction.etherTransfers, ...secAuction.etherTransfers],
      controlStatements: [],
      summary: { totalContracts: 2, totalFunctions: 3, totalStateVariables: 5, totalModifiers: 0, totalEvents: 0, totalStructs: 0, totalEnums: 0, totalExternalCalls: 2, totalEtherTransfers: 2, totalControlStatements: 0, publicOrExternalFunctions: 3, internalOrPrivateFunctions: 0, payableFunctions: 2, viewOrPureFunctions: 0 },
      rawAst: {}
    } as ASTAnalysisResult;

    const result = detectSecurityVulnerabilities(ast);
    const conf = result.findings.filter(f => f.classification === "CONFIRMED");

    // DosAuction.bid() -> CONFIRMED DoS
    const dosFind = conf.find(f => f.contractName === "DosAuction" && f.vulnerabilityType === "Denial of Service");
    expect(dosFind).toBeDefined();

    // SecureAuction.bid() -> NO DoS
    const secDosFind = conf.find(f => f.contractName === "SecureAuction" && f.vulnerabilityType === "Denial of Service");
    expect(secDosFind).toBeUndefined();

    // SecureAuction.withdraw() -> CONFIRMED Unchecked External Call
    const secUncFind = conf.find(f => f.contractName === "SecureAuction" && f.vulnerabilityType === "Unchecked External Call");
    expect(secUncFind).toBeDefined();

    // SecureAuction.withdraw() -> NO confirmed Reentrancy
    const secReFind = conf.find(f => f.contractName === "SecureAuction" && f.vulnerabilityType === "Reentrancy");
    expect(secReFind).toBeUndefined();

    // NO Timestamp Dependency
    const tsFind = result.findings.find(f => f.vulnerabilityType === "Timestamp Dependency");
    expect(tsFind).toBeUndefined();

    // NO Integer Overflow vulnerability merely from uint usage
    const ovFind = conf.find(f => f.vulnerabilityType === "Integer Overflow/Underflow");
    expect(ovFind).toBeUndefined();

    // NO Access Control vulnerability merely because functions are external/public
    const acFind = conf.find(f => f.vulnerabilityType === "Access Control");
    expect(acFind).toBeUndefined();

    // NO automatic Front-running vulnerability
    const frFind = conf.find(f => f.vulnerabilityType === "Front-running/Transaction Ordering");
    expect(frFind).toBeUndefined();

    // NO generic Ether/Payment vulnerability
    const ethFind = result.findings.find(f => f.vulnerabilityType === "Ether/Payment Logic");
    expect(ethFind).toBeUndefined();
  });
});
