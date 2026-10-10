// ─── Access Control Detector Regression Tests ─────────────────────────────────
//
// Benchmark expectations:
//
// 1. ReentrancyVulnerable constructor -> NO Access Control
// 2. ReentrancySafe.deposit() -> NO Access Control
// 3. ReentrancySafe.withdraw() -> NO Access Control
// 4. TokenERC20.transfer() -> NO Access Control
// 5. TokenERC20.approve() -> NO Access Control
// 6. DelegatecallVulnerable.execute() -> CONFIRMED Access Control
// 7. DelegatecallVulnerable.executeStored() -> CONFIRMED Access Control
// 8. AccessControlVulnerable.destroyContract() -> CONFIRMED Access Control
// 9. AccessControlVulnerable.emergencyWithdraw() -> CONFIRMED Access Control
// 10. AccessControlVulnerable.adminSweep() -> CONFIRMED Access Control
// 11. AccessControlVulnerable.withdrawUserBalance() -> NO Access Control
// 12. owned.transferOwnership() -> NO Access Control

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

describe("Access Control Detector Regression", () => {
  it("1. ReentrancyVulnerable constructor (old-style & modern) -> NO Access Control", () => {
    const oldConstructor: ASTFunction = {
      id: 1,
      name: "ReentrancyVulnerable",
      contractName: "ReentrancyVulnerable",
      kind: "function", // solc 0.4.x AST represented constructor as kind="function" with name matching contract
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "ReentrancyVulnerable()",
      location: BASE_LOC,
      codeSnippet: "function ReentrancyVulnerable() public { owner = msg.sender; }",
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const modernConstructor: ASTFunction = {
      id: 2,
      name: "constructor",
      contractName: "ModernContract",
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
      codeSnippet: "constructor() { owner = msg.sender; }",
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract1: ASTContract = {
      id: 1,
      name: "ReentrancyVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [oldConstructor],
      stateVariables: [
        { id: 10, name: "owner", contractName: "ReentrancyVulnerable", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
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

    const contract2: ASTContract = {
      id: 2,
      name: "ModernContract",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [modernConstructor],
      stateVariables: [
        { id: 20, name: "owner", contractName: "ModernContract", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
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

    const res = detectSecurityVulnerabilities(makeAST([contract1, contract2]));
    const acFindings = res.findings.filter((f) => f.vulnerabilityType === "Access Control");
    expect(acFindings.length).toBe(0);
  });

  it("2 & 3. ReentrancySafe.deposit() & withdraw() -> NO Access Control", () => {
    const depositFn: ASTFunction = {
      id: 3,
      name: "deposit",
      contractName: "ReentrancySafe",
      kind: "function",
      visibility: "public",
      stateMutability: "payable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "deposit()",
      location: BASE_LOC,
      codeSnippet: "function deposit() public payable { balances[msg.sender] += msg.value; }",
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const withdrawFn: ASTFunction = {
      id: 4,
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
      codeSnippet: "function withdraw() public { uint am = balances[msg.sender]; balances[msg.sender] = 0; msg.sender.transfer(am); }",
      externalCalls: [],
      etherTransfers: [
        { id: "e1", contractName: "ReentrancySafe", functionName: "withdraw", recipient: "msg.sender", amount: "am", transferType: "transfer", rawExpression: "msg.sender.transfer(am)", location: BASE_LOC }
      ],
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
      functions: [depositFn, withdrawFn],
      stateVariables: [
        { id: 30, name: "balances", contractName: "ReentrancySafe", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 31, name: "owner", contractName: "ReentrancySafe", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC }
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: [],
      etherTransfers: withdrawFn.etherTransfers,
      controlStatements: [],
      location: BASE_LOC,
    };

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const acFindings = res.findings.filter((f) => f.vulnerabilityType === "Access Control");
    expect(acFindings.length).toBe(0);
  });

  it("4 & 5. TokenERC20.transfer() & approve() -> NO Access Control", () => {
    const transferFn: ASTFunction = {
      id: 5,
      name: "transfer",
      contractName: "TokenERC20",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "to", type: "address" }, { name: "value", type: "uint256" }],
      returnParameters: [],
      signature: "transfer(address,uint256)",
      location: BASE_LOC,
      codeSnippet: "function transfer(address to, uint256 value) public returns (bool) { balanceOf[msg.sender] -= value; balanceOf[to] += value; return true; }",
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const approveFn: ASTFunction = {
      id: 6,
      name: "approve",
      contractName: "TokenERC20",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "spender", type: "address" }, { name: "value", type: "uint256" }],
      returnParameters: [],
      signature: "approve(address,uint256)",
      location: BASE_LOC,
      codeSnippet: "function approve(address spender, uint256 value) public returns (bool) { allowance[msg.sender][spender] = value; return true; }",
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 4,
      name: "TokenERC20",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [transferFn, approveFn],
      stateVariables: [
        { id: 40, name: "balanceOf", contractName: "TokenERC20", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 41, name: "allowance", contractName: "TokenERC20", type: "mapping(address => mapping(address => uint256))", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 42, name: "owner", contractName: "TokenERC20", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
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
    const acFindings = res.findings.filter((f) => f.vulnerabilityType === "Access Control");
    expect(acFindings.length).toBe(0);
  });

  it("6 & 7. DelegatecallVulnerable.execute() & executeStored() -> CONFIRMED Access Control", () => {
    const executeFn: ASTFunction = {
      id: 7,
      name: "execute",
      contractName: "DelegatecallVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "target", type: "address" }, { name: "data", type: "bytes" }],
      returnParameters: [],
      signature: "execute(address,bytes)",
      location: BASE_LOC,
      codeSnippet: "function execute(address target, bytes data) public { target.delegatecall(data); }",
      externalCalls: [
        { id: "c1", contractName: "DelegatecallVulnerable", functionName: "execute", target: "target", method: "delegatecall", callType: "delegatecall", arguments: ["data"], rawExpression: "target.delegatecall(data)", location: BASE_LOC }
      ],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const executeStoredFn: ASTFunction = {
      id: 8,
      name: "executeStored",
      contractName: "DelegatecallVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "data", type: "bytes" }],
      returnParameters: [],
      signature: "executeStored(bytes)",
      location: BASE_LOC,
      codeSnippet: "function executeStored(bytes data) public { lib.delegatecall(data); }",
      externalCalls: [
        { id: "c2", contractName: "DelegatecallVulnerable", functionName: "executeStored", target: "lib", method: "delegatecall", callType: "delegatecall", arguments: ["data"], rawExpression: "lib.delegatecall(data)", location: BASE_LOC }
      ],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 5,
      name: "DelegatecallVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [executeFn, executeStoredFn],
      stateVariables: [
        { id: 50, name: "lib", contractName: "DelegatecallVulnerable", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 51, name: "owner", contractName: "DelegatecallVulnerable", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: [...executeFn.externalCalls, ...executeStoredFn.externalCalls],
      etherTransfers: [],
      controlStatements: [],
      location: BASE_LOC,
    };

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const acFindings = res.findings.filter((f) => f.vulnerabilityType === "Access Control" && f.classification === "CONFIRMED");
    expect(acFindings.length).toBe(2);
    expect(acFindings.map((f) => f.functionName)).toContain("execute");
    expect(acFindings.map((f) => f.functionName)).toContain("executeStored");
  });

  it("8, 9 & 10. AccessControlVulnerable destroyContract, emergencyWithdraw & adminSweep -> CONFIRMED Access Control", () => {
    const destroyFn: ASTFunction = {
      id: 9,
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
        { id: "e2", contractName: "AccessControlVulnerable", functionName: "destroyContract", recipient: "msg.sender", amount: "balance", transferType: "selfdestruct", rawExpression: "selfdestruct(payable(msg.sender))", location: BASE_LOC }
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const emergencyWithdrawFn: ASTFunction = {
      id: 10,
      name: "emergencyWithdraw",
      contractName: "AccessControlVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "amount", type: "uint256" }],
      returnParameters: [],
      signature: "emergencyWithdraw(uint256)",
      location: BASE_LOC,
      codeSnippet: "function emergencyWithdraw(uint256 amount) public {\n  require(amount > 0);\n  require(amount <= emergencyLimit);\n  treasury.transfer(amount);\n  totalWithdrawals += amount;\n}",
      externalCalls: [
        { id: "c3", contractName: "AccessControlVulnerable", functionName: "emergencyWithdraw", target: "treasury", method: "transfer", callType: "transfer", arguments: ["amount"], rawExpression: "treasury.transfer(amount)", location: BASE_LOC }
      ],
      etherTransfers: [
        { id: "e3", contractName: "AccessControlVulnerable", functionName: "emergencyWithdraw", recipient: "treasury", amount: "amount", transferType: "transfer", rawExpression: "treasury.transfer(amount)", location: BASE_LOC }
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const adminSweepFn: ASTFunction = {
      id: 11,
      name: "adminSweep",
      contractName: "AccessControlVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "amount", type: "uint256" }],
      returnParameters: [],
      signature: "adminSweep(uint256)",
      location: BASE_LOC,
      codeSnippet: "function adminSweep(uint256 amount) public {\n  require(amount > 0);\n  require(amount <= address(this).balance);\n  treasury.transfer(amount);\n  totalWithdrawals += amount;\n}",
      externalCalls: [
        { id: "c4", contractName: "AccessControlVulnerable", functionName: "adminSweep", target: "treasury", method: "transfer", callType: "transfer", arguments: ["amount"], rawExpression: "treasury.transfer(amount)", location: BASE_LOC }
      ],
      etherTransfers: [
        { id: "e4", contractName: "AccessControlVulnerable", functionName: "adminSweep", recipient: "treasury", amount: "amount", transferType: "transfer", rawExpression: "treasury.transfer(amount)", location: BASE_LOC }
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract: ASTContract = {
      id: 6,
      name: "AccessControlVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [destroyFn, emergencyWithdrawFn, adminSweepFn],
      stateVariables: [
        { id: 60, name: "treasury", contractName: "AccessControlVulnerable", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 61, name: "owner", contractName: "AccessControlVulnerable", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 62, name: "emergencyLimit", contractName: "AccessControlVulnerable", type: "uint256", visibility: "public", mutability: "mutable", location: BASE_LOC },
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: [...emergencyWithdrawFn.externalCalls, ...adminSweepFn.externalCalls],
      etherTransfers: [...destroyFn.etherTransfers, ...emergencyWithdrawFn.etherTransfers, ...adminSweepFn.etherTransfers],
      controlStatements: [],
      location: BASE_LOC,
    };

    const res = detectSecurityVulnerabilities(makeAST([contract]));
    const acFindings = res.findings.filter((f) => f.vulnerabilityType === "Access Control" && f.classification === "CONFIRMED");
    expect(acFindings.length).toBe(3);
    const names = acFindings.map((f) => f.functionName);
    expect(names).toContain("destroyContract");
    expect(names).toContain("emergencyWithdraw");
    expect(names).toContain("adminSweep");
  });

  it("11 & 12. withdrawUserBalance & transferOwnership -> NO Access Control", () => {
    const withdrawUserBalanceFn: ASTFunction = {
      id: 12,
      name: "withdrawUserBalance",
      contractName: "AccessControlVulnerable",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "amount", type: "uint256" }],
      returnParameters: [],
      signature: "withdrawUserBalance(uint256)",
      location: BASE_LOC,
      codeSnippet: "function withdrawUserBalance(uint256 amount) public {\n  require(balances[msg.sender] >= amount);\n  balances[msg.sender] -= amount;\n  totalWithdrawals += amount;\n  msg.sender.transfer(amount);\n}",
      externalCalls: [],
      etherTransfers: [
        { id: "e5", contractName: "AccessControlVulnerable", functionName: "withdrawUserBalance", recipient: "msg.sender", amount: "amount", transferType: "transfer", rawExpression: "msg.sender.transfer(amount)", location: BASE_LOC }
      ],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const transferOwnershipFn: ASTFunction = {
      id: 13,
      name: "transferOwnership",
      contractName: "owned",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: ["onlyOwner"],
      parameters: [{ name: "newOwner", type: "address" }],
      returnParameters: [],
      signature: "transferOwnership(address)",
      location: BASE_LOC,
      codeSnippet: "function transferOwnership(address newOwner) public onlyOwner { owner = newOwner; }",
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      operations: EMPTY_OPS,
    };

    const contract1: ASTContract = {
      id: 7,
      name: "AccessControlVulnerable",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [withdrawUserBalanceFn],
      stateVariables: [
        { id: 70, name: "balances", contractName: "AccessControlVulnerable", type: "mapping(address => uint256)", visibility: "public", mutability: "mutable", location: BASE_LOC },
        { id: 71, name: "treasury", contractName: "AccessControlVulnerable", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC }
      ],
      modifiers: [],
      events: [],
      structs: [],
      enums: [],
      externalCalls: [],
      etherTransfers: withdrawUserBalanceFn.etherTransfers,
      controlStatements: [],
      location: BASE_LOC,
    };

    const contract2: ASTContract = {
      id: 8,
      name: "owned",
      kind: "contract",
      isAbstract: false,
      sourceFile: "Test.sol",
      bases: [],
      functions: [transferOwnershipFn],
      stateVariables: [
        { id: 80, name: "owner", contractName: "owned", type: "address", visibility: "public", mutability: "mutable", location: BASE_LOC }
      ],
      modifiers: [
        { id: 800, name: "onlyOwner", contractName: "owned", parameters: [], location: BASE_LOC, invokedBy: ["transferOwnership(address)"] }
      ],
      events: [],
      structs: [],
      enums: [],
      externalCalls: [],
      etherTransfers: [],
      controlStatements: [],
      location: BASE_LOC,
    };

    const res = detectSecurityVulnerabilities(makeAST([contract1, contract2]));
    const acFindings = res.findings.filter((f) => f.vulnerabilityType === "Access Control");
    expect(acFindings.length).toBe(0);
  });
});
