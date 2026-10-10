import { describe, it, expect } from "vitest";
import { analyzeTaint } from "../src/engines/taint-analyzer";
import { detectSecurityVulnerabilities } from "../../frontend/src/utils/security-detector";
import type {
  ASTAnalysisResult,
  ASTContract,
  ASTFunction,
  ASTExternalCall,
  ASTEtherTransfer,
  ASTOperation,
  SourceLocation,
} from "../src/types/ast";

const BASE_LOC: SourceLocation = {
  file: "TaintTest.sol",
  line: 15,
  column: 1,
  endLine: 20,
  start: 150,
  length: 100,
  end: 250,
};

function makeMinimalAST(
  contractName: string,
  functions: ASTFunction[]
): ASTAnalysisResult {
  const contract: ASTContract = {
    id: 1,
    name: contractName,
    kind: "contract",
    isAbstract: false,
    sourceFile: "TaintTest.sol",
    bases: [],
    functions,
    stateVariables: [],
    modifiers: [],
    events: [],
    structs: [],
    enums: [],
    externalCalls: functions.flatMap((f) => f.externalCalls),
    etherTransfers: functions.flatMap((f) => f.etherTransfers),
    controlStatements: functions.flatMap((f) => f.controlStatements),
    location: BASE_LOC,
  };
  return {
    contracts: [contract],
    functions,
    stateVariables: [],
    modifiers: [],
    events: [],
    structs: [],
    enums: [],
    inheritance: [],
    externalCalls: contract.externalCalls,
    etherTransfers: contract.etherTransfers,
    controlStatements: contract.controlStatements,
    summary: {
      totalContracts: 1,
      totalFunctions: functions.length,
      totalStateVariables: 0,
      totalModifiers: 0,
      totalEvents: 0,
      totalStructs: 0,
      totalEnums: 0,
      totalExternalCalls: contract.externalCalls.length,
      totalEtherTransfers: contract.etherTransfers.length,
      totalControlStatements: contract.controlStatements.length,
      publicOrExternalFunctions: functions.length,
      internalOrPrivateFunctions: 0,
      payableFunctions: 0,
      viewOrPureFunctions: 0,
    },
    rawAst: {},
  };
}

describe("Deterministic Taint / Data-Flow Analysis Engine", () => {
  it("1. Parameter -> Sink propagation", () => {
    const xfer: ASTEtherTransfer = {
      id: "xfer-1",
      contractName: "Vault",
      functionName: "withdraw",
      recipient: "recipient",
      amount: "amount",
      transferType: "transfer",
      rawExpression: "recipient.transfer(amount)",
      location: BASE_LOC,
    };

    const fn: ASTFunction = {
      id: 1,
      name: "withdraw",
      contractName: "Vault",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [
        { name: "recipient", type: "address", location: BASE_LOC },
        { name: "amount", type: "uint256", location: BASE_LOC },
      ],
      returnParameters: [],
      signature: "withdraw(address,uint256)",
      location: BASE_LOC,
      codeSnippet: "function withdraw(address recipient, uint256 amount) public { recipient.transfer(amount); }",
      externalCalls: [],
      etherTransfers: [xfer],
      controlStatements: [],
      operations: [],
    };

    const ast = makeMinimalAST("Vault", [fn]);
    const res = analyzeTaint(ast);

    expect(res.sources.length).toBeGreaterThan(0);
    expect(res.sinks.length).toBeGreaterThan(0);

    const taintedPath = res.paths.find((p) => p.isTainted && p.sink.type === "ether-transfer-recipient");
    expect(taintedPath).toBeDefined();
    expect(taintedPath?.source.type).toBe("parameter");
    expect(taintedPath?.source.name).toBe("recipient");
  });

  it("2. msg.sender -> Sink propagation", () => {
    const xfer: ASTEtherTransfer = {
      id: "xfer-2",
      contractName: "Vault",
      functionName: "claim",
      recipient: "msg.sender",
      amount: "100",
      transferType: "send",
      rawExpression: "msg.sender.send(100)",
      location: BASE_LOC,
    };

    const fn: ASTFunction = {
      id: 2,
      name: "claim",
      contractName: "Vault",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [],
      returnParameters: [],
      signature: "claim()",
      location: BASE_LOC,
      codeSnippet: "function claim() public { msg.sender.send(100); }",
      externalCalls: [],
      etherTransfers: [xfer],
      controlStatements: [],
      operations: [],
    };

    const ast = makeMinimalAST("Vault", [fn]);
    const res = analyzeTaint(ast);

    const msgSenderPath = res.paths.find((p) => p.isTainted && p.source.type === "msg.sender");
    expect(msgSenderPath).toBeDefined();
    expect(msgSenderPath?.sink.type).toBe("ether-transfer-recipient");
  });

  it("3. msg.value -> state variable propagation", () => {
    const opWrite: ASTOperation = {
      id: "op-write",
      kind: "state-write",
      functionName: "deposit",
      contractName: "Vault",
      expression: "balances[msg.sender] += msg.value",
      location: BASE_LOC,
      stateVariable: "balances",
    };

    const fn: ASTFunction = {
      id: 3,
      name: "deposit",
      contractName: "Vault",
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
      operations: [opWrite],
    };

    const ast = makeMinimalAST("Vault", [fn]);
    const res = analyzeTaint(ast);

    const msgValueSource = res.sources.find((s) => s.type === "msg.value");
    expect(msgValueSource).toBeDefined();
  });

  it("4. Variable -> Variable -> Sink multi-step propagation", () => {
    const opAssign1: ASTOperation = {
      id: "op-1",
      kind: "state-write",
      functionName: "process",
      contractName: "Vault",
      expression: "target = inputAddr",
      location: BASE_LOC,
    };

    const opAssign2: ASTOperation = {
      id: "op-2",
      kind: "state-write",
      functionName: "process",
      contractName: "Vault",
      expression: "dest = target",
      location: BASE_LOC,
    };

    const xfer: ASTEtherTransfer = {
      id: "xfer-3",
      contractName: "Vault",
      functionName: "process",
      recipient: "dest",
      amount: "10",
      transferType: "transfer",
      rawExpression: "dest.transfer(10)",
      location: BASE_LOC,
    };

    const fn: ASTFunction = {
      id: 4,
      name: "process",
      contractName: "Vault",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "inputAddr", type: "address", location: BASE_LOC }],
      returnParameters: [],
      signature: "process(address)",
      location: BASE_LOC,
      codeSnippet: "function process(address inputAddr) public { address target = inputAddr; address dest = target; dest.transfer(10); }",
      externalCalls: [],
      etherTransfers: [xfer],
      controlStatements: [],
      operations: [opAssign1, opAssign2],
    };

    const ast = makeMinimalAST("Vault", [fn]);
    const res = analyzeTaint(ast);

    const path = res.paths.find((p) => p.isTainted && p.source.name === "inputAddr");
    expect(path).toBeDefined();
    expect(path?.steps.length).toBeGreaterThanOrEqual(2);
  });

  it("5. Safe constant -> Sink should NOT be tainted", () => {
    const xfer: ASTEtherTransfer = {
      id: "xfer-safe",
      contractName: "Vault",
      functionName: "burn",
      recipient: "0x0",
      amount: "0",
      transferType: "transfer",
      rawExpression: "address(0).transfer(0)",
      location: BASE_LOC,
    };

    const fn: ASTFunction = {
      id: 5,
      name: "burn",
      contractName: "Vault",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "paramVal", type: "uint256", location: BASE_LOC }],
      returnParameters: [],
      signature: "burn(uint256)",
      location: BASE_LOC,
      codeSnippet: "function burn(uint256 paramVal) public { address(0).transfer(0); }",
      externalCalls: [],
      etherTransfers: [xfer],
      controlStatements: [],
      operations: [],
    };

    const ast = makeMinimalAST("Vault", [fn]);
    const res = analyzeTaint(ast);

    const safePath = res.paths.find((p) => p.sink.expression.includes("address(0)") && p.isTainted);
    expect(safePath).toBeUndefined();
  });

  it("6. Delegatecall target tainted by parameter", () => {
    const call: ASTExternalCall = {
      id: "call-dc",
      contractName: "Proxy",
      functionName: "upgrade",
      target: "customImpl",
      method: "delegatecall",
      callType: "delegatecall",
      arguments: [],
      rawExpression: "customImpl.delegatecall(msg.data)",
      location: BASE_LOC,
    };

    const fn: ASTFunction = {
      id: 6,
      name: "upgrade",
      contractName: "Proxy",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "customImpl", type: "address", location: BASE_LOC }],
      returnParameters: [],
      signature: "upgrade(address)",
      location: BASE_LOC,
      codeSnippet: "function upgrade(address customImpl) public { customImpl.delegatecall(msg.data); }",
      externalCalls: [call],
      etherTransfers: [],
      controlStatements: [],
      operations: [],
    };

    const ast = makeMinimalAST("Proxy", [fn]);
    const res = analyzeTaint(ast);

    const dcPath = res.paths.find((p) => p.isTainted && p.sink.type === "delegatecall-target");
    expect(dcPath).toBeDefined();
    expect(dcPath?.source.name).toBe("customImpl");
  });

  it("7. External call value tainted by parameter", () => {
    const call: ASTExternalCall = {
      id: "call-ext",
      contractName: "Vault",
      functionName: "payOut",
      target: "user",
      method: "call",
      callType: "low-level-call",
      value: "userAmount",
      arguments: [],
      rawExpression: "user.call{value: userAmount}(\"\")",
      location: BASE_LOC,
    };

    const fn: ASTFunction = {
      id: 7,
      name: "payOut",
      contractName: "Vault",
      kind: "function",
      visibility: "public",
      stateMutability: "payable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [
        { name: "user", type: "address", location: BASE_LOC },
        { name: "userAmount", type: "uint256", location: BASE_LOC },
      ],
      returnParameters: [],
      signature: "payOut(address,uint256)",
      location: BASE_LOC,
      codeSnippet: "function payOut(address user, uint256 userAmount) public payable { user.call{value: userAmount}(\"\"); }",
      externalCalls: [call],
      etherTransfers: [],
      controlStatements: [],
      operations: [],
    };

    const ast = makeMinimalAST("Vault", [fn]);
    const res = analyzeTaint(ast);

    const valueSinkPath = res.paths.find((p) => p.isTainted && p.sink.type === "low-level-call-value");
    expect(valueSinkPath).toBeDefined();
    expect(valueSinkPath?.source.name).toBe("userAmount");
  });

  it("8. Source location is preserved in sources, sinks, and steps", () => {
    const xfer: ASTEtherTransfer = {
      id: "xfer-loc",
      contractName: "Vault",
      functionName: "withdraw",
      recipient: "to",
      amount: "val",
      transferType: "transfer",
      rawExpression: "to.transfer(val)",
      location: BASE_LOC,
    };

    const fn: ASTFunction = {
      id: 8,
      name: "withdraw",
      contractName: "Vault",
      kind: "function",
      visibility: "public",
      stateMutability: "nonpayable",
      isVirtual: false,
      isOverride: false,
      modifiers: [],
      parameters: [{ name: "to", type: "address", location: BASE_LOC }],
      returnParameters: [],
      signature: "withdraw(address)",
      location: BASE_LOC,
      codeSnippet: "function withdraw(address to) public { to.transfer(10); }",
      externalCalls: [],
      etherTransfers: [xfer],
      controlStatements: [],
      operations: [],
    };

    const ast = makeMinimalAST("Vault", [fn]);
    const res = analyzeTaint(ast);

    expect(res.sources[0].location?.line).toBe(BASE_LOC.line);
    expect(res.sinks[0].location?.line).toBe(BASE_LOC.line);
  });

  it("9. Existing benchmark findings remain completely unchanged when running taint analysis", () => {
    const call: ASTExternalCall = {
      id: "c-bench",
      contractName: "Vault",
      functionName: "withdraw",
      target: "msg.sender",
      method: "call",
      callType: "low-level-call",
      arguments: [],
      rawExpression: "msg.sender.call{value: amount}(\"\")",
      location: BASE_LOC,
    };
    const xfer: ASTEtherTransfer = {
      id: "t-bench",
      contractName: "Vault",
      functionName: "withdraw",
      recipient: "msg.sender",
      amount: "amount",
      transferType: "call-value",
      rawExpression: call.rawExpression,
      location: BASE_LOC,
    };
    const fn: ASTFunction = {
      id: 9,
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
      codeSnippet: "function withdraw() public { msg.sender.call{value: amount}(\"\"); }",
      externalCalls: [call],
      etherTransfers: [xfer],
      controlStatements: [],
      operations: [],
    };

    const ast = makeMinimalAST("Vault", [fn]);

    const beforeResult = detectSecurityVulnerabilities(ast);
    const taintRes = analyzeTaint(ast);
    const afterResult = detectSecurityVulnerabilities(ast);

    expect(taintRes.sources.length).toBeGreaterThan(0);
    expect(afterResult.summary.totalFindings).toBe(beforeResult.summary.totalFindings);
    expect(afterResult.summary.confirmedCount).toBe(beforeResult.summary.confirmedCount);
  });
});

