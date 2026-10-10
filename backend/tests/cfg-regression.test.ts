// ─── CFG / Call Graph Regression Tests ───────────────────────────────────────
//
// Focused regression tests verifying:
//  1. Simple function A -> B internal call edge
//  2. Conditional branch (require) node in CFG
//  3. Loop header node in CFG
//  4. External call edge in Call Graph
//  5. Delegatecall edge in Call Graph
//  6. Source location preservation
//  7. CFG generation does NOT alter existing security findings

import { describe, it, expect } from "vitest";
import { buildCallGraph, buildFunctionCFG, buildContractCFG } from "../src/engines/cfg-builder";
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

// ─── Test Fixtures ────────────────────────────────────────────────────────────

const BASE_LOC: SourceLocation = {
  file: "Test.sol",
  line: 10,
  column: 1,
  endLine: 15,
  start: 100,
  length: 80,
  end: 180,
};

const LOC2: SourceLocation = { ...BASE_LOC, line: 20, endLine: 25, start: 200 };

function makeMinimalAST(
  contractName: string,
  functions: ASTFunction[]
): ASTAnalysisResult {
  const contract: ASTContract = {
    id: 1,
    name: contractName,
    kind: "contract",
    isAbstract: false,
    sourceFile: "Test.sol",
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

function makeFunc(
  name: string,
  contractName: string,
  externalCalls: ASTExternalCall[] = [],
  etherTransfers: ASTEtherTransfer[] = [],
  operations: ASTOperation[] = [],
  snippet?: string
): ASTFunction {
  return {
    id: Math.random(),
    name,
    contractName,
    kind: "function",
    visibility: "public",
    stateMutability: "nonpayable",
    isVirtual: false,
    isOverride: false,
    modifiers: [],
    parameters: [],
    returnParameters: [],
    signature: `${name}()`,
    location: BASE_LOC,
    codeSnippet: snippet,
    externalCalls,
    etherTransfers,
    controlStatements: [],
    operations,
  };
}

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe("CFG / Call Graph Regression Tests", () => {
  // ── Test 1: Internal call edge A -> B ────────────────────────────────────────
  it("1. Simple function A -> B internal call via codeSnippet", () => {
    const fnA = makeFunc("deposit", "Vault", [], [], [], "function deposit() { _updateBalance(); }");
    const fnB = makeFunc("_updateBalance", "Vault", [], [], [], "function _updateBalance() {}");
    const ast = makeMinimalAST("Vault", [fnA, fnB]);

    const cg = buildCallGraph(ast);

    const internalEdges = cg.edges.filter(
      (e) =>
        e.kind === "internal" &&
        e.caller.functionName === "deposit" &&
        e.callee.functionName === "_updateBalance"
    );

    expect(internalEdges.length).toBeGreaterThan(0);
    expect(internalEdges[0].caller.contractName).toBe("Vault");
    expect(internalEdges[0].callee.contractName).toBe("Vault");
  });

  // ── Test 2: Conditional branch (require) node in CFG ──────────────────────
  it("2. Require statement creates a branch node with exception edge to exit", () => {
    const requireOp: ASTOperation = {
      id: "op-1",
      kind: "control",
      functionName: "withdraw",
      contractName: "Vault",
      expression: "require(balance > 0)",
      location: BASE_LOC,
    };
    const fn = makeFunc("withdraw", "Vault", [], [], [requireOp]);
    const cfg = buildFunctionCFG(fn);

    const requireNode = cfg.nodes.find((n) => n.kind === "require");
    expect(requireNode).toBeDefined();

    // There must be an exception edge from the require node to exit
    const exceptionEdge = cfg.edges.find(
      (e) => e.from === requireNode!.id && e.to === cfg.exitNodeId && e.kind === "exception"
    );
    expect(exceptionEdge).toBeDefined();

    // There must also be a sequential edge INTO the require node
    const sequentialIn = cfg.edges.find(
      (e) => e.to === requireNode!.id && e.kind === "sequential"
    );
    expect(sequentialIn).toBeDefined();
  });

  // ── Test 3: Loop node in CFG ──────────────────────────────────────────────
  it("3. For loop creates a loop header node with a back-edge", () => {
    const fn = makeFunc(
      "distribute",
      "Distributor",
      [],
      [],
      [],
      "function distribute() { for (uint i = 0; i < users.length; i++) { pay(users[i]); } }"
    );
    const cfg = buildFunctionCFG(fn);

    const loopNode = cfg.nodes.find((n) => n.kind === "loop");
    expect(loopNode).toBeDefined();

    // Loop node must have a back-edge to itself
    const loopBack = cfg.edges.find(
      (e) => e.from === loopNode!.id && e.to === loopNode!.id && e.kind === "loop-back"
    );
    expect(loopBack).toBeDefined();
  });

  // ── Test 4: External call edge in Call Graph ──────────────────────────────
  it("4. External contract call appears as an 'external' edge in Call Graph", () => {
    const extCall: ASTExternalCall = {
      id: "c1",
      contractName: "Swapper",
      functionName: "swap",
      target: "IPool(pool)",
      method: "swap",
      callType: "regular",
      arguments: [],
      rawExpression: "IPool(pool).swap(amountIn, amountOut)",
      location: BASE_LOC,
    };
    const fn = makeFunc("swap", "Swapper", [extCall]);
    const ast = makeMinimalAST("Swapper", [fn]);
    const cg = buildCallGraph(ast);

    const extEdge = cg.edges.find((e) => e.kind === "external" && e.caller.functionName === "swap");
    expect(extEdge).toBeDefined();
    expect(extEdge!.callee.contractName).toBe("IPool(pool)");
    expect(extEdge!.callee.functionName).toBe("swap");
    expect(extEdge!.rawExpression).toBe("IPool(pool).swap(amountIn, amountOut)");
  });

  // ── Test 5: Delegatecall edge in Call Graph ───────────────────────────────
  it("5. Delegatecall appears as a 'delegatecall' edge in Call Graph", () => {
    const dc: ASTExternalCall = {
      id: "dc1",
      contractName: "Proxy",
      functionName: "fallback",
      target: "implementation",
      method: "delegatecall",
      callType: "delegatecall",
      arguments: [],
      rawExpression: "implementation.delegatecall(msg.data)",
      location: BASE_LOC,
    };
    const fn = makeFunc("fallback", "Proxy", [dc]);
    const ast = makeMinimalAST("Proxy", [fn]);
    const cg = buildCallGraph(ast);

    const dcEdge = cg.edges.find((e) => e.kind === "delegatecall");
    expect(dcEdge).toBeDefined();
    expect(dcEdge!.caller.contractName).toBe("Proxy");
    expect(dcEdge!.caller.functionName).toBe("fallback");
    expect(dcEdge!.callee.functionName).toBe("delegatecall");
  });

  // ── Test 6: Source location preservation ─────────────────────────────────
  it("6. Source locations are preserved verbatim in Call Graph edges and CFG nodes", () => {
    const extCall: ASTExternalCall = {
      id: "c2",
      contractName: "Token",
      functionName: "transfer",
      target: "IERC20(token)",
      method: "transferFrom",
      callType: "regular",
      arguments: [],
      rawExpression: "IERC20(token).transferFrom(from, to, amount)",
      location: LOC2,
    };
    const fn = makeFunc("transfer", "Token", [extCall]);
    const ast = makeMinimalAST("Token", [fn]);

    // Call Graph location
    const cg = buildCallGraph(ast);
    const edge = cg.edges.find((e) => e.rawExpression.includes("transferFrom"));
    expect(edge).toBeDefined();
    expect(edge!.location.line).toBe(LOC2.line);
    expect(edge!.location.start).toBe(LOC2.start);

    // CFG node location via operation
    const op: ASTOperation = {
      id: "op-loc",
      kind: "external-call",
      functionName: "transfer",
      contractName: "Token",
      expression: extCall.rawExpression,
      location: LOC2,
      externalCall: extCall,
    };
    const fnWithOp = makeFunc("transfer", "Token", [extCall], [], [op]);
    const cfg = buildFunctionCFG(fnWithOp);
    const callNode = cfg.nodes.find((n) => n.kind === "call");
    expect(callNode).toBeDefined();
    expect(callNode!.location?.line).toBe(LOC2.line);
    expect(callNode!.location?.start).toBe(LOC2.start);
  });

  // ── Test 7: CFG generation does not alter existing security findings ───────
  it("7. Running buildContractCFG does not change detectSecurityVulnerabilities output", () => {
    const call: ASTExternalCall = {
      id: "c3",
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
      id: "t1",
      contractName: "Vault",
      functionName: "withdraw",
      recipient: "msg.sender",
      amount: "amount",
      transferType: "call-value",
      rawExpression: call.rawExpression,
      location: BASE_LOC,
    };
    const fn = makeFunc("withdraw", "Vault", [call], [xfer]);
    const ast = makeMinimalAST("Vault", [fn]);

    // Security findings BEFORE CFG
    const beforeFindings = detectSecurityVulnerabilities(ast);

    // Build CFG (must not throw or mutate ast)
    const cfgResult = buildContractCFG(ast);

    // Security findings AFTER CFG
    const afterFindings = detectSecurityVulnerabilities(ast);

    expect(afterFindings.summary.totalFindings).toBe(beforeFindings.summary.totalFindings);
    expect(afterFindings.summary.confirmedCount).toBe(beforeFindings.summary.confirmedCount);
    expect(cfgResult.callGraph.edges.length).toBeGreaterThan(0);
    expect(cfgResult.functionCFGs.length).toBe(1);
  });

  // ── Test 8: Low-level call edge ───────────────────────────────────────────
  it("8. Low-level .call() appears as 'low-level-call' edge in Call Graph", () => {
    const llc: ASTExternalCall = {
      id: "llc1",
      contractName: "Vault",
      functionName: "withdraw",
      target: "recipient",
      method: "call",
      callType: "low-level-call",
      arguments: [],
      rawExpression: "recipient.call{value: amount}(\"\")",
      location: BASE_LOC,
    };
    const fn = makeFunc("withdraw", "Vault", [llc]);
    const ast = makeMinimalAST("Vault", [fn]);
    const cg = buildCallGraph(ast);

    const llEdge = cg.edges.find((e) => e.kind === "low-level-call");
    expect(llEdge).toBeDefined();
    expect(llEdge!.caller.functionName).toBe("withdraw");
    expect(llEdge!.callee.contractName).toBe("recipient");
  });

  // ── Test 9: edgesByCallerKey lookup ──────────────────────────────────────
  it("9. edgesByCallerKey lookup returns correct outgoing edges", () => {
    const extCall: ASTExternalCall = {
      id: "c4",
      contractName: "Router",
      functionName: "execute",
      target: "IAdapter(adapter)",
      method: "execute",
      callType: "regular",
      arguments: [],
      rawExpression: "IAdapter(adapter).execute(data)",
      location: BASE_LOC,
    };
    const fn = makeFunc("execute", "Router", [extCall]);
    const ast = makeMinimalAST("Router", [fn]);
    const cg = buildCallGraph(ast);

    const outgoing = cg.edgesByCallerKey.get("Router.execute") ?? [];
    expect(outgoing.length).toBeGreaterThan(0);
    expect(outgoing[0].caller.functionName).toBe("execute");
  });

  // ── Test 10: CFG entry/exit nodes always present ──────────────────────────
  it("10. Every CFG has exactly one entry and one exit node", () => {
    const fn = makeFunc("mint", "Token", [], [], []);
    const cfg = buildFunctionCFG(fn);

    const entryNodes = cfg.nodes.filter((n) => n.kind === "entry");
    const exitNodes  = cfg.nodes.filter((n) => n.kind === "exit");

    expect(entryNodes.length).toBe(1);
    expect(exitNodes.length).toBe(1);
    expect(cfg.entryNodeId).toBe(entryNodes[0].id);
    expect(cfg.exitNodeId).toBe(exitNodes[0].id);
  });
});

