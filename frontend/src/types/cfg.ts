// ─── CFG / Call Graph Types ───────────────────────────────────────────────────
//
// Lightweight deterministic Control Flow Graph (CFG) and Call Graph (CG)
// for Solidity contracts derived from ASTAnalysisResult.
//
// Design rules:
//  - No vulnerability claims. This is analysis infrastructure only.
//  - All node/edge ids are deterministic strings.
//  - Source locations are preserved from the AST layer.
//  - Do NOT duplicate the AST parsing layer; consume ASTAnalysisResult.

import type { SourceLocation } from "./ast";

// ─── Shared ───────────────────────────────────────────────────────────────────

/** Fully-qualified function identity within the contract graph. */
export interface FunctionRef {
  contractName: string;
  functionName: string;
}

// ─── Call Graph ───────────────────────────────────────────────────────────────

export type CallEdgeKind =
  | "internal"        // call to a function in the same contract
  | "external"        // call to an external contract (non-low-level)
  | "low-level-call"  // .call(...)
  | "delegatecall"    // .delegatecall(...)
  | "staticcall"      // .staticcall(...)
  | "transfer"        // .transfer(amount)
  | "send"            // .send(amount)
  | "selfdestruct";   // selfdestruct(recipient)

export interface CallEdge {
  /** Unique deterministic id for this edge. */
  id: string;
  kind: CallEdgeKind;
  /** Caller function. */
  caller: FunctionRef;
  /**
   * Callee function. For external/low-level calls, functionName is the method
   * name or "call"/"delegatecall"/"staticcall".  contractName is the target
   * expression string or "external".
   */
  callee: FunctionRef;
  /** Raw call expression as it appears in the source. */
  rawExpression: string;
  location: SourceLocation;
}

export interface CallGraph {
  /** All call edges across all contracts. */
  edges: CallEdge[];
  /**
   * Quick lookup: for each "contractName.functionName" key, the outgoing edges.
   */
  edgesByCallerKey: Map<string, CallEdge[]>;
  /**
   * Quick lookup: for each "contractName.functionName" key, the incoming edges.
   */
  edgesByCalleeKey: Map<string, CallEdge[]>;
}

// ─── CFG ─────────────────────────────────────────────────────────────────────

export type CFGNodeKind =
  | "entry"       // synthetic entry point of a function
  | "exit"        // synthetic exit point (normal return)
  | "statement"   // a sequential statement / expression
  | "branch"      // conditional: if/ternary → two successor edges (true/false)
  | "loop"        // for / while / do-while header
  | "require"     // require(condition) — can revert on false branch
  | "assert"      // assert(condition) — can revert on false branch
  | "revert"      // explicit revert / revert CustomError()
  | "return"      // return statement
  | "call";       // external/internal function call node

export interface CFGNode {
  /** Deterministic id: "<contract>.<function>.<seq>" */
  id: string;
  kind: CFGNodeKind;
  /** Human-readable label for display / debugging. */
  label: string;
  /** Source location if available. */
  location?: SourceLocation;
  /** Raw expression or statement text. */
  rawExpression?: string;
}

export type CFGEdgeKind =
  | "sequential"  // normal execution flow (A→B, no branch)
  | "true"        // branch taken (condition = true)
  | "false"       // branch not taken (condition = false)
  | "loop-back"   // loop back-edge
  | "exception";  // revert / require-fail path

export interface CFGEdge {
  /** Deterministic id: "<fromId>-><toId>[:<kind>]" */
  id: string;
  kind: CFGEdgeKind;
  from: string; // CFGNode id
  to: string;   // CFGNode id
}

/** CFG for a single function. */
export interface FunctionCFG {
  /** Contract this function belongs to. */
  contractName: string;
  /** Function name (may be "constructor" / "fallback" / "receive"). */
  functionName: string;
  /** All nodes in the CFG, including synthetic entry/exit. */
  nodes: CFGNode[];
  /** All edges in the CFG. */
  edges: CFGEdge[];
  /** Id of the entry node. */
  entryNodeId: string;
  /** Id of the exit node. */
  exitNodeId: string;
}

/** Full CFG result for an entire ASTAnalysisResult. */
export interface ContractCFGResult {
  /** One CFG per analysed function. */
  functionCFGs: FunctionCFG[];
  /** The contract-level / cross-contract call graph. */
  callGraph: CallGraph;
}
