// ─── CFG / Call Graph Builder ─────────────────────────────────────────────────
//
// Builds a lightweight deterministic Control Flow Graph (CFG) and Call Graph
// purely from an already-parsed ASTAnalysisResult.  No re-parsing, no
// duplication of AST infrastructure.
//
// Design rules enforced here:
//  - NEVER claim a vulnerability.  This is analysis infrastructure only.
//  - All node/edge ids are deterministic (contract+function+sequential counter).
//  - Source locations forwarded verbatim from ASTOperation / ASTExternalCall.
//  - Slither failure / AST absence is handled gracefully (returns empty result).

import type { ASTAnalysisResult, ASTFunction, ASTExternalCall, SourceLocation } from "../types/ast";
import type {
  ContractCFGResult,
  CallGraph,
  CallEdge,
  CallEdgeKind,
  FunctionCFG,
  CFGNode,
  CFGEdge,
  CFGNodeKind,
  FunctionRef,
} from "../types/cfg";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function callerKey(ref: FunctionRef): string {
  return `${ref.contractName}.${ref.functionName}`;
}


// ─── Call Graph Builder ───────────────────────────────────────────────────────

/**
 * Builds the inter- and intra-contract Call Graph from an ASTAnalysisResult.
 *
 * Reuses:
 *   - ast.externalCalls  → external / low-level / delegate / staticcall / send / transfer
 *   - ast.etherTransfers → selfdestruct
 *   - ast.functions      → internal calls inferred by cross-referencing function names
 *                          found inside the codeSnippet (lightweight heuristic, deterministic)
 */
export function buildCallGraph(ast: ASTAnalysisResult): CallGraph {
  const edges: CallEdge[] = [];
  let edgeSeq = 0;

  // Build a quick set of all function names per contract for internal-call detection
  const contractFuncNames = new Map<string, Set<string>>();
  for (const fn of ast.functions) {
    if (!contractFuncNames.has(fn.contractName)) {
      contractFuncNames.set(fn.contractName, new Set());
    }
    contractFuncNames.get(fn.contractName)!.add(fn.name);
  }

  // ── 1. External / low-level / transfer / send / staticcall / delegatecall edges ──
  for (const call of ast.externalCalls) {
    const kind = mapExternalCallKind(call);
    const edge: CallEdge = {
      id: `cg-${call.contractName}.${call.functionName}->${call.target}.${call.method}-${++edgeSeq}`,
      kind,
      caller: { contractName: call.contractName, functionName: call.functionName },
      callee: { contractName: call.target, functionName: call.method },
      rawExpression: call.rawExpression,
      location: call.location,
    };
    edges.push(edge);
  }

  // ── 2. Selfdestruct edges (from etherTransfers where type = "selfdestruct") ──
  for (const xfer of ast.etherTransfers) {
    if (xfer.transferType === "selfdestruct") {
      const edge: CallEdge = {
        id: `cg-${xfer.contractName}.${xfer.functionName}->selfdestruct-${++edgeSeq}`,
        kind: "selfdestruct",
        caller: { contractName: xfer.contractName, functionName: xfer.functionName },
        callee: { contractName: xfer.recipient, functionName: "selfdestruct" },
        rawExpression: xfer.rawExpression,
        location: xfer.location,
      };
      edges.push(edge);
    }
  }

  // ── 3. Internal call edges ─────────────────────────────────────────────────
  //
  // The existing AST analyzer doesn't explicitly tag internal calls, but the
  // ASTOperation list includes every call expression.  We detect internal calls
  // by checking if a call expression matches a known function name in the same
  // contract (or via "this." prefix), which the AST walker already recorded
  // inside the operations array as kind="external-call" with a same-contract
  // target OR we infer them from the codeSnippet heuristic below.
  //
  // Approach: for each function, scan its operations.  Any operation whose
  // externalCall target is "this" or whose method matches a function in the
  // same contract (and target is not clearly external) is tagged "internal".
  for (const fn of ast.functions) {
    const sameContractFuncs = contractFuncNames.get(fn.contractName) ?? new Set<string>();
    const processedExpressions = new Set<string>();

    for (const op of fn.operations) {
      if (op.kind !== "external-call" || !op.externalCall) continue;
      const call = op.externalCall;

      // Skip if already captured above (same rawExpression + same contract/func)
      const dedupKey = `${call.contractName}|${call.functionName}|${call.rawExpression}`;
      if (processedExpressions.has(dedupKey)) continue;
      processedExpressions.add(dedupKey);

      // Detect as internal if:
      //   target === "this"  OR
      //   callType is "regular" AND method name matches a known function in same contract
      const isInternalByTarget = call.target === "this";
      const isInternalByName =
        call.callType === "regular" && sameContractFuncs.has(call.method);

      if (isInternalByTarget || isInternalByName) {
        const edge: CallEdge = {
          id: `cg-internal-${fn.contractName}.${fn.name}->${call.method}-${++edgeSeq}`,
          kind: "internal",
          caller: { contractName: fn.contractName, functionName: fn.name },
          callee: { contractName: fn.contractName, functionName: call.method },
          rawExpression: call.rawExpression,
          location: call.location,
        };
        edges.push(edge);
      }
    }

    // ── Heuristic: scan codeSnippet for bare function calls (no "." prefix) ──
    // Handles patterns like `_processPayment()` or `refund(msg.sender)` that
    // the AST walker didn't capture as MemberAccess external calls.
    if (fn.codeSnippet) {
      for (const targetFunc of sameContractFuncs) {
        if (targetFunc === fn.name) continue; // skip self-recursion detection here
        // Match: word boundary + funcName + "("
        const pattern = new RegExp(`(?<![.a-zA-Z0-9_])${escapeRegExp(targetFunc)}\\s*\\(`, "g");
        if (pattern.test(fn.codeSnippet)) {
          const dedupKey = `internal-snippet-${fn.contractName}.${fn.name}->${targetFunc}`;
          if (!edges.some((e) => e.id.includes(dedupKey))) {
            const edge: CallEdge = {
              id: `${dedupKey}-${++edgeSeq}`,
              kind: "internal",
              caller: { contractName: fn.contractName, functionName: fn.name },
              callee: { contractName: fn.contractName, functionName: targetFunc },
              rawExpression: `${targetFunc}(...)`,
              location: fn.location,
            };
            edges.push(edge);
          }
        }
      }
    }
  }

  // ── Build lookup maps ──────────────────────────────────────────────────────
  const edgesByCallerKey = new Map<string, CallEdge[]>();
  const edgesByCalleeKey = new Map<string, CallEdge[]>();

  for (const edge of edges) {
    const ck = callerKey(edge.caller);
    const dk = callerKey(edge.callee);
    if (!edgesByCallerKey.has(ck)) edgesByCallerKey.set(ck, []);
    edgesByCallerKey.get(ck)!.push(edge);
    if (!edgesByCalleeKey.has(dk)) edgesByCalleeKey.set(dk, []);
    edgesByCalleeKey.get(dk)!.push(edge);
  }

  return { edges, edgesByCallerKey, edgesByCalleeKey };
}

function mapExternalCallKind(call: ASTExternalCall): CallEdgeKind {
  switch (call.callType) {
    case "low-level-call": return "low-level-call";
    case "delegatecall":   return "delegatecall";
    case "staticcall":     return "staticcall";
    case "transfer":       return "transfer";
    case "send":           return "send";
    default:               return "external";
  }
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ─── CFG Builder ──────────────────────────────────────────────────────────────

/**
 * Builds a lightweight CFG for a single function by linearising its
 * operations list (already source-ordered by the AST analyzer) into CFG nodes
 * and connecting them with typed edges.
 *
 * The CFG is intentionally simplified:
 *  - Sequential statements → sequential edges.
 *  - require/assert         → branch node with "sequential" (pass) and "exception" (revert) edges.
 *  - revert                 → terminal revert node, exception edge to exit.
 *  - External call ops      → call node, then sequential edge back to flow.
 *  - Loop detection         → a "loop" header node is synthesised when the snippet contains for/while.
 *
 * We do NOT implement full basic-block splitting or phi-nodes.
 * This is analysis infrastructure, not a compiler.
 */
export function buildFunctionCFG(fn: ASTFunction): FunctionCFG {
  const prefix = `${fn.contractName}.${fn.name}`;
  let seq = 0;
  const nodes: CFGNode[] = [];
  const cfgEdges: CFGEdge[] = [];

  function newNode(kind: CFGNodeKind, label: string, loc?: SourceLocation, rawExpression?: string): CFGNode {
    const node: CFGNode = {
      id: `${prefix}.${++seq}`,
      kind,
      label,
      location: loc,
      rawExpression,
    };
    nodes.push(node);
    return node;
  }

  function addEdge(from: string, to: string, kind: CFGEdge["kind"]): void {
    cfgEdges.push({ id: `${from}->${to}:${kind}`, kind, from, to });
  }

  // Synthetic entry / exit
  const entryNode = newNode("entry", `entry: ${fn.name}`);
  const exitNode  = newNode("exit",  `exit: ${fn.name}`);

  // We'll link last node to exitNode after processing all operations
  let prevNodeId = entryNode.id;

  // ── Track if the function has a loop (heuristic from snippet) ──────────────
  let loopNodeEmitted = false;
  if (fn.codeSnippet && /\b(for|while|do)\b/.test(fn.codeSnippet) && !loopNodeEmitted) {
    loopNodeEmitted = true;
    const loopNode = newNode("loop", "loop header", fn.location, "(loop)");
    addEdge(prevNodeId, loopNode.id, "sequential");
    // Back-edge from loop body end back to loop header (approximation)
    addEdge(loopNode.id, loopNode.id, "loop-back");
    prevNodeId = loopNode.id;
  }

  // ── Process operations list (already source-ordered) ─────────────────────
  for (const op of fn.operations) {
    const loc = op.location;
    const expr = op.expression;

    switch (op.kind) {
      case "control": {
        // require / assert / revert
        const ctrlKind: CFGNodeKind =
          expr.startsWith("require") ? "require" :
          expr.startsWith("assert")  ? "assert"  : "revert";

        const ctrlNode = newNode(ctrlKind, expr, loc, expr);
        addEdge(prevNodeId, ctrlNode.id, "sequential");

        if (ctrlKind === "revert") {
          // revert always terminates — exception edge to exit
          addEdge(ctrlNode.id, exitNode.id, "exception");
          // After revert the rest of the function is unreachable, but we
          // keep connecting in case there are more ops (dead code)
          prevNodeId = ctrlNode.id;
        } else {
          // require/assert: sequential (pass) path continues; exception (fail) path goes to exit
          addEdge(ctrlNode.id, exitNode.id, "exception");
          prevNodeId = ctrlNode.id; // sequential path continues from here
        }
        break;
      }

      case "external-call": {
        const callNode = newNode("call", expr || "external call", loc, expr);
        addEdge(prevNodeId, callNode.id, "sequential");
        prevNodeId = callNode.id;
        break;
      }

      case "ether-transfer": {
        const xferNode = newNode("call", expr || "ether transfer", loc, expr);
        addEdge(prevNodeId, xferNode.id, "sequential");
        prevNodeId = xferNode.id;
        break;
      }

      case "state-read":
      case "state-write": {
        const stmtNode = newNode("statement", expr || op.kind, loc, expr);
        addEdge(prevNodeId, stmtNode.id, "sequential");
        prevNodeId = stmtNode.id;
        break;
      }

      default: {
        // "other" operations
        const stmtNode = newNode("statement", expr || "statement", loc, expr);
        addEdge(prevNodeId, stmtNode.id, "sequential");
        prevNodeId = stmtNode.id;
        break;
      }
    }
  }

  // ── Connect last live node to exit ─────────────────────────────────────────
  if (prevNodeId !== exitNode.id) {
    addEdge(prevNodeId, exitNode.id, "sequential");
  }

  return {
    contractName: fn.contractName,
    functionName: fn.name,
    nodes,
    edges: cfgEdges,
    entryNodeId: entryNode.id,
    exitNodeId:  exitNode.id,
  };
}

// ─── Top-level API ────────────────────────────────────────────────────────────

/**
 * Build the full CFG + Call Graph for an ASTAnalysisResult.
 *
 * Gracefully returns an empty result on any error so the auditor pipeline
 * is never broken by CFG construction failures.
 */
export function buildContractCFG(ast: ASTAnalysisResult): ContractCFGResult {
  try {
    const callGraph = buildCallGraph(ast);
    const functionCFGs: FunctionCFG[] = ast.functions.map(buildFunctionCFG);
    return { functionCFGs, callGraph };
  } catch {
    // Graceful fallback
    return {
      functionCFGs: [],
      callGraph: {
        edges: [],
        edgesByCallerKey: new Map(),
        edgesByCalleeKey: new Map(),
      },
    };
  }
}

