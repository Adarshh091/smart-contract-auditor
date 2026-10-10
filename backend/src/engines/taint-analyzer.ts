// ─── Lightweight Deterministic Taint Analysis Engine ───────────────────────────
//
// Analyzes compiled Solidity ASTs and CFGs to trace data flow from sources
// (parameters, msg.sender, msg.value, block.timestamp, etc.) to security-sensitive
// sinks (delegatecall, low-level call target/value, selfdestruct, ETH transfer,
// privileged state changes, sensitive conditions).
//
// Invariants:
//   1. Lightweight & deterministic.
//   2. Conservative: uncertain flow = UNKNOWN / NOT tainted.
//   3. No vulnerability claims from taint alone.
//   4. Preserves source locations.
//   5. Supports old Solidity 0.4.x (now, .call.value()()) and modern 0.8.x syntax.

import type { ASTAnalysisResult } from "../types/ast";
import type { ContractCFGResult } from "../types/cfg";
import type {
  TaintAnalysisResult,
  TaintSource,
  TaintSink,
  TaintPath,
  TaintFlowStep,
} from "../types/taint";
import { buildContractCFG } from "./cfg-builder";

/** Helper: Check if a snippet/expression is a safe constant literal (e.g. 0, true, false, 0x0) */
function isSafeConstant(expr: string): boolean {
  if (!expr) return true;
  const clean = expr.trim().toLowerCase();
  if (clean === "0" || clean === "0x0" || clean === "address(0)" || clean === "true" || clean === "false") {
    return true;
  }
  if (/^\d+$/.test(clean) || /^0x[0-9a-f]+$/i.test(clean)) {
    return true;
  }
  return false;
}

/** Helper: Extract variable names or identifiers referenced in an expression */
function extractIdentifiers(expr: string): string[] {
  if (!expr) return [];
  // Match standard Solidity identifiers while ignoring keywords and numbers
  const keywords = new Set([
    "true", "false", "require", "assert", "revert", "return", "function",
    "uint", "uint256", "address", "bool", "bytes", "string", "mapping",
    "public", "private", "internal", "external", "pure", "view", "payable",
  ]);

  const matches = expr.match(/\b[a-zA-Z_][a-zA-Z0-9_]*\b/g) || [];
  return Array.from(new Set(matches.filter((m) => !keywords.has(m) && !/^\d+$/.test(m))));
}

/**
 * Main Entry Point: Performs deterministic Taint / Data-Flow analysis.
 */
export function analyzeTaint(
  ast: ASTAnalysisResult,
  cfgResult?: ContractCFGResult
): TaintAnalysisResult {
  const sources: TaintSource[] = [];
  const sinks: TaintSink[] = [];
  const paths: TaintPath[] = [];

  const cfg = cfgResult || buildContractCFG(ast);

  let sourceSeq = 0;
  let sinkSeq = 0;
  let pathSeq = 0;

  // Track global / contract state variable taint
  const stateVarTaint = new Map<string, TaintSource>();

  // ── Step 1: Collect Taint Sources across all functions ──────────────────────
  for (const fn of ast.functions) {
    const fnLoc = fn.location;

    // 1a. Function Parameters
    for (const param of fn.parameters) {
      if (param.name) {
        sources.push({
          id: `src-${++sourceSeq}`,
          type: "parameter",
          contractName: fn.contractName,
          functionName: fn.name,
          name: param.name,
          expression: `${param.type} ${param.name}`,
          location: param.location || fnLoc,
        });
      }
    }

    // 1b. Environment & Transaction Sources in Function Body / Snippet
    const snippet = fn.codeSnippet || "";

    if (snippet.includes("msg.sender")) {
      sources.push({
        id: `src-${++sourceSeq}`,
        type: "msg.sender",
        contractName: fn.contractName,
        functionName: fn.name,
        name: "msg.sender",
        expression: "msg.sender",
        location: fnLoc,
      });
    }

    if (snippet.includes("msg.value")) {
      sources.push({
        id: `src-${++sourceSeq}`,
        type: "msg.value",
        contractName: fn.contractName,
        functionName: fn.name,
        name: "msg.value",
        expression: "msg.value",
        location: fnLoc,
      });
    }

    if (snippet.includes("tx.origin")) {
      sources.push({
        id: `src-${++sourceSeq}`,
        type: "tx.origin",
        contractName: fn.contractName,
        functionName: fn.name,
        name: "tx.origin",
        expression: "tx.origin",
        location: fnLoc,
      });
    }

    if (snippet.includes("block.timestamp") || /\bnow\b/.test(snippet)) {
      sources.push({
        id: `src-${++sourceSeq}`,
        type: "block.timestamp",
        contractName: fn.contractName,
        functionName: fn.name,
        name: snippet.includes("block.timestamp") ? "block.timestamp" : "now",
        expression: snippet.includes("block.timestamp") ? "block.timestamp" : "now",
        location: fnLoc,
      });
    }

    if (snippet.includes("block.number")) {
      sources.push({
        id: `src-${++sourceSeq}`,
        type: "block.number",
        contractName: fn.contractName,
        functionName: fn.name,
        name: "block.number",
        expression: "block.number",
        location: fnLoc,
      });
    }

    // 1c. External Call Return Values
    for (const call of fn.externalCalls) {
      if (call.callType === "low-level-call" || call.callType === "send") {
        sources.push({
          id: `src-${++sourceSeq}`,
          type: "external-return",
          contractName: fn.contractName,
          functionName: fn.name,
          name: `${call.target}.${call.method}_return`,
          expression: call.rawExpression,
          location: call.location,
        });
      }
    }
  }

  // ── Step 2: Collect Taint Sinks across all functions ────────────────────────
  for (const fn of ast.functions) {
    // 2a. External Call & Delegatecall Sinks
    for (const call of fn.externalCalls) {
      if (call.callType === "delegatecall") {
        sinks.push({
          id: `sink-${++sinkSeq}`,
          type: "delegatecall-target",
          contractName: fn.contractName,
          functionName: fn.name,
          expression: call.rawExpression,
          targetOrVar: call.target,
          location: call.location,
        });
      } else if (call.callType === "low-level-call") {
        sinks.push({
          id: `sink-${++sinkSeq}`,
          type: "low-level-call-target",
          contractName: fn.contractName,
          functionName: fn.name,
          expression: call.rawExpression,
          targetOrVar: call.target,
          location: call.location,
        });
        if (call.value) {
          sinks.push({
            id: `sink-${++sinkSeq}`,
            type: "low-level-call-value",
            contractName: fn.contractName,
            functionName: fn.name,
            expression: call.rawExpression,
            targetOrVar: call.value,
            location: call.location,
          });
        }
      }
    }

    // 2b. Ether Transfer Sinks
    for (const xfer of fn.etherTransfers) {
      if (xfer.transferType === "selfdestruct") {
        sinks.push({
          id: `sink-${++sinkSeq}`,
          type: "selfdestruct-recipient",
          contractName: fn.contractName,
          functionName: fn.name,
          expression: xfer.rawExpression,
          targetOrVar: xfer.recipient,
          location: xfer.location,
        });
      } else {
        sinks.push({
          id: `sink-${++sinkSeq}`,
          type: "ether-transfer-recipient",
          contractName: fn.contractName,
          functionName: fn.name,
          expression: xfer.rawExpression,
          targetOrVar: xfer.recipient,
          location: xfer.location,
        });
        if (xfer.amount && !isSafeConstant(xfer.amount)) {
          sinks.push({
            id: `sink-${++sinkSeq}`,
            type: "ether-transfer-value",
            contractName: fn.contractName,
            functionName: fn.name,
            expression: xfer.rawExpression,
            targetOrVar: xfer.amount,
            location: xfer.location,
          });
        }
      }
    }

    // 2c. Privileged State Change Sinks (state variable writes)
    for (const op of fn.operations) {
      if (op.kind === "state-write" && op.stateVariable) {
        const lowerVar = op.stateVariable.toLowerCase();
        if (
          lowerVar.includes("owner") ||
          lowerVar.includes("admin") ||
          lowerVar.includes("authority") ||
          lowerVar.includes("frontrunner")
        ) {
          sinks.push({
            id: `sink-${++sinkSeq}`,
            type: "privileged-state-change",
            contractName: fn.contractName,
            functionName: fn.name,
            expression: op.expression,
            targetOrVar: op.stateVariable,
            location: op.location,
          });
        }
      } else if (op.kind === "control") {
        sinks.push({
          id: `sink-${++sinkSeq}`,
          type: "sensitive-condition",
          contractName: fn.contractName,
          functionName: fn.name,
          expression: op.expression,
          targetOrVar: op.expression,
          location: op.location,
        });
      }
    }
  }

  // ── Step 3: Analyze Taint Flow & Propagation per Function ──────────────────
  for (const fn of ast.functions) {
    const fnSources = sources.filter(
      (s) => s.contractName === fn.contractName && s.functionName === fn.name
    );
    const fnSinks = sinks.filter(
      (s) => s.contractName === fn.contractName && s.functionName === fn.name
    );

    if (fnSinks.length === 0) continue;

    // Track active variable taint map: varName -> TaintSource
    const activeTaint = new Map<string, TaintSource>();
    const flowSteps: TaintFlowStep[] = [];

    // Seed initial taint sources
    for (const src of fnSources) {
      activeTaint.set(src.name, src);
    }

    // Inter-function call propagation check using Call Graph
    const callerEdges = cfg.callGraph.edgesByCallerKey.get(`${fn.contractName}.${fn.name}`) || [];
    for (const edge of callerEdges) {
      if (edge.kind === "internal") {
        const calleeFunc = ast.functions.find(
          (f) => f.contractName === edge.callee.contractName && f.name === edge.callee.functionName
        );
        if (calleeFunc) {
          for (const param of calleeFunc.parameters) {
            const callerTainted = activeTaint.get(param.name) || activeTaint.get("msg.sender");
            if (callerTainted) {
              const calleeSrc: TaintSource = {
                id: `src-${++sourceSeq}`,
                type: callerTainted.type,
                contractName: calleeFunc.contractName,
                functionName: calleeFunc.name,
                name: param.name,
                expression: `internal_propagate(${param.name})`,
                location: edge.location,
              };
              sources.push(calleeSrc);
            }
          }
        }
      }
    }

    // Process operations in execution order (direct assignments, var-to-var, state writes)
    for (const op of fn.operations) {
      const expr = op.expression;

      // Assignment pattern: LHS = RHS or type var = RHS
      const assignMatch = expr.match(/(?:(?:[a-zA-Z0-9_<>\[\]]+)\s+)?([a-zA-Z0-9_\[\]\.]+)\s*(=|\+=|-=|\*=|\/=)\s*(.+)/);
      if (assignMatch) {
        const lhs = assignMatch[1].trim();
        const rhs = assignMatch[3].trim();

        if (isSafeConstant(rhs)) {
          // Explicitly clear taint if assigned a safe constant
          activeTaint.delete(lhs);
          continue;
        }

        // Check if RHS references any tainted source or variable
        let matchedSource: TaintSource | undefined = undefined;
        let matchedFromVar = "";

        for (const [varName, src] of activeTaint.entries()) {
          if (rhs.includes(varName)) {
            matchedSource = src;
            matchedFromVar = varName;
            break;
          }
        }

        if (matchedSource) {
          const cleanLhs = lhs.replace(/\[.*\]/, ""); // strip index access
          activeTaint.set(cleanLhs, matchedSource);

          // If writing to a state variable, propagate to global state map
          if (op.kind === "state-write" || op.stateVariable) {
            stateVarTaint.set(`${fn.contractName}.${cleanLhs}`, matchedSource);
          }

          flowSteps.push({
            from: matchedFromVar,
            to: cleanLhs,
            expression: expr,
            location: op.location,
          });
        }
      }
    }

    // Check sink taint status against active function taint and global state taint
    for (const sink of fnSinks) {
      let matchedSource: TaintSource | undefined = undefined;
      let matchedExpr = "";

      // 1. Direct variable/target check in active function taint
      const targetVars = extractIdentifiers(sink.targetOrVar).concat(extractIdentifiers(sink.expression));

      for (const v of targetVars) {
        if (activeTaint.has(v)) {
          matchedSource = activeTaint.get(v);
          matchedExpr = v;
          break;
        }
        // Check global state var taint
        const stateKey = `${fn.contractName}.${v}`;
        if (stateVarTaint.has(stateKey)) {
          matchedSource = stateVarTaint.get(stateKey);
          matchedExpr = v;
          break;
        }
      }

      // 2. Direct string inclusion check for environmental sources (e.g. msg.sender, msg.value)
      if (!matchedSource) {
        for (const src of fnSources) {
          if (sink.expression.includes(src.name) || sink.targetOrVar.includes(src.name)) {
            matchedSource = src;
            matchedExpr = src.name;
            break;
          }
        }
      }

      if (matchedSource) {
        paths.push({
          id: `path-${++pathSeq}`,
          source: matchedSource,
          sink,
          steps: [
            ...flowSteps,
            {
              from: matchedExpr || matchedSource.name,
              to: sink.targetOrVar,
              expression: sink.expression,
              location: sink.location,
            },
          ],
          isTainted: true,
          confidence: "high",
        });
      }
    }
  }

  const summary = {
    totalSources: sources.length,
    totalSinks: sinks.length,
    totalTaintedPaths: paths.filter((p) => p.isTainted).length,
  };

  return {
    sources,
    sinks,
    paths,
    summary,
  };
}

