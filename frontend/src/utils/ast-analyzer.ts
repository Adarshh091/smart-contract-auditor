// ─── Modular Solidity AST Analysis Engine (Stage 4) ───────────────────────────
//
// Pure TypeScript engine that parses compiled Solidity ASTs into structured,
// typed models with exact source code locations. Completely independent of React.

import type {
  SourceLocation,
  ASTParameter,
  ASTFunction,
  ASTStateVariable,
  ASTModifier,
  ASTEvent,
  ASTStruct,
  ASTEnum,
  ASTInheritance,
  ASTExternalCall,
  ASTEtherTransfer,
  ASTControlStatement,
  ASTContract,
  ASTAnalysisResult,
  ASTAnalysisSummary,
  FunctionVisibility,
  StateMutability,
  FunctionKind,
  VariableVisibility,
  VariableMutability,
  ContractKind,
  ExternalCallType,
  ASTOperation,
} from "../types/ast";

// ─── Internal AST Node Interface ──────────────────────────────────────────────

interface RawNode {
  id?: number;
  nodeType?: string;
  src?: string;
  name?: string;
  [key: string]: unknown;
}

// ─── Source Location & Line Index Helper ──────────────────────────────────────

class SourceLocator {
  private lineStarts: number[];
  private source: string;
  private fileName: string;

  constructor(source: string, fileName: string) {
    this.source = source;
    this.fileName = fileName;
    this.lineStarts = [0];

    for (let i = 0; i < source.length; i++) {
      if (source[i] === "\n") {
        this.lineStarts.push(i + 1);
      }
    }
  }

  public getSourceCode(): string {
    return this.source;
  }

  public getFileName(): string {
    return this.fileName;
  }

  public parseLocation(src?: string): SourceLocation {
    if (!src) {
      return {
        file: this.fileName,
        line: 1,
        column: 1,
        start: 0,
        length: 0,
        end: 0,
      };
    }

    const parts = src.split(":");
    const start = Math.max(0, parseInt(parts[0], 10) || 0);
    const length = Math.max(0, parseInt(parts[1], 10) || 0);
    const end = start + length;

    const startLoc = this.offsetToLineCol(start);
    const endLoc = this.offsetToLineCol(end);

    return {
      file: this.fileName,
      line: startLoc.line,
      column: startLoc.column,
      endLine: endLoc.line,
      endColumn: endLoc.column,
      start,
      length,
      end,
    };
  }

  public getSnippet(src?: string): string {
    if (!src || !this.source) return "";
    const parts = src.split(":");
    const start = parseInt(parts[0], 10);
    const length = parseInt(parts[1], 10);
    if (isNaN(start) || isNaN(length) || start < 0) return "";
    return this.source.slice(start, start + length).trim();
  }

  private offsetToLineCol(offset: number): { line: number; column: number } {
    if (this.lineStarts.length === 0) return { line: 1, column: 1 };

    let low = 0;
    let high = this.lineStarts.length - 1;
    let lineIdx = 0;

    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      if (this.lineStarts[mid] <= offset) {
        lineIdx = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }

    const line = lineIdx + 1;
    const colOffset = offset - this.lineStarts[lineIdx];
    const column = Math.max(1, colOffset + 1);
    return { line, column };
  }
}

// ─── AST Traversal Helpers ────────────────────────────────────────────────────

function walkNode(
  node: unknown,
  visitor: (node: RawNode, parent?: RawNode) => void,
  parent?: RawNode
): void {
  if (!node || typeof node !== "object") return;

  if (Array.isArray(node)) {
    for (const item of node) {
      walkNode(item, visitor, parent);
    }
    return;
  }

  const raw = node as RawNode;
  visitor(raw, parent);

  for (const [key, value] of Object.entries(raw)) {
    if (key === "parent" || !value || typeof value !== "object") continue;
    walkNode(value, visitor, raw);
  }
}

// ─── Type Extraction Helpers ──────────────────────────────────────────────────

function extractTypeName(node: RawNode | undefined, locator: SourceLocator): string {
  if (!node) return "unknown";

  const typeDesc = (node.typeDescriptions as { typeString?: string })?.typeString;
  if (typeDesc) {
    return cleanTypeString(typeDesc);
  }

  const typeNameNode = node.typeName as RawNode | undefined;
  if (typeNameNode) {
    const innerDesc = (typeNameNode.typeDescriptions as { typeString?: string })?.typeString;
    if (innerDesc) return cleanTypeString(innerDesc);

    if (typeNameNode.name && typeof typeNameNode.name === "string") {
      return typeNameNode.name;
    }

    const snippet = locator.getSnippet(typeNameNode.src);
    if (snippet) return snippet;
  }

  if (node.name && typeof node.name === "string") {
    return node.name;
  }

  const fallbackSnippet = locator.getSnippet(node.src);
  return fallbackSnippet || "unknown";
}

function cleanTypeString(typeStr: string): string {
  // Strip storage location pointers like "struct MyContract.User storage ref" -> "MyContract.User"
  return typeStr
    .replace(/\s+storage\s+ref/g, "")
    .replace(/\s+memory/g, "")
    .replace(/\s+calldata/g, "")
    .replace(/^contract\s+/g, "")
    .replace(/^struct\s+/g, "")
    .replace(/^enum\s+/g, "");
}

function extractParameters(
  paramList: RawNode | undefined,
  locator: SourceLocator
): ASTParameter[] {
  if (!paramList || !Array.isArray(paramList.parameters)) return [];

  return (paramList.parameters as RawNode[]).map((param) => {
    const name = typeof param.name === "string" ? param.name : "";
    const type = extractTypeName(param, locator);
    const indexed = param.indexed === true ? true : undefined;
    const location = locator.parseLocation(param.src);

    return {
      name,
      type,
      indexed,
      location,
    };
  });
}

function buildSignature(name: string, params: ASTParameter[]): string {
  const paramTypes = params.map((p) => p.type).join(",");
  return `${name}(${paramTypes})`;
}

// ─── Function Visibility & Mutability Normalizers ─────────────────────────────

function parseVisibility(vis?: unknown): FunctionVisibility {
  const v = String(vis || "").toLowerCase();
  if (v === "external" || v === "public" || v === "internal" || v === "private") {
    return v;
  }
  return "public";
}

function parseStateMutability(node: RawNode): StateMutability {
  const sm = String(node.stateMutability || "").toLowerCase();
  if (sm === "pure" || sm === "view" || sm === "payable" || sm === "nonpayable") {
    return sm;
  }
  if (node.payable === true) return "payable";
  if (node.constant === true) return "view";
  return "nonpayable";
}

function parseFunctionKind(node: RawNode): FunctionKind {
  const k = String(node.kind || "").toLowerCase();
  if (k === "constructor" || node.isConstructor === true) return "constructor";
  if (k === "fallback") return "fallback";
  if (k === "receive") return "receive";
  return "function";
}

// ─── Statement & Call Analyzer ────────────────────────────────────────────────

function nodeToString(node: RawNode | undefined, locator: SourceLocator): string {
  if (!node) return "";
  const snippet = locator.getSnippet(node.src);
  if (snippet) return snippet;

  if (node.name && typeof node.name === "string") return node.name;
  if (node.value !== undefined) return String(node.value);

  if (node.nodeType === "MemberAccess") {
    const base = nodeToString(node.expression as RawNode, locator);
    return `${base}.${node.memberName || ""}`;
  }

  if (node.nodeType === "FunctionCall") {
    const fn = nodeToString(node.expression as RawNode, locator);
    const args = Array.isArray(node.arguments)
      ? (node.arguments as RawNode[]).map((a) => nodeToString(a, locator)).join(", ")
      : "";
    return `${fn}(${args})`;
  }

  if (node.nodeType === "BinaryOperation") {
    const left = nodeToString(node.leftExpression as RawNode, locator);
    const right = nodeToString(node.rightExpression as RawNode, locator);
    return `${left} ${node.operator || "=="} ${right}`;
  }

  if (node.nodeType === "IndexAccess") {
    const base = nodeToString(node.baseExpression as RawNode, locator);
    const index = nodeToString(node.indexExpression as RawNode, locator);
    return `${base}[${index}]`;
  }

  return "";
}

interface ExtractedBodyItems {
  externalCalls: ASTExternalCall[];
  etherTransfers: ASTEtherTransfer[];
  controlStatements: ASTControlStatement[];
  operations: ASTOperation[];
}

// ─── Typed operation ID counter ────────────────────────────────────────────────

let _opSeq = 0;
function nextOpId(): string {
  return `op-${++_opSeq}`;
}

function analyzeFunctionBody(
  bodyNode: RawNode | null | undefined,
  contractName: string,
  functionName: string,
  locator: SourceLocator,
  stateVarNames: string[] = []
): ExtractedBodyItems {
  const externalCalls: ASTExternalCall[] = [];
  const etherTransfers: ASTEtherTransfer[] = [];
  const controlStatements: ASTControlStatement[] = [];
  // Raw operations collected during walk; will be sorted by src offset at end
  const rawOps: Array<{ srcStart: number; op: ASTOperation }> = [];

  if (!bodyNode) {
    return { externalCalls, etherTransfers, controlStatements, operations: [] };
  }

  let callCounter = 0;
  let transferCounter = 0;
  let controlCounter = 0;

  // ── Helpers ──────────────────────────────────────────────────────────────────

  /** Parse the integer byte-offset start from a Solidity src string "start:len:fileIdx" */
  function srcStart(src?: string): number {
    if (!src) return 0;
    return parseInt(src.split(":")[0], 10) || 0;
  }

  /** Determine if an lvalue expression (assignment target) names a state variable */
  function lhsVarName(lhs: RawNode | undefined): string | null {
    if (!lhs) return null;
    if (lhs.nodeType === "Identifier") {
      const n = String(lhs.name || "");
      if (stateVarNames.includes(n)) return n;
    }
    if (lhs.nodeType === "IndexAccess") {
      // e.g. balances[msg.sender]
      return lhsVarName(lhs.baseExpression as RawNode | undefined);
    }
    if (lhs.nodeType === "MemberAccess") {
      // e.g. user.amount
      return lhsVarName(lhs.expression as RawNode | undefined);
    }
    return null;
  }

  /** Collect all state variable names referenced (read) inside a subtree */
  function collectReads(node: RawNode, exclude: Set<string>): string[] {
    const found: string[] = [];
    walkNode(node, (n) => {
      if (n.nodeType === "Identifier") {
        const nm = String(n.name || "");
        if (stateVarNames.includes(nm) && !exclude.has(nm)) {
          found.push(nm);
        }
      }
    });
    return [...new Set(found)];
  }

  // ── Main AST walk ────────────────────────────────────────────────────────────

  walkNode(bodyNode, (node) => {
    const nodeType = node.nodeType;

    // ── 1. FunctionCall Analysis (Calls, ETH Transfers, require/assert/revert) ──
    if (nodeType === "FunctionCall") {
      const expr = node.expression as RawNode | undefined;
      const rawExpr = nodeToString(node, locator) || `${functionName}()`;
      const location = locator.parseLocation(node.src);
      const start = srcStart(node.src);
      const args = Array.isArray(node.arguments)
        ? (node.arguments as RawNode[]).map((a) => nodeToString(a, locator))
        : [];

      if (!expr) return;

      // ── Control Statements: require(cond, msg), assert(cond), revert(msg) ──
      if (expr.nodeType === "Identifier") {
        const idName = String(expr.name || "");
        if (idName === "require" || idName === "assert" || idName === "revert") {
          const condition =
            idName !== "revert" && args.length > 0 ? args[0] : undefined;
          const message =
            idName === "require" && args.length > 1
              ? args[1]
              : idName === "revert" && args.length > 0
              ? args[0]
              : undefined;

          controlCounter++;
          const ctrlEntry = {
            id: `ctrl-${contractName}-${functionName}-${controlCounter}`,
            contractName,
            functionName,
            kind: idName as "require" | "assert" | "revert",
            condition,
            message,
            rawExpression: rawExpr,
            location,
          };
          controlStatements.push(ctrlEntry);
          rawOps.push({
            srcStart: start,
            op: {
              id: nextOpId(),
              kind: "control",
              functionName,
              contractName,
              expression: rawExpr,
              location,
            },
          });
          return;
        }

        // Selfdestruct / suicide call (transfers all balance)
        if (idName === "selfdestruct" || idName === "suicide") {
          const recipient = args[0] || "unknown";
          transferCounter++;
          const ethEntry: ASTEtherTransfer = {
            id: `eth-${contractName}-${functionName}-${transferCounter}`,
            contractName,
            functionName,
            recipient,
            amount: "all contract balance",
            transferType: "selfdestruct",
            rawExpression: rawExpr,
            location,
          };
          etherTransfers.push(ethEntry);
          rawOps.push({
            srcStart: start,
            op: {
              id: nextOpId(),
              kind: "ether-transfer",
              functionName,
              contractName,
              expression: rawExpr,
              location,
              etherTransfer: ethEntry,
            },
          });
          return;
        }
      }

      // ── Old Solidity 0.4.x chained call: target.call.value(amount)() ────
      //
      // AST shape (solc 0.4.x):
      //   FunctionCall { expression: FunctionCall { expression: MemberAccess(.value),
      //                                             arguments: [amount] },
      //                  arguments: [] }
      //
      // The outer FunctionCall's expr is itself a FunctionCall whose callee is
      // a MemberAccess with memberName "value" (or "gas") on another MemberAccess
      // whose memberName is "call" / "delegatecall" etc.
      //
      // We must detect this BEFORE the generic MemberAccess branch so we can
      // correctly set callType = "low-level-call" and value = amount.
      if (expr.nodeType === "FunctionCall") {
        const innerCallExpr = expr.expression as RawNode | undefined;
        if (innerCallExpr && innerCallExpr.nodeType === "MemberAccess") {
          const chainedMember = String(innerCallExpr.memberName || "");
          const chainedBase = innerCallExpr.expression as RawNode | undefined;
          // chainedBase should be a MemberAccess for the actual call method
          if (
            chainedBase &&
            chainedBase.nodeType === "MemberAccess" &&
            (chainedMember === "value" || chainedMember === "gas")
          ) {
            const callMethodName = String(chainedBase.memberName || "");
            const isLowLevelMethod =
              callMethodName === "call" ||
              callMethodName === "delegatecall" ||
              callMethodName === "staticcall";

            if (isLowLevelMethod) {
              const target =
                nodeToString(chainedBase.expression as RawNode, locator) || "target";

              // arguments of the inner FunctionCall are the .value() / .gas() args
              const innerArgs = Array.isArray(expr.arguments)
                ? (expr.arguments as RawNode[]).map((a) => nodeToString(a, locator))
                : [];

              let valueArg: string | undefined = undefined;
              let gasArg: string | undefined = undefined;
              if (chainedMember === "value") valueArg = innerArgs[0];
              if (chainedMember === "gas") gasArg = innerArgs[0];

              const callType: ExternalCallType =
                callMethodName === "call"
                  ? "low-level-call"
                  : callMethodName === "delegatecall"
                  ? "delegatecall"
                  : "staticcall";

              callCounter++;
              const callEntry: ASTExternalCall = {
                id: `call-${contractName}-${functionName}-${callCounter}`,
                contractName,
                functionName,
                target,
                method: callMethodName,
                callType,
                value: valueArg,
                gas: gasArg,
                arguments: args, // outer () arguments
                rawExpression: rawExpr,
                location,
              };
              externalCalls.push(callEntry);
              rawOps.push({
                srcStart: start,
                op: {
                  id: nextOpId(),
                  kind: "external-call",
                  functionName,
                  contractName,
                  expression: rawExpr,
                  location,
                  externalCall: callEntry,
                },
              });

              // If value was attached, emit an ether-transfer op too
              if (valueArg) {
                transferCounter++;
                const ethEntry: ASTEtherTransfer = {
                  id: `eth-${contractName}-${functionName}-${transferCounter}`,
                  contractName,
                  functionName,
                  recipient: target,
                  amount: valueArg,
                  transferType: "call-value",
                  rawExpression: rawExpr,
                  location,
                };
                etherTransfers.push(ethEntry);
                rawOps.push({
                  srcStart: start + 0.5,
                  op: {
                    id: nextOpId(),
                    kind: "ether-transfer",
                    functionName,
                    contractName,
                    expression: rawExpr,
                    location,
                    etherTransfer: ethEntry,
                  },
                });
              }
              return;
            }
          }
        }
      }

      // ── Low-level call with options: target.call{value: X}("") ──────────
      if (expr.nodeType === "FunctionCallOptions") {
        const innerExpr = expr.expression as RawNode | undefined;
        if (innerExpr && innerExpr.nodeType === "MemberAccess") {
          const memberName = String(innerExpr.memberName || "");
          const target = nodeToString(innerExpr.expression as RawNode, locator) || "target";
          const optionNames = Array.isArray(expr.names) ? (expr.names as string[]) : [];
          const optionArgs = Array.isArray(expr.options)
            ? (expr.options as RawNode[]).map((o) => nodeToString(o, locator))
            : [];

          let valueArg: string | undefined = undefined;
          let gasArg: string | undefined = undefined;

          optionNames.forEach((optName, idx) => {
            if (optName === "value") valueArg = optionArgs[idx];
            if (optName === "gas") gasArg = optionArgs[idx];
          });

          // If no names array, inspect options dictionary
          if (!valueArg && typeof expr.options === "object" && expr.options !== null) {
            const opts = expr.options as Record<string, unknown>;
            if (opts.value) valueArg = String(opts.value);
            if (opts.gas) gasArg = String(opts.gas);
          }

          let callType: ExternalCallType = "regular";
          if (memberName === "call") callType = "low-level-call";
          else if (memberName === "delegatecall") callType = "delegatecall";
          else if (memberName === "staticcall") callType = "staticcall";

          callCounter++;
          const callEntry: ASTExternalCall = {
            id: `call-${contractName}-${functionName}-${callCounter}`,
            contractName,
            functionName,
            target,
            method: memberName,
            callType,
            value: valueArg,
            gas: gasArg,
            arguments: args,
            rawExpression: rawExpr,
            location,
          };
          externalCalls.push(callEntry);
          rawOps.push({
            srcStart: start,
            op: {
              id: nextOpId(),
              kind: "external-call",
              functionName,
              contractName,
              expression: rawExpr,
              location,
              externalCall: callEntry,
            },
          });

          // If value was attached, this is also an ETH transfer
          if (valueArg) {
            transferCounter++;
            const ethEntry: ASTEtherTransfer = {
              id: `eth-${contractName}-${functionName}-${transferCounter}`,
              contractName,
              functionName,
              recipient: target,
              amount: valueArg,
              transferType: "call-value",
              rawExpression: rawExpr,
              location,
            };
            etherTransfers.push(ethEntry);
            rawOps.push({
              srcStart: start + 0.5, // same location, ether-transfer op after external-call op
              op: {
                id: nextOpId(),
                kind: "ether-transfer",
                functionName,
                contractName,
                expression: rawExpr,
                location,
                etherTransfer: ethEntry,
              },
            });
          }
          return;
        }
      }

      // ── Standard Member Access: target.method(args) ──────────────────────
      if (expr.nodeType === "MemberAccess") {
        const memberName = String(expr.memberName || "");
        const innerTarget = expr.expression as RawNode | undefined;
        const target = nodeToString(innerTarget, locator) || "target";

        // 1. address.transfer(amount)
        if (memberName === "transfer" && args.length === 1) {
          transferCounter++;
          const ethEntry: ASTEtherTransfer = {
            id: `eth-${contractName}-${functionName}-${transferCounter}`,
            contractName,
            functionName,
            recipient: target,
            amount: args[0] || "unknown",
            transferType: "transfer",
            rawExpression: rawExpr,
            location,
          };
          etherTransfers.push(ethEntry);

          callCounter++;
          const callEntry: ASTExternalCall = {
            id: `call-${contractName}-${functionName}-${callCounter}`,
            contractName,
            functionName,
            target,
            method: "transfer",
            callType: "transfer",
            arguments: args,
            rawExpression: rawExpr,
            location,
          };
          externalCalls.push(callEntry);

          rawOps.push({
            srcStart: start,
            op: {
              id: nextOpId(),
              kind: "ether-transfer",
              functionName,
              contractName,
              expression: rawExpr,
              location,
              etherTransfer: ethEntry,
              externalCall: callEntry,
            },
          });
          return;
        }

        // 2. address.send(amount)
        if (memberName === "send" && args.length === 1) {
          transferCounter++;
          const ethEntry: ASTEtherTransfer = {
            id: `eth-${contractName}-${functionName}-${transferCounter}`,
            contractName,
            functionName,
            recipient: target,
            amount: args[0] || "unknown",
            transferType: "send",
            rawExpression: rawExpr,
            location,
          };
          etherTransfers.push(ethEntry);

          callCounter++;
          const callEntry: ASTExternalCall = {
            id: `call-${contractName}-${functionName}-${callCounter}`,
            contractName,
            functionName,
            target,
            method: "send",
            callType: "send",
            arguments: args,
            rawExpression: rawExpr,
            location,
          };
          externalCalls.push(callEntry);

          rawOps.push({
            srcStart: start,
            op: {
              id: nextOpId(),
              kind: "ether-transfer",
              functionName,
              contractName,
              expression: rawExpr,
              location,
              etherTransfer: ethEntry,
              externalCall: callEntry,
            },
          });
          return;
        }

        // 3. Low-level call without options: target.call(data), delegatecall, staticcall
        if (
          memberName === "call" ||
          memberName === "delegatecall" ||
          memberName === "staticcall"
        ) {
          const callType: ExternalCallType =
            memberName === "call"
              ? "low-level-call"
              : memberName === "delegatecall"
              ? "delegatecall"
              : "staticcall";

          callCounter++;
          const callEntry: ASTExternalCall = {
            id: `call-${contractName}-${functionName}-${callCounter}`,
            contractName,
            functionName,
            target,
            method: memberName,
            callType,
            arguments: args,
            rawExpression: rawExpr,
            location,
          };
          externalCalls.push(callEntry);

          rawOps.push({
            srcStart: start,
            op: {
              id: nextOpId(),
              kind: "external-call",
              functionName,
              contractName,
              expression: rawExpr,
              location,
              externalCall: callEntry,
            },
          });
          return;
        }

        // 4. External contract call: IERC20(token).transfer(to, amount), pool.swap(), etc.
        // Check if expression target is external contract or this
        const targetTypeDesc = (innerTarget?.typeDescriptions as { typeString?: string })
          ?.typeString || "";

        const isContractType =
          targetTypeDesc.startsWith("contract ") ||
          targetTypeDesc.includes("interface ") ||
          target === "this" ||
          (innerTarget?.nodeType === "FunctionCall" && !targetTypeDesc.startsWith("type("));

        const isSuper = target === "super";

        if (!isSuper && (isContractType || target.includes("(") || target.endsWith("Token"))) {
          callCounter++;
          const callEntry: ASTExternalCall = {
            id: `call-${contractName}-${functionName}-${callCounter}`,
            contractName,
            functionName,
            target,
            method: memberName,
            callType: "regular",
            arguments: args,
            rawExpression: rawExpr,
            location,
          };
          externalCalls.push(callEntry);

          rawOps.push({
            srcStart: start,
            op: {
              id: nextOpId(),
              kind: "external-call",
              functionName,
              contractName,
              expression: rawExpr,
              location,
              externalCall: callEntry,
            },
          });
        }
      }
    }

    // ── 2. RevertStatement (modern Solidity 0.8.4+ Custom Errors) ─────────────
    if (nodeType === "RevertStatement") {
      const errorCall = node.errorCall as RawNode | undefined;
      const rawExpr = locator.getSnippet(node.src) || "revert CustomError()";
      const message = errorCall
        ? locator.getSnippet(errorCall.src)
        : locator.getSnippet(node.src);
      const location = locator.parseLocation(node.src);
      const start = srcStart(node.src);

      controlCounter++;
      controlStatements.push({
        id: `ctrl-${contractName}-${functionName}-${controlCounter}`,
        contractName,
        functionName,
        kind: "revert",
        message,
        rawExpression: rawExpr,
        location,
      });
      rawOps.push({
        srcStart: start,
        op: {
          id: nextOpId(),
          kind: "control",
          functionName,
          contractName,
          expression: rawExpr,
          location,
        },
      });
    }

    // ── 3. State variable writes: Assignment and UnaryOperation (++/--) ────────
    if (nodeType === "ExpressionStatement") {
      const exprNode = node.expression as RawNode | undefined;
      if (!exprNode) return;

      if (exprNode.nodeType === "Assignment") {
        const lhs = exprNode.leftHandSide as RawNode | undefined;
        const varName = lhsVarName(lhs);
        if (varName) {
          const rawExpr = nodeToString(exprNode, locator) || locator.getSnippet(exprNode.src) || "";
          const location = locator.parseLocation(exprNode.src);
          const start = srcStart(exprNode.src);

          // Collect reads on the RHS
          const rhs = exprNode.rightHandSide as RawNode | undefined;
          if (rhs && stateVarNames.length > 0) {
            const reads = collectReads(rhs, new Set([varName]));
            for (const readVar of reads) {
              rawOps.push({
                srcStart: start - 0.1, // reads logically before the write
                op: {
                  id: nextOpId(),
                  kind: "state-read",
                  functionName,
                  contractName,
                  expression: readVar,
                  location,
                  stateVariable: readVar,
                },
              });
            }
          }

          rawOps.push({
            srcStart: start,
            op: {
              id: nextOpId(),
              kind: "state-write",
              functionName,
              contractName,
              expression: rawExpr,
              location,
              stateVariable: varName,
            },
          });
        }
      }

      // UnaryOperation: balances[msg.sender]++  /  pendingCount--
      if (exprNode.nodeType === "UnaryOperation") {
        const sub = exprNode.subExpression as RawNode | undefined;
        const varName = lhsVarName(sub);
        if (varName) {
          const rawExpr = nodeToString(exprNode, locator) || locator.getSnippet(exprNode.src) || "";
          const location = locator.parseLocation(exprNode.src);
          const start = srcStart(exprNode.src);
          rawOps.push({
            srcStart: start,
            op: {
              id: nextOpId(),
              kind: "state-write",
              functionName,
              contractName,
              expression: rawExpr,
              location,
              stateVariable: varName,
            },
          });
        }
      }
    }
  });

  // Sort all operations by source byte offset to get document order
  rawOps.sort((a, b) => a.srcStart - b.srcStart);
  const operations = rawOps.map((r) => r.op);

  return { externalCalls, etherTransfers, controlStatements, operations };
}

// ─── Main AST Analysis Function ───────────────────────────────────────────────

/**
 * Parses and analyzes Solidity ASTs extracted from compiler output.
 * Fully typed, deterministic, and modular.
 *
 * @param astInput   Can be `compilationResult.ast` (Record<string, unknown>)
 *                   or a single SourceUnit AST node.
 * @param sourceCode Original raw Solidity source text for precise location/snippets.
 * @param defaultFileName Filename to use if none is present in AST.
 */
export function analyzeSolidityAST(
  astInput: unknown,
  sourceCode: string = "",
  defaultFileName: string = "contract.sol"
): ASTAnalysisResult {
  // Normalize AST input map: Record<filename, SourceUnitNode>
  const astMap: Record<string, RawNode> = {};

  if (astInput && typeof astInput === "object") {
    const rawObj = astInput as Record<string, unknown>;

    // Case 1: astInput is already a single SourceUnit
    if (rawObj.nodeType === "SourceUnit") {
      const filePath = (rawObj.absolutePath as string) || defaultFileName;
      astMap[filePath] = rawObj as RawNode;
    } else {
      // Case 2: astInput is keyed by filename
      for (const [filePath, fileNode] of Object.entries(rawObj)) {
        if (fileNode && typeof fileNode === "object") {
          const rawFileNode = fileNode as RawNode;
          if (rawFileNode.nodeType === "SourceUnit") {
            astMap[filePath] = rawFileNode;
          } else if (rawFileNode.ast && typeof rawFileNode.ast === "object") {
            astMap[filePath] = rawFileNode.ast as RawNode;
          } else {
            astMap[filePath] = rawFileNode;
          }
        }
      }
    }
  }

  // Result aggregations
  const contracts: ASTContract[] = [];
  const functions: ASTFunction[] = [];
  const stateVariables: ASTStateVariable[] = [];
  const modifiers: ASTModifier[] = [];
  const events: ASTEvent[] = [];
  const structs: ASTStruct[] = [];
  const enums: ASTEnum[] = [];
  const inheritance: ASTInheritance[] = [];
  const externalCalls: ASTExternalCall[] = [];
  const etherTransfers: ASTEtherTransfer[] = [];
  const controlStatements: ASTControlStatement[] = [];

  // Track modifier usages across functions
  const modifierInvocationsMap = new Map<string, Set<string>>();

  // Iterate over all SourceUnits
  for (const [filePath, sourceUnit] of Object.entries(astMap)) {
    const locator = new SourceLocator(sourceCode, filePath || defaultFileName);
    const topLevelNodes = Array.isArray(sourceUnit.nodes)
      ? (sourceUnit.nodes as RawNode[])
      : [];

    for (const topNode of topLevelNodes) {
      if (topNode.nodeType === "ContractDefinition") {
        const contract = parseContractDefinition(
          topNode,
          filePath || defaultFileName,
          locator,
          modifierInvocationsMap
        );

        contracts.push(contract);

        // Aggregate contract child items into top-level lists
        functions.push(...contract.functions);
        stateVariables.push(...contract.stateVariables);
        modifiers.push(...contract.modifiers);
        events.push(...contract.events);
        structs.push(...contract.structs);
        enums.push(...contract.enums);
        externalCalls.push(...contract.externalCalls);
        etherTransfers.push(...contract.etherTransfers);
        controlStatements.push(...contract.controlStatements);

        // Record inheritance relations
        for (const base of contract.bases) {
          const baseContractSpec = (topNode.baseContracts as RawNode[] | undefined)?.find(
            (b) => {
              const name =
                (b.baseName as RawNode)?.name ||
                (b.baseName as RawNode)?.namePath ||
                locator.getSnippet(b.src);
              return name === base;
            }
          );

          const baseArgs = Array.isArray(baseContractSpec?.arguments)
            ? (baseContractSpec.arguments as RawNode[]).map((a) => locator.getSnippet(a.src))
            : undefined;

          inheritance.push({
            contractName: contract.name,
            baseContractName: base,
            arguments: baseArgs,
            location: locator.parseLocation(baseContractSpec?.src || topNode.src),
          });
        }
      } else if (topNode.nodeType === "FunctionDefinition") {
        // Free function at file level
        const freeFunc = parseFunctionDefinition(
          topNode,
          "FileLevel",
          locator,
          modifierInvocationsMap
        );
        functions.push(freeFunc);
        externalCalls.push(...freeFunc.externalCalls);
        etherTransfers.push(...freeFunc.etherTransfers);
        controlStatements.push(...freeFunc.controlStatements);
      } else if (topNode.nodeType === "StructDefinition") {
        // Free struct
        const freeStruct = parseStructDefinition(topNode, "FileLevel", locator);
        structs.push(freeStruct);
      } else if (topNode.nodeType === "EnumDefinition") {
        // Free enum
        const freeEnum = parseEnumDefinition(topNode, "FileLevel", locator);
        enums.push(freeEnum);
      } else if (topNode.nodeType === "EventDefinition") {
        // Free event (solc >= 0.8.20)
        const freeEvent = parseEventDefinition(topNode, "FileLevel", locator);
        events.push(freeEvent);
      }
    }
  }

  // Update invokedBy lists on modifiers
  for (const mod of modifiers) {
    const invocations = modifierInvocationsMap.get(mod.name);
    if (invocations) {
      mod.invokedBy = Array.from(invocations);
    }
  }

  // Generate summary metrics
  const summary = generateSummary(
    contracts,
    functions,
    stateVariables,
    modifiers,
    events,
    structs,
    enums,
    externalCalls,
    etherTransfers,
    controlStatements
  );

  return {
    contracts,
    functions,
    stateVariables,
    modifiers,
    events,
    structs,
    enums,
    inheritance,
    externalCalls,
    etherTransfers,
    controlStatements,
    summary,
    rawAst: astMap,
  };
}

// ─── Individual Entity Parsers ────────────────────────────────────────────────

function parseContractDefinition(
  node: RawNode,
  sourceFile: string,
  locator: SourceLocator,
  modifierMap: Map<string, Set<string>>
): ASTContract {
  const name = String(node.name || "UnnamedContract");
  const contractKindRaw = String(node.contractKind || "").toLowerCase();
  const isAbstract = node.abstract === true;

  let kind: ContractKind = "contract";
  if (contractKindRaw === "interface") kind = "interface";
  else if (contractKindRaw === "library") kind = "library";
  else if (isAbstract) kind = "abstract";

  // Base contracts
  const bases: string[] = [];
  if (Array.isArray(node.baseContracts)) {
    for (const base of node.baseContracts as RawNode[]) {
      const baseNameNode = base.baseName as RawNode | undefined;
      const baseName =
        (baseNameNode?.name as string) ||
        (baseNameNode?.namePath as string) ||
        locator.getSnippet(base.src);
      if (baseName) bases.push(baseName);
    }
  }

  const contractFunctions: ASTFunction[] = [];
  const contractStateVars: ASTStateVariable[] = [];
  const contractModifiers: ASTModifier[] = [];
  const contractEvents: ASTEvent[] = [];
  const contractStructs: ASTStruct[] = [];
  const contractEnums: ASTEnum[] = [];
  const contractExternalCalls: ASTExternalCall[] = [];
  const contractEtherTransfers: ASTEtherTransfer[] = [];
  const contractControlStmts: ASTControlStatement[] = [];

  let constructorDef: ASTFunction | undefined = undefined;
  let fallbackDef: ASTFunction | undefined = undefined;
  let receiveDef: ASTFunction | undefined = undefined;

  const childNodes = Array.isArray(node.nodes) ? (node.nodes as RawNode[]) : [];

  // ── Pass 1: collect state variable names first so function body analysis
  //            can distinguish state reads/writes from local variable accesses.
  for (const child of childNodes) {
    if (child.nodeType === "VariableDeclaration" && child.stateVariable === true) {
      contractStateVars.push(parseStateVariable(child, name, locator));
    }
    // Also handle StateVariableDeclaration wrapper (used by some AST fixture formats)
    if (child.nodeType === "StateVariableDeclaration" && Array.isArray(child.variables)) {
      for (const v of child.variables as RawNode[]) {
        if (v.nodeType === "VariableDeclaration" && v.stateVariable !== false) {
          contractStateVars.push(parseStateVariable(v, name, locator));
        }
      }
    }
  }
  const stateVarNames = contractStateVars.map((v) => v.name);

  // ── Pass 2: parse everything else (functions need stateVarNames)
  for (const child of childNodes) {
    const type = child.nodeType;

    if (type === "FunctionDefinition") {
      const fn = parseFunctionDefinition(child, name, locator, modifierMap, stateVarNames);
      contractFunctions.push(fn);
      contractExternalCalls.push(...fn.externalCalls);
      contractEtherTransfers.push(...fn.etherTransfers);
      contractControlStmts.push(...fn.controlStatements);

      if (fn.kind === "constructor") constructorDef = fn;
      if (fn.kind === "fallback") fallbackDef = fn;
      if (fn.kind === "receive") receiveDef = fn;
    } else if (type === "VariableDeclaration" && child.stateVariable === true) {
      // already parsed in pass 1 — skip
    } else if (type === "StateVariableDeclaration") {
      // already parsed in pass 1 — skip
    } else if (type === "ModifierDefinition") {
      contractModifiers.push(parseModifierDefinition(child, name, locator));
    } else if (type === "EventDefinition") {
      contractEvents.push(parseEventDefinition(child, name, locator));
    } else if (type === "StructDefinition") {
      contractStructs.push(parseStructDefinition(child, name, locator));
    } else if (type === "EnumDefinition") {
      contractEnums.push(parseEnumDefinition(child, name, locator));
    }
  }

  return {
    id: node.id || 0,
    name,
    kind,
    isAbstract,
    sourceFile,
    bases,
    functions: contractFunctions,
    stateVariables: contractStateVars,
    modifiers: contractModifiers,
    events: contractEvents,
    structs: contractStructs,
    enums: contractEnums,
    constructorDef,
    fallbackDef,
    receiveDef,
    externalCalls: contractExternalCalls,
    etherTransfers: contractEtherTransfers,
    controlStatements: contractControlStmts,
    location: locator.parseLocation(node.src),
  };
}

function parseFunctionDefinition(
  node: RawNode,
  contractName: string,
  locator: SourceLocator,
  modifierMap: Map<string, Set<string>>,
  stateVarNames: string[] = []
): ASTFunction {
  let kind = parseFunctionKind(node);
  let name = String(node.name || "");

  // Old Solidity (<0.5): constructors are named functions whose name matches
  // the contract name (e.g. `function ReentrancyVulnerable() public {}`).
  // solc >= 0.5 uses `kind: "constructor"` and `name: ""`.
  // Some older solc versions set `isConstructor: true` — already handled by
  // parseFunctionKind — but the name-match case isn't.
  if (
    kind === "function" &&
    name.length > 0 &&
    name === contractName
  ) {
    kind = "constructor";
  }

  if (!name) {
    name = kind;
  }

  const visibility = parseVisibility(node.visibility);
  const stateMutability = parseStateMutability(node);
  const isVirtual = node.virtual === true;
  const isOverride = Boolean(node.overrides);

  // Modifiers
  const modifiersApplied: string[] = [];
  if (Array.isArray(node.modifiers)) {
    for (const mod of node.modifiers as RawNode[]) {
      const modNameNode = mod.modifierName as RawNode | undefined;
      const modName =
        (modNameNode?.name as string) ||
        (modNameNode?.namePath as string) ||
        locator.getSnippet(mod.src) ||
        "";
      if (modName) {
        modifiersApplied.push(modName);
        if (!modifierMap.has(modName)) {
          modifierMap.set(modName, new Set());
        }
        modifierMap.get(modName)!.add(`${contractName}.${name}`);
      }
    }
  }

  // Parameters & returns
  const parameters = extractParameters(node.parameters as RawNode | undefined, locator);
  const returnParameters = extractParameters(
    node.returnParameters as RawNode | undefined,
    locator
  );
  const signature = buildSignature(name, parameters);

  // Body statements, calls, transfers, controls, operations (source-ordered)
  const { externalCalls, etherTransfers, controlStatements, operations } = analyzeFunctionBody(
    node.body as RawNode | null | undefined,
    contractName,
    name,
    locator,
    stateVarNames
  );

  return {
    id: node.id || 0,
    name,
    contractName,
    kind,
    visibility,
    stateMutability,
    isVirtual,
    isOverride,
    modifiers: modifiersApplied,
    parameters,
    returnParameters,
    signature,
    location: locator.parseLocation(node.src),
    codeSnippet: locator.getSnippet(node.src),
    externalCalls,
    etherTransfers,
    controlStatements,
    operations,
  };
}

function parseStateVariable(
  node: RawNode,
  contractName: string,
  locator: SourceLocator
): ASTStateVariable {
  const name = String(node.name || "unnamedVar");
  const type = extractTypeName(node, locator);
  const visibility = (node.visibility as VariableVisibility) || "internal";

  let mutability: VariableMutability = "mutable";
  if (node.mutability === "constant" || node.constant === true) {
    mutability = "constant";
  } else if (node.mutability === "immutable") {
    mutability = "immutable";
  }

  const initialValue = node.value
    ? locator.getSnippet((node.value as RawNode).src)
    : undefined;

  return {
    id: node.id || 0,
    name,
    contractName,
    type,
    visibility,
    mutability,
    initialValue,
    location: locator.parseLocation(node.src),
    codeSnippet: locator.getSnippet(node.src),
  };
}

function parseModifierDefinition(
  node: RawNode,
  contractName: string,
  locator: SourceLocator
): ASTModifier {
  const name = String(node.name || "unnamedModifier");
  const parameters = extractParameters(node.parameters as RawNode | undefined, locator);

  return {
    id: node.id || 0,
    name,
    contractName,
    parameters,
    location: locator.parseLocation(node.src),
    codeSnippet: locator.getSnippet(node.src),
    invokedBy: [],
  };
}

function parseEventDefinition(
  node: RawNode,
  contractName: string,
  locator: SourceLocator
): ASTEvent {
  const name = String(node.name || "unnamedEvent");
  const anonymous = node.anonymous === true;
  const parameters = extractParameters(node.parameters as RawNode | undefined, locator);
  const signature = buildSignature(name, parameters);

  return {
    id: node.id || 0,
    name,
    contractName,
    anonymous,
    parameters,
    signature,
    location: locator.parseLocation(node.src),
    codeSnippet: locator.getSnippet(node.src),
  };
}

function parseStructDefinition(
  node: RawNode,
  contractName: string,
  locator: SourceLocator
): ASTStruct {
  const name = String(node.name || "unnamedStruct");
  const members: ASTStruct["members"] = [];

  if (Array.isArray(node.members)) {
    for (const m of node.members as RawNode[]) {
      members.push({
        name: String(m.name || ""),
        type: extractTypeName(m, locator),
      });
    }
  }

  return {
    id: node.id || 0,
    name,
    contractName,
    members,
    location: locator.parseLocation(node.src),
  };
}

function parseEnumDefinition(
  node: RawNode,
  contractName: string,
  locator: SourceLocator
): ASTEnum {
  const name = String(node.name || "unnamedEnum");
  const members: string[] = [];

  if (Array.isArray(node.members)) {
    for (const m of node.members as RawNode[]) {
      if (m.name) members.push(String(m.name));
    }
  }

  return {
    id: node.id || 0,
    name,
    contractName,
    members,
    location: locator.parseLocation(node.src),
  };
}

// ─── Summary Generator ────────────────────────────────────────────────────────

function generateSummary(
  contracts: ASTContract[],
  functions: ASTFunction[],
  stateVariables: ASTStateVariable[],
  modifiers: ASTModifier[],
  events: ASTEvent[],
  structs: ASTStruct[],
  enums: ASTEnum[],
  externalCalls: ASTExternalCall[],
  etherTransfers: ASTEtherTransfer[],
  controlStatements: ASTControlStatement[]
): ASTAnalysisSummary {
  let publicOrExternal = 0;
  let internalOrPrivate = 0;
  let payable = 0;
  let viewOrPure = 0;

  for (const fn of functions) {
    if (fn.visibility === "public" || fn.visibility === "external") {
      publicOrExternal++;
    } else {
      internalOrPrivate++;
    }

    if (fn.stateMutability === "payable") {
      payable++;
    } else if (fn.stateMutability === "view" || fn.stateMutability === "pure") {
      viewOrPure++;
    }
  }

  return {
    totalContracts: contracts.length,
    totalFunctions: functions.length,
    totalStateVariables: stateVariables.length,
    totalModifiers: modifiers.length,
    totalEvents: events.length,
    totalStructs: structs.length,
    totalEnums: enums.length,
    totalExternalCalls: externalCalls.length,
    totalEtherTransfers: etherTransfers.length,
    totalControlStatements: controlStatements.length,
    publicOrExternalFunctions: publicOrExternal,
    internalOrPrivateFunctions: internalOrPrivate,
    payableFunctions: payable,
    viewOrPureFunctions: viewOrPure,
  };
}
