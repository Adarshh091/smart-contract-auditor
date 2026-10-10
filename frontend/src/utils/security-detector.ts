// ─── Real Vulnerability Detection Engine (Stage 7 / Security Detector) ──────
//
// Extensible engine that analyzes compiled Solidity ASTs and code evidence
// to confirm or refute security vulnerabilities with high precision and recall.
//
// Core rule: PATTERN ≠ VULNERABILITY
// Deep evidence analysis (CEI ordering, gas limits, guards, recipient control,
// check/require wrapping) is required to classify findings as:
//   CONFIRMED   - Strong AST/deterministic evidence
//   POTENTIAL   - Heuristic evidence, insufficient for CONFIRMED
//   NOT_VULNERABLE - Actively cleared by evidence (CEI safe, guarded, etc.)
//
// Ollama/ML outputs are CONTEXT ONLY and never produce final findings here.

import type {
  ASTAnalysisResult,
  ASTContract,
  ASTFunction,
  ASTExternalCall,
  SourceLocation,
} from "../types/ast";
import type {
  SecurityFinding,
  SecurityAnalysisResult,
  DetectionContext,
  VulnerabilityDetector,
  VulnerabilityClassification,
  FindingSeverity,
  FindingConfidence,
  DetectionSummary,
} from "../types/security";

// Re-export security types for downstream consumers
import { correlateSlitherWithAST } from "./slither-correlator";

export type {
  SecurityFinding,
  SecurityAnalysisResult,
  DetectionContext,
  VulnerabilityDetector,
  VulnerabilityClassification,
  FindingSeverity,
  FindingConfidence,
};

// ─── Helper Utilities ────────────────────────────────────────────────────────

interface StateModification {
  variableName: string;
  location: SourceLocation;
  rawCode: string;
  isBeforeCall: boolean;
}

/** Known reentrancy guard modifier names or lock patterns */
const REENTRANCY_GUARD_NAMES = [
  "nonreentrant",
  "noreentrancy",
  "lock",
  "mutex",
  "reentrancyguard",
  "initializer",
  "whennotpaused",
];

/** Check if a function is protected by a reentrancy guard modifier */
function hasReentrancyGuardModifier(fn: ASTFunction): { protected: boolean; guardName?: string } {
  for (const modName of fn.modifiers) {
    const clean = modName.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (REENTRANCY_GUARD_NAMES.some((g) => clean.includes(g))) {
      return { protected: true, guardName: modName };
    }
  }
  return { protected: false };
}

/** Check if a function body snippet contains inline reentrancy mutex logic */
function hasInlineMutexGuard(snippet: string): boolean {
  if (!snippet) return false;
  const s = snippet.toLowerCase();
  const hasLockSet =
    s.includes("locked = true") ||
    s.includes("_locked = true") ||
    s.includes("status = _entered") ||
    s.includes("_status = _entered") ||
    s.includes("entered = true");
  const hasLockReset =
    s.includes("locked = false") ||
    s.includes("_locked = false") ||
    s.includes("status = _not_entered") ||
    s.includes("_status = _not_entered") ||
    s.includes("entered = false");
  return hasLockSet && hasLockReset;
}

/** Check if a state variable is purely a metric or counter rather than security-critical state */
function isCounterOrMetricVariable(varName: string): boolean {
  if (!varName) return false;
  const clean = varName.toLowerCase().replace(/[^a-z0-9]/g, "");
  const metricKeywords = [
    "successtransfer",
    "successtransfers",
    "successfultransfer",
    "successfultransfers",
    "totalwithdrawal",
    "totalwithdrawals",
    "withdrawalcount",
    "withdrawalscount",
    "checksperformed",
    "checkperformed",
    "totalclaim",
    "totalclaims",
    "claimcount",
    "counter",
    "counters",
    "metric",
    "metrics",
    "stats",
    "statistics",
    "numtransfers",
    "transferscount",
    "totalpaidout",
    "totalpaid",
    "txcount",
    "transactioncount",
  ];
  return metricKeywords.some((k) => clean.includes(k) || clean === k);
}

/**
 * Determines whether a target/recipient expression is attacker-controllable.
 * e.g., `msg.sender`, `tx.origin`, function parameters, `payable(msg.sender)`, `to`, `recipient`
 */
function isAttackerControllableTarget(targetStr: string, fn: ASTFunction): boolean {
  if (!targetStr) return true; // conservative default
  const t = targetStr.toLowerCase();

  if (t.includes("msg.sender") || t.includes("tx.origin")) return true;

  for (const param of fn.parameters) {
    if (param.name && (t === param.name.toLowerCase() || t.includes(param.name.toLowerCase()))) {
      return true;
    }
  }

  if (
    t.includes("recipient") ||
    t.includes("receiver") ||
    t.includes("bidder") ||
    t.includes("investor")
  ) {
    return true;
  }

  // "to" is attacker controllable only if it's a standalone variable (not part of a longer expression)
  if (t === "to") return true;

  // "user", "account" — likely controllable
  if (t === "user" || t === "account") return true;

  // Hardcoded addresses or system keywords
  if (t.startsWith("0x") || t === "owner" || t.includes("address(this)") || t === "this") {
    return false;
  }

  // state variable names that look like "frontrunner", "currentFrontrunner", etc.
  if (t.includes("frontrunner") || t.includes("winner") || t.includes("highestbidder")) {
    return true; // these are user-settable state variables
  }

  return true; // conservative: unknown targets are treated as controllable
}

/** Extract state variable modifications from code snippet */
function detectStateModifications(fn: ASTFunction, contract: ASTContract): StateModification[] {
  const modifications: StateModification[] = [];
  const snippet = fn.codeSnippet || "";
  if (!snippet) return modifications;

  const lines = snippet.split("\n");
  const stateVarNames = contract.stateVariables.map((v) => v.name);

  stateVarNames.forEach((varName) => {
    if (!varName) return;
    const regex = new RegExp(
      `\\b(${varName})\\s*(\\[[^\\]]+\\])?\\s*(\\+=\\s*|-=\\s*|\\*=\\s*|\\/=\\s*|=(?!=)|\\+\\+|--)|delete\\s+\\b(${varName})`,
      "g"
    );
    lines.forEach((lineText, idx) => {
      if (regex.test(lineText)) {
        const lineNum = fn.location.line + idx;
        modifications.push({
          variableName: varName,
          location: {
            file: fn.location.file,
            line: lineNum,
            column: 1,
            start: fn.location.start,
            length: lineText.length,
            end: fn.location.end,
          },
          rawCode: lineText.trim(),
          isBeforeCall: false,
        });
      }
    });
  });

  return modifications;
}

/**
 * Determine if an external call's return value is checked.
 *
 * Strategy (in order of reliability):
 * 1. Check if this call's rawExpression appears as the condition of a require/assert
 *    in the function's controlStatements (populated by AST analyzer).
 * 2. Check if the codeSnippet text shows the call wrapped in require()/assert().
 * 3. Check if the codeSnippet shows the result assigned to a bool var that is later
 *    used in require/assert/if(!...) revert.
 *
 * Returns true if return value IS checked (safe), false if unchecked (vulnerable).
 */
function isCallReturnValueChecked(call: ASTExternalCall, fn: ASTFunction): boolean {
  const callExpr = call.rawExpression;

  // 1. AST-level: check controlStatements for require/assert whose condition contains this call
  for (const cs of fn.controlStatements) {
    if (!cs.condition) continue;
    if (cs.condition.includes(callExpr) || callExpr.includes(cs.condition)) {
      return true; // e.g. require(addr.send(x)) or assert(ok)
    }
  }

  // 2. Snippet-level text analysis (fallback when controlStatements is empty / not populated)
  const snippet = fn.codeSnippet || "";
  if (!snippet) return false;

  const callExprLow = callExpr.toLowerCase();
  const snippetLow = snippet.toLowerCase();

  // require(addr.send(x)) or require(addr.send(x), "msg")
  if (
    snippetLow.includes(`require(${callExprLow}`) ||
    snippetLow.includes(`require( ${callExprLow}`) ||
    snippetLow.includes(`assert(${callExprLow}`)
  ) {
    return true;
  }

  // if (!addr.send(x)) revert / if(!addr.send(x))
  const negatedCall = `if (!${callExprLow}`;
  const negatedCall2 = `if(!${callExprLow}`;
  if (snippetLow.includes(negatedCall) || snippetLow.includes(negatedCall2)) {
    return true;
  }

  // bool ok = addr.send(x); require(ok); or bool ok = addr.send(x); if (!ok) revert();
  // Look for variable assignment pattern: bool <varName> = <callExpr>
  const boolAssignRegex = /\bbool\s+(\w+)\s*=\s*(.+?);/g;
  let match: RegExpExecArray | null;
  while ((match = boolAssignRegex.exec(snippet)) !== null) {
    const assignedVarName = match[1];
    const assignedExpr = match[2].trim().toLowerCase();
    if (assignedExpr === callExprLow || assignedExpr.includes(callExprLow)) {
      // Now check if assignedVarName is subsequently checked
      const afterAssignment = snippet.slice(match.index + match[0].length).toLowerCase();
      if (
        afterAssignment.includes(`require(${assignedVarName.toLowerCase()}`) ||
        afterAssignment.includes(`assert(${assignedVarName.toLowerCase()}`) ||
        afterAssignment.includes(`if (!${assignedVarName.toLowerCase()}`) ||
        afterAssignment.includes(`if(!${assignedVarName.toLowerCase()}`)
      ) {
        return true;
      }
    }
  }

  // (bool ok,) = addr.call(...); require(ok);  — tuple destructuring for low-level calls
  const tupleAssignRegex = /\(bool\s+(\w+)[^)]*\)\s*=\s*(.+?);/g;
  while ((match = tupleAssignRegex.exec(snippet)) !== null) {
    const assignedVarName = match[1];
    const assignedExpr = match[2].trim().toLowerCase();
    if (assignedExpr === callExprLow || assignedExpr.includes(callExprLow.slice(0, 20))) {
      const afterAssignment = snippet.slice(match.index + match[0].length).toLowerCase();
      if (
        afterAssignment.includes(`require(${assignedVarName.toLowerCase()}`) ||
        afterAssignment.includes(`assert(${assignedVarName.toLowerCase()}`) ||
        afterAssignment.includes(`if (!${assignedVarName.toLowerCase()}`) ||
        afterAssignment.includes(`if(!${assignedVarName.toLowerCase()}`)
      ) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Determine if an external call is inside a require() (blocking dependency pattern).
 * This is the core DoS signal: if the call fails, the entire transaction reverts.
 *
 * Uses both AST controlStatements and snippet text.
 */
function isCallInsideRequire(call: ASTExternalCall, fn: ASTFunction): boolean {
  const callExpr = call.rawExpression;

  // 1. AST-level: controlStatements with kind "require" whose condition wraps this call
  for (const cs of fn.controlStatements) {
    if (cs.kind !== "require" && cs.kind !== "assert") continue;
    if (!cs.condition) continue;
    if (cs.condition.includes(callExpr) || callExpr.includes(cs.condition)) {
      return true;
    }
  }

  // 2. Snippet-level fallback
  const snippet = fn.codeSnippet || "";
  if (!snippet) return false;

  const callExprLow = callExpr.toLowerCase();
  const snippetLow = snippet.toLowerCase();

  if (
    snippetLow.includes(`require(${callExprLow}`) ||
    snippetLow.includes(`require( ${callExprLow}`)
  ) {
    return true;
  }

  // if (!call) revert() pattern also blocks
  if (
    snippetLow.includes(`if (!${callExprLow}`) ||
    snippetLow.includes(`if(!${callExprLow}`)
  ) {
    return true;
  }

  return false;
}

// ─── Reentrancy Detector ─────────────────────────────────────────────────────

export class ReentrancyDetector implements VulnerabilityDetector {
  public category = "Reentrancy" as const;
  public name = "Reentrancy Vulnerability Detector";
  public description =
    "Analyzes external calls, state modifications, CEI pattern compliance, gas limits, and reentrancy guards.";

  public detect(ctx: DetectionContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const { ast } = ctx;

    for (const contract of ast.contracts) {
      if (contract.kind === "interface") continue;

      for (const fn of contract.functions) {
        const calls = fn.externalCalls;
        const transfers = fn.etherTransfers;

        if (calls.length === 0 && transfers.length === 0) continue;
        if (fn.visibility !== "public" && fn.visibility !== "external") continue;

        const finding = this.analyzeFunctionReentrancy(fn, contract);
        if (finding) findings.push(finding);
      }
    }

    return findings;
  }

  private analyzeFunctionReentrancy(fn: ASTFunction, contract: ASTContract): SecurityFinding | null {
    const evidence: string[] = [];

    // 1. Reentrancy Guard Check
    const modifierGuard = hasReentrancyGuardModifier(fn);
    const inlineGuard = hasInlineMutexGuard(fn.codeSnippet || "");

    if (modifierGuard.protected || inlineGuard) {
      const guardDesc = modifierGuard.protected
        ? `Protected by modifier '${modifierGuard.guardName}'`
        : "Protected by inline mutex lock (_locked / status pattern)";
      evidence.push(guardDesc);
      evidence.push(`Function signature: ${fn.signature}`);
      evidence.push(`Visibility: ${fn.visibility}`);

      return {
        id: `SEC-REENTRANCY-GUARD-${contract.name}-${fn.name}`,
        vulnerabilityType: "Reentrancy",
        title: `Reentrancy Guard Protected: ${contract.name}.${fn.name}()`,
        severity: "informational",
        confidence: "high",
        classification: "NOT_VULNERABLE",
        contractName: contract.name,
        functionName: fn.name,
        location: fn.location,
        evidence,
        reason: `Function '${fn.name}' performs external interactions but is protected by a reentrancy guard. Reentrant calls will revert.`,
        recommendation: "Maintain the reentrancy guard and ensure all state-changing entry points are similarly protected.",
        codeSnippet: fn.codeSnippet,
      };
    }

    // 2. Analyze External Calls & ETH Transfers — find earliest call
    const externalCalls = fn.externalCalls;
    const etherTransfers = fn.etherTransfers;

    let earliestCallLine = Infinity;
    let primaryCallDesc = "";
    let isLowLevelCall = false;
    let isAttackerTarget = false;
    let isFixed2300Gas = false;
    let callTarget = "";

    for (const call of externalCalls) {
      if (call.location.line < earliestCallLine) {
        earliestCallLine = call.location.line;
        primaryCallDesc = call.rawExpression;
        callTarget = call.target;
      }
      if (call.callType === "low-level-call" || call.method === "call" || call.value !== undefined) {
        isLowLevelCall = true;
      }
      if (call.callType === "transfer" || call.callType === "send") {
        isFixed2300Gas = true;
      }
    }

    for (const transfer of etherTransfers) {
      if (transfer.location.line < earliestCallLine) {
        earliestCallLine = transfer.location.line;
        primaryCallDesc = transfer.rawExpression;
        callTarget = transfer.recipient;
      }
      if (transfer.transferType === "call-value") {
        isLowLevelCall = true;
      }
      if (transfer.transferType === "transfer" || transfer.transferType === "send") {
        isFixed2300Gas = true;
      }
    }

    isAttackerTarget = isAttackerControllableTarget(callTarget, fn);

    // 3a. State modifications via snippet text (primary path)
    const stateMods = detectStateModifications(fn, contract);
    let modsAfterCall: StateModification[] = [];
    let modsBeforeCall: StateModification[] = [];

    stateMods.forEach((mod) => {
      if (mod.location.line > earliestCallLine) {
        modsAfterCall.push(mod);
      } else {
        modsBeforeCall.push(mod);
      }
    });

    // 3b. Fallback: use operations[] ordering when codeSnippet is absent or line
    //     numbers collapsed (all ops at line 1 because source is "").
    //     Find index of first external-call/ether-transfer op, then check if any
    //     state-write op appears after it.
    const snippet = fn.codeSnippet || "";
    if (fn.operations.length > 0 && (stateMods.length === 0 || !snippet)) {
      const stateVarNames = contract.stateVariables.map((v) => v.name);
      let firstCallIdx = -1;
      for (let i = 0; i < fn.operations.length; i++) {
        const op = fn.operations[i];
        if (op.kind === "external-call" || op.kind === "ether-transfer") {
          firstCallIdx = i;
          break;
        }
      }
      if (firstCallIdx >= 0) {
        modsAfterCall = [];
        modsBeforeCall = [];
        for (let i = 0; i < fn.operations.length; i++) {
          const op = fn.operations[i];
          if (op.kind === "state-write" && op.stateVariable && stateVarNames.includes(op.stateVariable)) {
            const synthetic: StateModification = {
              variableName: op.stateVariable,
              location: op.location,
              rawCode: op.expression,
              isBeforeCall: i < firstCallIdx,
            };
            if (i > firstCallIdx) {
              modsAfterCall.push(synthetic);
            } else {
              modsBeforeCall.push(synthetic);
            }
          }
        }
      }
    }

    // Separate security-critical state modifications from counter/metric-only modifications
    const criticalModsAfterCall = modsAfterCall.filter(
      (m) => !isCounterOrMetricVariable(m.variableName)
    );

    // Determine if we have any evidence of state tracking at all
    const hasAnyStateMods = modsBeforeCall.length > 0 || modsAfterCall.length > 0;

    // Case A: All security-critical state mods are BEFORE the call — CEI safe
    if (hasAnyStateMods && criticalModsAfterCall.length === 0) {
      evidence.push(`External call at line ${earliestCallLine}: '${primaryCallDesc}'`);
      evidence.push(
        `State variable(s) [${modsBeforeCall.map((m) => m.variableName).join(", ")}] modified BEFORE external call.`
      );
      evidence.push("Checks-Effects-Interactions (CEI) pattern is strictly followed.");

      return {
        id: `SEC-REENTRANCY-CEI-SAFE-${contract.name}-${fn.name}`,
        vulnerabilityType: "Reentrancy",
        title: `Safe (CEI Pattern Followed): ${contract.name}.${fn.name}()`,
        severity: "informational",
        confidence: "high",
        classification: "NOT_VULNERABLE",
        contractName: contract.name,
        functionName: fn.name,
        location: fn.location,
        evidence,
        reason: `Function '${fn.name}' updates state variable(s) BEFORE performing external interactions, following the Checks-Effects-Interactions pattern.`,
        recommendation: "Continue adhering to the Checks-Effects-Interactions pattern for all external calls.",
        codeSnippet: fn.codeSnippet,
      };
    }

    // Case B: Security-critical state modified AFTER low-level call / forwarded gas to attacker target → CONFIRMED
    if (criticalModsAfterCall.length > 0 && (isLowLevelCall || !isFixed2300Gas) && isAttackerTarget) {
      evidence.push(`External call with forwarded gas at line ${earliestCallLine}: '${primaryCallDesc}'`);
      evidence.push(`Target '${callTarget}' is attacker-controllable.`);
      evidence.push(
        `Security-critical state variable(s) [${criticalModsAfterCall.map((m) => m.variableName).join(", ")}] updated AFTER call at line(s) ${criticalModsAfterCall.map((m) => m.location.line).join(", ")}: '${criticalModsAfterCall.map((m) => m.rawCode).join("; ")}'`
      );
      evidence.push("No reentrancy guard (nonReentrant modifier or mutex lock) is present.");

      return {
        id: `SEC-REENTRANCY-CONFIRMED-${contract.name}-${fn.name}`,
        vulnerabilityType: "Reentrancy",
        title: `Confirmed Reentrancy Vulnerability: ${contract.name}.${fn.name}()`,
        severity: "critical",
        confidence: "high",
        classification: "CONFIRMED",
        contractName: contract.name,
        functionName: fn.name,
        location: fn.location,
        evidence,
        reason: `Function '${fn.name}' calls an external attacker-controllable address '${callTarget}' with forwarded gas BEFORE updating security-critical state variable(s) [${criticalModsAfterCall.map((m) => m.variableName).join(", ")}]. An attacker can re-enter before state is updated.`,
        recommendation: `1. Update state variables BEFORE the external call (Checks-Effects-Interactions).\n2. Add OpenZeppelin's ReentrancyGuard 'nonReentrant' modifier to ${fn.name}().\n3. Avoid low-level .call() where transfer() or send() is sufficient.`,
        codeSnippet: fn.codeSnippet,
      };
    }

    // Case C: State modified AFTER transfer()/send() → POTENTIAL (2300 gas mitigates but CEI violated)
    if (modsAfterCall.length > 0 && isFixed2300Gas) {
      evidence.push(`ETH transfer via transfer()/send() at line ${earliestCallLine}: '${primaryCallDesc}'`);
      evidence.push("2300 gas limit mitigates standard state-changing reentrancy.");
      evidence.push(
        `State variable(s) [${modsAfterCall.map((m) => m.variableName).join(", ")}] updated AFTER transfer at line(s) ${modsAfterCall.map((m) => m.location.line).join(", ")}.`
      );
      evidence.push("Violates Checks-Effects-Interactions (CEI) pattern.");

      return {
        id: `SEC-REENTRANCY-POTENTIAL-GASLIMIT-${contract.name}-${fn.name}`,
        vulnerabilityType: "Reentrancy",
        title: `Potential Reentrancy (CEI Violation): ${contract.name}.${fn.name}()`,
        severity: "medium",
        confidence: "medium",
        classification: "POTENTIAL",
        contractName: contract.name,
        functionName: fn.name,
        location: fn.location,
        evidence,
        reason: `Function '${fn.name}' modifies state AFTER transferring ETH via transfer()/send(). Although the 2300 gas limit currently prevents complex reentrancy, this violates the CEI pattern and could become exploitable if gas costs change or in read-only reentrancy scenarios.`,
        recommendation: `Move state modifications above the transfer()/send() call to strictly follow the Checks-Effects-Interactions pattern.`,
        codeSnippet: fn.codeSnippet,
      };
    }

    // Case D: External call present without explicit state modification after call — low-level, attacker target
    if (isLowLevelCall && isAttackerTarget) {
      evidence.push(`Low-level call with forwarded gas at line ${earliestCallLine}: '${primaryCallDesc}'`);
      evidence.push(`Target '${callTarget}' is external / attacker-controllable.`);
      evidence.push("No explicit state variable modification detected after call in function scope.");

      return {
        id: `SEC-REENTRANCY-POTENTIAL-UNGUARDED-${contract.name}-${fn.name}`,
        vulnerabilityType: "Reentrancy",
        title: `Potential Cross-Function / Read-Only Reentrancy: ${contract.name}.${fn.name}()`,
        severity: "low",
        confidence: "low",
        classification: "POTENTIAL",
        contractName: contract.name,
        functionName: fn.name,
        location: fn.location,
        evidence,
        reason: `Function '${fn.name}' performs a low-level call to an external attacker-controllable address with forwarded gas without a reentrancy guard. Cross-function or read-only reentrancy may be possible.`,
        recommendation: "Add a nonReentrant modifier if this function interacts with state relied upon by other public contract methods.",
        codeSnippet: fn.codeSnippet,
      };
    }

    return null;
  }
}

// ─── Unchecked External Call Detector ────────────────────────────────────────
//
// A call's return value is "unchecked" when:
//   - It is NOT wrapped in require(call) or assert(call)
//   - Its boolean result is NOT assigned to a variable that is subsequently checked
//   - It is NOT in an if(!call) revert() pattern
//
// Only send() and low-level call() need checking — transfer() reverts on failure
// so its return value is not an issue.

export class UncheckedCallDetector implements VulnerabilityDetector {
  public category = "Unchecked External Call" as const;
  public name = "Unchecked External Call Detector";
  public description =
    "Detects send() and low-level call() whose return value is not verified.";

  public detect(ctx: DetectionContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const { ast } = ctx;

    for (const contract of ast.contracts) {
      for (const fn of contract.functions) {
        for (const call of fn.externalCalls) {
          // transfer() reverts on failure — no unchecked return value issue
          // delegatecall/staticcall/regular: handled separately if needed
          if (call.callType !== "send" && call.callType !== "low-level-call") continue;

          const checked = isCallReturnValueChecked(call, fn);
          if (!checked) {
            findings.push({
              id: `SEC-UNCHECKED-${contract.name}-${fn.name}-L${call.location.line}`,
              vulnerabilityType: "Unchecked External Call",
              title: `Unchecked ${call.callType === "send" ? "send()" : "call()"} Return Value in ${contract.name}.${fn.name}()`,
              severity: "high",
              confidence: "high",
              classification: "CONFIRMED",
              contractName: contract.name,
              functionName: fn.name,
              location: call.location,
              evidence: [
                `${call.callType === "send" ? "send()" : "low-level call()"} at line ${call.location.line}: '${call.rawExpression}'`,
                "The boolean return value is not verified by require(), assert(), or an if-revert check.",
                "If the call fails, execution continues silently — funds may be permanently lost.",
              ],
              reason: `The return value of '${call.rawExpression}' is not checked. If this call fails (e.g., recipient runs out of gas or is a rejecting contract), the failure is silently ignored, leading to inconsistent state or loss of funds.`,
              recommendation: "Use require(success, \"Transfer failed\") or handle the boolean return explicitly. For ETH transfers, prefer transfer() which reverts automatically, or use call() with a require check.",
              codeSnippet: fn.codeSnippet,
            });
          }
        }
      }
    }

    return findings;
  }
}

// ─── Denial of Service Detector ──────────────────────────────────────────────
//
// A CONFIRMED DoS requires ALL of:
//   1. An external call to a non-self (non-msg.sender) attacker-controllable address
//   2. The call is inside require() or if(!call) revert() — failure blocks ALL users
//   3. The blocked operation is shared/global (other users are affected, not just caller)
//
// What does NOT trigger DoS:
//   - msg.sender.send(x) / msg.sender.transfer(x) — failure only affects the
//     caller's own transaction; other users are completely unaffected
//   - treasury.transfer(x) or any bare send/transfer outside require() — plain
//     ETH transfer is an interaction, not a vulnerability by itself
//   - Any transfer/send to msg.sender inside require() — self-affecting only
//   - Generic heuristics: transfer exists → DoS, send exists → DoS, payable → DoS
//
// Core rule: External ETH transfer ≠ DoS.
// Only require(nonSelf.externalCall()) where the recipient is user-settable confirms DoS.

export class DosDetector implements VulnerabilityDetector {
  public category = "Denial of Service" as const;
  public name = "Denial of Service (DoS) Detector";
  public description =
    "Detects external calls whose failure can permanently block a shared operation for all users.";

  public detect(ctx: DetectionContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const { ast } = ctx;

    for (const contract of ast.contracts) {
      for (const fn of contract.functions) {
        // Only state-changing functions are DoS targets
        if (fn.stateMutability === "view" || fn.stateMutability === "pure") continue;

        for (const call of fn.externalCalls) {
          // ── Rule 1: skip msg.sender / tx.origin as recipient ───────────────
          // A send/transfer to msg.sender only affects the calling user's own
          // transaction. Other users can always call the function independently.
          // This is NEVER a global/shared DoS — it is self-affecting only.
          //
          // Examples that must NOT be flagged:
          //   msg.sender.send(amount)        ← caller's own withdrawal
          //   msg.sender.transfer(amount)    ← caller's own withdrawal
          //   payable(msg.sender).send(x)    ← caller's own withdrawal
          const targetLow = (call.target || "").toLowerCase();
          const isSelfTarget =
            targetLow.includes("msg.sender") || targetLow.includes("tx.origin");
          if (isSelfTarget) continue;

          // ── Rule 2: call must be inside require() / if(!call) revert() ─────
          // Bare send()/transfer() outside require() is just an ETH interaction.
          // Even if it reverts, it only affects the current transaction — there
          // is no evidence that it permanently blocks a shared/global workflow.
          //
          // To confirm DoS, the call's failure must be the direct cause of a
          // revert that prevents ALL users from making progress:
          //
          //   ✅ require(currentFrontrunner.send(currentBid))  ← classic DoS
          //   ✅ require(winner.call{value: prize}(""))        ← prize distribution DoS
          //
          //   ❌ treasury.transfer(amount)                     ← bare transfer, no require()
          //   ❌ payable(owner).transfer(fee)                  ← admin address, not user-settable
          //   ❌ msg.sender.transfer(amount)                   ← self-affecting (already skipped)
          const isInsideRequire = isCallInsideRequire(call, fn);
          if (!isInsideRequire) continue;

          // ── Rule 3: recipient must be attacker-controllable ────────────────
          // Hardcoded addresses, owner, admin — these are system/admin addresses
          // and cannot be weaponized by an external attacker.
          const attackerControlled = isAttackerControllableTarget(call.target, fn);
          if (!attackerControlled) continue;

          // ── CONFIRMED DoS: require(attacker-controlled-addr.send/call/transfer) ──
          // The classic Denial-of-Service via unexpected revert pattern.
          // The attacker deploys a contract that always reverts its fallback,
          // becoming the stored recipient, and then every future caller's
          // transaction reverts at the require().
          findings.push({
            id: `SEC-DOS-${contract.name}-${fn.name}-L${call.location.line}`,
            vulnerabilityType: "Denial of Service",
            title: `Denial of Service via Blocking External Call in ${contract.name}.${fn.name}()`,
            severity: "high",
            confidence: "high",
            classification: "CONFIRMED",
            contractName: contract.name,
            functionName: fn.name,
            location: call.location,
            evidence: [
              `External call inside require() at line ${call.location.line}: '${call.rawExpression}'`,
              `Target '${call.target}' is attacker-controllable (user-settable stored address or parameter).`,
              "If the recipient contract deploys a reverting fallback, this require() will always fail, permanently blocking this function for all users.",
            ],
            reason: `The function calls '${call.rawExpression}' inside require(). If the recipient '${call.target}' is a malicious contract that always reverts its fallback function, this call will always fail, permanently blocking this function for all users. This is a classic Denial of Service via unexpected revert.`,
            recommendation: "Use the pull-payment (withdrawal) pattern: store owed ETH in a mapping and let recipients withdraw it themselves. Never push ETH to untrusted addresses in blocking require() checks.",
            codeSnippet: fn.codeSnippet,
          });
        }
      }
    }

    return findings;
  }
}

// ─── Timestamp Dependency Detector ───────────────────────────────────────────
//
// Only reports when actual block.timestamp or `now` is found in source code
// AND it is used in control flow (require/if/assert).
// Never infers from contract category, function names, or Ollama output.

export class TimestampDependencyDetector implements VulnerabilityDetector {
  public category = "Timestamp Dependency" as const;
  public name = "Timestamp Dependency Detector";
  public description = "Detects usage of block.timestamp or now in critical control flow.";

  public detect(ctx: DetectionContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const { ast } = ctx;

    for (const contract of ast.contracts) {
      for (const fn of contract.functions) {
        // 1. Skip constructors (initialization usage like deadline = now + 1 days is normal)
        if (
          fn.kind === "constructor" ||
          fn.name === "constructor" ||
          fn.name === contract.name
        ) {
          continue;
        }

        // 2. Skip VIEW and PURE helper functions (read-only getters like isExpired() or timeRemaining())
        if (fn.stateMutability === "view" || fn.stateMutability === "pure") {
          continue;
        }

        const snippet = fn.codeSnippet || "";
        let evidenceLine = "";
        let isControlFlow = false;
        let isValidationCheckOnly = false;

        // Primary: check codeSnippet text for block.timestamp / now
        if (snippet) {
          const lines = snippet.split("\n");
          for (const line of lines) {
            if (line.includes("block.timestamp") || /\bnow\b/.test(line)) {
              const lineTrim = line.trim();
              if (
                lineTrim.includes("require") ||
                lineTrim.includes("assert") ||
                /\bif\b/.test(lineTrim)
              ) {
                // Check if this is merely a parameter validation comparison (e.g. setDeadline: require(newDeadline > now))
                // where function receives a parameter and validates it relative to current time rather than making a state-changing execution decision based on time.
                const lineLow = lineTrim.toLowerCase();
                const isSetterName = fn.name.toLowerCase().startsWith("set");
                const hasParamInCond = fn.parameters.some(
                  (p) => p.name && lineLow.includes(p.name.toLowerCase())
                );
                if (isSetterName && hasParamInCond && (lineLow.includes("newdeadline") || lineLow.includes("deadline"))) {
                  isValidationCheckOnly = true;
                }

                evidenceLine = lineTrim;
                isControlFlow = true;
                break;
              }
            }
          }
        }

        // Fallback: check AST controlStatements conditions (populated even without source text)
        if (!isControlFlow) {
          for (const cs of fn.controlStatements) {
            const cond = cs.condition || "";
            if (cond.includes("block.timestamp") || /\bnow\b/.test(cond)) {
              isControlFlow = true;
              evidenceLine = `${cs.kind}(${cond})`;
              break;
            }
          }
        }

        if (!isControlFlow || isValidationCheckOnly) continue;

        findings.push({
          id: `SEC-TIMESTAMP-${contract.name}-${fn.name}`,
          vulnerabilityType: "Timestamp Dependency",
          title: `Timestamp Dependency in ${contract.name}.${fn.name}()`,
          severity: "low",
          confidence: "medium",
          classification: "POTENTIAL",
          contractName: contract.name,
          functionName: fn.name,
          location: fn.location,
          evidence: [
            `Timestamp usage in control flow: '${evidenceLine}'`,
            "Miners can manipulate block.timestamp by up to ~15 seconds.",
          ],
          reason: `The function uses block.timestamp (or 'now') in a control flow statement. Miners have limited ability to manipulate block timestamps, which could allow bypassing time-based constraints.`,
          recommendation:
            "Avoid relying on block.timestamp for strict equality or short-interval constraints. For long intervals (days), it is generally safe. Consider using block numbers instead.",
          codeSnippet: fn.codeSnippet,
        });
      }
    }

    return findings;
  }
}

// ─── Block Number Dependency Detector ─────────────────────────────────────────
//
// Detects usage of block.number in state-changing / security-critical control flow.
// Does NOT flag constructors, view/pure functions, simple metadata assignments, or informational usage.

export class BlockNumberDetector implements VulnerabilityDetector {
  public category = "Block Number Dependency" as const;
  public name = "Block Number Dependency Detector";
  public description = "Detects usage of block.number in critical control flow.";

  public detect(ctx: DetectionContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const { ast } = ctx;

    for (const contract of ast.contracts) {
      for (const fn of contract.functions) {
        // 1. Skip constructors (metadata / initialization)
        if (
          fn.kind === "constructor" ||
          fn.name === "constructor" ||
          fn.name === contract.name
        ) {
          continue;
        }

        // 2. Skip VIEW and PURE helper functions (read-only getters like isRoundActive(), currentBlock(), etc.)
        if (fn.stateMutability === "view" || fn.stateMutability === "pure") {
          continue;
        }

        const snippet = fn.codeSnippet || "";
        let evidenceLine = "";
        let isControlFlow = false;

        // Check codeSnippet text for block.number in control flow (require/assert/if)
        if (snippet) {
          const lines = snippet.split("\n");
          for (const line of lines) {
            if (line.includes("block.number")) {
              const lineTrim = line.trim();
              if (
                lineTrim.includes("require") ||
                lineTrim.includes("assert") ||
                /\bif\b/.test(lineTrim)
              ) {
                evidenceLine = lineTrim;
                isControlFlow = true;
                break;
              }
            }
          }
        }

        // Fallback: check AST controlStatements conditions
        if (!isControlFlow) {
          for (const cs of fn.controlStatements) {
            const cond = cs.condition || "";
            if (cond.includes("block.number")) {
              isControlFlow = true;
              evidenceLine = `${cs.kind}(${cond})`;
              break;
            }
          }
        }

        if (!isControlFlow) continue;

        findings.push({
          id: `SEC-BLOCKNUM-${contract.name}-${fn.name}`,
          vulnerabilityType: "Block Number Dependency",
          title: `Block Number Dependency in ${contract.name}.${fn.name}()`,
          severity: "low",
          confidence: "medium",
          classification: "POTENTIAL",
          contractName: contract.name,
          functionName: fn.name,
          location: fn.location,
          evidence: [
            `Block number usage in control flow: '${evidenceLine}'`,
            "Execution decision depends directly on block.number.",
          ],
          reason: `The function uses block.number in a control flow statement (require/if). Miners or validators have influence over block inclusion and ordering, which can affect time- or block-sensitive logic.`,
          recommendation:
            "Ensure block.number comparisons accommodate potential reorgs and block time variations.",
          codeSnippet: fn.codeSnippet,
        });
      }
    }

    return findings;
  }
}

// ─── Ether Strict Equality Detector ──────────────────────────────────────────
//
// Only reports when actual strict equality on address(this).balance is found.
// selfdestruct alone does NOT trigger this.

export class EtherStrictEqualityDetector implements VulnerabilityDetector {
  public category = "Ether Strict Equality" as const;
  public name = "Ether Strict Equality Detector";
  public description = "Detects strict equality checks (== or !=) on contract ETH balance in execution paths.";

  public detect(ctx: DetectionContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const { ast } = ctx;
    // balance == or != pattern in source text or AST condition string
    const strictEqRegex =
      /address\s*\(\s*this\s*\)\s*\.\s*balance\s*(==|!=)|(==|!=)\s*address\s*\(\s*this\s*\)\s*\.\s*balance|\.balance\s*(==|!=)|(==|!=)\s*\.balance/;

    for (const contract of ast.contracts) {
      for (const fn of contract.functions) {
        const snippet = fn.codeSnippet || "";
        const snippetLow = snippet.toLowerCase();
        let evidenceLine = "";
        let found = false;
        let isControlPath = false;

        // Check AST controlStatements conditions first
        for (const cs of fn.controlStatements) {
          const cond = cs.condition || "";
          if (strictEqRegex.test(cond)) {
            evidenceLine = `${cs.kind}(${cond})`;
            found = true;
            isControlPath = true;
            break;
          }
        }

        // Check source text
        if (!found && snippet && strictEqRegex.test(snippet)) {
          const lines = snippet.split("\n");
          const line = lines.find((l) => strictEqRegex.test(l))?.trim() ?? "";
          if (line) {
            evidenceLine = line;
            found = true;
            const lineLow = line.toLowerCase();
            if (
              lineLow.includes("require") ||
              lineLow.includes("assert") ||
              lineLow.includes("if") ||
              snippetLow.includes("require") ||
              snippetLow.includes("if")
            ) {
              isControlPath = true;
            }
          }
        }

        if (!found) continue;

        // Non-view/pure functions with strict balance equality are state-changing execution paths
        if (fn.stateMutability !== "view" && fn.stateMutability !== "pure") {
          isControlPath = true;
        }

        // Skip view/pure helper functions where equality is merely returned without controlling execution flow
        if (!isControlPath) continue;

        findings.push({
          id: `SEC-STRICT-BAL-${contract.name}-${fn.name}`,
          vulnerabilityType: "Ether Strict Equality",
          title: `Ether Strict Balance Equality in ${contract.name}.${fn.name}()`,
          severity: "medium",
          confidence: "high",
          classification: "CONFIRMED",
          contractName: contract.name,
          functionName: fn.name,
          location: fn.location,
          evidence: [
            `Strict balance comparison: '${evidenceLine}'`,
            "Attackers can force-send ETH via selfdestruct to change the balance without calling any function.",
          ],
          reason:
            "The contract uses strict equality (== or !=) on address(this).balance in an execution path. An attacker can use selfdestruct() from another contract to forcibly send ETH, breaking the equality invariant and potentially causing a permanent denial of service or unexpected behavior.",
          recommendation:
            "Track internal ETH accounting with a state variable instead of relying on address(this).balance. Use >= comparisons rather than == or != for balance checks.",
          codeSnippet: fn.codeSnippet,
        });
      }
    }

    return findings;
  }
}

// ─── Integer Overflow/Underflow Detector ─────────────────────────────────────
//
// For Solidity >= 0.8: built-in checked arithmetic. Only POTENTIAL if inside unchecked{}.
// For Solidity < 0.8: arithmetic on user-controlled values may overflow.
// Never CONFIRMED from syntax alone — requires exploitability context.
//
// The detector only looks at explicit `unchecked {}` blocks since we cannot
// reliably determine Solidity version without the compiled AST's pragma.
// Pre-0.8 detection would require version info from the AST metadata.

/** Returns true when the resolved Solidity version is strictly < 0.8.0 */
function isPreV8(solidityVersion: string | undefined): boolean {
  if (!solidityVersion) return false;
  const m = solidityVersion.match(/^(\d+)\.(\d+)/);
  if (!m) return false;
  const major = parseInt(m[1], 10);
  const minor = parseInt(m[2], 10);
  return major === 0 && minor < 8;
}

export class IntegerOverflowDetector implements VulnerabilityDetector {
  public category = "Integer Overflow/Underflow" as const;
  public name = "Integer Overflow/Underflow Detector";
  public description =
    "Detects integer overflow/underflow: all arithmetic in Solidity <0.8, unchecked{} blocks in >=0.8.";

  public detect(ctx: DetectionContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const { ast, solidityVersion } = ctx;
    const preV8 = isPreV8(solidityVersion);

    for (const contract of ast.contracts) {
      for (const fn of contract.functions) {
        const snippet = fn.codeSnippet || "";
        if (!snippet) continue;

        if (preV8) {
          // ── Pre-0.8: ALL arithmetic is unprotected ──────────────────────
          // Look for += / -= / * = or binary +/-/* on integer expressions.
          const hasArithmetic = /[\+\-\*]=/.test(snippet) ||
            /\b\d+\s*[\+\-\*]\s*\w/.test(snippet) ||
            /\w+\s*[\+\-\*]\s*\w/.test(snippet);

          if (!hasArithmetic) continue;

          // Find the first evidence line
          const lines = snippet.split("\n");
          const arithLine = lines.find((l) =>
            /[\+\-\*]=|\b\d+\s*[\+\-\*]|\w+\s*[\+\-\*]\s*\w/.test(l)
          )?.trim() ?? "arithmetic expression";

          findings.push({
            id: `SEC-OVERFLOW-PRE08-${contract.name}-${fn.name}`,
            vulnerabilityType: "Integer Overflow/Underflow",
            title: `Integer Overflow/Underflow Risk (Solidity ${solidityVersion}): ${contract.name}.${fn.name}()`,
            severity: "high",
            confidence: "medium",
            classification: "POTENTIAL",
            contractName: contract.name,
            functionName: fn.name,
            location: fn.location,
            evidence: [
              `Solidity version ${solidityVersion} has NO built-in overflow/underflow protection.`,
              `Arithmetic expression found: '${arithLine}'`,
              "SafeMath or manual bounds checking must be used to prevent overflow.",
            ],
            reason:
              `Solidity versions before 0.8.0 do not revert on integer overflow or underflow. ` +
              `The function '${fn.name}' contains arithmetic that may overflow/underflow if operands are attacker-influenced. ` +
              `Use OpenZeppelin's SafeMath library or migrate to Solidity >=0.8.0.`,
            recommendation:
              "Use SafeMath for all arithmetic operations, or upgrade to Solidity >=0.8.0 which has built-in overflow protection.",
            codeSnippet: fn.codeSnippet,
          });
        } else {
          // ── >= 0.8: Only report explicit unchecked {} blocks ────────────
          const hasUncheckedBlock = /unchecked\s*\{/.test(snippet);
          if (!hasUncheckedBlock) continue;

          // Extract the contents of the unchecked block
          const uncheckedMatch = /unchecked\s*\{([^}]+)\}/.exec(snippet);
          const uncheckedBody = uncheckedMatch?.[1] ?? snippet;

          const hasArithmetic =
            ["+", "-", "*"].some((op) =>
              uncheckedBody.includes(op) && !uncheckedBody.includes(`${op}=`)
            ) || /[\+\-\*]=/.test(uncheckedBody);

          if (!hasArithmetic) continue;

          const lines = uncheckedBody.split("\n");
          const arithLine = lines.find((l) =>
            /[+\-*\/]=|\b\+\+|--/.test(l)
          )?.trim() ?? "unchecked arithmetic";

          findings.push({
            id: `SEC-OVERFLOW-UNCHECKED-${contract.name}-${fn.name}`,
            vulnerabilityType: "Integer Overflow/Underflow",
            title: `Unchecked Arithmetic Block in ${contract.name}.${fn.name}()`,
            severity: "medium",
            confidence: "medium",
            classification: "POTENTIAL",
            contractName: contract.name,
            functionName: fn.name,
            location: fn.location,
            evidence: [
              `unchecked {} block found with arithmetic: '${arithLine}'`,
              "Solidity >=0.8 built-in overflow protections are explicitly disabled.",
            ],
            reason:
              "The unchecked {} block disables Solidity 0.8's built-in overflow/underflow protection. If the arithmetic operands can be attacker-influenced to overflow or underflow, this could lead to incorrect accounting or unexpected behavior.",
            recommendation:
              "Verify that all inputs to unchecked arithmetic are strictly bounded and cannot overflow/underflow. Remove the unchecked block if overflow protection is not required for gas optimization here.",
            codeSnippet: fn.codeSnippet,
          });
        }
      }
    }

    return findings;
  }
}

// ─── Access Control Detector ──────────────────────────────────────────────────
//
// CONFIRMED only when BOTH hold:
//   A) Function performs a genuinely privileged/sensitive operation:
//      - selfdestruct / suicide
//      - delegatecall
//      - modifying owner/admin/controller state variables
//      - contract ETH transfer / sweep to stored privileged address (treasury/owner/admin)
//   B) There is NO effective authorization check or access modifier (onlyOwner, etc.)
//
// What does NOT trigger Access Control:
//   - Constructor (modern kind="constructor", name="constructor", or old-style name=contract.name)
//   - Public/external visibility alone
//   - Presence of owner variable in contract alone
//   - User withdrawals (msg.sender.transfer / withdrawal of user balance)
//   - ERC20 transfers/approvals (transfer, transferFrom, approve)
//   - Functions protected by onlyOwner, onlyAdmin, require(msg.sender == owner), etc.

export class AccessControlDetector implements VulnerabilityDetector {
  public category = "Access Control" as const;
  public name = "Access Control Detector";
  public description = "Detects missing authorization on privileged operations.";

  public detect(ctx: DetectionContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const { ast } = ctx;

    for (const contract of ast.contracts) {
      for (const fn of contract.functions) {
        // 1. Skip constructors (modern kind === "constructor", name === "constructor", or old-style name === contract.name)
        if (
          fn.kind === "constructor" ||
          fn.name === "constructor" ||
          fn.name === contract.name
        ) {
          continue;
        }

        // 2. Only public and external non-view/pure functions can have missing access control
        if (fn.visibility !== "public" && fn.visibility !== "external") continue;
        if (fn.stateMutability === "view" || fn.stateMutability === "pure") continue;

        // 3. Skip functions protected by access control modifiers
        const hasAccessModifier = fn.modifiers.some((m) => {
          const ml = m.toLowerCase().replace(/[^a-z0-9]/g, "");
          return (
            ml.includes("onlyowner") ||
            ml.includes("onlyadmin") ||
            ml.includes("onlyrole") ||
            ml.includes("authorized") ||
            ml.includes("onlycontroller") ||
            ml.includes("onlyoperator") ||
            ml.includes("restricted") ||
            ml.includes("isowner") ||
            ml.includes("isadmin") ||
            ml.includes("isoperator")
          );
        });
        if (hasAccessModifier) continue;

        const snippet = fn.codeSnippet || "";
        const snippetLow = snippet.toLowerCase();

        // 4. Skip functions with inline authorization checks
        const hasInlineAuth =
          snippetLow.includes("msg.sender == owner") ||
          snippetLow.includes("msg.sender == admin") ||
          snippetLow.includes("msg.sender == operator") ||
          snippetLow.includes("msg.sender == treasury") ||
          snippetLow.includes("msg.sender == controller") ||
          snippetLow.includes("msg.sender == manager") ||
          snippetLow.includes("owner == msg.sender") ||
          snippetLow.includes("admin == msg.sender") ||
          snippetLow.includes("operator == msg.sender") ||
          snippetLow.includes("require(owner") ||
          snippetLow.includes("require(admin") ||
          snippetLow.includes("require(operator") ||
          snippetLow.includes("require(msg.sender") ||
          snippetLow.includes("_checkowner()") ||
          snippetLow.includes("onlyowner") ||
          snippetLow.includes("onlyadmin") ||
          snippetLow.includes("onlyoperator") ||
          snippetLow.includes("hasrole(");

        if (hasInlineAuth) continue;

        // Check AST control statements for inline authorization conditions
        let hasControlAuth = false;
        for (const cs of fn.controlStatements) {
          const cond = (cs.condition || "").toLowerCase();
          if (
            cond.includes("msg.sender") &&
            (cond.includes("owner") ||
              cond.includes("admin") ||
              cond.includes("operator") ||
              cond.includes("controller") ||
              cond.includes("treasury"))
          ) {
            hasControlAuth = true;
            break;
          }
        }
        if (hasControlAuth) continue;

        // 5. Identify privileged operations
        // A) selfdestruct
        const hasSelfDestruct =
          snippetLow.includes("selfdestruct") ||
          snippetLow.includes("suicide(") ||
          fn.etherTransfers.some((t) => t.transferType === "selfdestruct");

        // B) delegatecall
        const hasDelegateCall =
          snippetLow.includes("delegatecall") ||
          fn.externalCalls.some((c) => c.callType === "delegatecall");

        // C) Owner / admin / operator state variable modification
        const adminStateVarNames = ["owner", "admin", "controller", "operator", "pendingowner"];
        const ownerAdminVars = contract.stateVariables.filter((v) => {
          const vn = v.name.toLowerCase();
          return adminStateVarNames.includes(vn) || vn.endsWith("owner") || vn.endsWith("admin");
        });
        const changesOwnerAdmin = ownerAdminVars.some((v) =>
          new RegExp(`\\b${v.name}\\s*=\\s*`).test(snippet)
        );

        // D) Unprotected privileged ETH transfer / fund sweep to stored treasury/admin address
        let hasPrivilegedTransfer = false;
        let privilegedTransferTarget = "";

        const allTransfers = [
          ...fn.etherTransfers.map((t) => ({ recipient: t.recipient, raw: t.rawExpression })),
          ...fn.externalCalls
            .filter(
              (c) =>
                c.callType === "transfer" ||
                c.callType === "send" ||
                c.callType === "low-level-call" ||
                c.value !== undefined
            )
            .map((c) => ({ recipient: c.target, raw: c.rawExpression })),
        ];

        for (const tr of allTransfers) {
          const targetRaw = (tr.recipient || "").toLowerCase();
          // Skip if target is caller (user withdrawal)
          if (targetRaw.includes("msg.sender") || targetRaw.includes("tx.origin")) {
            continue;
          }

          // Check if target matches stored privileged address in contract state variables
          const isPrivilegedStateVar = contract.stateVariables.some((sv) => {
            const svName = sv.name.toLowerCase();
            const isPrivName =
              svName === "treasury" ||
              svName === "owner" ||
              svName === "admin" ||
              svName === "operator" ||
              svName === "collector" ||
              svName.includes("treasury") ||
              svName.includes("wallet");
            return isPrivName && (targetRaw === svName || targetRaw.includes(svName));
          });

          // Check if snippet shows contract balance sweep without caller balance deduction
          const isContractBalanceSweep =
            (tr.raw.includes("address(this).balance") || snippetLow.includes("address(this).balance")) &&
            !snippetLow.includes("balances[msg.sender]");

          if (isPrivilegedStateVar || isContractBalanceSweep) {
            hasPrivilegedTransfer = true;
            privilegedTransferTarget = tr.recipient || "treasury";
            break;
          }
        }

        // Text fallback for privileged ETH transfer if AST calls list was incomplete
        if (!hasPrivilegedTransfer) {
          if (
            (snippetLow.includes("treasury.transfer") ||
              snippetLow.includes("treasury.send") ||
              snippetLow.includes("treasury.call")) &&
            !snippetLow.includes("msg.sender")
          ) {
            hasPrivilegedTransfer = true;
            privilegedTransferTarget = "treasury";
          }
        }

        const privilegedOps: string[] = [];
        if (hasSelfDestruct) privilegedOps.push("selfdestruct");
        if (hasDelegateCall) privilegedOps.push("delegatecall");
        if (changesOwnerAdmin) privilegedOps.push("owner/admin transfer");
        if (hasPrivilegedTransfer)
          privilegedOps.push(`unprotected ETH transfer to stored address (${privilegedTransferTarget})`);

        if (privilegedOps.length === 0) continue; // Not a privileged function

        findings.push({
          id: `SEC-ACCESS-${contract.name}-${fn.name}`,
          vulnerabilityType: "Access Control",
          title: `Missing Access Control on Privileged Operation: ${contract.name}.${fn.name}()`,
          severity: "critical",
          confidence: "high",
          classification: "CONFIRMED",
          contractName: contract.name,
          functionName: fn.name,
          location: fn.location,
          evidence: [
            `Function '${fn.name}' is ${fn.visibility} with no access control modifiers.`,
            `Performs privileged operation(s): ${privilegedOps.join(", ")}.`,
            "No inline msg.sender authorization check (require/if) found.",
          ],
          reason: `The function '${fn.name}' performs sensitive privileged operations (${privilegedOps.join(", ")}) but has no access control. Any address can call this function.`,
          recommendation: `Add an onlyOwner modifier or require(msg.sender == owner, "Unauthorized") check to restrict access to this function.`,
          codeSnippet: fn.codeSnippet,
        });
      }
    }

    return findings;
  }
}

// ─── Front-Running Detector ───────────────────────────────────────────────────
//
// Precision-first: no findings unless concrete transaction-order dependency can
// be established from AST evidence. Semantic category (Auction, etc.) alone is
// NOT sufficient. An empty detector is better than false positives.

export class FrontRunningDetector implements VulnerabilityDetector {
  public category = "Front-running/Transaction Ordering" as const;
  public name = "Front-running Detector";
  public description =
    "Detects transaction-order-dependent vulnerabilities. Requires concrete AST evidence.";

  public detect(_ctx: DetectionContext): SecurityFinding[] {
    // No generic heuristics. Return empty — prefer precision over recall here.
    // A concrete pattern-based sub-detector can be added here in the future.
    return [];
  }
}

// ─── Detector Registry & Main Security Analysis Engine ───────────────────────

export class SecurityDetectorRegistry {
  private detectors: VulnerabilityDetector[] = [];

  constructor() {
    this.registerDetector(new ReentrancyDetector());
    this.registerDetector(new UncheckedCallDetector());
    this.registerDetector(new DosDetector());
    this.registerDetector(new TimestampDependencyDetector());
    this.registerDetector(new BlockNumberDetector());
    this.registerDetector(new EtherStrictEqualityDetector());
    this.registerDetector(new IntegerOverflowDetector());
    this.registerDetector(new AccessControlDetector());
    this.registerDetector(new FrontRunningDetector());
  }

  public registerDetector(detector: VulnerabilityDetector): void {
    this.detectors = this.detectors.filter((d) => d.category !== detector.category);
    this.detectors.push(detector);
  }

  public getDetectors(): VulnerabilityDetector[] {
    return [...this.detectors];
  }

  public analyze(ctx: DetectionContext): SecurityAnalysisResult {
    const allFindings: SecurityFinding[] = [];

    const selectedCategories = ctx.plan
      ? new Set(ctx.plan.selectedChecks.map((c) => c.category))
      : null;

    for (const detector of this.detectors) {
      if (selectedCategories && !selectedCategories.has(detector.category)) {
        continue;
      }
      const detectorFindings = detector.detect(ctx);
      allFindings.push(...detectorFindings);
    }

    // Deduplicate: merge findings with the same (contractName, functionName, vulnerabilityType)
    // keeping the highest-confidence one and merging evidence arrays
    const deduped = this.deduplicateFindings(allFindings);

    // Correlate with Slither findings if provided (Requirement 1-7)
    const finalFindings = ctx.slitherFindings
      ? correlateSlitherWithAST(deduped, ctx.slitherFindings, ctx.ast)
      : deduped;

    const summary: DetectionSummary = {
      totalFindings: finalFindings.length,
      confirmedCount: finalFindings.filter((f) => f.classification === "CONFIRMED").length,
      potentialCount: finalFindings.filter((f) => f.classification === "POTENTIAL").length,
      notVulnerableCount: finalFindings.filter((f) => f.classification === "NOT_VULNERABLE").length,
      criticalCount: finalFindings.filter((f) => f.severity === "critical").length,
      highCount: finalFindings.filter((f) => f.severity === "high").length,
      mediumCount: finalFindings.filter((f) => f.severity === "medium").length,
      lowCount: finalFindings.filter((f) => f.severity === "low").length,
      infoCount: finalFindings.filter((f) => f.severity === "informational").length,
    };

    return { findings: finalFindings, summary, analyzedAt: Date.now() };
  }

  private deduplicateFindings(findings: SecurityFinding[]): SecurityFinding[] {
    const seen = new Map<string, SecurityFinding>();
    const classOrder: Record<VulnerabilityClassification, number> = {
      CONFIRMED: 0,
      POTENTIAL: 1,
      NOT_VULNERABLE: 2,
    };

    for (const f of findings) {
      const key = `${f.contractName}|${f.functionName}|${f.vulnerabilityType}`;
      const existing = seen.get(key);
      if (!existing) {
        seen.set(key, f);
      } else {
        // Keep the higher-priority classification; merge evidence
        const existingOrder = classOrder[existing.classification];
        const newOrder = classOrder[f.classification];
        if (newOrder < existingOrder) {
          // New finding has higher priority — merge evidence into it
          seen.set(key, {
            ...f,
            evidence: [...new Set([...f.evidence, ...existing.evidence])],
          });
        } else {
          // Existing has higher priority — just merge evidence
          seen.set(key, {
            ...existing,
            evidence: [...new Set([...existing.evidence, ...f.evidence])],
          });
        }
      }
    }

    return Array.from(seen.values());
  }
}

// Global default registry instance
const defaultRegistry = new SecurityDetectorRegistry();

/**
 * Main entry point: run all registered detectors against an AST analysis result.
 * Optionally accepts a VulnerabilityPlan (from Stage 6) to scope which detectors run.
 * Pass `solidityVersion` (pragma lower-bound, e.g. "0.4.19") to enable
 * version-aware detection (e.g. overflow analysis for pre-0.8).
 * Optionally accepts `slitherFindings` (raw JSON or array) to correlate with AST evidence.
 */
export function detectSecurityVulnerabilities(
  ast: ASTAnalysisResult,
  plan?: DetectionContext["plan"],
  semantic?: DetectionContext["semantic"],
  solidityVersion?: string,
  slitherFindings?: unknown
): SecurityAnalysisResult {
  return defaultRegistry.analyze({ ast, plan, semantic, solidityVersion, slitherFindings });
}
