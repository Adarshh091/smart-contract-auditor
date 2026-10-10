import type { ASTAnalysisResult, SourceLocation } from "../types/ast";
import type { SecurityFinding, FindingSeverity, FindingConfidence } from "../types/security";
import type { VulnerabilityCategory } from "../types/vulnerability";
import type { SlitherFinding, RawSlitherFinding, RawSlitherOutput } from "../types/slither";

/**
 * Maps Slither detector/check names to our canonical VulnerabilityCategory.
 */
export function mapSlitherCheckToCategory(check: string): VulnerabilityCategory {
  const c = check.toLowerCase();

  if (c.includes("reentrancy")) {
    return "Reentrancy";
  }
  if (
    c.includes("arbitrary-send") ||
    c.includes("suicidal") ||
    c.includes("unprotected") ||
    c.includes("tx-origin") ||
    c.includes("access-control") ||
    c.includes("owner")
  ) {
    return "Access Control";
  }
  if (c.includes("unchecked") || c.includes("unused-return")) {
    return "Unchecked External Call";
  }
  if (c.includes("delegatecall")) {
    return "Dangerous Delegatecall";
  }
  if (c.includes("overflow") || c.includes("underflow") || c.includes("divide-before-multiply")) {
    return "Integer Overflow/Underflow";
  }
  if (c.includes("timestamp") || c.includes("time")) {
    return "Timestamp Dependency";
  }
  if (c.includes("block-number") || c.includes("number")) {
    return "Block Number Dependency";
  }
  if (c.includes("strict") || c.includes("equality")) {
    return "Ether Strict Equality";
  }
  if (c.includes("dos") || c.includes("calls-loop")) {
    return "Denial of Service";
  }

  return "Unchecked External Call"; // Default fallback category for unmapped Slither checks
}

/**
 * Maps Slither impact/severity strings to standard FindingSeverity.
 */
export function mapSlitherImpactToSeverity(impact?: string): FindingSeverity {
  if (!impact) return "medium";
  const i = impact.toLowerCase();
  if (i.includes("high") || i.includes("critical")) return "high";
  if (i.includes("medium")) return "medium";
  if (i.includes("low")) return "low";
  if (i.includes("info") || i.includes("optimization")) return "informational";
  return "medium";
}

/**
 * Maps Slither confidence strings to standard FindingConfidence.
 */
export function mapSlitherConfidence(confidence?: string): FindingConfidence {
  if (!confidence) return "medium";
  const c = confidence.toLowerCase();
  if (c.includes("high")) return "high";
  if (c.includes("medium")) return "medium";
  if (c.includes("low")) return "low";
  return "medium";
}

/**
 * Parses raw or structured Slither input into normalized SlitherFinding objects.
 */
export function parseSlitherFindings(input: unknown): SlitherFinding[] {
  if (!input) return [];

  const rawList: (RawSlitherFinding | SlitherFinding | Record<string, unknown>)[] = [];

  if (Array.isArray(input)) {
    rawList.push(...input);
  } else if (typeof input === "object" && input !== null) {
    const obj = input as RawSlitherOutput;
    if (obj.success === false && !obj.results?.detectors) {
      return [];
    }
    if (obj.results?.detectors && Array.isArray(obj.results.detectors)) {
      rawList.push(...obj.results.detectors);
    }
  }

  const normalized: SlitherFinding[] = [];

  for (const item of rawList) {
    if (!item || typeof item !== "object") continue;

    // Check if it's already a normalized SlitherFinding
    if ("check" in item && "contractName" in item && "functionName" in item) {
      const sf = item as SlitherFinding;
      normalized.push({
        id: sf.id || `slither-${sf.check}-${sf.contractName}-${sf.functionName}`,
        check: sf.check || "unknown-check",
        vulnerabilityType: sf.vulnerabilityType || mapSlitherCheckToCategory(sf.check || ""),
        contractName: sf.contractName,
        functionName: sf.functionName,
        description: sf.description || `Slither signal: ${sf.check}`,
        severity: sf.severity || "medium",
        confidence: sf.confidence || "medium",
        location: sf.location,
        lines: sf.lines,
        raw: sf,
      });
      continue;
    }

    // Process raw Slither detector element format
    const rawF = item as RawSlitherFinding;
    if (!rawF.check) continue;

    let contractName = "";
    let functionName = "";
    const linesSet = new Set<number>();
    let loc: SourceLocation | undefined = undefined;

    if (Array.isArray(rawF.elements)) {
      for (const elem of rawF.elements) {
        if (elem.type === "contract" && elem.name) {
          contractName = elem.name;
        } else if (elem.type === "function" && elem.name) {
          functionName = elem.name;
          if (elem.type_specific_fields?.parent?.name) {
            contractName = elem.type_specific_fields.parent.name;
          }
        } else if (elem.type === "node" && elem.type_specific_fields?.parent?.name) {
          if (!functionName) functionName = elem.type_specific_fields.parent.name;
        }

        if (elem.source_mapping?.lines && Array.isArray(elem.source_mapping.lines)) {
          elem.source_mapping.lines.forEach((l) => linesSet.add(l));
        }
      }
    }

    const lines = Array.from(linesSet).sort((a, b) => a - b);
    if (lines.length > 0) {
      loc = {
        file: "",
        line: lines[0],
        column: 1,
        endLine: lines[lines.length - 1],
        start: 0,
        length: 0,
        end: 0,
      };
    }

    const category = mapSlitherCheckToCategory(rawF.check);

    normalized.push({
      id: `slither-${rawF.check}-${contractName || "global"}-${functionName || "global"}`,
      check: rawF.check,
      vulnerabilityType: category,
      contractName: contractName || "UnknownContract",
      functionName: functionName || "UnknownFunction",
      description: rawF.description || rawF.first_markdown_element || `Slither found ${rawF.check}`,
      severity: mapSlitherImpactToSeverity(rawF.impact),
      confidence: mapSlitherConfidence(rawF.confidence),
      location: loc,
      lines,
      raw: rawF,
    });
  }

  return normalized;
}

/**
 * Checks if a Slither finding matches an AST finding using strong identifier rules:
 * 1. Contract name matching
 * 2. Vulnerability category / operation matching
 * 3. Function name matching or source line overlap or AST evidence match
 */
export function isSlitherASTMatch(
  astFinding: SecurityFinding,
  slitherFinding: SlitherFinding,
  ast?: ASTAnalysisResult
): boolean {
  // 1. Contract name matching (case-insensitive)
  if (
    astFinding.contractName &&
    slitherFinding.contractName &&
    astFinding.contractName.toLowerCase() !== slitherFinding.contractName.toLowerCase()
  ) {
    return false;
  }

  // 2. Vulnerability type / operation matching
  if (astFinding.vulnerabilityType !== slitherFinding.vulnerabilityType) {
    return false;
  }

  // 3. Function name matching
  const astFunc = astFinding.functionName ? astFinding.functionName.toLowerCase() : "";
  const slitherFunc = slitherFinding.functionName ? slitherFinding.functionName.toLowerCase() : "";

  if (astFunc && slitherFunc && astFunc === slitherFunc) {
    return true;
  }

  // 4. Source location / line range matching
  if (astFinding.location && (slitherFinding.location || (slitherFinding.lines && slitherFinding.lines.length > 0))) {
    const astStart = astFinding.location.line;
    const astEnd = astFinding.location.endLine || astFinding.location.line;

    const slitherLines = slitherFinding.lines || [];
    if (slitherFinding.location) {
      slitherLines.push(slitherFinding.location.line);
      if (slitherFinding.location.endLine) slitherLines.push(slitherFinding.location.endLine);
    }

    const hasLineOverlap = slitherLines.some((line) => line >= astStart - 2 && line <= astEnd + 2);
    if (hasLineOverlap) {
      return true;
    }
  }

  // 5. AST external-call/state-change evidence correlation
  if (ast && astFinding.contractName && astFinding.functionName) {
    const targetFunc = ast.functions.find(
      (f) =>
        f.contractName.toLowerCase() === astFinding.contractName.toLowerCase() &&
        f.name.toLowerCase() === astFinding.functionName.toLowerCase()
    );
    if (targetFunc) {
      if (slitherFunc && targetFunc.name.toLowerCase() === slitherFunc) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Boosts confidence deterministically when supported by both AST and Slither.
 * When both independent analyses support the issue, confidence is elevated to high.
 */
function boostConfidence(_current: FindingConfidence): FindingConfidence {
  return "high";
}

/**
 * Correlates Slither findings with AST evidence.
 *
 * Rules enforced:
 * - Matching Slither + AST finding => ONE finding, merged evidence, boosted confidence, marked correlation.
 * - AST-only finding => PRESERVED completely, not downgraded.
 * - Slither-only finding => NOT automatically CONFIRMED; kept as separate POTENTIAL candidate.
 * - Slither failure => Graceful fallback to AST findings without throwing.
 * - Duplicate suppression => Ensures no duplicate cards for same contract/function/vulnerabilityType.
 */
export function correlateSlitherWithAST(
  astFindings: SecurityFinding[],
  slitherInput: unknown,
  ast?: ASTAnalysisResult
): SecurityFinding[] {
  try {
    const slitherFindings = parseSlitherFindings(slitherInput);

    if (slitherFindings.length === 0) {
      return astFindings;
    }

    const resultFindings: SecurityFinding[] = astFindings.map((f) => ({
      ...f,
      evidence: [...f.evidence],
    }));

    const matchedSlitherIndices = new Set<number>();

    // Step 1: Match Slither findings with AST findings
    for (const astFinding of resultFindings) {
      for (let i = 0; i < slitherFindings.length; i++) {
        const slitherFinding = slitherFindings[i];
        if (isSlitherASTMatch(astFinding, slitherFinding, ast)) {
          matchedSlitherIndices.add(i);

          // Merge evidence
          const correlationTag = "Correlation: Supported by both Slither and AST static analysis";
          const slitherDesc = slitherFinding.description
            ? `Slither detector '${slitherFinding.check}': ${slitherFinding.description}`
            : `Slither detector '${slitherFinding.check}' confirmed match`;

          if (!astFinding.evidence.includes(correlationTag)) {
            astFinding.evidence.push(correlationTag);
          }
          if (!astFinding.evidence.includes(slitherDesc)) {
            astFinding.evidence.push(slitherDesc);
          }

          // Deterministic confidence elevation
          astFinding.confidence = boostConfidence(astFinding.confidence);

          // Slither does NOT alter AST classification authority (keeps CONFIRMED / POTENTIAL as derived by AST)
        }
      }
    }

    // Step 2: Process unmatched Slither findings (Requirement 4 & 5)
    for (let i = 0; i < slitherFindings.length; i++) {
      if (matchedSlitherIndices.has(i)) continue;

      const sf = slitherFindings[i];

      // Check if an AST finding already exists for this contract+function+category
      const existingAstFinding = resultFindings.find(
        (f) =>
          f.contractName.toLowerCase() === sf.contractName.toLowerCase() &&
          f.functionName.toLowerCase() === sf.functionName.toLowerCase() &&
          f.vulnerabilityType === sf.vulnerabilityType
      );

      if (existingAstFinding) {
        // Suppress duplicate: merge into existing AST finding
        const correlationTag = "Correlation: Supported by both Slither and AST static analysis";
        const slitherDesc = `Slither detector '${sf.check}': ${sf.description}`;
        if (!existingAstFinding.evidence.includes(correlationTag)) {
          existingAstFinding.evidence.push(correlationTag);
        }
        if (!existingAstFinding.evidence.includes(slitherDesc)) {
          existingAstFinding.evidence.push(slitherDesc);
        }
        existingAstFinding.confidence = boostConfidence(existingAstFinding.confidence);
      } else {
        // Keep as separate/unverified Slither signal candidate (POTENTIAL only, never CONFIRMED)
        const candidateFinding: SecurityFinding = {
          id: sf.id || `slither-${sf.check}-${sf.contractName}-${sf.functionName}-${i}`,
          vulnerabilityType: sf.vulnerabilityType,
          title: `[Slither Signal] ${sf.check} in ${sf.contractName}.${sf.functionName}`,
          severity: sf.severity,
          confidence: sf.confidence === "high" ? "medium" : "low",
          classification: "POTENTIAL", // Slither alone NEVER produces CONFIRMED final findings
          contractName: sf.contractName,
          functionName: sf.functionName,
          location: sf.location,
          evidence: [
            sf.description,
            "Unverified Slither signal (requires AST deterministic security evidence to confirm)",
          ],
          reason: `Slither detector '${sf.check}' reported a potential issue in ${sf.contractName}.${sf.functionName}, but AST analysis did not find confirming deterministic evidence.`,
          recommendation: `Review function ${sf.contractName}.${sf.functionName} to verify if the Slither signal represents a true vulnerability.`,
        };
        resultFindings.push(candidateFinding);
      }
    }

    // Step 3: Final deduplication pass to guarantee NO duplicate cards
    return deduplicateCorrelatedFindings(resultFindings);
  } catch (_err) {
    // Slither failure (compiler mismatch, parsing failure, timeout, etc.) must NEVER break the auditor
    return astFindings;
  }
}

/**
 * Deduplicates findings by (contractName, functionName, vulnerabilityType).
 */
function deduplicateCorrelatedFindings(findings: SecurityFinding[]): SecurityFinding[] {
  const seen = new Map<string, SecurityFinding>();
  const classOrder = { CONFIRMED: 0, POTENTIAL: 1, NOT_VULNERABLE: 2 };

  for (const f of findings) {
    const key = `${f.contractName.toLowerCase()}|${f.functionName.toLowerCase()}|${f.vulnerabilityType}`;
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, f);
    } else {
      const existingOrder = classOrder[existing.classification] ?? 1;
      const newOrder = classOrder[f.classification] ?? 1;

      if (newOrder < existingOrder) {
        seen.set(key, {
          ...f,
          evidence: Array.from(new Set([...f.evidence, ...existing.evidence])),
        });
      } else {
        seen.set(key, {
          ...existing,
          evidence: Array.from(new Set([...existing.evidence, ...f.evidence])),
        });
      }
    }
  }

  return Array.from(seen.values());
}
