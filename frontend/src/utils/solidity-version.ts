// ─── Solidity Version Detection & Compiler Selection ──────────────────────────
//
// This module is intentionally self-contained so Stage 3 (compilation) can
// import just what it needs without touching detection logic.

// ─── Types ────────────────────────────────────────────────────────────────────

export type VersionConstraintKind = "exact" | "range" | "caret" | "tilde" | "unknown";

export interface ParsedPragma {
  /** Raw constraint string as it appears in the source, e.g. "^0.8.20" */
  raw: string;
  /** Human-friendly classification */
  kind: VersionConstraintKind;
  /** Lower bound (inclusive), e.g. "0.8.20" */
  lowerBound: string;
  /** Upper bound (exclusive), e.g. "0.9.0" — undefined for exact versions */
  upperBound?: string;
}

export interface CompilerSelection {
  /** The solc version string that will be used, e.g. "0.8.20" */
  version: string;
  /** Why this version was selected */
  reason: string;
  /** Whether the chosen version satisfies the pragma constraint */
  compatible: boolean;
}

export interface PragmaAnalysis {
  /** Whether a valid pragma solidity statement was found */
  found: boolean;
  /** Present when `found` is true */
  pragma?: ParsedPragma;
  /** Present when `found` is true and a compatible compiler was located */
  compiler?: CompilerSelection;
  /** Human-readable error when `found` is false or compiler is unavailable */
  error?: string;
}

// ─── Known compiler versions ──────────────────────────────────────────────────
// Ordered newest → oldest so we always prefer the latest stable release that
// satisfies the constraint.  Extend this list as new solc versions are released.

export const KNOWN_COMPILER_VERSIONS: readonly string[] = [
  "0.8.28",
  "0.8.27",
  "0.8.26",
  "0.8.25",
  "0.8.24",
  "0.8.23",
  "0.8.22",
  "0.8.21",
  "0.8.20",
  "0.8.19",
  "0.8.18",
  "0.8.17",
  "0.8.16",
  "0.8.15",
  "0.8.14",
  "0.8.13",
  "0.8.12",
  "0.8.11",
  "0.8.10",
  "0.8.9",
  "0.8.7",
  "0.8.6",
  "0.8.4",
  "0.8.2",
  "0.8.1",
  "0.8.0",
  "0.7.6",
  "0.7.5",
  "0.7.4",
  "0.7.3",
  "0.7.2",
  "0.7.1",
  "0.7.0",
  "0.6.12",
  "0.6.11",
  "0.6.10",
  "0.6.9",
  "0.6.8",
  "0.6.7",
  "0.6.6",
  "0.6.5",
  "0.6.4",
  "0.6.3",
  "0.6.2",
  "0.6.1",
  "0.6.0",
  "0.5.17",
  "0.5.16",
  "0.5.15",
  "0.5.14",
  "0.5.13",
  "0.5.12",
  "0.5.11",
  "0.5.10",
  "0.5.9",
  "0.5.8",
  "0.5.7",
  "0.5.6",
  "0.5.5",
  "0.5.4",
  "0.5.3",
  "0.5.2",
  "0.5.1",
  "0.5.0",
  "0.4.26",
  "0.4.25",
  "0.4.24",
  "0.4.23",
  "0.4.22",
  "0.4.21",
  "0.4.20",
  "0.4.19",
  "0.4.18",
  "0.4.17",
  "0.4.16",
] as const;

// ─── Semver helpers ────────────────────────────────────────────────────────────

/** Parse a semver string into a comparable numeric triple. */
function parseSemver(v: string): [number, number, number] | null {
  const m = v.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

/** Compare two semver strings. Returns negative / 0 / positive. */
function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return 0;
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i];
  }
  return 0;
}

/** true if `v` is >= `lower` */
function semverGte(v: string, lower: string): boolean {
  return compareSemver(v, lower) >= 0;
}

/** true if `v` is < `upper` */
function semverLt(v: string, upper: string): boolean {
  return compareSemver(v, upper) < 0;
}

/** true if `v` is <= `upper` */
function semverLte(v: string, upper: string): boolean {
  return compareSemver(v, upper) <= 0;
}

/** true if `v` is > `lower` */
function semverGt(v: string, lower: string): boolean {
  return compareSemver(v, lower) > 0;
}

/**
 * Increment the MINOR component and zero out PATCH.
 * e.g.  "0.8.20" → "0.9.0"
 */
function nextMinor(v: string): string | null {
  const p = parseSemver(v);
  if (!p) return null;
  return `${p[0]}.${p[1] + 1}.0`;
}

/**
 * Increment the PATCH component.
 * e.g.  "0.8.20" → "0.8.21"
 */
function nextPatch(v: string): string | null {
  const p = parseSemver(v);
  if (!p) return null;
  return `${p[0]}.${p[1]}.${p[2] + 1}`;
}

// ─── Pragma parsing ────────────────────────────────────────────────────────────

/**
 * Extract and parse the first `pragma solidity` statement from Solidity source.
 * Handles:
 *   pragma solidity ^0.8.20;
 *   pragma solidity >=0.7.0 <0.9.0;
 *   pragma solidity 0.4.24;
 *   pragma solidity ~0.8.0;
 *   pragma solidity >=0.8.0 <=0.8.20;
 */
export function parsePragma(source: string): ParsedPragma | null {
  // Match the pragma statement, ignoring line comments before it
  const pragmaRe =
    /pragma\s+solidity\s+([^;]+);/;
  const match = source.match(pragmaRe);
  if (!match) return null;

  const raw = match[1].trim();

  // ── Exact version  e.g.  0.8.20 ─────────────────────────────────────────
  if (/^\d+\.\d+\.\d+$/.test(raw)) {
    return { raw, kind: "exact", lowerBound: raw, upperBound: undefined };
  }

  // ── Caret  e.g.  ^0.8.20  →  >=0.8.20 <0.9.0 ───────────────────────────
  const caretMatch = raw.match(/^\^(\d+\.\d+\.\d+)$/);
  if (caretMatch) {
    const ver = caretMatch[1];
    const upper = nextMinor(ver);
    return {
      raw,
      kind: "caret",
      lowerBound: ver,
      upperBound: upper ?? undefined,
    };
  }

  // ── Tilde  e.g.  ~0.8.0  →  >=0.8.0 <0.9.0 ─────────────────────────────
  const tildeMatch = raw.match(/^~(\d+\.\d+\.\d+)$/);
  if (tildeMatch) {
    const ver = tildeMatch[1];
    const upper = nextMinor(ver);
    return {
      raw,
      kind: "tilde",
      lowerBound: ver,
      upperBound: upper ?? undefined,
    };
  }

  // ── Range  e.g.  >=0.7.0 <0.9.0  or  >=0.8.0 <=0.8.20 ─────────────────
  // Lower part
  const lowerMatch = raw.match(/>=\s*(\d+\.\d+\.\d+)/);
  // Strict lower (>)
  const strictLowerMatch = raw.match(/(?<![=])>\s*(\d+\.\d+\.\d+)/);

  // Upper part
  const strictUpperMatch = raw.match(/<\s*(\d+\.\d+\.\d+)/);
  const inclusiveUpperMatch = raw.match(/<=\s*(\d+\.\d+\.\d+)/);

  if (lowerMatch || strictLowerMatch) {
    const lowerVer = lowerMatch ? lowerMatch[1] : strictLowerMatch![1];

    let upperVer: string | undefined;
    if (strictUpperMatch) {
      upperVer = strictUpperMatch[1]; // exclusive
    } else if (inclusiveUpperMatch) {
      // Convert <= X to < (X+patch)
      const np = nextPatch(inclusiveUpperMatch[1]);
      upperVer = np ?? inclusiveUpperMatch[1];
    }

    return {
      raw,
      kind: "range",
      lowerBound: lowerVer,
      upperBound: upperVer,
    };
  }

  // ── Could not parse ───────────────────────────────────────────────────────
  return { raw, kind: "unknown", lowerBound: "", upperBound: undefined };
}

// ─── Compiler satisfaction check ──────────────────────────────────────────────

/**
 * Returns true if `compilerVersion` satisfies the given `pragma`.
 */
export function satisfiesPragma(
  compilerVersion: string,
  pragma: ParsedPragma
): boolean {
  switch (pragma.kind) {
    case "exact":
      return compilerVersion === pragma.lowerBound;

    case "caret":
    case "tilde": {
      const ok = semverGte(compilerVersion, pragma.lowerBound);
      if (!pragma.upperBound) return ok;
      return ok && semverLt(compilerVersion, pragma.upperBound);
    }

    case "range": {
      // Determine whether the lower bound operator is >= or >
      const isStrictLower = pragma.raw.match(/(?<![=])>\s*\d/) !== null &&
        !pragma.raw.match(/>=\s*\d/);
      const lowerOk = isStrictLower
        ? semverGt(compilerVersion, pragma.lowerBound)
        : semverGte(compilerVersion, pragma.lowerBound);

      if (!pragma.upperBound) return lowerOk;

      // Determine whether the upper bound is exclusive (<) or inclusive (<=)
      const isInclusiveUpper = pragma.raw.includes("<=");
      const upperOk = isInclusiveUpper
        ? semverLte(compilerVersion, pragma.upperBound)
        : semverLt(compilerVersion, pragma.upperBound);

      return lowerOk && upperOk;
    }

    case "unknown":
      return false;
  }
}

// ─── Compiler selection ────────────────────────────────────────────────────────

/**
 * Given a parsed pragma, choose the best compiler version from the known list.
 * Strategy: pick the newest version that satisfies the constraint.
 */
export function selectCompiler(pragma: ParsedPragma): CompilerSelection | null {
  // KNOWN_COMPILER_VERSIONS is already sorted newest → oldest
  for (const version of KNOWN_COMPILER_VERSIONS) {
    if (satisfiesPragma(version, pragma)) {
      const reason =
        pragma.kind === "exact"
          ? `Exact version match`
          : `Latest stable release satisfying ${pragma.raw}`;
      return { version, reason, compatible: true };
    }
  }
  return null;
}

// ─── Top-level analyser ────────────────────────────────────────────────────────

/**
 * Full pipeline: source → pragma detection → compiler selection.
 * This is the single entry point Stage 2 calls.
 */
export function analysePragma(source: string): PragmaAnalysis {
  const pragma = parsePragma(source);

  if (!pragma) {
    return {
      found: false,
      error:
        "No pragma solidity statement found. Add a pragma (e.g. pragma solidity ^0.8.20;) before compiling.",
    };
  }

  if (pragma.kind === "unknown") {
    return {
      found: true,
      pragma,
      error: `Pragma constraint "${pragma.raw}" could not be parsed. Check the version syntax.`,
    };
  }

  const compiler = selectCompiler(pragma);

  if (!compiler) {
    return {
      found: true,
      pragma,
      error: `No known compiler version satisfies "${pragma.raw}". The constraint may be too restrictive or use a very old version not in the bundled list.`,
    };
  }

  return { found: true, pragma, compiler };
}

// ─── Formatting helpers (pure, no React) ──────────────────────────────────────

export function formatPragmaKind(kind: VersionConstraintKind): string {
  switch (kind) {
    case "exact":  return "Exact version";
    case "caret":  return "Caret range (^)";
    case "tilde":  return "Tilde range (~)";
    case "range":  return "Version range";
    case "unknown": return "Unknown constraint";
  }
}
