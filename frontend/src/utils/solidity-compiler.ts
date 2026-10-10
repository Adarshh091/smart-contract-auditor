// ─── Solidity Compilation Engine (Stage 3) ────────────────────────────────────
//
// Runs actual Solidity compilation via web-solc (solc-js in a Web Worker).
// Exposes a single async function `compileContract` that Stage 3 calls.
// All outputs are typed and consumed by later stages (AST, ABI, bytecode).

import { fetchAndLoadSolc } from "web-solc";

// ─── Standard JSON I/O types ──────────────────────────────────────────────────

export interface SolcInput {
  language: "Solidity";
  sources: Record<string, { content: string }>;
  settings: {
    outputSelection: Record<string, Record<string, string[]>>;
    optimizer?: { enabled: boolean; runs: number };
    evmVersion?: string;
  };
}

export interface SolcError {
  /** "error" | "warning" | "info" */
  severity: string;
  /** Short error code, e.g. "7576" */
  errorCode?: string;
  /** e.g. "DeclarationError" */
  type: string;
  /** Human-readable message */
  message: string;
  /** Formatted with source location */
  formattedMessage?: string;
  sourceLocation?: {
    file: string;
    start: number;
    end: number;
  };
}

export interface SolcContractOutput {
  abi: unknown[];
  /** Hex-encoded bytecode */
  evm: {
    bytecode: {
      object: string;
      opcodes?: string;
      sourceMap?: string;
    };
    deployedBytecode?: {
      object: string;
    };
  };
  /** Solidity IR / metadata */
  metadata?: string;
}

export interface SolcOutput {
  errors?: SolcError[];
  sources?: Record<string, { ast?: unknown; id?: number }>;
  contracts?: Record<string, Record<string, SolcContractOutput>>;
}

// ─── Compilation result (Stage 3 output, consumed by Stage 4+) ────────────────

export interface CompiledContract {
  /** Contract name, e.g. "Token" */
  name: string;
  /** Source file the contract was defined in */
  sourceFile: string;
  /** ABI as a parsed array */
  abi: unknown[];
  /** Hex-encoded deploy bytecode (0x-prefixed) */
  bytecode: string;
  /** Hex-encoded runtime bytecode (0x-prefixed) */
  deployedBytecode: string;
}

export type CompilationStatus = "success" | "failed" | "partial";

export interface CompilationResult {
  /** Which solc version actually compiled this */
  compilerVersion: string;
  /** Overall outcome */
  status: CompilationStatus;
  /** Errors only (severity === "error") */
  errors: SolcError[];
  /** Warnings (severity === "warning") */
  warnings: SolcError[];
  /** Other info messages */
  infos: SolcError[];
  /** One entry per compiled contract */
  contracts: CompiledContract[];
  /** AST data per source file, keyed by filename */
  ast: Record<string, unknown>;
  /** Wall-clock time in milliseconds */
  durationMs: number;
}

// ─── Build the Standard JSON input ───────────────────────────────────────────

function buildInput(fileName: string, source: string): SolcInput {
  return {
    language: "Solidity",
    sources: {
      [fileName]: { content: source },
    },
    settings: {
      outputSelection: {
        "*": {
          "*": ["abi", "evm.bytecode", "evm.deployedBytecode", "metadata"],
          "": ["ast"],
        },
      },
      optimizer: { enabled: false, runs: 200 },
    },
  };
}

// ─── Parse raw solc output ────────────────────────────────────────────────────

function parseOutput(
  raw: SolcOutput,
  compilerVersion: string,
  durationMs: number
): CompilationResult {
  const allErrors = (raw.errors ?? []) as SolcError[];

  const errors   = allErrors.filter((e) => e.severity === "error");
  const warnings = allErrors.filter((e) => e.severity === "warning");
  const infos    = allErrors.filter((e) => e.severity !== "error" && e.severity !== "warning");

  // Extract contracts
  const contracts: CompiledContract[] = [];
  if (raw.contracts) {
    for (const [filePath, fileContracts] of Object.entries(raw.contracts)) {
      for (const [name, output] of Object.entries(fileContracts)) {
        const bytecodeRaw = output.evm?.bytecode?.object ?? "";
        const deployedRaw = output.evm?.deployedBytecode?.object ?? "";
        contracts.push({
          name,
          sourceFile: filePath,
          abi: Array.isArray(output.abi) ? output.abi : [],
          bytecode: bytecodeRaw ? `0x${bytecodeRaw}` : "",
          deployedBytecode: deployedRaw ? `0x${deployedRaw}` : "",
        });
      }
    }
  }

  // Extract AST
  const ast: Record<string, unknown> = {};
  if (raw.sources) {
    for (const [filePath, srcData] of Object.entries(raw.sources)) {
      if (srcData?.ast) ast[filePath] = srcData.ast;
    }
  }

  const hasContracts = contracts.length > 0;
  const status: CompilationStatus =
    errors.length === 0 && hasContracts
      ? "success"
      : errors.length > 0 && hasContracts
      ? "partial"
      : "failed";

  return { compilerVersion, status, errors, warnings, infos, contracts, ast, durationMs };
}

// ─── Main compilation function ────────────────────────────────────────────────

/**
 * Compile `source` using the exact `compilerVersion` selected by Stage 2.
 *
 * @param fileName    The .sol filename (used as key in the Standard JSON input)
 * @param source      Raw Solidity source text
 * @param compilerVersion  Exact version string, e.g. "0.8.20"
 */
export async function compileContract(
  fileName: string,
  source: string,
  compilerVersion: string
): Promise<CompilationResult> {
  const t0 = performance.now();

  let solc: Awaited<ReturnType<typeof fetchAndLoadSolc>> | null = null;

  try {
    // Load the exact compiler version (fetched from binaries.soliditylang.org)
    solc = await fetchAndLoadSolc(compilerVersion);

    const input = buildInput(fileName, source);
    const raw = (await solc.compile(input)) as unknown as SolcOutput;

    const durationMs = Math.round(performance.now() - t0);
    return parseOutput(raw, compilerVersion, durationMs);
  } finally {
    // Always terminate the Web Worker to free memory
    solc?.stopWorker();
  }
}

// ─── Formatting helpers (pure, no React) ──────────────────────────────────────

/**
 * Extract a user-friendly line/column prefix from a formatted message.
 * e.g. "contract.sol:12:5: DeclarationError: …" → "Line 12, Col 5"
 */
export function extractLocation(error: SolcError): string | null {
  if (!error.formattedMessage) return null;
  const m = error.formattedMessage.match(/:(\d+):(\d+):/);
  if (!m) return null;
  return `Line ${m[1]}, Col ${m[2]}`;
}

/** Human-friendly short description of the error type. */
export function formatErrorType(error: SolcError): string {
  return error.type ?? error.severity ?? "Error";
}
