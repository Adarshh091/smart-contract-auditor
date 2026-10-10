import React, { useEffect, useState, useCallback } from "react";
import type { SolidityFile, CompilerInfo } from "../types/pipeline";
import {
  compileContract,
  extractLocation,
  formatErrorType,
  type CompilationResult,
  type SolcError,
} from "../utils/solidity-compiler";

// ─── Props ─────────────────────────────────────────────────────────────────────

interface StageCompileProps {
  file: SolidityFile;
  compilerInfo: CompilerInfo;
  /** Called when compilation succeeds — passes result to pipeline state */
  onSuccess: (result: CompilationResult) => void;
  /** Called when the user clicks Back */
  onBack: () => void;
}

// ─── Compilation phases ────────────────────────────────────────────────────────

type Phase =
  | { kind: "idle" }
  | { kind: "fetching" }        // Downloading the compiler binary
  | { kind: "compiling" }       // Running the compiler in the worker
  | { kind: "done"; result: CompilationResult }
  | { kind: "error"; message: string };

// ─── Component ─────────────────────────────────────────────────────────────────

export const StageCompile: React.FC<StageCompileProps> = ({
  file,
  compilerInfo,
  onSuccess,
  onBack,
}) => {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [activeTab, setActiveTab] = useState<"contracts" | "errors" | "warnings" | "abi" | "bytecode">("contracts");

  // ── Start compilation automatically on mount ────────────────────────────
  useEffect(() => {
    let cancelled = false;

    const run = async () => {
      try {
        setPhase({ kind: "fetching" });
        // Small delay so the "Fetching compiler" UI is visible
        await new Promise((r) => setTimeout(r, 120));

        if (cancelled) return;
        setPhase({ kind: "compiling" });

        const result = await compileContract(
          file.name,
          file.source,
          compilerInfo.selectedVersion
        );

        if (cancelled) return;
        setPhase({ kind: "done", result });
        if (result.errors.length > 0 && result.contracts.length === 0) {
          setActiveTab("errors");
        }
      } catch (err: unknown) {
        if (cancelled) return;
        const msg =
          err instanceof Error
            ? err.message
            : "An unexpected error occurred during compilation.";
        setPhase({ kind: "error", message: msg });
      }
    };

    run();
    return () => { cancelled = true; };
  }, [file, compilerInfo]);

  const result = phase.kind === "done" ? phase.result : null;

  const handleContinue = useCallback(() => {
    if (result && result.status === "success") {
      onSuccess(result);
    }
  }, [result, onSuccess]);

  const canContinue = result?.status === "success";

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: "24px",
        animation: "fade-in-up 0.35s ease forwards",
      }}
    >
      {/* ── Section header ─────────────────────────────────────────────────── */}
      <div style={{ width: "100%", maxWidth: "860px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
          <StageNumber>03</StageNumber>
          <h2
            style={{
              margin: 0,
              fontSize: "18px",
              fontWeight: 700,
              color: "#e2e8f0",
              letterSpacing: "-0.02em",
            }}
          >
            Compilation
          </h2>
        </div>
        <p style={{ margin: "0 0 0 42px", fontSize: "13px", color: "#4a5568" }}>
          Compiling{" "}
          <code style={inlineCode}>{file.name}</code>{" "}
          using{" "}
          <code style={inlineCode}>solc v{compilerInfo.selectedVersion}</code>.
          Results include ABI, bytecode, and AST for later stages.
        </p>
      </div>

      {/* ── Compiler info badge ─────────────────────────────────────────────── */}
      <CompilerBadge compilerInfo={compilerInfo} file={file} />

      {/* ── Phase display ───────────────────────────────────────────────────── */}
      {phase.kind === "fetching" && (
        <ProgressPanel
          icon="download"
          title={`Fetching solc v${compilerInfo.selectedVersion}`}
          detail="Downloading compiler from binaries.soliditylang.org…"
        />
      )}

      {phase.kind === "compiling" && (
        <ProgressPanel
          icon="compile"
          title="Compiling contract…"
          detail="Running Solidity compiler in a Web Worker."
        />
      )}

      {phase.kind === "error" && (
        <FatalErrorPanel message={phase.message} />
      )}

      {phase.kind === "done" && result && (
        <>
          {/* ── Status banner ─────────────────────────────────────────────── */}
          <StatusBanner result={result} />

          {/* ── Results tabs ──────────────────────────────────────────────── */}
          <div style={{ width: "100%", maxWidth: "860px" }}>
            {/* Tab bar */}
            <div
              style={{
                display: "flex",
                gap: "2px",
                borderBottom: "1px solid #1e2d4a",
                marginBottom: "0",
              }}
            >
              <Tab
                label={`Contracts (${result.contracts.length})`}
                active={activeTab === "contracts"}
                onClick={() => setActiveTab("contracts")}
              />
              {result.errors.length > 0 && (
                <Tab
                  label={`Errors (${result.errors.length})`}
                  active={activeTab === "errors"}
                  onClick={() => setActiveTab("errors")}
                  variant="error"
                />
              )}
              {result.warnings.length > 0 && (
                <Tab
                  label={`Warnings (${result.warnings.length})`}
                  active={activeTab === "warnings"}
                  onClick={() => setActiveTab("warnings")}
                  variant="warning"
                />
              )}
              {result.contracts.length > 0 && (
                <>
                  <Tab
                    label="ABI"
                    active={activeTab === "abi"}
                    onClick={() => setActiveTab("abi")}
                  />
                  <Tab
                    label="Bytecode"
                    active={activeTab === "bytecode"}
                    onClick={() => setActiveTab("bytecode")}
                  />
                </>
              )}
            </div>

            {/* Tab content */}
            <div
              style={{
                backgroundColor: "#0f1629",
                border: "1px solid #1e2d4a",
                borderTop: "none",
                borderRadius: "0 0 12px 12px",
                overflow: "hidden",
              }}
            >
              {activeTab === "contracts" && (
                <ContractsTab contracts={result.contracts} />
              )}
              {activeTab === "errors" && (
                <DiagnosticsTab items={result.errors} kind="error" />
              )}
              {activeTab === "warnings" && (
                <DiagnosticsTab items={result.warnings} kind="warning" />
              )}
              {activeTab === "abi" && result.contracts[0] && (
                <JsonTab
                  label="ABI"
                  data={result.contracts[0].abi}
                  hint={`Contract: ${result.contracts[0].name}`}
                />
              )}
              {activeTab === "bytecode" && result.contracts[0] && (
                <BytecodeTab contract={result.contracts[0]} />
              )}
            </div>
          </div>
        </>
      )}

      {/* ── Action row ──────────────────────────────────────────────────────── */}
      <div
        style={{
          width: "100%",
          maxWidth: "860px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          paddingBottom: "8px",
        }}
      >
        <BackButton onClick={onBack} />

        {phase.kind === "done" && (
          <button
            onClick={handleContinue}
            disabled={!canContinue}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "10px 24px",
              borderRadius: "8px",
              border: canContinue
                ? "1px solid rgba(0,255,136,0.4)"
                : "1px solid #1e2d4a",
              backgroundColor: canContinue
                ? "rgba(0,255,136,0.08)"
                : "rgba(255,255,255,0.03)",
              color: canContinue ? "#00ff88" : "#2a3f6a",
              fontSize: "14px",
              fontWeight: 600,
              cursor: canContinue ? "pointer" : "not-allowed",
              letterSpacing: "0.02em",
              transition: "all 0.2s ease",
              fontFamily: "inherit",
              opacity: canContinue ? 1 : 0.5,
            }}
            onMouseEnter={(e) => {
              if (!canContinue) return;
              const b = e.currentTarget as HTMLButtonElement;
              b.style.backgroundColor = "rgba(0,255,136,0.14)";
              b.style.borderColor = "#00ff88";
              b.style.boxShadow = "0 0 20px rgba(0,255,136,0.15)";
            }}
            onMouseLeave={(e) => {
              if (!canContinue) return;
              const b = e.currentTarget as HTMLButtonElement;
              b.style.backgroundColor = "rgba(0,255,136,0.08)";
              b.style.borderColor = "rgba(0,255,136,0.4)";
              b.style.boxShadow = "none";
            }}
          >
            Continue to AST Analysis
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path
                d="M2 7h10M8 3l4 4-4 4"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </button>
        )}
      </div>
    </div>
  );
};

// ─── Status banner ─────────────────────────────────────────────────────────────

const StatusBanner: React.FC<{ result: CompilationResult }> = ({ result }) => {
  const isSuccess = result.status === "success";
  const isPartial = result.status === "partial";

  const bg = isSuccess
    ? "rgba(0,255,136,0.07)"
    : isPartial
    ? "rgba(255,170,0,0.07)"
    : "rgba(255,68,68,0.07)";

  const border = isSuccess
    ? "rgba(0,255,136,0.22)"
    : isPartial
    ? "rgba(255,170,0,0.22)"
    : "rgba(255,68,68,0.22)";

  const color = isSuccess ? "#00ff88" : isPartial ? "#ffaa00" : "#ff6666";

  const icon = isSuccess ? (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <circle cx="10" cy="10" r="9" stroke="#00ff88" strokeWidth="1.5" />
      <path d="M5 10l4 4 6-6" stroke="#00ff88" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ) : (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <circle cx="10" cy="10" r="9" stroke={color} strokeWidth="1.5" />
      <path d="M10 5v6M10 13.5h.01" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );

  const title = isSuccess
    ? "SUCCESS"
    : isPartial
    ? "COMPILATION PARTIAL"
    : "COMPILATION FAILED";

  const detail = isSuccess
    ? `${result.contracts.length} contract${result.contracts.length !== 1 ? "s" : ""} compiled · ${result.durationMs} ms · ${result.warnings.length} warning${result.warnings.length !== 1 ? "s" : ""}`
    : `${result.errors.length} error${result.errors.length !== 1 ? "s" : ""} · ${result.warnings.length} warning${result.warnings.length !== 1 ? "s" : ""} · ${result.durationMs} ms`;

  return (
    <div
      style={{
        width: "100%",
        maxWidth: "860px",
        padding: "16px 20px",
        borderRadius: "12px",
        backgroundColor: bg,
        border: `1px solid ${border}`,
        display: "flex",
        alignItems: "center",
        gap: "14px",
      }}
    >
      {icon}
      <div>
        <div style={{ fontSize: "14px", fontWeight: 700, color, marginBottom: "3px" }}>
          {title}
        </div>
        <div style={{ fontSize: "12px", color: "#4a5568" }}>{detail}</div>
      </div>
      <div style={{ marginLeft: "auto" }}>
        <code
          style={{
            fontSize: "11px",
            color: "#4a5568",
            fontFamily: "monospace",
            backgroundColor: "#0a0e1a",
            padding: "3px 8px",
            borderRadius: "5px",
            border: "1px solid #1e2d4a",
          }}
        >
          solc v{result.compilerVersion}
        </code>
      </div>
    </div>
  );
};

// ─── Contracts tab ─────────────────────────────────────────────────────────────

type ContractItem = { name: string; sourceFile: string; abi: unknown[]; bytecode: string; deployedBytecode: string };

const ContractsTab: React.FC<{ contracts: ContractItem[] }> = ({ contracts }) => {
  if (contracts.length === 0) {
    return (
      <div
        style={{
          padding: "32px",
          textAlign: "center",
          color: "#4a5568",
          fontSize: "13px",
        }}
      >
        No contracts compiled successfully.
      </div>
    );
  }

  return (
    <div>
      {contracts.map((c, i) => {
        const byteLen = c.bytecode
          ? Math.floor((c.bytecode.length - 2) / 2)
          : 0;
        const abiLen = Array.isArray(c.abi) ? c.abi.length : 0;
        return (
          <div
            key={i}
            style={{
              padding: "16px 20px",
              borderBottom: i < contracts.length - 1 ? "1px solid #1e2d4a" : "none",
              display: "flex",
              alignItems: "center",
              gap: "16px",
            }}
          >
            {/* Contract icon */}
            <div
              style={{
                width: "38px",
                height: "38px",
                borderRadius: "8px",
                backgroundColor: "rgba(0,255,136,0.08)",
                border: "1px solid rgba(0,255,136,0.2)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
              }}
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <rect x="2" y="2" width="12" height="12" rx="2" stroke="#00ff88" strokeWidth="1.3" />
                <path d="M5 6h6M5 9h4" stroke="#00ff88" strokeWidth="1.3" strokeLinecap="round" />
              </svg>
            </div>

            <div style={{ flex: 1 }}>
              <div
                style={{
                  fontSize: "14px",
                  fontWeight: 700,
                  color: "#e2e8f0",
                  fontFamily: "monospace",
                  marginBottom: "4px",
                }}
              >
                {c.name}
              </div>
              <div style={{ display: "flex", gap: "16px", flexWrap: "wrap" }}>
                <MetaStat label="Source" value={c.sourceFile} />
                <MetaStat label="ABI entries" value={String(abiLen)} />
                <MetaStat label="Bytecode" value={byteLen > 0 ? `${byteLen} bytes` : "—"} />
              </div>
            </div>

            <div
              style={{
                fontSize: "10px",
                fontWeight: 700,
                color: "#00ff88",
                backgroundColor: "rgba(0,255,136,0.08)",
                border: "1px solid rgba(0,255,136,0.2)",
                borderRadius: "5px",
                padding: "3px 8px",
                letterSpacing: "0.08em",
                flexShrink: 0,
              }}
            >
              COMPILED
            </div>
          </div>
        );
      })}
    </div>
  );
};

// ─── Diagnostics tab (errors / warnings) ──────────────────────────────────────

const DiagnosticsTab: React.FC<{
  items: SolcError[];
  kind: "error" | "warning";
}> = ({ items, kind }) => {
  const isErr = kind === "error";
  const accent = isErr ? "#ff6666" : "#ffaa00";
  const accentBg = isErr ? "rgba(255,68,68,0.06)" : "rgba(255,170,0,0.06)";
  const accentBorder = isErr ? "rgba(255,68,68,0.18)" : "rgba(255,170,0,0.18)";

  if (items.length === 0) {
    return (
      <div style={{ padding: "28px", textAlign: "center", color: "#4a5568", fontSize: "13px" }}>
        No {kind}s.
      </div>
    );
  }

  return (
    <div>
      {items.map((item, i) => {
        const loc = extractLocation(item);
        const type = formatErrorType(item);
        return (
          <div
            key={i}
            style={{
              padding: "14px 18px",
              borderBottom: i < items.length - 1 ? "1px solid #1e2d4a" : "none",
            }}
          >
            {/* Header row */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                marginBottom: "6px",
              }}
            >
              <span
                style={{
                  fontSize: "10px",
                  fontWeight: 700,
                  color: accent,
                  backgroundColor: accentBg,
                  border: `1px solid ${accentBorder}`,
                  borderRadius: "4px",
                  padding: "2px 7px",
                  letterSpacing: "0.06em",
                  fontFamily: "monospace",
                }}
              >
                {type.toUpperCase()}
              </span>
              {item.errorCode && (
                <span
                  style={{
                    fontSize: "10px",
                    color: "#4a5568",
                    fontFamily: "monospace",
                  }}
                >
                  [{item.errorCode}]
                </span>
              )}
              {loc && (
                <span
                  style={{
                    fontSize: "11px",
                    color: "#2a3f6a",
                    fontFamily: "monospace",
                    marginLeft: "auto",
                  }}
                >
                  {loc}
                </span>
              )}
            </div>
            {/* Message */}
            <div
              style={{
                fontSize: "12px",
                color: "#8892a4",
                lineHeight: 1.55,
                fontFamily: "monospace",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {item.formattedMessage ?? item.message}
            </div>
          </div>
        );
      })}
    </div>
  );
};

// ─── JSON tab (ABI) ────────────────────────────────────────────────────────────

const JsonTab: React.FC<{
  label: string;
  data: unknown;
  hint?: string;
}> = ({ data, hint }) => {
  const json = JSON.stringify(data, null, 2);
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(json).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 16px",
          borderBottom: "1px solid #1e2d4a",
          backgroundColor: "#0a0e1a",
        }}
      >
        <span style={{ fontSize: "11px", color: "#4a5568" }}>{hint}</span>
        <button
          onClick={handleCopy}
          style={{
            fontSize: "11px",
            color: copied ? "#00ff88" : "#4a5568",
            background: "none",
            border: "none",
            cursor: "pointer",
            fontFamily: "monospace",
            padding: "2px 6px",
          }}
        >
          {copied ? "Copied ✓" : "Copy"}
        </button>
      </div>
      <pre
        style={{
          margin: 0,
          padding: "16px 18px",
          fontSize: "11px",
          color: "#8892a4",
          fontFamily: "monospace",
          overflowX: "auto",
          maxHeight: "360px",
          overflowY: "auto",
          lineHeight: 1.6,
        }}
      >
        {json}
      </pre>
    </div>
  );
};

// ─── Bytecode tab ──────────────────────────────────────────────────────────────

const BytecodeTab: React.FC<{ contract: ContractItem }> = ({ contract }) => {
  const [view, setView] = useState<"deploy" | "runtime">("deploy");
  const hex = view === "deploy" ? contract.bytecode : contract.deployedBytecode;
  const bytes = hex ? Math.floor((hex.length - 2) / 2) : 0;

  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(hex).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 16px",
          borderBottom: "1px solid #1e2d4a",
          backgroundColor: "#0a0e1a",
          gap: "12px",
        }}
      >
        <div style={{ display: "flex", gap: "4px" }}>
          {(["deploy", "runtime"] as const).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              style={{
                fontSize: "11px",
                fontWeight: view === v ? 700 : 400,
                color: view === v ? "#00d4ff" : "#4a5568",
                background: view === v ? "rgba(0,212,255,0.08)" : "none",
                border: view === v ? "1px solid rgba(0,212,255,0.25)" : "1px solid transparent",
                borderRadius: "5px",
                padding: "3px 10px",
                cursor: "pointer",
                fontFamily: "monospace",
              }}
            >
              {v === "deploy" ? "Deployment" : "Runtime"}
            </button>
          ))}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
            {bytes.toLocaleString()} bytes
          </span>
          <button
            onClick={handleCopy}
            style={{
              fontSize: "11px",
              color: copied ? "#00ff88" : "#4a5568",
              background: "none",
              border: "none",
              cursor: "pointer",
              fontFamily: "monospace",
              padding: "2px 6px",
            }}
          >
            {copied ? "Copied ✓" : "Copy"}
          </button>
        </div>
      </div>
      <pre
        style={{
          margin: 0,
          padding: "16px 18px",
          fontSize: "11px",
          color: "#8892a4",
          fontFamily: "monospace",
          overflowX: "auto",
          wordBreak: "break-all",
          whiteSpace: "pre-wrap",
          maxHeight: "260px",
          overflowY: "auto",
          lineHeight: 1.6,
        }}
      >
        {hex || "—"}
      </pre>
    </div>
  );
};

// ─── Progress panel ────────────────────────────────────────────────────────────

const ProgressPanel: React.FC<{
  icon: "download" | "compile";
  title: string;
  detail: string;
}> = ({ icon, title, detail }) => (
  <div
    style={{
      width: "100%",
      maxWidth: "860px",
      backgroundColor: "#0f1629",
      border: "1px solid #1e2d4a",
      borderRadius: "12px",
      padding: "28px 24px",
      display: "flex",
      alignItems: "center",
      gap: "18px",
    }}
  >
    <LoadingSpinner />
    <div>
      <div style={{ fontSize: "14px", fontWeight: 600, color: "#e2e8f0", marginBottom: "4px" }}>
        {title}
      </div>
      <div style={{ fontSize: "12px", color: "#4a5568" }}>{detail}</div>
    </div>
    {icon === "download" && (
      <span
        style={{
          marginLeft: "auto",
          fontSize: "10px",
          color: "#2a3f6a",
          fontFamily: "monospace",
          backgroundColor: "#0a0e1a",
          padding: "3px 8px",
          borderRadius: "4px",
          border: "1px solid #1e2d4a",
        }}
      >
        CDN fetch
      </span>
    )}
  </div>
);

// ─── Fatal error panel ─────────────────────────────────────────────────────────

const FatalErrorPanel: React.FC<{ message: string }> = ({ message }) => (
  <div
    style={{
      width: "100%",
      maxWidth: "860px",
      padding: "16px 20px",
      borderRadius: "12px",
      backgroundColor: "rgba(255,68,68,0.07)",
      border: "1px solid rgba(255,68,68,0.22)",
      display: "flex",
      alignItems: "flex-start",
      gap: "14px",
    }}
  >
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" style={{ flexShrink: 0, marginTop: "1px" }}>
      <circle cx="9" cy="9" r="8" stroke="#ff4444" strokeWidth="1.5" />
      <path d="M9 5v5M9 12h.01" stroke="#ff4444" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
    <div>
      <div style={{ fontSize: "13px", fontWeight: 600, color: "#ff6666", marginBottom: "4px" }}>
        Compilation engine error
      </div>
      <div style={{ fontSize: "12px", color: "#8892a4", lineHeight: 1.55 }}>{message}</div>
    </div>
  </div>
);

// ─── Compiler badge ────────────────────────────────────────────────────────────

const CompilerBadge: React.FC<{ compilerInfo: CompilerInfo; file: SolidityFile }> = ({
  compilerInfo,
  file,
}) => (
  <div
    style={{
      width: "100%",
      maxWidth: "860px",
      backgroundColor: "#0f1629",
      border: "1px solid #1e2d4a",
      borderRadius: "10px",
      padding: "12px 16px",
      display: "flex",
      alignItems: "center",
      gap: "16px",
      flexWrap: "wrap",
    }}
  >
    <MetaStat label="File" value={file.name} mono />
    <div style={{ width: "1px", height: "20px", backgroundColor: "#1e2d4a" }} />
    <MetaStat label="Pragma" value={compilerInfo.detectedConstraint} mono />
    <div style={{ width: "1px", height: "20px", backgroundColor: "#1e2d4a" }} />
    <MetaStat label="Selected compiler" value={`solc v${compilerInfo.selectedVersion}`} mono accent />
    <div style={{ marginLeft: "auto" }}>
      <span
        style={{
          fontSize: "10px",
          fontWeight: 700,
          color: "#00d4ff",
          backgroundColor: "rgba(0,212,255,0.08)",
          border: "1px solid rgba(0,212,255,0.2)",
          borderRadius: "5px",
          padding: "3px 8px",
          fontFamily: "monospace",
          letterSpacing: "0.06em",
        }}
      >
        {compilerInfo.constraintKind.toUpperCase()}
      </span>
    </div>
  </div>
);

// ─── Micro components ──────────────────────────────────────────────────────────

const MetaStat: React.FC<{ label: string; value: string; mono?: boolean; accent?: boolean }> = ({
  label,
  value,
  mono,
  accent,
}) => (
  <span style={{ fontSize: "12px" }}>
    <span style={{ color: "#4a5568" }}>{label}: </span>
    <span
      style={{
        color: accent ? "#00d4ff" : "#8892a4",
        fontFamily: mono ? "monospace" : "inherit",
        fontWeight: accent ? 600 : 400,
      }}
    >
      {value}
    </span>
  </span>
);

const Tab: React.FC<{
  label: string;
  active: boolean;
  onClick: () => void;
  variant?: "error" | "warning";
}> = ({ label, active, onClick, variant }) => {
  const activeColor =
    variant === "error"
      ? "#ff6666"
      : variant === "warning"
      ? "#ffaa00"
      : "#00d4ff";

  return (
    <button
      onClick={onClick}
      style={{
        padding: "9px 14px",
        fontSize: "12px",
        fontWeight: active ? 700 : 400,
        color: active ? activeColor : "#4a5568",
        background: "none",
        border: "none",
        borderBottom: active ? `2px solid ${activeColor}` : "2px solid transparent",
        cursor: "pointer",
        fontFamily: "inherit",
        transition: "color 0.15s",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </button>
  );
};

const BackButton: React.FC<{ onClick: () => void }> = ({ onClick }) => (
  <button
    onClick={onClick}
    style={{
      display: "flex",
      alignItems: "center",
      gap: "7px",
      padding: "9px 18px",
      borderRadius: "8px",
      border: "1px solid #1e2d4a",
      backgroundColor: "transparent",
      color: "#4a5568",
      fontSize: "13px",
      fontWeight: 500,
      cursor: "pointer",
      fontFamily: "inherit",
      transition: "all 0.2s ease",
    }}
    onMouseEnter={(e) => {
      const b = e.currentTarget as HTMLButtonElement;
      b.style.borderColor = "#2a3f6a";
      b.style.color = "#8892a4";
    }}
    onMouseLeave={(e) => {
      const b = e.currentTarget as HTMLButtonElement;
      b.style.borderColor = "#1e2d4a";
      b.style.color = "#4a5568";
    }}
  >
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none">
      <path
        d="M12 7H2M6 3L2 7l4 4"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
    Back
  </button>
);

const StageNumber: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div
    style={{
      width: "32px",
      height: "32px",
      borderRadius: "8px",
      backgroundColor: "rgba(0,212,255,0.1)",
      border: "1px solid rgba(0,212,255,0.3)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontSize: "11px",
      fontWeight: 700,
      color: "#00d4ff",
      fontFamily: "monospace",
      flexShrink: 0,
    }}
  >
    {children}
  </div>
);

const LoadingSpinner: React.FC = () => (
  <svg
    width="22"
    height="22"
    viewBox="0 0 22 22"
    fill="none"
    style={{ animation: "spin 1s linear infinite", flexShrink: 0 }}
  >
    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    <circle cx="11" cy="11" r="9" stroke="#1e2d4a" strokeWidth="2" />
    <path d="M11 2a9 9 0 019 9" stroke="#00d4ff" strokeWidth="2" strokeLinecap="round" />
  </svg>
);

// ─── Shared style tokens ───────────────────────────────────────────────────────

const inlineCode: React.CSSProperties = {
  backgroundColor: "#131c35",
  color: "#00d4ff",
  padding: "1px 5px",
  borderRadius: "4px",
  fontFamily: "monospace",
  fontSize: "12px",
};
