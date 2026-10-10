import React, { useEffect, useState, useCallback } from "react";
import type { SolidityFile, CompilerInfo } from "../types/pipeline";
import {
  analysePragma,
  formatPragmaKind,
  type PragmaAnalysis,
} from "../utils/solidity-version";

// ─── Props ─────────────────────────────────────────────────────────────────────

interface StageCompilerProps {
  file: SolidityFile;
  /** Called when the user clicks "Compile Contract" with collected info */
  onCompile: (info: CompilerInfo) => void;
  /** Called to go back to the upload stage */
  onBack: () => void;
}

// ─── Component ─────────────────────────────────────────────────────────────────

export const StageCompiler: React.FC<StageCompilerProps> = ({
  file,
  onCompile,
  onBack,
}) => {
  const [analysis, setAnalysis] = useState<PragmaAnalysis | null>(null);
  const [isAnalysing, setIsAnalysing] = useState(true);

  // Run analysis once when the component mounts / file changes
  useEffect(() => {
    setIsAnalysing(true);
    // Defer to allow the loading state to render first
    const timer = setTimeout(() => {
      const result = analysePragma(file.source);
      setAnalysis(result);
      setIsAnalysing(false);
    }, 300);
    return () => clearTimeout(timer);
  }, [file]);

  const handleCompile = useCallback(() => {
    if (!analysis?.compiler || !analysis.pragma) return;
    const info: CompilerInfo = {
      detectedConstraint: analysis.pragma.raw,
      constraintKind: analysis.pragma.kind,
      selectedVersion: analysis.compiler.version,
      selectionReason: analysis.compiler.reason,
      isCompatible: analysis.compiler.compatible,
    };
    onCompile(info);
  }, [analysis, onCompile]);

  const canCompile =
    !isAnalysing && analysis?.found && !!analysis.compiler && !analysis.error;

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
          <StageNumber>02</StageNumber>
          <h2
            style={{
              margin: 0,
              fontSize: "18px",
              fontWeight: 700,
              color: "#e2e8f0",
              letterSpacing: "-0.02em",
            }}
          >
            Compiler Detection
          </h2>
        </div>
        <p style={{ margin: "0 0 0 42px", fontSize: "13px", color: "#4a5568" }}>
          Reads the{" "}
          <code
            style={{
              backgroundColor: "#131c35",
              color: "#00d4ff",
              padding: "1px 5px",
              borderRadius: "4px",
              fontFamily: "monospace",
              fontSize: "12px",
            }}
          >
            pragma solidity
          </code>{" "}
          statement and selects the most compatible{" "}
          <code
            style={{
              backgroundColor: "#131c35",
              color: "#00d4ff",
              padding: "1px 5px",
              borderRadius: "4px",
              fontFamily: "monospace",
              fontSize: "12px",
            }}
          >
            solc
          </code>{" "}
          compiler version.
        </p>
      </div>

      {/* ── Source file badge ───────────────────────────────────────────────── */}
      <div style={{ width: "100%", maxWidth: "860px" }}>
        <SectionLabel>Source File</SectionLabel>
        <div
          style={{
            marginTop: "10px",
            backgroundColor: "#0f1629",
            border: "1px solid #1e2d4a",
            borderRadius: "10px",
            padding: "12px 16px",
            display: "flex",
            alignItems: "center",
            gap: "12px",
          }}
        >
          {/* File icon */}
          <div
            style={{
              width: "36px",
              height: "36px",
              borderRadius: "8px",
              backgroundColor: "#131c35",
              border: "1px solid #1e2d4a",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            <svg width="18" height="18" viewBox="0 0 20 20" fill="none">
              <path
                d="M5 2h8l4 4v12a1 1 0 01-1 1H4a1 1 0 01-1-1V3a1 1 0 011-1z"
                stroke="#00d4ff"
                strokeWidth="1.5"
              />
              <path d="M13 2v4h4" stroke="#00d4ff" strokeWidth="1.5" strokeLinecap="round" />
              <path d="M7 10h6M7 13h4" stroke="#8892a4" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </div>
          <span
            style={{
              fontSize: "13px",
              fontFamily: "monospace",
              color: "#e2e8f0",
              fontWeight: 600,
            }}
          >
            {file.name}
          </span>
          <span style={{ marginLeft: "auto", fontSize: "11px", color: "#4a5568" }}>
            loaded from Stage 1
          </span>
        </div>
      </div>

      {/* ── Analysis panel ──────────────────────────────────────────────────── */}
      <div style={{ width: "100%", maxWidth: "860px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "10px" }}>
          <SectionLabel>Pragma Analysis</SectionLabel>
          <div style={{ flex: 1, height: "1px", backgroundColor: "#1e2d4a" }} />
        </div>

        {isAnalysing ? (
          <AnalysingPlaceholder />
        ) : analysis?.error && !analysis.pragma ? (
          /* Pragma completely missing or invalid syntax */
          <ErrorPanel message={analysis.error} />
        ) : analysis ? (
          <AnalysisGrid analysis={analysis} />
        ) : null}
      </div>

      {/* ── Error panel (pragma found but no compiler matched) ─────────────── */}
      {!isAnalysing && analysis?.error && analysis.pragma && (
        <div style={{ width: "100%", maxWidth: "860px" }}>
          <ErrorPanel message={analysis.error} />
        </div>
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
        {/* Back */}
        <button
          onClick={onBack}
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

        {/* Compile */}
        <button
          onClick={handleCompile}
          disabled={!canCompile}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            padding: "10px 24px",
            borderRadius: "8px",
            border: canCompile
              ? "1px solid rgba(0,212,255,0.4)"
              : "1px solid #1e2d4a",
            backgroundColor: canCompile
              ? "rgba(0,212,255,0.1)"
              : "rgba(255,255,255,0.03)",
            color: canCompile ? "#00d4ff" : "#2a3f6a",
            fontSize: "14px",
            fontWeight: 600,
            cursor: canCompile ? "pointer" : "not-allowed",
            letterSpacing: "0.02em",
            transition: "all 0.2s ease",
            fontFamily: "inherit",
            opacity: canCompile ? 1 : 0.6,
          }}
          onMouseEnter={(e) => {
            if (!canCompile) return;
            const b = e.currentTarget as HTMLButtonElement;
            b.style.backgroundColor = "rgba(0,212,255,0.18)";
            b.style.borderColor = "#00d4ff";
            b.style.boxShadow = "0 0 20px rgba(0,212,255,0.2)";
          }}
          onMouseLeave={(e) => {
            if (!canCompile) return;
            const b = e.currentTarget as HTMLButtonElement;
            b.style.backgroundColor = "rgba(0,212,255,0.1)";
            b.style.borderColor = "rgba(0,212,255,0.4)";
            b.style.boxShadow = "none";
          }}
        >
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <path
              d="M2 2l10 5-10 5V2z"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinejoin="round"
            />
          </svg>
          Compile Contract
          {canCompile && (
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path
                d="M2 7h10M8 3l4 4-4 4"
                stroke="#00d4ff"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          )}
        </button>
      </div>
    </div>
  );
};

// ─── Analysis grid ─────────────────────────────────────────────────────────────

const AnalysisGrid: React.FC<{ analysis: PragmaAnalysis }> = ({ analysis }) => {
  const { pragma, compiler } = analysis;

  return (
    <div
      style={{
        backgroundColor: "#0f1629",
        border: "1px solid #1e2d4a",
        borderRadius: "12px",
        overflow: "hidden",
      }}
    >
      {/* Grid rows */}
      <InfoRow
        label="Detected Pragma"
        value={pragma?.raw ?? "—"}
        mono
        accent
      />

      <InfoRow
        label="Constraint Type"
        value={pragma ? formatPragmaKind(pragma.kind) : "—"}
      />

      {pragma && pragma.kind !== "exact" && pragma.lowerBound && (
        <InfoRow
          label="Lower Bound"
          value={`>= ${pragma.lowerBound}`}
          mono
        />
      )}

      {pragma && pragma.upperBound && (
        <InfoRow
          label="Upper Bound"
          value={`< ${pragma.upperBound}`}
          mono
        />
      )}

      <div
        style={{
          height: "1px",
          backgroundColor: "#1e2d4a",
          margin: "0",
        }}
      />

      {compiler ? (
        <>
          <InfoRow
            label="Selected Compiler"
            value={`solc v${compiler.version}`}
            mono
            positive
          />
          <InfoRow
            label="Selection Reason"
            value={compiler.reason}
          />
          <InfoRow
            label="Compatibility"
            value="Compatible ✓"
            positive
          />
        </>
      ) : (
        <InfoRow
          label="Selected Compiler"
          value="No compatible compiler found"
          negative
        />
      )}
    </div>
  );
};

// ─── Sub-components ────────────────────────────────────────────────────────────

interface InfoRowProps {
  label: string;
  value: string;
  mono?: boolean;
  accent?: boolean;
  positive?: boolean;
  negative?: boolean;
}

const InfoRow: React.FC<InfoRowProps> = ({
  label,
  value,
  mono = false,
  accent = false,
  positive = false,
  negative = false,
}) => {
  let valueColor = "#8892a4";
  if (accent) valueColor = "#00d4ff";
  else if (positive) valueColor = "#00ff88";
  else if (negative) valueColor = "#ff6666";

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        padding: "13px 18px",
        borderBottom: "1px solid #1e2d4a",
        gap: "16px",
      }}
    >
      <span
        style={{
          fontSize: "12px",
          color: "#4a5568",
          minWidth: "170px",
          flexShrink: 0,
          fontWeight: 500,
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontSize: "13px",
          color: valueColor,
          fontFamily: mono ? "monospace" : "inherit",
          fontWeight: accent || positive || negative ? 600 : 400,
          wordBreak: "break-all",
        }}
      >
        {value}
      </span>
    </div>
  );
};

const AnalysingPlaceholder: React.FC = () => (
  <div
    style={{
      backgroundColor: "#0f1629",
      border: "1px solid #1e2d4a",
      borderRadius: "12px",
      padding: "32px",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      gap: "14px",
    }}
  >
    <LoadingSpinner />
    <span style={{ fontSize: "13px", color: "#4a5568" }}>
      Scanning pragma statement…
    </span>
  </div>
);

const ErrorPanel: React.FC<{ message: string }> = ({ message }) => (
  <div
    style={{
      padding: "14px 18px",
      borderRadius: "10px",
      backgroundColor: "rgba(255,68,68,0.07)",
      border: "1px solid rgba(255,68,68,0.22)",
      display: "flex",
      alignItems: "flex-start",
      gap: "12px",
    }}
  >
    {/* Error icon */}
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      style={{ flexShrink: 0, marginTop: "1px" }}
    >
      <circle cx="8" cy="8" r="7" stroke="#ff4444" strokeWidth="1.5" />
      <path
        d="M8 4.5v4M8 10.5h.01"
        stroke="#ff4444"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
    <span style={{ fontSize: "13px", color: "#ff6666", lineHeight: 1.5 }}>
      {message}
    </span>
  </div>
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

const SectionLabel: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <span
    style={{
      fontSize: "11px",
      fontWeight: 600,
      color: "#4a5568",
      letterSpacing: "0.1em",
      textTransform: "uppercase",
      whiteSpace: "nowrap",
    }}
  >
    {children}
  </span>
);

const LoadingSpinner: React.FC = () => (
  <svg
    width="20"
    height="20"
    viewBox="0 0 20 20"
    fill="none"
    style={{ animation: "spin 1s linear infinite" }}
  >
    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    <circle cx="10" cy="10" r="8" stroke="#1e2d4a" strokeWidth="2" />
    <path d="M10 2a8 8 0 018 8" stroke="#00d4ff" strokeWidth="2" strokeLinecap="round" />
  </svg>
);
