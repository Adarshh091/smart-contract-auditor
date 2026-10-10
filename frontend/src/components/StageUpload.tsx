import React from "react";
import type { SolidityFile } from "../types/pipeline";
import { FileUploadZone } from "./FileUploadZone";
import { FileMetaBadge } from "./FileMetaBadge";
import { CodeViewer } from "./CodeViewer";

interface StageUploadProps {
  file: SolidityFile | null;
  onFileAccepted: (file: SolidityFile) => void;
  onFileRemoved: () => void;
  onContinue: () => void;
}

export const StageUpload: React.FC<StageUploadProps> = ({
  file,
  onFileAccepted,
  onFileRemoved,
  onContinue,
}) => {
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "24px" }}>
      {/* Section header */}
      <div style={{ width: "100%", maxWidth: "860px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
          <StageNumber>01</StageNumber>
          <h2
            style={{
              margin: 0,
              fontSize: "18px",
              fontWeight: 700,
              color: "#e2e8f0",
              letterSpacing: "-0.02em",
            }}
          >
            Load Contract
          </h2>
        </div>
        <p style={{ margin: "0 0 0 42px", fontSize: "13px", color: "#4a5568" }}>
          Upload a Solidity source file to begin the audit pipeline. Only{" "}
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
            .sol
          </code>{" "}
          files are accepted.
        </p>
      </div>

      {/* Upload zone or file meta */}
      <div
        style={{
          width: "100%",
          maxWidth: "860px",
          display: "flex",
          justifyContent: file ? "flex-start" : "center",
        }}
      >
        {file ? (
          <FileMetaBadge file={file} onRemove={onFileRemoved} />
        ) : (
          <FileUploadZone onFileAccepted={onFileAccepted} />
        )}
      </div>

      {/* Code viewer */}
      {file && (
        <div style={{ width: "100%", maxWidth: "860px" }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              marginBottom: "12px",
            }}
          >
            <SectionLabel>Source Preview</SectionLabel>
            <div style={{ flex: 1, height: "1px", backgroundColor: "#1e2d4a" }} />
            <span style={{ fontSize: "11px", color: "#4a5568" }}>read-only</span>
          </div>
          <CodeViewer file={file} />
        </div>
      )}

      {/* Continue button */}
      {file && (
        <div
          style={{
            width: "100%",
            maxWidth: "860px",
            display: "flex",
            justifyContent: "flex-end",
            paddingBottom: "8px",
            animation: "fade-in-up 0.3s ease forwards",
          }}
        >
          <button
            onClick={onContinue}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "10px 24px",
              borderRadius: "8px",
              border: "1px solid rgba(0,212,255,0.4)",
              backgroundColor: "rgba(0,212,255,0.1)",
              color: "#00d4ff",
              fontSize: "14px",
              fontWeight: 600,
              cursor: "pointer",
              letterSpacing: "0.02em",
              transition: "all 0.2s ease",
              fontFamily: "inherit",
            }}
            onMouseEnter={(e) => {
              const btn = e.currentTarget as HTMLButtonElement;
              btn.style.backgroundColor = "rgba(0,212,255,0.18)";
              btn.style.borderColor = "#00d4ff";
              btn.style.boxShadow = "0 0 20px rgba(0,212,255,0.2)";
            }}
            onMouseLeave={(e) => {
              const btn = e.currentTarget as HTMLButtonElement;
              btn.style.backgroundColor = "rgba(0,212,255,0.1)";
              btn.style.borderColor = "rgba(0,212,255,0.4)";
              btn.style.boxShadow = "none";
            }}
          >
            Continue to Compiler Detection
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path
                d="M2 7h10M8 3l4 4-4 4"
                stroke="#00d4ff"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </button>
        </div>
      )}
    </div>
  );
};

// ─── Micro components ──────────────────────────────────────────────────────────

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
