import React from "react";
import type { SolidityFile } from "../types/pipeline";
import { formatBytes, countLines } from "../utils/format";

interface FileMetaBadgeProps {
  file: SolidityFile;
  onRemove: () => void;
}

export const FileMetaBadge: React.FC<FileMetaBadgeProps> = ({ file, onRemove }) => {
  const lines = countLines(file.source);

  return (
    <div
      style={{
        backgroundColor: "#0f1629",
        border: "1px solid #1e2d4a",
        borderRadius: "10px",
        padding: "14px 18px",
        display: "flex",
        alignItems: "center",
        gap: "14px",
        width: "100%",
        maxWidth: "560px",
        animation: "fade-in-up 0.3s ease forwards",
      }}
    >
      {/* File icon */}
      <div
        style={{
          width: "40px",
          height: "40px",
          borderRadius: "8px",
          backgroundColor: "#131c35",
          border: "1px solid #1e2d4a",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
          <path
            d="M5 2h8l4 4v12a1 1 0 01-1 1H4a1 1 0 01-1-1V3a1 1 0 011-1z"
            stroke="#00d4ff"
            strokeWidth="1.5"
          />
          <path d="M13 2v4h4" stroke="#00d4ff" strokeWidth="1.5" strokeLinecap="round" />
          <path d="M7 10h6M7 13h4" stroke="#8892a4" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      </div>

      {/* File info */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontSize: "14px",
            fontWeight: 600,
            color: "#e2e8f0",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            fontFamily: "monospace",
          }}
        >
          {file.name}
        </div>
        <div style={{ display: "flex", gap: "12px", marginTop: "4px" }}>
          <Stat label="Size" value={formatBytes(file.size)} />
          <StatDivider />
          <Stat label="Lines" value={lines.toLocaleString()} />
          <StatDivider />
          <Stat label="Encoding" value="UTF-8" />
        </div>
      </div>

      {/* Status badge */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "6px",
          backgroundColor: "rgba(0,255,136,0.08)",
          border: "1px solid rgba(0,255,136,0.2)",
          borderRadius: "6px",
          padding: "4px 10px",
          fontSize: "11px",
          color: "#00ff88",
          fontWeight: 600,
          flexShrink: 0,
        }}
      >
        <span style={{ fontSize: "8px" }}>●</span>
        Ready
      </div>

      {/* Remove button */}
      <button
        onClick={onRemove}
        title="Remove file"
        style={{
          width: "28px",
          height: "28px",
          borderRadius: "6px",
          border: "1px solid #1e2d4a",
          backgroundColor: "transparent",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
          color: "#4a5568",
          transition: "all 0.15s ease",
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLButtonElement).style.borderColor = "#ff4444";
          (e.currentTarget as HTMLButtonElement).style.color = "#ff4444";
          (e.currentTarget as HTMLButtonElement).style.backgroundColor = "rgba(255,68,68,0.08)";
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLButtonElement).style.borderColor = "#1e2d4a";
          (e.currentTarget as HTMLButtonElement).style.color = "#4a5568";
          (e.currentTarget as HTMLButtonElement).style.backgroundColor = "transparent";
        }}
      >
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      </button>
    </div>
  );
};

const Stat: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <span style={{ fontSize: "11px" }}>
    <span style={{ color: "#4a5568" }}>{label}: </span>
    <span style={{ color: "#8892a4", fontFamily: "monospace" }}>{value}</span>
  </span>
);

const StatDivider: React.FC = () => (
  <span style={{ color: "#1e2d4a", fontSize: "11px" }}>·</span>
);
