import React, { useCallback, useRef, useState } from "react";
import type { SolidityFile } from "../types/pipeline";
import { formatBytes as _formatBytes } from "../utils/format";

interface FileUploadZoneProps {
  onFileAccepted: (file: SolidityFile) => void;
}

export const FileUploadZone: React.FC<FileUploadZoneProps> = ({ onFileAccepted }) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const processFile = useCallback(
    async (rawFile: File) => {
      setError(null);

      if (!rawFile.name.endsWith(".sol")) {
        setError("Only Solidity (.sol) files are accepted.");
        return;
      }

      if (rawFile.size > 5 * 1024 * 1024) {
        setError("File exceeds 5 MB limit.");
        return;
      }

      try {
        const source = await rawFile.text();
        onFileAccepted({
          name: rawFile.name,
          size: rawFile.size,
          lastModified: rawFile.lastModified,
          source,
        });
      } catch {
        setError("Failed to read file. Please try again.");
      }
    },
    [onFileAccepted]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) processFile(file);
    },
    [processFile]
  );

  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) processFile(file);
    },
    [processFile]
  );

  return (
    <div style={{ width: "100%", maxWidth: "560px" }}>
      {/* Drop zone */}
      <div
        className={isDragOver ? "dropzone-active" : ""}
        onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
        onDragLeave={() => setIsDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        style={{
          border: `2px dashed ${isDragOver ? "#00d4ff" : "#1e2d4a"}`,
          borderRadius: "12px",
          padding: "48px 32px",
          textAlign: "center",
          cursor: "pointer",
          backgroundColor: isDragOver ? "rgba(0,212,255,0.04)" : "#0f1629",
          transition: "all 0.2s ease",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Corner accents */}
        <CornerAccent position="top-left" />
        <CornerAccent position="top-right" />
        <CornerAccent position="bottom-left" />
        <CornerAccent position="bottom-right" />

        <input
          ref={inputRef}
          type="file"
          accept=".sol"
          style={{ display: "none" }}
          onChange={handleInputChange}
        />

        {/* Upload icon */}
        <div style={{ marginBottom: "20px" }}>
          <div
            style={{
              width: "64px",
              height: "64px",
              borderRadius: "16px",
              border: "1px solid #1e2d4a",
              backgroundColor: "#131c35",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              margin: "0 auto",
              boxShadow: isDragOver ? "0 0 20px rgba(0,212,255,0.2)" : "none",
              transition: "box-shadow 0.2s ease",
            }}
          >
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
              <path
                d="M14 4v14M7 11l7-7 7 7"
                stroke={isDragOver ? "#00d4ff" : "#8892a4"}
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M4 20v2a2 2 0 002 2h16a2 2 0 002-2v-2"
                stroke={isDragOver ? "#00d4ff" : "#4a5568"}
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
          </div>
        </div>

        <div
          style={{
            fontSize: "16px",
            fontWeight: 600,
            color: isDragOver ? "#00d4ff" : "#e2e8f0",
            marginBottom: "8px",
            transition: "color 0.2s",
          }}
        >
          {isDragOver ? "Drop to load contract" : "Drop your Solidity contract here"}
        </div>

        <div style={{ fontSize: "13px", color: "#4a5568", marginBottom: "20px" }}>
          or click to browse your filesystem
        </div>

        {/* Badge */}
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "6px",
            backgroundColor: "#131c35",
            border: "1px solid #1e2d4a",
            borderRadius: "6px",
            padding: "4px 12px",
            fontSize: "11px",
            color: "#8892a4",
            fontFamily: "monospace",
          }}
        >
          <span style={{ color: "#00d4ff" }}>●</span>
          .sol files only · max 5 MB
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div
          style={{
            marginTop: "12px",
            padding: "10px 14px",
            borderRadius: "8px",
            backgroundColor: "rgba(255,68,68,0.08)",
            border: "1px solid rgba(255,68,68,0.2)",
            fontSize: "13px",
            color: "#ff6666",
            display: "flex",
            alignItems: "center",
            gap: "8px",
          }}
        >
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <circle cx="7" cy="7" r="6" stroke="#ff4444" strokeWidth="1.5" />
            <path d="M7 4v4M7 10h.01" stroke="#ff4444" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
          {error}
        </div>
      )}
    </div>
  );
};

// ─── Corner accent SVG decoration ─────────────────────────────────────────────

type CornerPosition = "top-left" | "top-right" | "bottom-left" | "bottom-right";

const CornerAccent: React.FC<{ position: CornerPosition }> = ({ position }) => {
  const style: React.CSSProperties = {
    position: "absolute",
    width: "12px",
    height: "12px",
    ...(position === "top-left" && { top: 8, left: 8 }),
    ...(position === "top-right" && { top: 8, right: 8 }),
    ...(position === "bottom-left" && { bottom: 8, left: 8 }),
    ...(position === "bottom-right" && { bottom: 8, right: 8 }),
  };

  const rotate =
    position === "top-right" ? "90deg"
    : position === "bottom-right" ? "180deg"
    : position === "bottom-left" ? "270deg"
    : "0deg";

  return (
    <svg style={{ ...style, transform: `rotate(${rotate})` }} viewBox="0 0 12 12" fill="none">
      <path d="M1 11V1h10" stroke="#2a3f6a" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
};
