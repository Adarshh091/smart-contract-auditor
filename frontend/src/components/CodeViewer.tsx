import React, { useState } from "react";
import Editor from "@monaco-editor/react";
import type { SolidityFile } from "../types/pipeline";
import { countLines, formatBytes } from "../utils/format";

interface CodeViewerProps {
  file: SolidityFile;
}

export const CodeViewer: React.FC<CodeViewerProps> = ({ file }) => {
  const [isEditorReady, setIsEditorReady] = useState(false);
  const lines = countLines(file.source);

  return (
    <div
      style={{
        width: "100%",
        border: "1px solid #1e2d4a",
        borderRadius: "12px",
        overflow: "hidden",
        backgroundColor: "#0a0e1a",
        animation: "fade-in-up 0.4s ease forwards",
      }}
    >
      {/* Editor toolbar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 16px",
          backgroundColor: "#0f1629",
          borderBottom: "1px solid #1e2d4a",
        }}
      >
        {/* Left: traffic lights + filename */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <TrafficLights />
          <span
            style={{
              fontSize: "12px",
              color: "#8892a4",
              fontFamily: "monospace",
              marginLeft: "4px",
            }}
          >
            {file.name}
          </span>
        </div>

        {/* Right: stats */}
        <div style={{ display: "flex", gap: "16px", alignItems: "center" }}>
          <EditorStat icon="⚡" label={`${lines} lines`} />
          <EditorStat icon="◉" label={formatBytes(file.size)} />
          <LanguageBadge />
          {!isEditorReady && (
            <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
              Loading…
            </span>
          )}
        </div>
      </div>

      {/* Monaco Editor */}
      <div style={{ height: "480px", position: "relative" }}>
        {!isEditorReady && (
          <div
            style={{
              position: "absolute",
              inset: 0,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              backgroundColor: "#0a0e1a",
              zIndex: 10,
            }}
          >
            <div style={{ textAlign: "center" }}>
              <LoadingSpinner />
              <div style={{ fontSize: "12px", color: "#4a5568", marginTop: "12px" }}>
                Initialising editor…
              </div>
            </div>
          </div>
        )}

        <Editor
          height="480px"
          defaultLanguage="sol"
          language="sol"
          value={file.source}
          theme="vs-dark"
          options={{
            readOnly: true,
            minimap: { enabled: true, scale: 1 },
            fontSize: 13,
            lineHeight: 20,
            fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace",
            fontLigatures: true,
            scrollBeyondLastLine: false,
            wordWrap: "off",
            lineNumbers: "on",
            glyphMargin: false,
            folding: true,
            renderLineHighlight: "line",
            cursorBlinking: "smooth",
            smoothScrolling: true,
            contextmenu: false,
            scrollbar: {
              verticalScrollbarSize: 6,
              horizontalScrollbarSize: 6,
            },
          }}
          beforeMount={(monaco) => {
            // Register Solidity language basics if not present
            if (!monaco.languages.getLanguages().find((l: { id: string }) => l.id === "sol")) {
              monaco.languages.register({ id: "sol", extensions: [".sol"] });
            }

            // Custom dark theme matching the dashboard
            monaco.editor.defineTheme("auditor-dark", {
              base: "vs-dark",
              inherit: true,
              rules: [
                { token: "comment", foreground: "4a5568", fontStyle: "italic" },
                { token: "keyword", foreground: "00d4ff" },
                { token: "string", foreground: "00ff88" },
                { token: "number", foreground: "ffaa00" },
                { token: "type", foreground: "c084fc" },
                { token: "identifier", foreground: "e2e8f0" },
              ],
              colors: {
                "editor.background": "#0a0e1a",
                "editor.foreground": "#e2e8f0",
                "editorLineNumber.foreground": "#2a3f6a",
                "editorLineNumber.activeForeground": "#00d4ff",
                "editor.lineHighlightBackground": "#0f1629",
                "editor.selectionBackground": "#1e3a5f",
                "editorCursor.foreground": "#00d4ff",
                "editorIndentGuide.background1": "#1e2d4a",
                "editorIndentGuide.activeBackground1": "#2a3f6a",
                "editor.inactiveSelectionBackground": "#1a2540",
                "scrollbarSlider.background": "#1e2d4a",
                "scrollbarSlider.hoverBackground": "#2a3f6a",
                "minimap.background": "#0a0e1a",
                "editorGutter.background": "#0a0e1a",
              },
            });
          }}
          onMount={(_, monaco) => {
            monaco.editor.setTheme("auditor-dark");
            setIsEditorReady(true);
          }}
        />
      </div>

      {/* Footer status bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "6px 16px",
          backgroundColor: "#060910",
          borderTop: "1px solid #1e2d4a",
        }}
      >
        <div style={{ display: "flex", gap: "16px" }}>
          <StatusBarItem label="Ln 1, Col 1" />
          <StatusBarItem label="Spaces: 4" />
          <StatusBarItem label="UTF-8" />
        </div>
        <StatusBarItem label="Solidity" accent />
      </div>
    </div>
  );
};

// ─── Sub-components ────────────────────────────────────────────────────────────

const TrafficLights: React.FC = () => (
  <div style={{ display: "flex", gap: "6px" }}>
    {(["#ff5f57", "#febc2e", "#28c840"] as const).map((color, i) => (
      <div
        key={i}
        style={{
          width: "10px",
          height: "10px",
          borderRadius: "50%",
          backgroundColor: color,
          opacity: 0.7,
        }}
      />
    ))}
  </div>
);

const LanguageBadge: React.FC = () => (
  <div
    style={{
      backgroundColor: "rgba(0,212,255,0.08)",
      border: "1px solid rgba(0,212,255,0.2)",
      borderRadius: "4px",
      padding: "2px 8px",
      fontSize: "10px",
      fontWeight: 700,
      color: "#00d4ff",
      letterSpacing: "0.08em",
      fontFamily: "monospace",
    }}
  >
    SOLIDITY
  </div>
);

const EditorStat: React.FC<{ icon: string; label: string }> = ({ icon, label }) => (
  <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
    {icon} {label}
  </span>
);

const StatusBarItem: React.FC<{ label: string; accent?: boolean }> = ({ label, accent }) => (
  <span
    style={{
      fontSize: "11px",
      fontFamily: "monospace",
      color: accent ? "#00d4ff" : "#4a5568",
    }}
  >
    {label}
  </span>
);

const LoadingSpinner: React.FC = () => (
  <svg
    width="28"
    height="28"
    viewBox="0 0 28 28"
    fill="none"
    style={{ animation: "spin 1s linear infinite", display: "block", margin: "0 auto" }}
  >
    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    <circle cx="14" cy="14" r="11" stroke="#1e2d4a" strokeWidth="2" />
    <path
      d="M14 3a11 11 0 0111 11"
      stroke="#00d4ff"
      strokeWidth="2"
      strokeLinecap="round"
    />
  </svg>
);
