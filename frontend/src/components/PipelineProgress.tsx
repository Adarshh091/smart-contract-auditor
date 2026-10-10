import React from "react";
import type { PipelineStage } from "../types/pipeline";

interface PipelineProgressProps {
  stages: PipelineStage[];
}

const statusColors: Record<string, string> = {
  pending: "#1e2d4a",
  active: "#00d4ff",
  complete: "#00ff88",
  error: "#ff4444",
};

const statusTextColors: Record<string, string> = {
  pending: "#4a5568",
  active: "#00d4ff",
  complete: "#00ff88",
  error: "#ff4444",
};

export const PipelineProgress: React.FC<PipelineProgressProps> = ({ stages }) => {
  return (
    <div style={{ padding: "24px 32px 0" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "28px" }}>
        <div
          style={{
            width: "8px",
            height: "8px",
            borderRadius: "50%",
            backgroundColor: "#00d4ff",
            boxShadow: "0 0 8px #00d4ff",
            animation: "glow-pulse 2s ease-in-out infinite",
          }}
        />
        <span
          style={{
            fontSize: "11px",
            fontWeight: 600,
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            color: "#8892a4",
          }}
        >
          Smart Contract Auditor
        </span>
        <span style={{ marginLeft: "auto", fontSize: "11px", color: "#4a5568" }}>
          Pipeline v1.0
        </span>
      </div>

      {/* Stage track */}
      <div style={{ display: "flex", alignItems: "center", gap: 0 }}>
        {stages.map((stage, idx) => {
          const isLast = idx === stages.length - 1;
          const color = statusColors[stage.status];
          const textColor = statusTextColors[stage.status];

          return (
            <React.Fragment key={stage.id}>
              {/* Stage node */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: "80px" }}>
                {/* Circle */}
                <div
                  style={{
                    width: "36px",
                    height: "36px",
                    borderRadius: "50%",
                    border: `2px solid ${color}`,
                    backgroundColor:
                      stage.status === "active"
                        ? "rgba(0,212,255,0.1)"
                        : stage.status === "complete"
                        ? "rgba(0,255,136,0.08)"
                        : "#0f1629",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    position: "relative",
                    boxShadow:
                      stage.status === "active"
                        ? "0 0 16px rgba(0,212,255,0.3)"
                        : stage.status === "complete"
                        ? "0 0 12px rgba(0,255,136,0.2)"
                        : "none",
                    transition: "all 0.3s ease",
                  }}
                >
                  {stage.status === "complete" ? (
                    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                      <path d="M2 7l4 4 6-6" stroke="#00ff88" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  ) : stage.status === "error" ? (
                    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                      <path d="M7 3v5M7 10.5v.5" stroke="#ff4444" strokeWidth="2" strokeLinecap="round" />
                    </svg>
                  ) : (
                    <span
                      style={{
                        fontSize: "11px",
                        fontWeight: 700,
                        color: textColor,
                        fontFamily: "monospace",
                      }}
                    >
                      {String(idx + 1).padStart(2, "0")}
                    </span>
                  )}
                </div>

                {/* Label */}
                <div style={{ marginTop: "8px", textAlign: "center" }}>
                  <div
                    style={{
                      fontSize: "11px",
                      fontWeight: 600,
                      color: textColor,
                      letterSpacing: "0.05em",
                    }}
                  >
                    {stage.label}
                  </div>
                  <div style={{ fontSize: "10px", color: "#4a5568", marginTop: "1px" }}>
                    {stage.description}
                  </div>
                </div>
              </div>

              {/* Connector line */}
              {!isLast && (
                <div
                  style={{
                    flex: 1,
                    height: "2px",
                    backgroundColor:
                      stages[idx + 1].status === "pending" ? "#1e2d4a" :
                      stages[idx].status === "complete" ? "#00ff88" : "#2a3f6a",
                    marginBottom: "28px",
                    transition: "background-color 0.3s ease",
                  }}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};
