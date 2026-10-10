// ─── Stage 5: Semantic / Purpose Analysis UI (Gemini API Powered) ─────────────

import React, { useState, useCallback } from "react";
import type { SolidityFile } from "../types/pipeline";
import type { ASTAnalysisResult } from "../types/ast";
import type { SemanticResult } from "../types/semantic";
import {
  runSemanticAnalysis,
  type SemanticAnalysisError,
} from "../utils/semantic-analyzer";

// ─── Props ────────────────────────────────────────────────────────────────────

interface StageSemanticProps {
  file: SolidityFile;
  astAnalysis: ASTAnalysisResult;
  onBack: () => void;
  onContinue: (result: SemanticResult) => void;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

const StageNumber: React.FC<{ n: number }> = ({ n }) => (
  <div
    style={{
      width: "28px",
      height: "28px",
      borderRadius: "8px",
      background: "linear-gradient(135deg,#00d4ff22,#7b2fff22)",
      border: "1px solid #00d4ff44",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontSize: "12px",
      fontWeight: 700,
      color: "#00d4ff",
      flexShrink: 0,
    }}
  >
    {n}
  </div>
);

const MetricCard: React.FC<{ label: string; value: string | number; accent?: string }> = ({
  label,
  value,
  accent = "#00d4ff",
}) => (
  <div
    style={{
      background: "#0d1628",
      border: "1px solid #1e2d4a",
      borderRadius: "10px",
      padding: "16px",
      display: "flex",
      flexDirection: "column",
      gap: "6px",
    }}
  >
    <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>{label}</span>
    <span style={{ fontSize: "22px", fontWeight: 700, color: accent }}>{value}</span>
  </div>
);

const SectionCard: React.FC<{
  title: string;
  icon: string;
  items: string[];
  emptyText?: string;
  accent?: string;
}> = ({ title, icon, items, emptyText = "None identified.", accent = "#00d4ff" }) => (
  <div
    style={{
      background: "#0d1628",
      border: "1px solid #1e2d4a",
      borderRadius: "10px",
      padding: "16px",
    }}
  >
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "8px",
        marginBottom: "12px",
      }}
    >
      <span style={{ fontSize: "16px" }}>{icon}</span>
      <span style={{ fontSize: "13px", fontWeight: 600, color: "#e2e8f0" }}>{title}</span>
    </div>
    {items.length === 0 ? (
      <span style={{ fontSize: "12px", color: "#2a3f6a", fontStyle: "italic" }}>{emptyText}</span>
    ) : (
      <ul
        style={{
          listStyle: "none",
          margin: 0,
          padding: 0,
          display: "flex",
          flexDirection: "column",
          gap: "6px",
        }}
      >
        {items.map((item, i) => (
          <li
            key={i}
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "8px",
              fontSize: "12px",
              color: "#b0bec5",
              lineHeight: 1.5,
            }}
          >
            <span
              style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                background: accent,
                flexShrink: 0,
                marginTop: "5px",
              }}
            />
            {item}
          </li>
        ))}
      </ul>
    )}
  </div>
);

const ConfidenceBar: React.FC<{ value: number }> = ({ value }) => {
  const pct = Math.round(value * 100);
  const color = pct >= 75 ? "#00d4ff" : pct >= 50 ? "#f59e0b" : "#ef4444";
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <span style={{ fontSize: "12px", color: "#8892a4" }}>Model confidence</span>
        <span style={{ fontSize: "12px", fontWeight: 700, color }}>{pct}%</span>
      </div>
      <div
        style={{
          height: "4px",
          borderRadius: "2px",
          background: "#1e2d4a",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
            background: color,
            transition: "width 0.6s ease",
          }}
        />
      </div>
    </div>
  );
};

// ─── Main Component ───────────────────────────────────────────────────────────

export const StageSemantic: React.FC<StageSemanticProps> = ({
  file,
  astAnalysis,
  onBack,
  onContinue,
}) => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SemanticResult | null>(null);
  const [error, setError] = useState<SemanticAnalysisError | null>(null);
  const [durationMs, setDurationMs] = useState<number | null>(null);
  const [usedModel, setUsedModel] = useState<string>("");

  const handleAnalyze = useCallback(async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    setDurationMs(null);
    setUsedModel("");

    const outcome = await runSemanticAnalysis(astAnalysis);

    setLoading(false);

    if (outcome.ok) {
      setResult(outcome.result);
      setDurationMs(outcome.durationMs);
      setUsedModel(outcome.model);
    } else {
      setError(outcome.error);
    }
  }, [astAnalysis]);

  const handleContinue = useCallback(() => {
    if (result) {
      onContinue(result);
    }
  }, [result, onContinue]);

  const summary = astAnalysis.summary;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "24px",
        animation: "fade-in-up 0.3s ease forwards",
      }}
    >
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: "14px" }}>
        <StageNumber n={5} />
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            <h2
              style={{
                margin: 0,
                fontSize: "18px",
                fontWeight: 700,
                color: "#e2e8f0",
              }}
            >
              Semantic / Purpose Analysis
            </h2>
            <span
              style={{
                fontSize: "10px",
                fontWeight: 600,
                color: "#7b2fff",
                background: "rgba(123,47,255,0.12)",
                border: "1px solid rgba(123,47,255,0.3)",
                borderRadius: "4px",
                padding: "2px 7px",
                fontFamily: "monospace",
              }}
            >
              GEMINI AI ENGINE
            </span>
          </div>
          <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#4a5568" }}>
            Uses Gemini API to understand what the contract does before vulnerability detection.
          </p>
        </div>
      </div>

      {/* AST snapshot metrics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "12px",
        }}
      >
        <MetricCard label="Contracts" value={summary.totalContracts} />
        <MetricCard label="Functions" value={summary.totalFunctions} />
        <MetricCard label="State Variables" value={summary.totalStateVariables} />
        <MetricCard label="External Calls" value={summary.totalExternalCalls} />
      </div>

      {/* Gemini engine info */}
      <div
        style={{
          background: "#0d1628",
          border: "1px solid #1e2d4a",
          borderRadius: "10px",
          padding: "14px 16px",
          display: "flex",
          alignItems: "center",
          gap: "12px",
          flexWrap: "wrap",
        }}
      >
        <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
          ENGINE
        </span>
        <span
          style={{
            fontSize: "12px",
            color: "#7b2fff",
            fontFamily: "monospace",
            fontWeight: 600,
          }}
        >
          Google Gemini API (Hosted Backend Proxy)
        </span>
        <span style={{ fontSize: "11px", color: "#2a3f6a", marginLeft: "auto" }}>
          Key secured server-side via GEMINI_API_KEY
        </span>
      </div>

      {/* Analyze button */}
      {!result && (
        <div style={{ display: "flex", justifyContent: "center" }}>
          <button
            onClick={handleAnalyze}
            disabled={loading}
            style={{
              padding: "14px 40px",
              background: loading
                ? "#1e2d4a"
                : "linear-gradient(135deg,#7b2fff,#00d4ff)",
              border: "none",
              borderRadius: "10px",
              color: loading ? "#4a5568" : "#fff",
              fontSize: "14px",
              fontWeight: 700,
              cursor: loading ? "not-allowed" : "pointer",
              display: "flex",
              alignItems: "center",
              gap: "10px",
              transition: "opacity 0.15s",
              minWidth: "220px",
              justifyContent: "center",
            }}
          >
            {loading ? (
              <>
                <span
                  style={{
                    width: "14px",
                    height: "14px",
                    border: "2px solid #4a5568",
                    borderTopColor: "#00d4ff",
                    borderRadius: "50%",
                    display: "inline-block",
                    animation: "spin 0.8s linear infinite",
                  }}
                />
                Analyzing with Gemini…
              </>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M5.5 8l2 2 3-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                Analyze Contract
              </>
            )}
          </button>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div
          style={{
            background: "#0d1628",
            border: "1px solid #1e2d4a",
            borderRadius: "10px",
            padding: "24px",
            textAlign: "center",
          }}
        >
          <p style={{ margin: "0 0 8px", fontSize: "13px", color: "#8892a4" }}>
            Sending contract summary to Gemini API…
          </p>
          <p style={{ margin: 0, fontSize: "11px", color: "#2a3f6a" }}>
            Performing AI purpose identification and operational classification.
          </p>
        </div>
      )}

      {/* Error state */}
      {error && !loading && (
        <div
          style={{
            background: "rgba(239,68,68,0.06)",
            border: "1px solid rgba(239,68,68,0.3)",
            borderRadius: "10px",
            padding: "20px",
            display: "flex",
            flexDirection: "column",
            gap: "12px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <circle cx="9" cy="9" r="7.5" stroke="#ef4444" strokeWidth="1.5" />
              <path d="M9 5.5v4M9 11.5v1" stroke="#ef4444" strokeWidth="1.8" strokeLinecap="round" />
            </svg>
            <span
              style={{
                fontSize: "13px",
                fontWeight: 600,
                color: "#ef4444",
                textTransform: "capitalize",
              }}
            >
              {error.type.replace(/-/g, " ")} error
            </span>
          </div>
          <p style={{ margin: 0, fontSize: "13px", color: "#fca5a5", lineHeight: 1.6 }}>
            {error.message}
          </p>
          {error.detail && (
            <pre
              style={{
                margin: 0,
                padding: "10px",
                background: "#0a0e1a",
                borderRadius: "6px",
                fontSize: "11px",
                color: "#4a5568",
                fontFamily: "monospace",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                maxHeight: "120px",
                overflow: "auto",
              }}
            >
              {error.detail}
            </pre>
          )}
          {error.type === "missing-key" && (
            <p style={{ margin: 0, fontSize: "12px", color: "#4a5568" }}>
              ► Ensure <code style={{ color: "#00d4ff" }}>GEMINI_API_KEY</code> is configured in your server environment or .env file.
            </p>
          )}
          <div style={{ display: "flex", gap: "10px", marginTop: "4px" }}>
            <button
              onClick={handleAnalyze}
              style={{
                padding: "8px 20px",
                background: "rgba(239,68,68,0.15)",
                border: "1px solid rgba(239,68,68,0.4)",
                borderRadius: "7px",
                color: "#ef4444",
                fontSize: "12px",
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              Retry
            </button>
          </div>
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <>
          {/* Duration badge */}
          {durationMs !== null && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                fontSize: "11px",
                color: "#2a3f6a",
              }}
            >
              <span>✓ Gemini analysis complete in {(durationMs / 1000).toFixed(1)}s</span>
              <span>·</span>
              <span>Model: {usedModel}</span>
              <span>·</span>
              <span>File: {file.name}</span>
            </div>
          )}

          {/* Purpose & Category header */}
          <div
            style={{
              background: "linear-gradient(135deg,rgba(0,212,255,0.05),rgba(123,47,255,0.05))",
              border: "1px solid rgba(0,212,255,0.2)",
              borderRadius: "12px",
              padding: "20px 24px",
              display: "flex",
              flexDirection: "column",
              gap: "14px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
              <span
                style={{
                  fontSize: "13px",
                  fontWeight: 700,
                  color: "#00d4ff",
                  background: "rgba(0,212,255,0.1)",
                  border: "1px solid rgba(0,212,255,0.3)",
                  borderRadius: "6px",
                  padding: "3px 10px",
                  fontFamily: "monospace",
                }}
              >
                {result.category}
              </span>
            </div>
            <p
              style={{
                margin: 0,
                fontSize: "14px",
                color: "#cbd5e1",
                lineHeight: 1.7,
              }}
            >
              {result.purpose}
            </p>
            <ConfidenceBar value={result.confidence} />
          </div>

          {/* Grid of analysis sections */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "16px",
            }}
          >
            <SectionCard
              title="Assets"
              icon="💎"
              items={result.assets}
              emptyText="No specific assets identified."
              accent="#00d4ff"
            />
            <SectionCard
              title="Main Functions"
              icon="⚙️"
              items={result.mainFunctions}
              emptyText="No main functions identified."
              accent="#7b2fff"
            />
            <SectionCard
              title="Critical Operations"
              icon="⚡"
              items={result.criticalOperations}
              emptyText="No critical operations identified."
              accent="#f59e0b"
            />
            <SectionCard
              title="Access Control"
              icon="🔒"
              items={result.accessControl}
              emptyText="No access control mechanisms identified."
              accent="#10b981"
            />
            <SectionCard
              title="External Interactions"
              icon="🔗"
              items={result.externalInteractions}
              emptyText="No external interactions identified."
              accent="#00d4ff"
            />
            <SectionCard
              title="Financial Operations"
              icon="💰"
              items={result.financialOperations}
              emptyText="No financial operations identified."
              accent="#f59e0b"
            />
          </div>

          {/* Security critical areas */}
          <div
            style={{
              background: "rgba(239,68,68,0.05)",
              border: "1px solid rgba(239,68,68,0.2)",
              borderRadius: "10px",
              padding: "16px",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                marginBottom: "12px",
              }}
            >
              <span style={{ fontSize: "16px" }}>🎯</span>
              <span style={{ fontSize: "13px", fontWeight: 600, color: "#e2e8f0" }}>
                Potentially Security-Critical Areas
              </span>
              <span
                style={{
                  fontSize: "10px",
                  color: "#4a5568",
                  fontStyle: "italic",
                  marginLeft: "4px",
                }}
              >
                (not a vulnerability finding — for awareness only)
              </span>
            </div>
            {result.securityCriticalAreas.length === 0 ? (
              <span style={{ fontSize: "12px", color: "#2a3f6a", fontStyle: "italic" }}>
                None identified.
              </span>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {result.securityCriticalAreas.map((area, i) => (
                  <div
                    key={i}
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: "10px",
                      padding: "8px 12px",
                      background: "rgba(239,68,68,0.07)",
                      borderRadius: "6px",
                      border: "1px solid rgba(239,68,68,0.15)",
                    }}
                  >
                    <span
                      style={{
                        width: "6px",
                        height: "6px",
                        borderRadius: "50%",
                        background: "#ef4444",
                        flexShrink: 0,
                        marginTop: "5px",
                      }}
                    />
                    <span style={{ fontSize: "12px", color: "#fca5a5", lineHeight: 1.5 }}>
                      {area}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Re-analyze button */}
          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <button
              onClick={handleAnalyze}
              style={{
                padding: "7px 16px",
                background: "transparent",
                border: "1px solid #1e2d4a",
                borderRadius: "7px",
                color: "#4a5568",
                fontSize: "12px",
                cursor: "pointer",
              }}
            >
              Re-analyze
            </button>
          </div>
        </>
      )}

      {/* Navigation */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          paddingTop: "8px",
          borderTop: "1px solid #1e2d4a",
        }}
      >
        <button
          onClick={onBack}
          style={{
            padding: "9px 20px",
            background: "transparent",
            border: "1px solid #1e2d4a",
            borderRadius: "8px",
            color: "#4a5568",
            fontSize: "13px",
            cursor: "pointer",
          }}
        >
          ← Back to AST Analysis
        </button>

        <button
          onClick={handleContinue}
          disabled={!result}
          style={{
            padding: "9px 24px",
            background: result
              ? "linear-gradient(135deg,#7b2fff,#00d4ff)"
              : "#1e2d4a",
            border: "none",
            borderRadius: "8px",
            color: result ? "#fff" : "#2a3f6a",
            fontSize: "13px",
            fontWeight: 600,
            cursor: result ? "pointer" : "not-allowed",
            opacity: result ? 1 : 0.5,
          }}
        >
          Continue to Security Analysis →
        </button>
      </div>

      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        @keyframes fade-in-up {
          from { opacity: 0; transform: translateY(12px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
};
