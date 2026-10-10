import React, { useMemo, useState, useEffect } from "react";
import type { SolidityFile } from "../types/pipeline";
import type { ASTAnalysisResult } from "../types/ast";
import type { SemanticResult } from "../types/semantic";
import type { VulnerabilityPlan } from "../types/vulnerability";
import { detectSecurityVulnerabilities } from "../utils/security-detector";
import type { SecurityFinding, FindingSeverity, VulnerabilityClassification } from "../types/security";
import { checkMLModelAvailability, runMLInference, runMLInferenceAsync, correlateMLWithFindings } from "../utils/ml-analyzer";
import type { MLAnalysisResult } from "../types/ml";
import { checkForgeAvailability } from "../utils/foundry-runner";

interface StageFindingsProps {
  file: SolidityFile;
  astAnalysis: ASTAnalysisResult;
  semanticResult: SemanticResult;
  vulnerabilityPlan: VulnerabilityPlan;
  onBack: () => void;
}

const SEVERITY_COLORS: Record<FindingSeverity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#10b981",
  informational: "#6366f1",
};

const CLASS_COLORS: Record<VulnerabilityClassification, string> = {
  CONFIRMED: "#ef4444",
  POTENTIAL: "#f59e0b",
  NOT_VULNERABLE: "#10b981",
};

const CLASS_BG: Record<VulnerabilityClassification, string> = {
  CONFIRMED: "rgba(239, 68, 68, 0.15)",
  POTENTIAL: "rgba(245, 158, 11, 0.15)",
  NOT_VULNERABLE: "rgba(16, 185, 129, 0.15)",
};

const FindingCard: React.FC<{ finding: SecurityFinding }> = ({ finding }) => {
  // Visually distinguish evidence sources
  const parseEvidenceSource = (ev: string) => {
    if (ev.startsWith("ML Supporting Signal:")) {
      return { tag: "ML", color: "#818cf8", bg: "rgba(129, 140, 248, 0.12)", border: "rgba(129, 140, 248, 0.3)", text: ev };
    }
    if (ev.toLowerCase().includes("slither")) {
      return { tag: "Slither", color: "#38bdf8", bg: "rgba(56, 189, 248, 0.12)", border: "rgba(56, 189, 248, 0.3)", text: ev };
    }
    if (ev.toLowerCase().includes("foundry") || ev.toLowerCase().includes("poc") || ev.toLowerCase().includes("verified")) {
      return { tag: "Dynamic / PoC", color: "#c084fc", bg: "rgba(192, 132, 252, 0.12)", border: "rgba(192, 132, 252, 0.3)", text: ev };
    }
    return { tag: "AST", color: "#34d399", bg: "rgba(52, 211, 153, 0.12)", border: "rgba(52, 211, 153, 0.3)", text: ev };
  };

  const hasSlitherAndAst = finding.evidence.some(e => e.toLowerCase().includes("slither")) &&
                           finding.evidence.some(e => !e.startsWith("ML") && !e.toLowerCase().includes("slither"));

  return (
    <div
      data-testid={`finding-card-${finding.id}`}
      style={{
        background: "#0d1628",
        border: `1px solid ${CLASS_COLORS[finding.classification] || "#1e2d4a"}44`,
        borderLeft: `4px solid ${CLASS_COLORS[finding.classification] || "#4a5568"}`,
        borderRadius: "10px",
        padding: "18px",
        display: "flex",
        flexDirection: "column",
        gap: "14px",
        marginBottom: "14px",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "8px" }}>
        <div>
          <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "6px" }}>
            <span
              style={{
                fontSize: "11px",
                fontWeight: 700,
                color: CLASS_COLORS[finding.classification],
                background: CLASS_BG[finding.classification],
                border: `1px solid ${CLASS_COLORS[finding.classification]}44`,
                padding: "2px 8px",
                borderRadius: "4px",
                fontFamily: "monospace",
              }}
            >
              {finding.classification}
            </span>
            <span
              style={{
                fontSize: "11px",
                fontWeight: 700,
                color: SEVERITY_COLORS[finding.severity],
                background: `${SEVERITY_COLORS[finding.severity]}18`,
                border: `1px solid ${SEVERITY_COLORS[finding.severity]}44`,
                padding: "2px 8px",
                borderRadius: "4px",
                fontFamily: "monospace",
              }}
            >
              {finding.severity.toUpperCase()}
            </span>

            {hasSlitherAndAst && (
              <span
                style={{
                  fontSize: "10px",
                  fontWeight: 600,
                  color: "#38bdf8",
                  background: "rgba(56, 189, 248, 0.12)",
                  border: "1px solid rgba(56, 189, 248, 0.3)",
                  borderRadius: "4px",
                  padding: "2px 6px",
                  fontFamily: "monospace",
                }}
              >
                AST + Slither Correlated
              </span>
            )}
          </div>
          <h3 style={{ margin: 0, fontSize: "16px", fontWeight: 700, color: "#e2e8f0" }}>
            {finding.title}
          </h3>
        </div>
        <div style={{ fontSize: "12px", color: "#94a3b8", fontFamily: "monospace", background: "#060910", padding: "4px 8px", borderRadius: "4px", border: "1px solid #1e2d4a" }}>
          Contract: <strong style={{ color: "#e2e8f0" }}>{finding.contractName}</strong> | Function: <strong style={{ color: "#00d4ff" }}>{finding.functionName}()</strong>
          {finding.location?.line && <span style={{ marginLeft: "6px", color: "#64748b" }}>Line {finding.location.line}</span>}
        </div>
      </div>

      <div style={{ fontSize: "13px", color: "#cbd5e1", lineHeight: 1.5 }}>
        {finding.reason}
      </div>

      {finding.codeSnippet && (
        <div style={{ background: "#060910", border: "1px solid #1e2d4a", borderRadius: "6px", padding: "10px", fontSize: "11px", fontFamily: "monospace", color: "#94a3b8", overflowX: "auto" }}>
          <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{finding.codeSnippet}</pre>
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        <div style={{ fontSize: "11px", fontWeight: 700, color: "#94a3b8", letterSpacing: "0.05em", fontFamily: "monospace" }}>
          EVIDENCE & CORRELATION:
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {finding.evidence.map((ev, i) => {
            const src = parseEvidenceSource(ev);
            return (
              <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "8px", fontSize: "12px", color: "#cbd5e1" }}>
                <span
                  style={{
                    fontSize: "9px",
                    fontWeight: 700,
                    color: src.color,
                    background: src.bg,
                    border: `1px solid ${src.border}`,
                    padding: "1px 5px",
                    borderRadius: "3px",
                    fontFamily: "monospace",
                    marginTop: "2px",
                    flexShrink: 0,
                  }}
                >
                  {src.tag}
                </span>
                <span style={{ lineHeight: 1.4 }}>{src.text}</span>
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.2)", padding: "10px 12px", borderRadius: "6px", fontSize: "12px", color: "#34d399" }}>
        <strong style={{ color: "#10b981" }}>Recommendation:</strong> {finding.recommendation}
      </div>
    </div>
  );
};

export const StageFindings: React.FC<StageFindingsProps> = ({
  file,
  astAnalysis,
  semanticResult,
  vulnerabilityPlan,
  onBack,
}) => {
  const [mlResult, setMlResult] = useState<MLAnalysisResult>(() => {
    if (checkMLModelAvailability()) {
      return runMLInference(file.source);
    }
    return { available: false, predictions: [], modelName: "CodeBERT-MultiLabel-Classifier" };
  });

  useEffect(() => {
    let active = true;
    runMLInferenceAsync(file.source).then((res) => {
      if (active) {
        setMlResult(res);
      }
    });
    return () => {
      active = false;
    };
  }, [file.source]);

  const rawResult = useMemo(() => {
    return detectSecurityVulnerabilities(astAnalysis, vulnerabilityPlan, semanticResult);
  }, [astAnalysis, vulnerabilityPlan, semanticResult]);

  const result = useMemo(() => {
    if (mlResult.available && mlResult.predictions.length > 0) {
      return {
        ...rawResult,
        findings: correlateMLWithFindings(rawResult.findings, mlResult),
      };
    }
    return rawResult;
  }, [rawResult, mlResult]);

  const forgeAvailable = useMemo(() => checkForgeAvailability(), []);

  // Filter findings into explicit sections
  const confirmedFindings = useMemo(() => result.findings.filter(f => f.classification === "CONFIRMED"), [result.findings]);
  const potentialFindings = useMemo(() => result.findings.filter(f => f.classification === "POTENTIAL"), [result.findings]);
  const infoFindings = useMemo(() => result.findings.filter(f => f.classification === "NOT_VULNERABLE"), [result.findings]);

  // Calculate Overall Risk Level strictly from FINAL VERIFIED findings (CONFIRMED & POTENTIAL)
  const overallRisk = useMemo(() => {
    if (confirmedFindings.some(f => f.severity === "critical")) return { level: "CRITICAL RISK", color: "#ef4444", bg: "rgba(239,68,68,0.12)", border: "rgba(239,68,68,0.3)" };
    if (confirmedFindings.some(f => f.severity === "high")) return { level: "HIGH RISK", color: "#f97316", bg: "rgba(249,115,22,0.12)", border: "rgba(249,115,22,0.3)" };
    if (confirmedFindings.length > 0 || potentialFindings.some(f => f.severity === "high" || f.severity === "medium")) {
      return { level: "MEDIUM RISK", color: "#f59e0b", bg: "rgba(245,158,11,0.12)", border: "rgba(245,158,11,0.3)" };
    }
    if (potentialFindings.length > 0) return { level: "LOW RISK", color: "#10b981", bg: "rgba(16,185,129,0.12)", border: "rgba(16,185,129,0.3)" };
    return { level: "MINIMAL / INFORMATIONAL", color: "#6366f1", bg: "rgba(99,102,241,0.12)", border: "rgba(99,102,241,0.3)" };
  }, [confirmedFindings, potentialFindings]);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "24px",
        animation: "fade-in-up 0.3s ease forwards",
      }}
    >
      {/* Header with Risk Banner */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "16px" }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: "14px" }}>
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
            7
          </div>
          <div>
            <h2 style={{ margin: 0, fontSize: "18px", fontWeight: 700, color: "#e2e8f0" }}>
              Audit Report & Final Verified Findings
            </h2>
            <p style={{ margin: "4px 0 0", fontSize: "12px", color: "#4a5568" }}>
              Comprehensive correlation of AST evidence, Slither findings, ML signals, and control flow.
            </p>
          </div>
        </div>

        {/* Overall Risk Badge */}
        <div
          style={{
            background: overallRisk.bg,
            border: `1px solid ${overallRisk.border}`,
            padding: "8px 16px",
            borderRadius: "8px",
            display: "flex",
            flexDirection: "column",
            alignItems: "flex-end",
          }}
        >
          <span style={{ fontSize: "10px", color: "#94a3b8", fontFamily: "monospace", textTransform: "uppercase" }}>OVERALL AUDIT RISK</span>
          <span style={{ fontSize: "14px", fontWeight: 800, color: overallRisk.color, letterSpacing: "0.05em" }}>{overallRisk.level}</span>
        </div>
      </div>

      {/* Audit Summary Cards at top */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: "8px" }}>
        <div style={{ background: "#0d1628", padding: "12px", borderRadius: "8px", border: "1px solid #1e2d4a" }}>
          <div style={{ fontSize: "10px", color: "#94a3b8", fontFamily: "monospace" }}>TOTAL</div>
          <div style={{ fontSize: "20px", fontWeight: 700, color: "#e2e8f0" }}>{result.summary.totalFindings}</div>
        </div>
        <div style={{ background: "#0d1628", padding: "12px", borderRadius: "8px", border: "1px solid #ef444444" }}>
          <div style={{ fontSize: "10px", color: "#ef4444", fontFamily: "monospace", fontWeight: 700 }}>CONFIRMED</div>
          <div style={{ fontSize: "20px", fontWeight: 700, color: "#ef4444" }}>{result.summary.confirmedCount}</div>
        </div>
        <div style={{ background: "#0d1628", padding: "12px", borderRadius: "8px", border: "1px solid #f59e0b44" }}>
          <div style={{ fontSize: "10px", color: "#f59e0b", fontFamily: "monospace", fontWeight: 700 }}>POTENTIAL</div>
          <div style={{ fontSize: "20px", fontWeight: 700, color: "#f59e0b" }}>{result.summary.potentialCount}</div>
        </div>
        <div style={{ background: "#0d1628", padding: "12px", borderRadius: "8px", border: "1px solid #ef444433" }}>
          <div style={{ fontSize: "10px", color: "#94a3b8", fontFamily: "monospace" }}>CRITICAL</div>
          <div style={{ fontSize: "20px", fontWeight: 700, color: "#ef4444" }}>{result.summary.criticalCount}</div>
        </div>
        <div style={{ background: "#0d1628", padding: "12px", borderRadius: "8px", border: "1px solid #f9731633" }}>
          <div style={{ fontSize: "10px", color: "#94a3b8", fontFamily: "monospace" }}>HIGH</div>
          <div style={{ fontSize: "20px", fontWeight: 700, color: "#f97316" }}>{result.summary.highCount}</div>
        </div>
        <div style={{ background: "#0d1628", padding: "12px", borderRadius: "8px", border: "1px solid #f59e0b33" }}>
          <div style={{ fontSize: "10px", color: "#94a3b8", fontFamily: "monospace" }}>MEDIUM</div>
          <div style={{ fontSize: "20px", fontWeight: 700, color: "#f59e0b" }}>{result.summary.mediumCount}</div>
        </div>
        <div style={{ background: "#0d1628", padding: "12px", borderRadius: "8px", border: "1px solid #10b98133" }}>
          <div style={{ fontSize: "10px", color: "#94a3b8", fontFamily: "monospace" }}>LOW</div>
          <div style={{ fontSize: "20px", fontWeight: 700, color: "#10b981" }}>{result.summary.lowCount}</div>
        </div>
      </div>

      {/* Main Findings Sections */}
      {result.findings.length === 0 ? (
        <div style={{ padding: "40px", textAlign: "center", color: "#64748b", border: "1px solid #1e2d4a", borderRadius: "10px", background: "#08101e" }}>
          <h3 style={{ margin: "0 0 8px", color: "#10b981", fontSize: "16px" }}>No Vulnerabilities Detected</h3>
          <p style={{ margin: 0, fontSize: "13px" }}>Deterministic AST, Slither correlation, and control flow analysis found no actionable vulnerabilities in this contract.</p>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
          {/* CONFIRMED FINDINGS */}
          {confirmedFindings.length > 0 && (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
                <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#ef4444" }}></span>
                <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "#ef4444", letterSpacing: "0.03em" }}>
                  CONFIRMED FINDINGS ({confirmedFindings.length})
                </h3>
              </div>
              {confirmedFindings.map(f => (
                <FindingCard key={f.id} finding={f} />
              ))}
            </div>
          )}

          {/* POTENTIAL FINDINGS */}
          {potentialFindings.length > 0 && (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
                <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#f59e0b" }}></span>
                <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "#f59e0b", letterSpacing: "0.03em" }}>
                  POTENTIAL FINDINGS ({potentialFindings.length})
                </h3>
              </div>
              {potentialFindings.map(f => (
                <FindingCard key={f.id} finding={f} />
              ))}
            </div>
          )}

          {/* INFORMATIONAL / NOT_VULNERABLE */}
          {infoFindings.length > 0 && (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
                <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#10b981" }}></span>
                <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "#10b981", letterSpacing: "0.03em" }}>
                  INFORMATIONAL / GUARDED CODE ({infoFindings.length})
                </h3>
              </div>
              {infoFindings.map(f => (
                <FindingCard key={f.id} finding={f} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Candidate Security Checks section (Stage 6 Scoping Plan) */}
      <div
        style={{
          background: "#08101e",
          border: "1px dashed #1e2d4a",
          borderRadius: "10px",
          padding: "16px",
          display: "flex",
          flexDirection: "column",
          gap: "10px",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: "12px", fontWeight: 700, color: "#94a3b8", fontFamily: "monospace" }}>
            SECURITY CHECKS / CANDIDATES (STAGE 6 PLAN)
          </span>
          <span style={{ fontSize: "11px", color: "#64748b", fontFamily: "monospace" }}>
            {vulnerabilityPlan.selectedChecks.length} CHECKS EVALUATED
          </span>
        </div>
        <div style={{ fontSize: "12px", color: "#64748b", lineHeight: 1.4 }}>
          These security candidate checks were scoped based on contract type ({vulnerabilityPlan.contractCategory}). Candidates are evaluated deterministically to produce final verified findings above.
        </div>
      </div>

      {/* ML Supporting Signal Informational Panel */}
      <div
        style={{
          background: "#08101e",
          border: "1px solid #1e2d4a",
          borderRadius: "10px",
          padding: "16px",
          display: "flex",
          flexDirection: "column",
          gap: "12px",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "#818cf8", letterSpacing: "0.05em", fontFamily: "monospace" }}>
            ML SUPPORTING SIGNAL
          </div>
          <span style={{ fontSize: "11px", color: mlResult.available ? "#34d399" : "#64748b", fontFamily: "monospace" }}>
            {mlResult.available
              ? `MODEL: ${mlResult.modelName || "CodeBERT-MultiLabel"}${mlResult.device ? ` (${mlResult.device.toUpperCase()})` : ""}`
              : "ML MODEL UNAVAILABLE"}
          </span>
        </div>

        {mlResult.available ? (
          <div>
            <div style={{ fontSize: "12px", color: "#94a3b8", lineHeight: 1.4, marginBottom: "10px" }}>
              Secondary CodeBERT multi-label classifier predictions are used strictly as supporting context.
              Deterministic AST analysis remains authoritative for final confirmed findings.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "8px" }}>
              {mlResult.predictions.map((p) => (
                <div
                  key={p.label}
                  style={{
                    background: "#060910",
                    border: `1px solid ${p.predicted ? "#818cf844" : "#1e2d4a"}`,
                    padding: "6px 10px",
                    borderRadius: "6px",
                    display: "flex",
                    justifyContent: "space-between",
                    fontSize: "11px",
                  }}
                >
                  <span style={{ color: p.predicted ? "#e2e8f0" : "#64748b", fontFamily: "monospace" }}>{p.label}</span>
                  <span style={{ color: p.predicted ? "#818cf8" : "#475569", fontWeight: p.predicted ? 700 : 400 }}>
                    {(p.score * 100).toFixed(1)}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div style={{ fontSize: "12px", color: "#64748b" }}>
            Local ML Model unavailable (requires PyTorch & CodeBERT model artifacts). Static AST detectors remain 100% operational.
          </div>
        )}
      </div>

      {/* Empty States / Status Footer for Integrations */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "12px" }}>
        <div style={{ background: "#060910", border: "1px solid #1e2d4a", padding: "10px 14px", borderRadius: "8px", fontSize: "11px", color: "#64748b" }}>
          <strong style={{ color: "#94a3b8" }}>Slither Static Analyzer:</strong> Integrated via AST correlation.
        </div>
        <div style={{ background: "#060910", border: "1px solid #1e2d4a", padding: "10px 14px", borderRadius: "8px", fontSize: "11px", color: "#64748b" }}>
          <strong style={{ color: "#94a3b8" }}>Foundry Dynamic Testing:</strong> {forgeAvailable ? "Available" : "Dynamic analysis unavailable (Foundry forge CLI not found in PATH)"}.
        </div>
      </div>

      <div
        style={{
          display: "flex",
          justifyContent: "flex-start",
          paddingTop: "16px",
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
            color: "#94a3b8",
            fontSize: "13px",
            cursor: "pointer",
          }}
        >
          ← Back to Vulnerability Plan
        </button>
      </div>
    </div>
  );
};
