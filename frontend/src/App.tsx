import React, { useState, useCallback } from "react";
import type { PipelineState, SolidityFile, CompilerInfo } from "./types/pipeline";
import { DEFAULT_PIPELINE_STAGES } from "./types/pipeline";
import type { CompilationResult } from "./utils/solidity-compiler";
import { PipelineProgress } from "./components/PipelineProgress";
import { StageUpload } from "./components/StageUpload";
import { StageCompiler } from "./components/StageCompiler";
import { StageCompile } from "./components/StageCompile";
import { StageAST } from "./components/StageAST";
import { StageSemantic } from "./components/StageSemantic";
import { StageVulnerability } from "./components/StageVulnerability";
import { StageFindings } from "./components/StageFindings";
import type { ASTAnalysisResult } from "./types/ast";
import type { SemanticResult } from "./types/semantic";
import type { VulnerabilityPlan } from "./types/vulnerability";

// ─── Initial pipeline state ────────────────────────────────────────────────────

const initialState: PipelineState = {
  currentStage: "upload",
  stages: DEFAULT_PIPELINE_STAGES,
  solidityFile: null,
  compilerInfo: null,
  compilationResult: null,
  astAnalysis: null,
  semanticResult: null,
  vulnerabilityPlan: null,
  securityAnalysis: null,
};

// ─── App ───────────────────────────────────────────────────────────────────────

const App: React.FC = () => {
  const [pipeline, setPipeline] = useState<PipelineState>(initialState);

  // ── Stage 1: file accepted ────────────────────────────────────────────────
  const handleFileAccepted = useCallback((file: SolidityFile) => {
    setPipeline((prev) => ({ ...prev, solidityFile: file }));
  }, []);

  // ── Stage 1: file removed ─────────────────────────────────────────────────
  const handleFileRemoved = useCallback(() => {
    setPipeline((prev) => ({
      ...prev,
      solidityFile: null,
      compilerInfo: null,
      compilationResult: null,
      astAnalysis: null,
      semanticResult: null,
      vulnerabilityPlan: null,
    }));
  }, []);

  // ── Stage 1 → Stage 2: continue ──────────────────────────────────────────
  const handleUploadContinue = useCallback(() => {
    setPipeline((prev) => ({
      ...prev,
      currentStage: "compiler",
      stages: prev.stages.map((s) =>
        s.id === "upload"
          ? { ...s, status: "complete" }
          : s.id === "compiler"
          ? { ...s, status: "active" }
          : s
      ),
    }));
  }, []);

  // ── Stage 2 → Stage 1: back ───────────────────────────────────────────────
  const handleCompilerBack = useCallback(() => {
    setPipeline((prev) => ({
      ...prev,
      currentStage: "upload",
      compilerInfo: null,
      compilationResult: null,
      astAnalysis: null,
      semanticResult: null,
      vulnerabilityPlan: null,
      stages: prev.stages.map((s) =>
        s.id === "upload"
          ? { ...s, status: "active" }
          : s.id === "compiler"
          ? { ...s, status: "pending" }
          : s
      ),
    }));
  }, []);

  // ── Stage 2: compile triggered ────────────────────────────────────────────
  const handleCompile = useCallback((info: CompilerInfo) => {
    setPipeline((prev) => ({
      ...prev,
      compilerInfo: info,
      compilationResult: null,           // reset previous result when re-entering
      astAnalysis: null,
      semanticResult: null,
      vulnerabilityPlan: null,
      currentStage: "compile",
      stages: prev.stages.map((s) =>
        s.id === "compiler"
          ? { ...s, status: "complete" }
          : s.id === "compile"
          ? { ...s, status: "active" }
          : s
      ),
    }));
  }, []);

  // ── Stage 3 → Stage 2: back ───────────────────────────────────────────────
  const handleCompileBack = useCallback(() => {
    setPipeline((prev) => ({
      ...prev,
      currentStage: "compiler",
      compilationResult: null,
      astAnalysis: null,
      semanticResult: null,
      vulnerabilityPlan: null,
      stages: prev.stages.map((s) =>
        s.id === "compiler"
          ? { ...s, status: "active" }
          : s.id === "compile"
          ? { ...s, status: "pending" }
          : s
      ),
    }));
  }, []);

  // ── Stage 3: compilation succeeded ────────────────────────────────────────
  const handleCompileSuccess = useCallback((result: CompilationResult) => {
    setPipeline((prev) => ({
      ...prev,
      compilationResult: result,
      currentStage: "ast",
      stages: prev.stages.map((s) =>
        s.id === "compile"
          ? { ...s, status: "complete" }
          : s.id === "ast"
          ? { ...s, status: "active" }
          : s
      ),
    }));
  }, []);

  // ── Stage 4 → Stage 3: back ───────────────────────────────────────────────
  const handleAstBack = useCallback(() => {
    setPipeline((prev) => ({
      ...prev,
      currentStage: "compile",
      astAnalysis: null,
      semanticResult: null,
      vulnerabilityPlan: null,
      stages: prev.stages.map((s) =>
        s.id === "compile"
          ? { ...s, status: "active" }
          : s.id === "ast"
          ? { ...s, status: "pending" }
          : s
      ),
    }));
  }, []);

  // ── Stage 4: continue to semantic analysis ─────────────────────────────────
  const handleAstContinue = useCallback((result: ASTAnalysisResult) => {
    setPipeline((prev) => ({
      ...prev,
      astAnalysis: result,
      semanticResult: null,
      vulnerabilityPlan: null,
      currentStage: "analysis",
      stages: prev.stages.map((s) =>
        s.id === "ast"
          ? { ...s, status: "complete" }
          : s.id === "analysis"
          ? { ...s, status: "active" }
          : s
      ),
    }));
  }, []);

  // ── Stage 5 → Stage 4: back ───────────────────────────────────────────────
  const handleSemanticBack = useCallback(() => {
    setPipeline((prev) => ({
      ...prev,
      currentStage: "ast",
      semanticResult: null,
      vulnerabilityPlan: null,
      stages: prev.stages.map((s) =>
        s.id === "ast"
          ? { ...s, status: "active" }
          : s.id === "analysis"
          ? { ...s, status: "pending" }
          : s
      ),
    }));
  }, []);

  // ── Stage 5: continue → move to Stage 6 ──────────────────────────────────
  const handleSemanticContinue = useCallback((result: SemanticResult) => {
    setPipeline((prev) => ({
      ...prev,
      semanticResult: result,
      vulnerabilityPlan: null,
      currentStage: "security",
      stages: prev.stages.map((s) =>
        s.id === "analysis"
          ? { ...s, status: "complete" }
          : s.id === "security"
          ? { ...s, status: "active" }
          : s
      ),
    }));
  }, []);

  // ── Stage 6 → Stage 5: back ───────────────────────────────────────────────
  const handleVulnerabilityBack = useCallback(() => {
    setPipeline((prev) => ({
      ...prev,
      currentStage: "analysis",
      vulnerabilityPlan: null,
      stages: prev.stages.map((s) =>
        s.id === "analysis"
          ? { ...s, status: "active" }
          : s.id === "security"
          ? { ...s, status: "pending" }
          : s
      ),
    }));
  }, []);

  // ── Stage 6: continue (stores plan, moves to next stage) ─────────────────
  const handleVulnerabilityContinue = useCallback((plan: VulnerabilityPlan) => {
    setPipeline((prev) => ({
      ...prev,
      vulnerabilityPlan: plan,
      currentStage: "findings",
      stages: prev.stages.map((s) =>
        s.id === "security"
          ? { ...s, status: "complete" }
          : s.id === "findings"
          ? { ...s, status: "active" }
          : s
      ),
    }));
  }, []);

  // ── Stage 7 → Stage 6: back ───────────────────────────────────────────────
  const handleFindingsBack = useCallback(() => {
    setPipeline((prev) => ({
      ...prev,
      currentStage: "security",
      securityAnalysis: null,
      stages: prev.stages.map((s) =>
        s.id === "security"
          ? { ...s, status: "active" }
          : s.id === "findings"
          ? { ...s, status: "pending" }
          : s
      ),
    }));
  }, []);

  // ── Render active stage ───────────────────────────────────────────────────
  const renderStage = () => {
    switch (pipeline.currentStage) {
      case "upload":
        return (
          <StageUpload
            file={pipeline.solidityFile}
            onFileAccepted={handleFileAccepted}
            onFileRemoved={handleFileRemoved}
            onContinue={handleUploadContinue}
          />
        );

      case "compiler":
        return pipeline.solidityFile ? (
          <StageCompiler
            file={pipeline.solidityFile}
            onCompile={handleCompile}
            onBack={handleCompilerBack}
          />
        ) : (
          <ComingSoon label="Stage 2 · Compiler Detection" />
        );

      case "compile":
        return pipeline.solidityFile && pipeline.compilerInfo ? (
          <StageCompile
            file={pipeline.solidityFile}
            compilerInfo={pipeline.compilerInfo}
            onSuccess={handleCompileSuccess}
            onBack={handleCompileBack}
          />
        ) : (
          <ComingSoon label="Stage 3 · Compilation" />
        );

      case "ast":
        return pipeline.solidityFile && pipeline.compilationResult ? (
          <StageAST
            file={pipeline.solidityFile}
            compilationResult={pipeline.compilationResult}
            onContinue={handleAstContinue}
            onBack={handleAstBack}
          />
        ) : (
          <ComingSoon label="Stage 4 · AST Analysis" />
        );

      case "analysis":
        return pipeline.solidityFile && pipeline.astAnalysis ? (
          <StageSemantic
            file={pipeline.solidityFile}
            astAnalysis={pipeline.astAnalysis}
            onBack={handleSemanticBack}
            onContinue={handleSemanticContinue}
          />
        ) : (
          <ComingSoon label="Stage 5 · Semantic Analysis" />
        );

      case "security":
        return pipeline.solidityFile && pipeline.astAnalysis && pipeline.semanticResult ? (
          <StageVulnerability
            file={pipeline.solidityFile}
            astAnalysis={pipeline.astAnalysis}
            semanticResult={pipeline.semanticResult}
            onBack={handleVulnerabilityBack}
            onContinue={handleVulnerabilityContinue}
          />
        ) : (
          <ComingSoon label="Stage 6 · Vulnerability Analysis" />
        );

      case "findings":
        return pipeline.solidityFile && pipeline.astAnalysis && pipeline.semanticResult && pipeline.vulnerabilityPlan ? (
          <StageFindings
            file={pipeline.solidityFile}
            astAnalysis={pipeline.astAnalysis}
            semanticResult={pipeline.semanticResult}
            vulnerabilityPlan={pipeline.vulnerabilityPlan}
            onBack={handleFindingsBack}
          />
        ) : (
          <ComingSoon label="Stage 7 · Verified Final Findings" />
        );

      default:
        return null;
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        backgroundColor: "#0a0e1a",
        display: "flex",
        flexDirection: "column",
      }}
    >
      {/* Top navigation bar */}
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 32px",
          height: "56px",
          backgroundColor: "#060910",
          borderBottom: "1px solid #1e2d4a",
          flexShrink: 0,
        }}
      >
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div
            style={{
              width: "28px",
              height: "28px",
              borderRadius: "7px",
              backgroundColor: "rgba(0,212,255,0.12)",
              border: "1px solid rgba(0,212,255,0.3)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
              <path
                d="M7.5 1L2 4v4c0 3.3 2.4 6.4 5.5 7.5C10.6 14.4 13 11.3 13 8V4L7.5 1z"
                stroke="#00d4ff"
                strokeWidth="1.2"
                strokeLinejoin="round"
                fill="rgba(0,212,255,0.1)"
              />
              <path
                d="M5 7.5l2 2 3-3"
                stroke="#00d4ff"
                strokeWidth="1.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <span
            style={{
              fontSize: "14px",
              fontWeight: 700,
              color: "#e2e8f0",
              letterSpacing: "-0.01em",
            }}
          >
            ContractAudit
          </span>
          <span
            style={{
              fontSize: "10px",
              fontWeight: 600,
              color: "#4a5568",
              backgroundColor: "#131c35",
              border: "1px solid #1e2d4a",
              borderRadius: "4px",
              padding: "2px 6px",
              fontFamily: "monospace",
            }}
          >
            v1.0
          </span>
        </div>

        {/* Right side nav indicators */}
        <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
          <NavIndicator label="Audit Pipeline" active />
          <NavIndicator label="Reports" />
          <NavIndicator label="Settings" />
          <div
            style={{
              width: "28px",
              height: "28px",
              borderRadius: "50%",
              backgroundColor: "#131c35",
              border: "1px solid #1e2d4a",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <circle cx="7" cy="5" r="2.5" stroke="#8892a4" strokeWidth="1.3" />
              <path d="M2 12c0-2.8 2.2-4 5-4s5 1.2 5 4" stroke="#8892a4" strokeWidth="1.3" strokeLinecap="round" />
            </svg>
          </div>
        </div>
      </header>

      {/* Pipeline progress track */}
      <div
        style={{
          backgroundColor: "#060910",
          borderBottom: "1px solid #1e2d4a",
          paddingBottom: "20px",
        }}
      >
        <PipelineProgress stages={pipeline.stages} />
      </div>

      {/* Main content area */}
      <main
        style={{
          flex: 1,
          padding: "32px",
          maxWidth: "960px",
          width: "100%",
          margin: "0 auto",
          boxSizing: "border-box",
        }}
      >
        {renderStage()}
      </main>

      {/* Footer */}
      <footer
        style={{
          padding: "16px 32px",
          borderTop: "1px solid #1e2d4a",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <span style={{ fontSize: "11px", color: "#2a3f6a", fontFamily: "monospace" }}>
          Smart Contract Auditor · Pipeline Stage {pipeline.stages.findIndex((s) => s.id === pipeline.currentStage) + 1} of {pipeline.stages.length}
        </span>
        <span style={{ fontSize: "11px", color: "#2a3f6a" }}>
          No data leaves your browser
        </span>
      </footer>
    </div>
  );
};

// ─── Placeholder for future stages ────────────────────────────────────────────

const ComingSoon: React.FC<{ label: string }> = ({ label }) => (
  <div
    style={{
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      minHeight: "340px",
      gap: "16px",
      color: "#4a5568",
      animation: "fade-in-up 0.3s ease forwards",
    }}
  >
    <svg width="48" height="48" viewBox="0 0 48 48" fill="none" style={{ opacity: 0.4 }}>
      <circle cx="24" cy="24" r="21" stroke="#2a3f6a" strokeWidth="2" />
      <path d="M24 14v14M24 32v2" stroke="#2a3f6a" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
    <div style={{ fontSize: "15px", fontWeight: 600, color: "#2a3f6a" }}>{label}</div>
    <div style={{ fontSize: "12px", color: "#1e2d4a" }}>This stage will be implemented next.</div>
  </div>
);

// ─── Nav indicator ─────────────────────────────────────────────────────────────

const NavIndicator: React.FC<{ label: string; active?: boolean }> = ({ label, active }) => (
  <button
    style={{
      background: "none",
      border: "none",
      cursor: "pointer",
      padding: "4px 0",
      fontSize: "12px",
      color: active ? "#e2e8f0" : "#4a5568",
      fontWeight: active ? 600 : 400,
      borderBottom: active ? "2px solid #00d4ff" : "2px solid transparent",
      fontFamily: "inherit",
      transition: "color 0.15s",
    }}
  >
    {label}
  </button>
);

export default App;
