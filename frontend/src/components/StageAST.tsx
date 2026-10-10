import React, { useState, useMemo } from "react";
import type { SolidityFile } from "../types/pipeline";
import type { CompilationResult } from "../utils/solidity-compiler";
import type {
  ASTAnalysisResult,
  ASTContract,
  ASTFunction,
  ASTStateVariable,
  ASTModifier,
  ASTEvent,
  ASTExternalCall,
  ASTEtherTransfer,
  ASTInheritance,
  SourceLocation,
  FunctionVisibility,
} from "../types/ast";
import { analyzeSolidityAST } from "../utils/ast-analyzer";

// ─── Component Props ───────────────────────────────────────────────────────────

interface StageASTProps {
  file: SolidityFile;
  compilationResult: CompilationResult;
  onContinue: (result: ASTAnalysisResult) => void;
  onBack: () => void;
}

type TabKey =
  | "overview"
  | "functions"
  | "stateVars"
  | "modifiers"
  | "events"
  | "externalCalls"
  | "etherTransfers"
  | "inheritance"
  | "rawAst";

// ─── Component ─────────────────────────────────────────────────────────────────

export const StageAST: React.FC<StageASTProps> = ({
  file,
  compilationResult,
  onContinue,
  onBack,
}) => {
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [selectedContract, setSelectedContract] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [filterVisibility, setFilterVisibility] = useState<string>("all");
  const [snippetModal, setSnippetModal] = useState<{
    title: string;
    snippet: string;
    location: SourceLocation;
  } | null>(null);

  // ── Run AST Analysis ─────────────────────────────────────────────────────────
  const { analysisResult, error } = useMemo(() => {
    try {
      const astData = compilationResult.ast || {};
      const result = analyzeSolidityAST(astData, file.source, file.name);
      return { analysisResult: result, error: null };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to analyze Solidity AST";
      return { analysisResult: null, error: msg };
    }
  }, [compilationResult, file]);

  // ── Filtered items based on selectedContract and search query ───────────────
  const filteredContracts = useMemo(() => {
    if (!analysisResult) return [];
    if (selectedContract === "all") return analysisResult.contracts;
    return analysisResult.contracts.filter((c) => c.name === selectedContract);
  }, [analysisResult, selectedContract]);

  const filteredFunctions = useMemo(() => {
    if (!analysisResult) return [];
    let list = analysisResult.functions;

    if (selectedContract !== "all") {
      list = list.filter((f) => f.contractName === selectedContract);
    }

    if (filterVisibility !== "all") {
      list = list.filter((f) => f.visibility === filterVisibility);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (f) =>
          f.name.toLowerCase().includes(q) ||
          f.signature.toLowerCase().includes(q) ||
          f.contractName.toLowerCase().includes(q)
      );
    }

    return list;
  }, [analysisResult, selectedContract, filterVisibility, searchQuery]);

  const filteredStateVars = useMemo(() => {
    if (!analysisResult) return [];
    let list = analysisResult.stateVariables;

    if (selectedContract !== "all") {
      list = list.filter((v) => v.contractName === selectedContract);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (v) =>
          v.name.toLowerCase().includes(q) ||
          v.type.toLowerCase().includes(q) ||
          v.contractName.toLowerCase().includes(q)
      );
    }

    return list;
  }, [analysisResult, selectedContract, searchQuery]);

  const filteredModifiers = useMemo(() => {
    if (!analysisResult) return [];
    let list = analysisResult.modifiers;

    if (selectedContract !== "all") {
      list = list.filter((m) => m.contractName === selectedContract);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (m) =>
          m.name.toLowerCase().includes(q) ||
          m.contractName.toLowerCase().includes(q)
      );
    }

    return list;
  }, [analysisResult, selectedContract, searchQuery]);

  const filteredEvents = useMemo(() => {
    if (!analysisResult) return [];
    let list = analysisResult.events;

    if (selectedContract !== "all") {
      list = list.filter((e) => e.contractName === selectedContract);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (e) =>
          e.name.toLowerCase().includes(q) ||
          e.signature.toLowerCase().includes(q) ||
          e.contractName.toLowerCase().includes(q)
      );
    }

    return list;
  }, [analysisResult, selectedContract, searchQuery]);

  const filteredCalls = useMemo(() => {
    if (!analysisResult) return [];
    let list = analysisResult.externalCalls;

    if (selectedContract !== "all") {
      list = list.filter((c) => c.contractName === selectedContract);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (c) =>
          c.target.toLowerCase().includes(q) ||
          c.method.toLowerCase().includes(q) ||
          c.contractName.toLowerCase().includes(q) ||
          c.functionName.toLowerCase().includes(q)
      );
    }

    return list;
  }, [analysisResult, selectedContract, searchQuery]);

  const filteredTransfers = useMemo(() => {
    if (!analysisResult) return [];
    let list = analysisResult.etherTransfers;

    if (selectedContract !== "all") {
      list = list.filter((t) => t.contractName === selectedContract);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (t) =>
          t.recipient.toLowerCase().includes(q) ||
          t.amount.toLowerCase().includes(q) ||
          t.contractName.toLowerCase().includes(q) ||
          t.functionName.toLowerCase().includes(q)
      );
    }

    return list;
  }, [analysisResult, selectedContract, searchQuery]);

  const filteredInheritance = useMemo(() => {
    if (!analysisResult) return [];
    if (selectedContract === "all") return analysisResult.inheritance;
    return analysisResult.inheritance.filter(
      (i) => i.contractName === selectedContract
    );
  }, [analysisResult, selectedContract]);

  const canContinue = analysisResult !== null && !error;

  const handleContinue = () => {
    if (analysisResult && canContinue) {
      onContinue(analysisResult);
    }
  };

  const handleOpenSnippet = (title: string, snippet: string | undefined, location: SourceLocation) => {
    setSnippetModal({
      title,
      snippet: snippet || file.source.slice(location.start, location.end),
      location,
    });
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: "20px",
        animation: "fade-in-up 0.35s ease forwards",
        width: "100%",
      }}
    >
      {/* ── Section header ─────────────────────────────────────────────────── */}
      <div style={{ width: "100%", maxWidth: "960px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
          <StageNumber>04</StageNumber>
          <h2
            style={{
              margin: 0,
              fontSize: "18px",
              fontWeight: 700,
              color: "#e2e8f0",
              letterSpacing: "-0.02em",
            }}
          >
            AST Analysis
          </h2>
        </div>
        <p style={{ margin: "0 0 0 42px", fontSize: "13px", color: "#4a5568" }}>
          Abstract Syntax Tree analysis for <code style={inlineCode}>{file.name}</code>.
          Extracting contracts, functions, state variables, modifiers, events, external calls, and ETH transfers.
        </p>
      </div>

      {/* ── Error State ───────────────────────────────────────────────────── */}

      {error && (
        <div
          style={{
            width: "100%",
            maxWidth: "960px",
            padding: "16px 20px",
            borderRadius: "12px",
            backgroundColor: "rgba(255,68,68,0.07)",
            border: "1px solid rgba(255,68,68,0.22)",
            color: "#ff6666",
            fontSize: "13px",
          }}
        >
          <strong>AST Extraction Error:</strong> {error}
        </div>
      )}

      {/* ── Main Content when analysis completes ────────────────────────────── */}
      {analysisResult && (
        <>
          {/* ── Metrics Banner ──────────────────────────────────────────────── */}
          <div
            style={{
              width: "100%",
              maxWidth: "960px",
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(110px, 1fr))",
              gap: "10px",
            }}
          >
            <MetricCard
              label="Contracts"
              value={analysisResult.summary.totalContracts}
              color="#00d4ff"
              active={activeTab === "overview"}
              onClick={() => setActiveTab("overview")}
            />
            <MetricCard
              label="Functions"
              value={analysisResult.summary.totalFunctions}
              color="#38bdf8"
              sub={`${analysisResult.summary.publicOrExternalFunctions} pub/ext`}
              active={activeTab === "functions"}
              onClick={() => setActiveTab("functions")}
            />
            <MetricCard
              label="State Vars"
              value={analysisResult.summary.totalStateVariables}
              color="#a78bfa"
              active={activeTab === "stateVars"}
              onClick={() => setActiveTab("stateVars")}
            />
            <MetricCard
              label="Modifiers"
              value={analysisResult.summary.totalModifiers}
              color="#818cf8"
              active={activeTab === "modifiers"}
              onClick={() => setActiveTab("modifiers")}
            />
            <MetricCard
              label="Events"
              value={analysisResult.summary.totalEvents}
              color="#c084fc"
              active={activeTab === "events"}
              onClick={() => setActiveTab("events")}
            />
            <MetricCard
              label="External Calls"
              value={analysisResult.summary.totalExternalCalls}
              color="#f59e0b"
              alert={analysisResult.summary.totalExternalCalls > 0}
              active={activeTab === "externalCalls"}
              onClick={() => setActiveTab("externalCalls")}
            />
            <MetricCard
              label="ETH Transfers"
              value={analysisResult.summary.totalEtherTransfers}
              color="#ff6666"
              alert={analysisResult.summary.totalEtherTransfers > 0}
              active={activeTab === "etherTransfers"}
              onClick={() => setActiveTab("etherTransfers")}
            />
          </div>

          {/* ── Toolbar: Contract filter, Search, Tabs ───────────────────────── */}
          <div
            style={{
              width: "100%",
              maxWidth: "960px",
              display: "flex",
              flexDirection: "column",
              gap: "12px",
            }}
          >
            {/* Filter controls row */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "12px",
                flexWrap: "wrap",
              }}
            >
              {/* Contract filter dropdown */}
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "12px", color: "#4a5568" }}>Contract:</span>
                <select
                  value={selectedContract}
                  onChange={(e) => setSelectedContract(e.target.value)}
                  style={{
                    backgroundColor: "#0f1629",
                    color: "#e2e8f0",
                    border: "1px solid #1e2d4a",
                    borderRadius: "6px",
                    padding: "6px 12px",
                    fontSize: "12px",
                    fontFamily: "monospace",
                    cursor: "pointer",
                    outline: "none",
                  }}
                >
                  <option value="all">All Contracts ({analysisResult.contracts.length})</option>
                  {analysisResult.contracts.map((c) => (
                    <option key={c.name} value={c.name}>
                      {c.name} ({c.kind})
                    </option>
                  ))}
                </select>
              </div>

              {/* Search input */}
              <div style={{ display: "flex", alignItems: "center", gap: "8px", flex: 1, maxWidth: "340px" }}>
                <input
                  type="text"
                  placeholder="Search functions, variables, events…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    width: "100%",
                    backgroundColor: "#0f1629",
                    color: "#e2e8f0",
                    border: "1px solid #1e2d4a",
                    borderRadius: "6px",
                    padding: "6px 12px",
                    fontSize: "12px",
                    outline: "none",
                    fontFamily: "inherit",
                  }}
                />
              </div>

              {/* Function visibility filter (visible on functions tab) */}
              {activeTab === "functions" && (
                <div style={{ display: "flex", gap: "4px" }}>
                  {(["all", "external", "public", "internal", "private"] as const).map((v) => (
                    <button
                      key={v}
                      onClick={() => setFilterVisibility(v)}
                      style={{
                        padding: "4px 8px",
                        fontSize: "11px",
                        borderRadius: "4px",
                        border: filterVisibility === v ? "1px solid #00d4ff" : "1px solid #1e2d4a",
                        backgroundColor: filterVisibility === v ? "rgba(0,212,255,0.1)" : "transparent",
                        color: filterVisibility === v ? "#00d4ff" : "#4a5568",
                        cursor: "pointer",
                        textTransform: "capitalize",
                      }}
                    >
                      {v}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Tab navigation bar */}
            <div
              style={{
                display: "flex",
                gap: "2px",
                borderBottom: "1px solid #1e2d4a",
                overflowX: "auto",
                whiteSpace: "nowrap",
              }}
            >
              <Tab
                label={`Overview (${filteredContracts.length})`}
                active={activeTab === "overview"}
                onClick={() => setActiveTab("overview")}
              />
              <Tab
                label={`Functions (${filteredFunctions.length})`}
                active={activeTab === "functions"}
                onClick={() => setActiveTab("functions")}
              />
              <Tab
                label={`State Vars (${filteredStateVars.length})`}
                active={activeTab === "stateVars"}
                onClick={() => setActiveTab("stateVars")}
              />
              <Tab
                label={`Modifiers (${filteredModifiers.length})`}
                active={activeTab === "modifiers"}
                onClick={() => setActiveTab("modifiers")}
              />
              <Tab
                label={`Events (${filteredEvents.length})`}
                active={activeTab === "events"}
                onClick={() => setActiveTab("events")}
              />
              <Tab
                label={`External Calls (${filteredCalls.length})`}
                active={activeTab === "externalCalls"}
                onClick={() => setActiveTab("externalCalls")}
                variant={filteredCalls.length > 0 ? "warning" : undefined}
              />
              <Tab
                label={`ETH Transfers (${filteredTransfers.length})`}
                active={activeTab === "etherTransfers"}
                onClick={() => setActiveTab("etherTransfers")}
                variant={filteredTransfers.length > 0 ? "error" : undefined}
              />
              <Tab
                label={`Inheritance (${filteredInheritance.length})`}
                active={activeTab === "inheritance"}
                onClick={() => setActiveTab("inheritance")}
              />
              <Tab
                label="Raw AST"
                active={activeTab === "rawAst"}
                onClick={() => setActiveTab("rawAst")}
              />
            </div>

            {/* Tab Panels */}
            <div
              style={{
                backgroundColor: "#0f1629",
                border: "1px solid #1e2d4a",
                borderTop: "none",
                borderRadius: "0 0 12px 12px",
                overflow: "hidden",
                minHeight: "360px",
              }}
            >
              {activeTab === "overview" && (
                <OverviewTab
                  contracts={filteredContracts}
                  inheritance={analysisResult.inheritance}
                  onSelectSnippet={handleOpenSnippet}
                />
              )}

              {activeTab === "functions" && (
                <FunctionsTab
                  functions={filteredFunctions}
                  onSelectSnippet={handleOpenSnippet}
                />
              )}

              {activeTab === "stateVars" && (
                <StateVarsTab
                  stateVars={filteredStateVars}
                  onSelectSnippet={handleOpenSnippet}
                />
              )}

              {activeTab === "modifiers" && (
                <ModifiersTab
                  modifiers={filteredModifiers}
                  onSelectSnippet={handleOpenSnippet}
                />
              )}

              {activeTab === "events" && (
                <EventsTab
                  events={filteredEvents}
                  onSelectSnippet={handleOpenSnippet}
                />
              )}

              {activeTab === "externalCalls" && (
                <ExternalCallsTab
                  calls={filteredCalls}
                  onSelectSnippet={handleOpenSnippet}
                />
              )}

              {activeTab === "etherTransfers" && (
                <EtherTransfersTab
                  transfers={filteredTransfers}
                  onSelectSnippet={handleOpenSnippet}
                />
              )}

              {activeTab === "inheritance" && (
                <InheritanceTab
                  inheritance={filteredInheritance}
                  contracts={analysisResult.contracts}
                  onSelectSnippet={handleOpenSnippet}
                />
              )}

              {activeTab === "rawAst" && (
                <RawAstTab ast={analysisResult.rawAst} />
              )}
            </div>
          </div>
        </>
      )}

      {/* ── Action Row (Back and Continue) ─────────────────────────────────── */}
      <div
        style={{
          width: "100%",
          maxWidth: "960px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          paddingTop: "8px",
          paddingBottom: "8px",
        }}
      >
        <BackButton onClick={onBack} />

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
          Continue to Semantic Analysis
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
      </div>

      {/* ── Snippet Viewer Modal ────────────────────────────────────────────── */}
      {snippetModal && (
        <SnippetModal
          title={snippetModal.title}
          snippet={snippetModal.snippet}
          location={snippetModal.location}
          onClose={() => setSnippetModal(null)}
        />
      )}
    </div>
  );
};

// ─── Overview Tab ─────────────────────────────────────────────────────────────

const OverviewTab: React.FC<{
  contracts: ASTContract[];
  inheritance: ASTInheritance[];
  onSelectSnippet: (title: string, snippet: string | undefined, loc: SourceLocation) => void;
}> = ({ contracts, onSelectSnippet }) => {
  if (contracts.length === 0) {
    return <EmptyMessage message="No contracts found matching filter." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px", padding: "20px" }}>
      {contracts.map((c) => (
        <div
          key={c.name}
          style={{
            backgroundColor: "#0a0e1a",
            border: "1px solid #1e2d4a",
            borderRadius: "10px",
            padding: "18px 20px",
            display: "flex",
            flexDirection: "column",
            gap: "14px",
          }}
        >
          {/* Header */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <span
                style={{
                  fontSize: "16px",
                  fontWeight: 700,
                  color: "#e2e8f0",
                  fontFamily: "monospace",
                }}
              >
                {c.name}
              </span>
              <KindBadge kind={c.kind} />
              {c.bases.length > 0 && (
                <span style={{ fontSize: "11px", color: "#4a5568" }}>
                  is <span style={{ color: "#00d4ff", fontFamily: "monospace" }}>{c.bases.join(", ")}</span>
                </span>
              )}
            </div>

            <LocationButton
              location={c.location}
              onClick={() => onSelectSnippet(`Contract: ${c.name}`, undefined, c.location)}
            />
          </div>

          {/* Stats Bar */}
          <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", fontSize: "12px" }}>
            <StatItem label="Functions" value={c.functions.length} />
            <StatItem label="State Variables" value={c.stateVariables.length} />
            <StatItem label="Modifiers" value={c.modifiers.length} />
            <StatItem label="Events" value={c.events.length} />
            <StatItem label="Structs" value={c.structs.length} />
            <StatItem label="Enums" value={c.enums.length} />
            <StatItem
              label="External Calls"
              value={c.externalCalls.length}
              highlight={c.externalCalls.length > 0 ? "#f59e0b" : undefined}
            />
            <StatItem
              label="ETH Transfers"
              value={c.etherTransfers.length}
              highlight={c.etherTransfers.length > 0 ? "#ff6666" : undefined}
            />
          </div>

          {/* Special Functions indicators */}
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            {c.constructorDef ? (
              <SpecialBadge label="Constructor" detail={`params: ${c.constructorDef.parameters.length}`} />
            ) : (
              <SpecialBadge label="Default Constructor" dim />
            )}
            {c.receiveDef && <SpecialBadge label="receive() payable" accent="#f59e0b" />}
            {c.fallbackDef && <SpecialBadge label="fallback()" accent="#a78bfa" />}
          </div>
        </div>
      ))}
    </div>
  );
};

// ─── Functions Tab ────────────────────────────────────────────────────────────

const FunctionsTab: React.FC<{
  functions: ASTFunction[];
  onSelectSnippet: (title: string, snippet: string | undefined, loc: SourceLocation) => void;
}> = ({ functions, onSelectSnippet }) => {
  if (functions.length === 0) {
    return <EmptyMessage message="No functions found matching query." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {functions.map((fn, idx) => (
        <div
          key={`${fn.contractName}-${fn.signature}-${idx}`}
          style={{
            padding: "16px 20px",
            borderBottom: idx < functions.length - 1 ? "1px solid #1e2d4a" : "none",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: "16px",
            transition: "background-color 0.15s",
          }}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "6px", flex: 1 }}>
            {/* Signature & Badges */}
            <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
              <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
                {fn.contractName}.
              </span>
              <span
                style={{
                  fontSize: "13px",
                  fontWeight: 700,
                  color: "#e2e8f0",
                  fontFamily: "monospace",
                }}
              >
                {fn.name}
              </span>
              <VisibilityBadge visibility={fn.visibility} />
              <MutabilityBadge mutability={fn.stateMutability} />
              {fn.kind !== "function" && <KindBadge kind={fn.kind} />}
              {fn.isVirtual && <Pill label="virtual" />}
              {fn.isOverride && <Pill label="override" />}
              {fn.modifiers.map((m) => (
                <Pill key={m} label={m} color="#818cf8" />
              ))}
              {fn.externalCalls.length > 0 && (
                <Pill label={`${fn.externalCalls.length} calls`} color="#f59e0b" />
              )}
              {fn.etherTransfers.length > 0 && (
                <Pill label="ETH transfer" color="#ff4444" />
              )}
            </div>

            {/* Parameters & Return */}
            <div style={{ fontSize: "11px", color: "#8892a4", fontFamily: "monospace" }}>
              <span>({fn.parameters.map((p) => `${p.type}${p.name ? ` ${p.name}` : ""}`).join(", ")})</span>
              {fn.returnParameters.length > 0 && (
                <span style={{ color: "#4a5568" }}>
                  {" "}returns ({fn.returnParameters.map((r) => `${r.type}${r.name ? ` ${r.name}` : ""}`).join(", ")})
                </span>
              )}
            </div>
          </div>

          <LocationButton
            location={fn.location}
            onClick={() => onSelectSnippet(`Function: ${fn.name}`, fn.codeSnippet, fn.location)}
          />
        </div>
      ))}
    </div>
  );
};

// ─── State Variables Tab ──────────────────────────────────────────────────────

const StateVarsTab: React.FC<{
  stateVars: ASTStateVariable[];
  onSelectSnippet: (title: string, snippet: string | undefined, loc: SourceLocation) => void;
}> = ({ stateVars, onSelectSnippet }) => {
  if (stateVars.length === 0) {
    return <EmptyMessage message="No state variables found matching query." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {stateVars.map((v, idx) => (
        <div
          key={`${v.contractName}-${v.name}-${idx}`}
          style={{
            padding: "14px 20px",
            borderBottom: idx < stateVars.length - 1 ? "1px solid #1e2d4a" : "none",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "16px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap", flex: 1 }}>
            <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
              {v.contractName}.
            </span>
            <span
              style={{
                fontSize: "13px",
                fontWeight: 700,
                color: "#e2e8f0",
                fontFamily: "monospace",
              }}
            >
              {v.name}
            </span>
            <code
              style={{
                fontSize: "11px",
                color: "#00d4ff",
                backgroundColor: "#131c35",
                padding: "2px 6px",
                borderRadius: "4px",
                fontFamily: "monospace",
              }}
            >
              {v.type}
            </code>
            <VisibilityBadge visibility={v.visibility} />
            {v.mutability !== "mutable" && (
              <Pill
                label={v.mutability}
                color={v.mutability === "constant" ? "#38bdf8" : "#a78bfa"}
              />
            )}
            {v.initialValue && (
              <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
                = {v.initialValue}
              </span>
            )}
          </div>

          <LocationButton
            location={v.location}
            onClick={() => onSelectSnippet(`Variable: ${v.name}`, v.codeSnippet, v.location)}
          />
        </div>
      ))}
    </div>
  );
};

// ─── Modifiers Tab ────────────────────────────────────────────────────────────

const ModifiersTab: React.FC<{
  modifiers: ASTModifier[];
  onSelectSnippet: (title: string, snippet: string | undefined, loc: SourceLocation) => void;
}> = ({ modifiers, onSelectSnippet }) => {
  if (modifiers.length === 0) {
    return <EmptyMessage message="No modifiers found." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {modifiers.map((m, idx) => (
        <div
          key={`${m.contractName}-${m.name}-${idx}`}
          style={{
            padding: "16px 20px",
            borderBottom: idx < modifiers.length - 1 ? "1px solid #1e2d4a" : "none",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: "16px",
          }}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
                {m.contractName}.
              </span>
              <span style={{ fontSize: "13px", fontWeight: 700, color: "#818cf8", fontFamily: "monospace" }}>
                {m.name}
              </span>
              <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
                ({m.parameters.map((p) => `${p.type} ${p.name}`).join(", ")})
              </span>
            </div>

            <div style={{ fontSize: "11px", color: "#4a5568" }}>
              Invoked by {m.invokedBy.length} function{m.invokedBy.length !== 1 ? "s" : ""}:
              {m.invokedBy.length > 0 ? (
                <span style={{ color: "#8892a4", fontFamily: "monospace", marginLeft: "6px" }}>
                  {m.invokedBy.join(", ")}
                </span>
              ) : (
                <span style={{ color: "#4a5568", fontStyle: "italic", marginLeft: "6px" }}>none</span>
              )}
            </div>
          </div>

          <LocationButton
            location={m.location}
            onClick={() => onSelectSnippet(`Modifier: ${m.name}`, m.codeSnippet, m.location)}
          />
        </div>
      ))}
    </div>
  );
};

// ─── Events Tab ───────────────────────────────────────────────────────────────

const EventsTab: React.FC<{
  events: ASTEvent[];
  onSelectSnippet: (title: string, snippet: string | undefined, loc: SourceLocation) => void;
}> = ({ events, onSelectSnippet }) => {
  if (events.length === 0) {
    return <EmptyMessage message="No events declared." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {events.map((e, idx) => (
        <div
          key={`${e.contractName}-${e.name}-${idx}`}
          style={{
            padding: "16px 20px",
            borderBottom: idx < events.length - 1 ? "1px solid #1e2d4a" : "none",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: "16px",
          }}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
              <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
                {e.contractName}.
              </span>
              <span style={{ fontSize: "13px", fontWeight: 700, color: "#c084fc", fontFamily: "monospace" }}>
                event {e.name}
              </span>
              {e.anonymous && <Pill label="anonymous" color="#ffaa00" />}
            </div>

            <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
              {e.parameters.map((p, pIdx) => (
                <span
                  key={pIdx}
                  style={{
                    fontSize: "11px",
                    fontFamily: "monospace",
                    backgroundColor: "#0a0e1a",
                    border: "1px solid #1e2d4a",
                    borderRadius: "4px",
                    padding: "2px 6px",
                    color: "#8892a4",
                  }}
                >
                  {p.indexed && <span style={{ color: "#00d4ff", marginRight: "4px" }}>indexed</span>}
                  <span style={{ color: "#e2e8f0" }}>{p.type}</span> {p.name}
                </span>
              ))}
            </div>
          </div>

          <LocationButton
            location={e.location}
            onClick={() => onSelectSnippet(`Event: ${e.name}`, e.codeSnippet, e.location)}
          />
        </div>
      ))}
    </div>
  );
};

// ─── External Calls Tab ───────────────────────────────────────────────────────

const ExternalCallsTab: React.FC<{
  calls: ASTExternalCall[];
  onSelectSnippet: (title: string, snippet: string | undefined, loc: SourceLocation) => void;
}> = ({ calls, onSelectSnippet }) => {
  if (calls.length === 0) {
    return <EmptyMessage message="No external contract calls detected in AST." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {calls.map((c) => {
        const isDelegate = c.callType === "delegatecall";
        const isLowLevel = c.callType === "low-level-call";
        const badgeColor = isDelegate ? "#ff4444" : isLowLevel ? "#f59e0b" : "#38bdf8";

        return (
          <div
            key={c.id}
            style={{
              padding: "16px 20px",
              borderBottom: "1px solid #1e2d4a",
              display: "flex",
              alignItems: "flex-start",
              justifyContent: "space-between",
              gap: "16px",
            }}
          >
            <div style={{ display: "flex", flexDirection: "column", gap: "6px", flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
                  in {c.contractName}.{c.functionName}()
                </span>
                <Pill label={c.callType.toUpperCase()} color={badgeColor} />
                {c.value && <Pill label={`value: ${c.value}`} color="#ffaa00" />}
                {c.gas && <Pill label={`gas: ${c.gas}`} color="#38bdf8" />}
              </div>

              <div
                style={{
                  fontSize: "12px",
                  color: "#e2e8f0",
                  fontFamily: "monospace",
                  backgroundColor: "#0a0e1a",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  border: "1px solid #1e2d4a",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                }}
              >
                {c.rawExpression}
              </div>

              <div style={{ fontSize: "11px", color: "#4a5568" }}>
                Target: <span style={{ color: "#00d4ff", fontFamily: "monospace" }}>{c.target}</span> ·
                Method: <span style={{ color: "#e2e8f0", fontFamily: "monospace" }}>{c.method}</span>
              </div>
            </div>

            <LocationButton
              location={c.location}
              onClick={() => onSelectSnippet(`Call: ${c.method}`, c.rawExpression, c.location)}
            />
          </div>
        );
      })}
    </div>
  );
};

// ─── ETH Transfers Tab ────────────────────────────────────────────────────────

const EtherTransfersTab: React.FC<{
  transfers: ASTEtherTransfer[];
  onSelectSnippet: (title: string, snippet: string | undefined, loc: SourceLocation) => void;
}> = ({ transfers, onSelectSnippet }) => {
  if (transfers.length === 0) {
    return <EmptyMessage message="No direct ether transfers found." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {/* Alert banner */}
      <div
        style={{
          margin: "16px 20px",
          padding: "12px 16px",
          backgroundColor: "rgba(255,102,102,0.08)",
          border: "1px solid rgba(255,102,102,0.25)",
          borderRadius: "8px",
          display: "flex",
          alignItems: "center",
          gap: "10px",
          fontSize: "12px",
          color: "#ff8888",
        }}
      >
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <circle cx="8" cy="8" r="7" stroke="#ff6666" strokeWidth="1.5" />
          <path d="M8 5v4M8 11.5h.01" stroke="#ff6666" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
        <span>
          Detected <strong>{transfers.length}</strong> ether transfer statement{transfers.length !== 1 ? "s" : ""}. Review recipient destinations and reentrancy protections in Semantic Analysis.
        </span>
      </div>

      {transfers.map((t) => (
        <div
          key={t.id}
          style={{
            padding: "16px 20px",
            borderBottom: "1px solid #1e2d4a",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: "16px",
          }}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "6px", flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
              <span style={{ fontSize: "11px", color: "#4a5568", fontFamily: "monospace" }}>
                in {t.contractName}.{t.functionName}()
              </span>
              <Pill label={t.transferType.toUpperCase()} color="#ff6666" />
            </div>

            <div
              style={{
                fontSize: "12px",
                color: "#e2e8f0",
                fontFamily: "monospace",
                backgroundColor: "#0a0e1a",
                padding: "6px 10px",
                borderRadius: "6px",
                border: "1px solid #1e2d4a",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}
            >
              {t.rawExpression}
            </div>

            <div style={{ fontSize: "11px", color: "#4a5568", display: "flex", gap: "16px" }}>
              <span>
                Recipient: <span style={{ color: "#00d4ff", fontFamily: "monospace" }}>{t.recipient}</span>
              </span>
              <span>
                Amount: <span style={{ color: "#ffaa00", fontFamily: "monospace" }}>{t.amount}</span>
              </span>
            </div>
          </div>

          <LocationButton
            location={t.location}
            onClick={() => onSelectSnippet(`Transfer: ${t.transferType}`, t.rawExpression, t.location)}
          />
        </div>
      ))}
    </div>
  );
};

// ─── Inheritance Tab ──────────────────────────────────────────────────────────

const InheritanceTab: React.FC<{
  inheritance: ASTInheritance[];
  contracts: ASTContract[];
  onSelectSnippet: (title: string, snippet: string | undefined, loc: SourceLocation) => void;
}> = ({ inheritance, contracts, onSelectSnippet }) => {
  if (inheritance.length === 0) {
    return <EmptyMessage message="No contract inheritance specifiers defined." />;
  }

  return (
    <div style={{ padding: "20px", display: "flex", flexDirection: "column", gap: "16px" }}>
      <div style={{ fontSize: "12px", color: "#8892a4" }}>
        Contract inheritance hierarchy and base initializations:
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px" }}>
        {contracts
          .filter((c) => c.bases.length > 0)
          .map((c) => (
            <div
              key={c.name}
              style={{
                backgroundColor: "#0a0e1a",
                border: "1px solid #1e2d4a",
                borderRadius: "8px",
                padding: "16px",
                display: "flex",
                flexDirection: "column",
                gap: "10px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ fontSize: "14px", fontWeight: 700, color: "#e2e8f0", fontFamily: "monospace" }}>
                  {c.name}
                </span>
                <KindBadge kind={c.kind} />
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <span style={{ fontSize: "10px", color: "#4a5568", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Inherits From
                </span>
                {c.bases.map((baseName) => {
                  const rel = inheritance.find(
                    (i) => i.contractName === c.name && i.baseContractName === baseName
                  );
                  return (
                    <div
                      key={baseName}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "6px 10px",
                        backgroundColor: "#0f1629",
                        border: "1px solid #1e2d4a",
                        borderRadius: "6px",
                        fontSize: "12px",
                      }}
                    >
                      <span style={{ color: "#00d4ff", fontFamily: "monospace" }}>
                        ↳ {baseName}
                        {rel?.arguments && rel.arguments.length > 0 && (
                          <span style={{ color: "#4a5568" }}>({rel.arguments.join(", ")})</span>
                        )}
                      </span>
                      {rel && (
                        <button
                          onClick={() => onSelectSnippet(`Inheritance: ${c.name} is ${baseName}`, undefined, rel.location)}
                          style={{
                            background: "none",
                            border: "none",
                            color: "#4a5568",
                            fontSize: "10px",
                            cursor: "pointer",
                            fontFamily: "monospace",
                          }}
                        >
                          L{rel.location.line}
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
      </div>
    </div>
  );
};

// ─── Raw AST Tab ──────────────────────────────────────────────────────────────

const RawAstTab: React.FC<{ ast: Record<string, unknown> }> = ({ ast }) => {
  const json = JSON.stringify(ast, null, 2);
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
        <span style={{ fontSize: "11px", color: "#4a5568" }}>Solidity Standard JSON AST</span>
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
          {copied ? "Copied ✓" : "Copy JSON"}
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
          maxHeight: "420px",
          overflowY: "auto",
          lineHeight: 1.6,
        }}
      >
        {json}
      </pre>
    </div>
  );
};

// ─── Snippet Viewer Modal ─────────────────────────────────────────────────────

const SnippetModal: React.FC<{
  title: string;
  snippet: string;
  location: SourceLocation;
  onClose: () => void;
}> = ({ title, snippet, location, onClose }) => (
  <div
    style={{
      position: "fixed",
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: "rgba(0,0,0,0.75)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      zIndex: 1000,
      padding: "20px",
    }}
    onClick={onClose}
  >
    <div
      style={{
        backgroundColor: "#0f1629",
        border: "1px solid #2a3f6a",
        borderRadius: "12px",
        width: "100%",
        maxWidth: "680px",
        overflow: "hidden",
        boxShadow: "0 20px 40px rgba(0,0,0,0.6)",
      }}
      onClick={(e) => e.stopPropagation()}
    >
      {/* Modal header */}
      <div
        style={{
          padding: "14px 18px",
          borderBottom: "1px solid #1e2d4a",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          backgroundColor: "#0a0e1a",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ fontSize: "13px", fontWeight: 700, color: "#e2e8f0" }}>{title}</span>
          <span
            style={{
              fontSize: "10px",
              fontFamily: "monospace",
              color: "#00d4ff",
              backgroundColor: "rgba(0,212,255,0.08)",
              border: "1px solid rgba(0,212,255,0.2)",
              borderRadius: "4px",
              padding: "2px 6px",
            }}
          >
            Line {location.line}:{location.column}
          </span>
        </div>
        <button
          onClick={onClose}
          style={{
            background: "none",
            border: "none",
            color: "#4a5568",
            cursor: "pointer",
            fontSize: "16px",
            lineHeight: 1,
          }}
        >
          ✕
        </button>
      </div>

      {/* Snippet body */}
      <pre
        style={{
          margin: 0,
          padding: "16px 18px",
          fontSize: "12px",
          color: "#00ff88",
          fontFamily: "monospace",
          overflowX: "auto",
          maxHeight: "360px",
          overflowY: "auto",
          lineHeight: 1.6,
          backgroundColor: "#060910",
        }}
      >
        {snippet || "// No code snippet available"}
      </pre>

      <div
        style={{
          padding: "10px 18px",
          borderTop: "1px solid #1e2d4a",
          fontSize: "11px",
          color: "#4a5568",
          display: "flex",
          justifyContent: "space-between",
          backgroundColor: "#0a0e1a",
        }}
      >
        <span>File: {location.file}</span>
        <span>Range: {location.start} – {location.end} ({location.length} bytes)</span>
      </div>
    </div>
  </div>
);

// ─── Micro UI Components ──────────────────────────────────────────────────────

const MetricCard: React.FC<{
  label: string;
  value: number;
  color: string;
  sub?: string;
  alert?: boolean;
  active?: boolean;
  onClick?: () => void;
}> = ({ label, value, color, sub, alert, active, onClick }) => (
  <div
    onClick={onClick}
    style={{
      backgroundColor: active ? "rgba(0,212,255,0.05)" : "#0f1629",
      border: active ? "1px solid #00d4ff" : "1px solid #1e2d4a",
      borderRadius: "8px",
      padding: "12px 14px",
      display: "flex",
      flexDirection: "column",
      gap: "4px",
      cursor: onClick ? "pointer" : "default",
      transition: "all 0.15s ease",
    }}
  >
    <span style={{ fontSize: "10px", color: "#4a5568", textTransform: "uppercase", letterSpacing: "0.06em" }}>
      {label}
    </span>
    <div style={{ display: "flex", alignItems: "baseline", gap: "6px" }}>
      <span
        style={{
          fontSize: "20px",
          fontWeight: 700,
          fontFamily: "monospace",
          color: alert ? "#ff6666" : color,
        }}
      >
        {value}
      </span>
      {sub && <span style={{ fontSize: "10px", color: "#4a5568" }}>{sub}</span>}
    </div>
  </div>
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

const KindBadge: React.FC<{ kind: string }> = ({ kind }) => {
  const isInterface = kind === "interface";
  const isLibrary = kind === "library";
  const color = isInterface ? "#c084fc" : isLibrary ? "#a78bfa" : "#00d4ff";

  return (
    <span
      style={{
        fontSize: "10px",
        fontWeight: 600,
        color,
        backgroundColor: `${color}14`,
        border: `1px solid ${color}33`,
        borderRadius: "4px",
        padding: "2px 6px",
        fontFamily: "monospace",
        textTransform: "uppercase",
        letterSpacing: "0.05em",
      }}
    >
      {kind}
    </span>
  );
};

const VisibilityBadge: React.FC<{ visibility: FunctionVisibility }> = ({ visibility }) => {
  let color = "#4a5568";
  if (visibility === "external") color = "#38bdf8";
  else if (visibility === "public") color = "#00d4ff";
  else if (visibility === "internal") color = "#a78bfa";
  else if (visibility === "private") color = "#94a3b8";

  return (
    <span
      style={{
        fontSize: "10px",
        fontWeight: 600,
        color,
        backgroundColor: `${color}14`,
        border: `1px solid ${color}33`,
        borderRadius: "4px",
        padding: "1px 6px",
        fontFamily: "monospace",
      }}
    >
      {visibility}
    </span>
  );
};

const MutabilityBadge: React.FC<{ mutability: string }> = ({ mutability }) => {
  let color = "#4a5568";
  if (mutability === "payable") color = "#f59e0b";
  else if (mutability === "view") color = "#14b8a6";
  else if (mutability === "pure") color = "#10b981";

  return (
    <span
      style={{
        fontSize: "10px",
        fontWeight: 600,
        color,
        backgroundColor: `${color}14`,
        border: `1px solid ${color}33`,
        borderRadius: "4px",
        padding: "1px 6px",
        fontFamily: "monospace",
      }}
    >
      {mutability}
    </span>
  );
};

const Pill: React.FC<{ label: string; color?: string }> = ({ label, color = "#4a5568" }) => (
  <span
    style={{
      fontSize: "10px",
      fontWeight: 500,
      color,
      backgroundColor: `${color}14`,
      border: `1px solid ${color}33`,
      borderRadius: "4px",
      padding: "1px 6px",
      fontFamily: "monospace",
    }}
  >
    {label}
  </span>
);

const SpecialBadge: React.FC<{ label: string; detail?: string; accent?: string; dim?: boolean }> = ({
  label,
  detail,
  accent = "#00d4ff",
  dim,
}) => (
  <span
    style={{
      fontSize: "11px",
      color: dim ? "#4a5568" : accent,
      backgroundColor: dim ? "transparent" : `${accent}10`,
      border: `1px solid ${dim ? "#1e2d4a" : `${accent}33`}`,
      borderRadius: "5px",
      padding: "3px 8px",
      fontFamily: "monospace",
    }}
  >
    {label}
    {detail && <span style={{ color: "#4a5568", marginLeft: "4px" }}>({detail})</span>}
  </span>
);

const LocationButton: React.FC<{ location: SourceLocation; onClick: () => void }> = ({
  location,
  onClick,
}) => (
  <button
    onClick={onClick}
    style={{
      background: "none",
      border: "1px solid #1e2d4a",
      borderRadius: "4px",
      padding: "2px 8px",
      color: "#4a5568",
      fontSize: "10px",
      fontFamily: "monospace",
      cursor: "pointer",
      transition: "all 0.15s ease",
    }}
    onMouseEnter={(e) => {
      const b = e.currentTarget as HTMLButtonElement;
      b.style.borderColor = "#00d4ff";
      b.style.color = "#00d4ff";
    }}
    onMouseLeave={(e) => {
      const b = e.currentTarget as HTMLButtonElement;
      b.style.borderColor = "#1e2d4a";
      b.style.color = "#4a5568";
    }}
  >
    L{location.line}:{location.column}
  </button>
);

const StatItem: React.FC<{ label: string; value: number; highlight?: string }> = ({
  label,
  value,
  highlight,
}) => (
  <span>
    <span style={{ color: "#4a5568" }}>{label}: </span>
    <span
      style={{
        color: highlight || "#8892a4",
        fontFamily: "monospace",
        fontWeight: highlight ? 700 : 400,
      }}
    >
      {value}
    </span>
  </span>
);

const EmptyMessage: React.FC<{ message: string }> = ({ message }) => (
  <div style={{ padding: "36px", textAlign: "center", color: "#4a5568", fontSize: "13px" }}>
    {message}
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

const inlineCode: React.CSSProperties = {
  backgroundColor: "#131c35",
  color: "#00d4ff",
  padding: "1px 5px",
  borderRadius: "4px",
  fontFamily: "monospace",
  fontSize: "12px",
};
