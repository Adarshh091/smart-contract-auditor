// ─── Semantic / Purpose Analysis Types (Stage 5) ─────────────────────────────
//
// Defines the JSON structure returned by the Ollama-powered semantic analysis
// engine. This is NOT a vulnerability finding – it is a high-level
// understanding of what the contract does.

export interface SemanticResult {
  /** High-level description of what the contract does */
  purpose: string;
  /**
   * Broad category, e.g.:
   * Token | NFT | Marketplace | Auction | DAO | Lending | Staking |
   * Escrow | Payment | Governance | Wallet | Proxy/Upgradeable | Lottery | Other
   */
  category: string;
  /** Model's self-reported confidence in its analysis (0.0 – 1.0) */
  confidence: number;
  /** Main assets the contract handles (e.g. ERC-20 tokens, ETH, NFTs) */
  assets: string[];
  /** Important function signatures / names identified by the model */
  mainFunctions: string[];
  /** Critical operations identified (e.g. minting, burning, upgrades) */
  criticalOperations: string[];
  /** Access-control mechanisms used (e.g. onlyOwner, Role-based, multisig) */
  accessControl: string[];
  /** External interactions (oracle calls, external contract calls, etc.) */
  externalInteractions: string[];
  /** Financial operations (payments, staking rewards, fee collection, etc.) */
  financialOperations: string[];
  /** Areas the model flags as potentially security-critical */
  securityCriticalAreas: string[];
}

/** Required keys that must be present in the Ollama JSON response */
export const SEMANTIC_RESULT_REQUIRED_KEYS: (keyof SemanticResult)[] = [
  "purpose",
  "category",
  "confidence",
  "assets",
  "mainFunctions",
  "criticalOperations",
  "accessControl",
  "externalInteractions",
  "financialOperations",
  "securityCriticalAreas",
];
