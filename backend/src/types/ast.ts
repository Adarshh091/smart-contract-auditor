// ─── Solidity AST Analysis Types (Stage 4) ───────────────────────────────────
//
// Structured, strongly-typed representation of the compiled Solidity AST.
// Completely decoupled from React and compiler internals.

export interface SourceLocation {
  file: string;
  line: number;         // 1-indexed start line
  column: number;       // 1-indexed start column
  endLine?: number;     // 1-indexed end line
  endColumn?: number;   // 1-indexed end column
  start: number;        // character/byte offset start
  length: number;       // character/byte offset length
  end: number;          // start + length
}

export interface ASTParameter {
  name: string;
  type: string;
  indexed?: boolean;    // present for event parameters
  location?: SourceLocation;
}

export type FunctionVisibility = "external" | "public" | "internal" | "private";
export type StateMutability = "pure" | "view" | "nonpayable" | "payable";
export type FunctionKind = "function" | "constructor" | "fallback" | "receive";

export type ASTOperationKind =
  | "external-call"
  | "ether-transfer"
  | "state-read"
  | "state-write"
  | "control"
  | "other";

export interface ASTOperation {
  id: string;
  kind: ASTOperationKind;
  functionName: string;
  contractName: string;
  expression: string;
  location: SourceLocation;

  externalCall?: ASTExternalCall;
  etherTransfer?: ASTEtherTransfer;
  stateVariable?: string;
}

export interface ASTFunction {
  id: number;
  name: string;
  contractName: string;
  kind: FunctionKind;
  visibility: FunctionVisibility;
  stateMutability: StateMutability;
  isVirtual: boolean;
  isOverride: boolean;
  modifiers: string[];
  parameters: ASTParameter[];
  returnParameters: ASTParameter[];
  signature: string;
  location: SourceLocation;
  codeSnippet?: string;
  // Statements and calls inside this function
  externalCalls: ASTExternalCall[];
  etherTransfers: ASTEtherTransfer[];
  controlStatements: ASTControlStatement[];
  operations: ASTOperation[];
}

export type VariableVisibility = "public" | "internal" | "private";
export type VariableMutability = "mutable" | "immutable" | "constant";

export interface ASTStateVariable {
  id: number;
  name: string;
  contractName: string;
  type: string;
  visibility: VariableVisibility;
  mutability: VariableMutability;
  initialValue?: string;
  location: SourceLocation;
  codeSnippet?: string;
}

export interface ASTModifier {
  id: number;
  name: string;
  contractName: string;
  parameters: ASTParameter[];
  location: SourceLocation;
  codeSnippet?: string;
  invokedBy: string[]; // function signatures that invoke this modifier
}

export interface ASTEvent {
  id: number;
  name: string;
  contractName: string;
  anonymous: boolean;
  parameters: ASTParameter[];
  signature: string;
  location: SourceLocation;
  codeSnippet?: string;
}

export interface ASTStructMember {
  name: string;
  type: string;
}

export interface ASTStruct {
  id: number;
  name: string;
  contractName: string;
  members: ASTStructMember[];
  location: SourceLocation;
}

export interface ASTEnum {
  id: number;
  name: string;
  contractName: string;
  members: string[];
  location: SourceLocation;
}

export interface ASTInheritance {
  contractName: string;
  baseContractName: string;
  arguments?: string[];
  location: SourceLocation;
}

export type ExternalCallType =
  | "regular"          // external contract call e.g. token.balanceOf(addr)
  | "low-level-call"   // .call(...)
  | "delegatecall"     // .delegatecall(...)
  | "staticcall"       // .staticcall(...)
  | "transfer"         // recipient.transfer(...)
  | "send";            // recipient.send(...)

export interface ASTExternalCall {
  id: string;
  contractName: string;
  functionName: string;
  target: string;
  method: string;
  callType: ExternalCallType;
  value?: string;
  gas?: string;
  arguments: string[];
  rawExpression: string;
  location: SourceLocation;
}

export type EtherTransferType = "transfer" | "send" | "call-value" | "selfdestruct";

export interface ASTEtherTransfer {
  id: string;
  contractName: string;
  functionName: string;
  recipient: string;
  amount: string;
  transferType: EtherTransferType;
  rawExpression: string;
  location: SourceLocation;
}

export type ControlStatementKind = "require" | "assert" | "revert";

export interface ASTControlStatement {
  id: string;
  contractName: string;
  functionName: string;
  kind: ControlStatementKind;
  condition?: string;
  message?: string;
  rawExpression: string;
  location: SourceLocation;
}

export type ContractKind = "contract" | "interface" | "library" | "abstract";

export interface ASTContract {
  id: number;
  name: string;
  kind: ContractKind;
  isAbstract: boolean;
  sourceFile: string;
  bases: string[];
  functions: ASTFunction[];
  stateVariables: ASTStateVariable[];
  modifiers: ASTModifier[];
  events: ASTEvent[];
  structs: ASTStruct[];
  enums: ASTEnum[];
  constructorDef?: ASTFunction;
  fallbackDef?: ASTFunction;
  receiveDef?: ASTFunction;
  externalCalls: ASTExternalCall[];
  etherTransfers: ASTEtherTransfer[];
  controlStatements: ASTControlStatement[];
  location: SourceLocation;
}

export interface ASTAnalysisSummary {
  totalContracts: number;
  totalFunctions: number;
  totalStateVariables: number;
  totalModifiers: number;
  totalEvents: number;
  totalStructs: number;
  totalEnums: number;
  totalExternalCalls: number;
  totalEtherTransfers: number;
  totalControlStatements: number;
  publicOrExternalFunctions: number;
  internalOrPrivateFunctions: number;
  payableFunctions: number;
  viewOrPureFunctions: number;
}

export interface ASTAnalysisResult {
  contracts: ASTContract[];
  functions: ASTFunction[];
  stateVariables: ASTStateVariable[];
  modifiers: ASTModifier[];
  events: ASTEvent[];
  structs: ASTStruct[];
  enums: ASTEnum[];
  inheritance: ASTInheritance[];
  externalCalls: ASTExternalCall[];
  etherTransfers: ASTEtherTransfer[];
  controlStatements: ASTControlStatement[];
  summary: ASTAnalysisSummary;
  rawAst: Record<string, unknown>;
}
