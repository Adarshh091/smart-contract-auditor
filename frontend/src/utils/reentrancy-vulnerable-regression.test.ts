// ─── End-to-End Regression Test: ReentrancyVulnerable (Solidity 0.4.19) ────────
//
// This test validates the full pipeline for the canonical regression contract:
//
//   pragma solidity ^0.4.19;
//   contract ReentrancyVulnerable {
//     mapping(address => uint256) public balances;
//     address public owner;
//     uint256 public totalDeposits;
//
//     function ReentrancyVulnerable() public {      ← old-style constructor
//       owner = msg.sender;
//     }
//
//     function deposit() public payable {
//       require(msg.value > 0);
//       balances[msg.sender] += msg.value;
//       totalDeposits += msg.value;
//     }
//
//     function withdraw(uint256 amount) public {
//       require(amount > 0);
//       require(balances[msg.sender] >= amount);
//       msg.sender.call.value(amount)();          ← old-style call with value
//       balances[msg.sender] -= amount;
//     }
//   }
//
// EXPECTED:
//  - Reentrancy          → CONFIRMED
//  - Unchecked External Call → CONFIRMED
//  - Constructor (old-style) → NOT a privileged function, no Access Control false positive
//  - Integer Overflow (pre-0.8 arithmetic) → POTENTIAL
//  - Solidity version 0.4.x confirmed pre-0.8 — no >=0.8 protection claims
//
// Bug coverage:
//  1. AST: msg.sender.call.value(amount)() chained call properly detected
//  2. Solidity version: 0.4.19 → pre-0.8 detected correctly
//  3. Integer overflow: reported for pre-0.8 without unchecked{}
//  4. Constructor false positive: old-style constructor not flagged as Access Control issue

import { describe, it, expect } from "vitest";
import { analyzeSolidityAST } from "./ast-analyzer";
import { detectSecurityVulnerabilities } from "./security-detector";
import { parsePragma } from "./solidity-version";

// ─── Fixture builders (minimal but structurally correct solc AST) ─────────────

function makeSourceUnit(nodes: object[]): object {
  return {
    nodeType: "SourceUnit",
    absolutePath: "ReentrancyVulnerable.sol",
    nodes,
  };
}

function makeContract(name: string, nodes: object[]): object {
  return {
    nodeType: "ContractDefinition",
    name,
    contractKind: "contract",
    abstract: false,
    baseContracts: [],
    nodes,
    src: "0:1200:0",
  };
}

function makeStateVar(name: string, type: string): object {
  return {
    nodeType: "StateVariableDeclaration",
    variables: [
      {
        nodeType: "VariableDeclaration",
        name,
        typeName: { nodeType: "ElementaryTypeName", name: type },
        stateVariable: true,
        visibility: "public",
        mutability: "mutable",
        src: "20:40:0",
      },
    ],
    src: "20:40:0",
  };
}

function makeFunction(
  name: string,
  visibility: string,
  stateMutability: string,
  body: object[],
  params: object[] = []
): object {
  return {
    nodeType: "FunctionDefinition",
    name,
    kind: "function", // old-style: always "function", not "constructor"
    visibility,
    stateMutability,
    virtual: false,
    overrides: null,
    modifiers: [],
    parameters: { nodeType: "ParameterList", parameters: params },
    returnParameters: { nodeType: "ParameterList", parameters: [] },
    body: { nodeType: "Block", statements: body },
    src: "100:300:0",
  };
}

function makeParam(name: string, type: string): object {
  return {
    nodeType: "VariableDeclaration",
    name,
    typeName: { nodeType: "ElementaryTypeName", name: type },
    src: "0:10:0",
  };
}

function makeRequire(condNode: object): object {
  return {
    nodeType: "ExpressionStatement",
    expression: {
      nodeType: "FunctionCall",
      expression: { nodeType: "Identifier", name: "require", src: "0:7:0" },
      arguments: [condNode],
      src: "0:30:0",
    },
    src: "0:30:0",
  };
}

/**
 * Builds an assignment statement: varName op= value  (compound assignment).
 * The `srcOffset` parameter controls source ordering when no real source code
 * is provided (all snippets are empty).  Use ascending values to match the
 * intended statement order.
 */
function makeCompoundAssign(varName: string, op: string, value: string, srcOffset = 100): object {
  const o = srcOffset;
  return {
    nodeType: "ExpressionStatement",
    expression: {
      nodeType: "Assignment",
      operator: op,
      leftHandSide: { nodeType: "Identifier", name: varName, src: `${o}:10:0` },
      rightHandSide: { nodeType: "Identifier", name: value, src: `${o + 15}:5:0` },
      src: `${o}:20:0`,
    },
    src: `${o}:20:0`,
  };
}

/**
 * Builds the old Solidity 0.4.x `msg.sender.call.value(amount)()` statement.
 *
 * solc AST shape:
 *   ExpressionStatement {
 *     expression: FunctionCall (outer — the final ()) {
 *       expression: FunctionCall (inner — the .value(amount) call) {
 *         expression: MemberAccess(.value) {
 *           expression: MemberAccess(.call) {
 *             expression: Identifier(msg.sender)
 *           }
 *         }
 *         arguments: [amount]
 *       }
 *       arguments: []
 *     }
 *   }
 *
 * The `srcOffset` parameter controls source ordering — pass values higher than
 * any preceding statement and lower than any following statement.
 */
function makeOldStyleCallValue(target: string, amount: string, srcOffset = 200): object {
  const o = srcOffset;
  return {
    nodeType: "ExpressionStatement",
    expression: {
      // Outer FunctionCall: the final ()
      nodeType: "FunctionCall",
      arguments: [],
      src: `${o}:40:0`,
      expression: {
        // Inner FunctionCall: .value(amount)
        nodeType: "FunctionCall",
        arguments: [{ nodeType: "Identifier", name: amount, src: `${o + 15}:6:0` }],
        src: `${o}:30:0`,
        expression: {
          // MemberAccess: .value on (.call on target)
          nodeType: "MemberAccess",
          memberName: "value",
          src: `${o}:25:0`,
          expression: {
            // MemberAccess: .call on target
            nodeType: "MemberAccess",
            memberName: "call",
            src: `${o}:20:0`,
            expression: {
              nodeType: "MemberAccess",
              memberName: "sender",
              expression: { nodeType: "Identifier", name: "msg", src: `${o}:3:0` },
              src: `${o}:10:0`,
            },
          },
        },
      },
    },
    src: `${o}:40:0`,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("ReentrancyVulnerable 0.4.19 Regression — AST + Detector Pipeline", () => {

  // ── 1. Pragma parsing ─────────────────────────────────────────────────────

  describe("1. Pragma version parsing", () => {
    it("^0.4.19 must parse to lowerBound=0.4.19 (pre-0.8)", () => {
      const pragma = parsePragma("pragma solidity ^0.4.19;");
      expect(pragma).not.toBeNull();
      expect(pragma!.lowerBound).toBe("0.4.19");
      expect(pragma!.kind).toBe("caret");
    });

    it("^0.8.20 must parse to lowerBound=0.8.20 (>=0.8)", () => {
      const pragma = parsePragma("pragma solidity ^0.8.20;");
      expect(pragma).not.toBeNull();
      expect(pragma!.lowerBound).toBe("0.8.20");
    });

    it("plain 0.4.19 must parse as exact pre-0.8", () => {
      const pragma = parsePragma("pragma solidity 0.4.19;");
      expect(pragma).not.toBeNull();
      expect(pragma!.lowerBound).toBe("0.4.19");
      expect(pragma!.kind).toBe("exact");
    });
  });

  // ── 2. AST extraction: old-style call.value() ─────────────────────────────

  describe("2. AST extraction — msg.sender.call.value(amount)()", () => {
    it("old-style call.value() must be extracted as external-call kind=low-level-call", () => {
      const ast = analyzeSolidityAST(
        makeSourceUnit([
          makeContract("TestCallValue", [
            makeStateVar("balances", "mapping"),
            makeFunction("withdraw", "public", "nonpayable", [
              makeOldStyleCallValue("msgSender", "amount"),
            ]),
          ]),
        ]),
        "",
        "Test.sol"
      );

      const fn = ast.functions.find((f) => f.name === "withdraw");
      expect(fn).toBeDefined();

      // Must have at least one external call
      expect(fn!.externalCalls.length).toBeGreaterThan(0);

      const call = fn!.externalCalls[0];
      expect(call.callType).toBe("low-level-call");
      expect(call.method).toBe("call");
      // Value should be captured
      expect(call.value).toBeDefined();
      expect(call.value).toBe("amount");

      // Must produce an operation with kind "external-call"
      const extCallOp = fn!.operations.find((op) => op.kind === "external-call");
      expect(extCallOp).toBeDefined();

      // Must also produce an ether-transfer (value was attached)
      expect(fn!.etherTransfers.length).toBeGreaterThan(0);
      expect(fn!.etherTransfers[0].transferType).toBe("call-value");
    });
  });

  // ── 3. Constructor detection (old-style name == contract name) ────────────

  describe("3. Constructor detection — old-style named constructor", () => {
    it("function with same name as contract must be kind=constructor", () => {
      const ast = analyzeSolidityAST(
        makeSourceUnit([
          makeContract("MyContract", [
            makeStateVar("owner", "address"),
            makeFunction("MyContract", "public", "nonpayable", [
              {
                nodeType: "ExpressionStatement",
                expression: {
                  nodeType: "Assignment",
                  operator: "=",
                  leftHandSide: { nodeType: "Identifier", name: "owner", src: "0:5:0" },
                  rightHandSide: { nodeType: "Identifier", name: "msgSender", src: "0:5:0" },
                  src: "0:15:0",
                },
                src: "0:15:0",
              },
            ]),
          ]),
        ]),
        "",
        "Test.sol"
      );

      const fn = ast.functions.find((f) => f.name === "MyContract");
      expect(fn).toBeDefined();
      expect(fn!.kind).toBe("constructor");
    });
  });

  // ── 4. Full detector pipeline for ReentrancyVulnerable ───────────────────

  describe("4. Full pipeline — ReentrancyVulnerable", () => {
    // Build the full contract AST fixture
    const ast = analyzeSolidityAST(
      makeSourceUnit([
        makeContract("ReentrancyVulnerable", [
          makeStateVar("balances", "mapping"),
          makeStateVar("owner", "address"),
          makeStateVar("totalDeposits", "uint256"),

          // Old-style constructor: function name matches contract name
          makeFunction("ReentrancyVulnerable", "public", "nonpayable", [
            {
              nodeType: "ExpressionStatement",
              expression: {
                nodeType: "Assignment",
                operator: "=",
                leftHandSide: { nodeType: "Identifier", name: "owner", src: "50:5:0" },
                rightHandSide: { nodeType: "Identifier", name: "msgSender", src: "58:10:0" },
                src: "50:18:0",
              },
              src: "50:18:0",
            },
          ]),

          makeFunction("deposit", "public", "payable", [
            makeRequire({ nodeType: "Identifier", name: "msgValueGt0", src: "170:30:0" }),
            makeCompoundAssign("balances", "+=", "msgValue", 205),
            makeCompoundAssign("totalDeposits", "+=", "msgValue", 240),
          ]),

          makeFunction(
            "withdraw",
            "public",
            "nonpayable",
            [
              makeRequire({ nodeType: "Identifier", name: "amountGt0", src: "270:30:0" }),
              makeRequire({ nodeType: "Identifier", name: "balanceCheck", src: "305:30:0" }),
              // The vulnerable call: msg.sender.call.value(amount)()
              // srcOffset 340 — comes BEFORE the balances update at 390
              makeOldStyleCallValue("msgSender", "amount", 340),
              // State update AFTER the call (reentrancy violation)
              // srcOffset 390 — comes AFTER the call at 340
              makeCompoundAssign("balances", "-=", "amount", 390),
            ],
            [makeParam("amount", "uint256")]
          ),
        ]),
      ]),
      "",
      "ReentrancyVulnerable.sol"
    );

    it("4a. Reentrancy — CONFIRMED (call before state update)", () => {
      const result = detectSecurityVulnerabilities(ast, undefined, undefined, "0.4.19");
      const reentrancy = result.findings.filter(
        (f) =>
          f.contractName === "ReentrancyVulnerable" &&
          f.vulnerabilityType === "Reentrancy" &&
          f.classification === "CONFIRMED"
      );
      expect(reentrancy.length).toBeGreaterThan(0);
      expect(reentrancy[0].severity).toBe("critical");
    });

    it("4b. Unchecked External Call — CONFIRMED (call.value return not checked)", () => {
      const result = detectSecurityVulnerabilities(ast, undefined, undefined, "0.4.19");
      const unchecked = result.findings.filter(
        (f) =>
          f.contractName === "ReentrancyVulnerable" &&
          f.vulnerabilityType === "Unchecked External Call" &&
          f.classification === "CONFIRMED"
      );
      expect(unchecked.length).toBeGreaterThan(0);
    });

    it("4c. Constructor — NO Access Control false positive", () => {
      const result = detectSecurityVulnerabilities(ast, undefined, undefined, "0.4.19");
      const constructorAC = result.findings.filter(
        (f) =>
          f.contractName === "ReentrancyVulnerable" &&
          f.vulnerabilityType === "Access Control" &&
          f.functionName === "ReentrancyVulnerable"
      );
      expect(constructorAC.length).toBe(0);
    });

    it("4d. Integer overflow — POTENTIAL reported for pre-0.8 arithmetic", () => {
      // This sub-test uses its own fixture with real source code so that
      // codeSnippet is populated and the arithmetic detector can find the += expression.
      const src = [
        "pragma solidity ^0.4.19;",
        "contract ReentrancyVulnerable {",
        "    mapping(address => uint256) public balances;",
        "    uint256 public totalDeposits;",
        "    function deposit() public payable {",
        "        require(msg.value > 0);",
        "        balances[msg.sender] += msg.value;",
        "        totalDeposits += msg.value;",
        "    }",
        "}",
      ].join("\n");

      // Compute approximate byte offsets for the deposit function body
      // We only need the codeSnippet to contain the arithmetic — so we use
      // the full source as codeSnippet by pointing src at offset 0.
      const depositFnSrc = `0:${src.length}:0`; // covers entire source

      const overflowAST = analyzeSolidityAST(
        makeSourceUnit([
          makeContract("ReentrancyVulnerable", [
            makeStateVar("balances", "mapping"),
            makeStateVar("totalDeposits", "uint256"),
            makeFunction("deposit", "public", "payable", [
              makeRequire({ nodeType: "Identifier", name: "msgValueGt0", src: "0:5:0" }),
              {
                nodeType: "ExpressionStatement",
                expression: {
                  nodeType: "Assignment",
                  operator: "+=",
                  leftHandSide: { nodeType: "Identifier", name: "balances", src: "0:5:0" },
                  rightHandSide: { nodeType: "Identifier", name: "msgValue", src: "0:5:0" },
                  src: "0:30:0",
                },
                src: "0:30:0",
              },
              // Explicitly override the function's src to cover the whole source
              // We do this by patching the function after construction — see below.
            ]),
          ]),
        ]),
        // Provide the real source so getSnippet returns the code content
        src,
        "ReentrancyVulnerable.sol",
        // The function's src="50:500:0" (from makeFunction default) covers enough
      );

      const result = detectSecurityVulnerabilities(overflowAST, undefined, undefined, "0.4.19");
      const overflow = result.findings.filter(
        (f) =>
          f.vulnerabilityType === "Integer Overflow/Underflow"
      );
      // At least one overflow finding for the pre-0.8 arithmetic
      expect(overflow.length).toBeGreaterThan(0);
      // Must NOT claim >=0.8 built-in protection
      const anyClaimsProtection = overflow.some((f) =>
        f.evidence.some((e) => e.includes("built-in overflow protections are explicitly disabled"))
      );
      expect(anyClaimsProtection).toBe(false);
      // Must mention the actual version
      const mentionsPreV8 = overflow.some((f) =>
        f.evidence.some((e) => e.includes("0.4.19"))
      );
      expect(mentionsPreV8).toBe(true);
    });

    it("4e. No >=0.8 protection claim in any finding", () => {
      const result = detectSecurityVulnerabilities(ast, undefined, undefined, "0.4.19");
      const hasWrongClaim = result.findings.some((f) =>
        f.reason.includes("Solidity 0.8") &&
        f.reason.includes("built-in overflow")
      );
      expect(hasWrongClaim).toBe(false);
    });
  });
});
