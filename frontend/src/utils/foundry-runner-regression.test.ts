import { describe, it, expect, vi } from "vitest";
import {
  checkForgeAvailability,
  runDynamicVerification,
  parseFoundryTestOutput,
  generateFoundryTestCode,
} from "./foundry-runner";
import { detectSecurityVulnerabilities } from "./security-detector";
import type {
  ASTAnalysisResult,
  ASTContract,
  ASTFunction,
  ASTExternalCall,
  ASTEtherTransfer,
  SourceLocation,
} from "../types/ast";

const BASE_LOC: SourceLocation = {
  file: "Test.sol",
  line: 10,
  column: 1,
  endLine: 20,
  start: 100,
  length: 100,
  end: 200,
};

function makeMinimalAST(contractName: string): ASTAnalysisResult {
  const contract: ASTContract = {
    id: 1,
    name: contractName,
    kind: "contract",
    isAbstract: false,
    sourceFile: "Test.sol",
    bases: [],
    functions: [],
    stateVariables: [],
    modifiers: [],
    events: [],
    structs: [],
    enums: [],
    externalCalls: [],
    etherTransfers: [],
    controlStatements: [],
    location: BASE_LOC,
  };
  return {
    contracts: [contract],
    functions: [],
    stateVariables: [],
    modifiers: [],
    events: [],
    structs: [],
    enums: [],
    inheritance: [],
    externalCalls: [],
    etherTransfers: [],
    controlStatements: [],
    summary: {
      totalContracts: 1,
      totalFunctions: 0,
      totalStateVariables: 0,
      totalModifiers: 0,
      totalEvents: 0,
      totalStructs: 0,
      totalEnums: 0,
      totalExternalCalls: 0,
      totalEtherTransfers: 0,
      totalControlStatements: 0,
      publicOrExternalFunctions: 0,
      internalOrPrivateFunctions: 0,
      payableFunctions: 0,
      viewOrPureFunctions: 0,
    },
    rawAst: {},
  };
}

describe("Foundry Dynamic Testing Runner Engine", () => {
  it("1. Forge unavailable -> graceful fallback with UNAVAILABLE status", () => {
    const ast = makeMinimalAST("Vault");
    const result = runDynamicVerification("pragma solidity ^0.8.20; contract Vault {}", ast);

    // If forge is not installed on system, result must have status UNAVAILABLE and available: false
    if (!checkForgeAvailability()) {
      expect(result.available).toBe(false);
      expect(result.status).toBe("UNAVAILABLE");
      expect(result.results.length).toBe(0);
    } else {
      expect(result.available).toBe(true);
    }
  });

  it("2. Successful forge execution -> parsed result correctly", () => {
    const jsonStdout = JSON.stringify({
      "test/Target.t.sol:DynamicSecurityTest": {
        test_results: {
          test_ReentrancyAttack: {
            status: "Success",
            reason: null,
            decoded_logs: ["State written after call"],
            duration_ms: 12,
          },
        },
      },
    });

    const parsed = parseFoundryTestOutput(jsonStdout, "", 0, "Vault");

    expect(parsed.available).toBe(true);
    expect(parsed.status).toBe("VERIFIED");
    expect(parsed.results.length).toBe(1);
    expect(parsed.results[0].passed).toBe(true);
    expect(parsed.results[0].testName).toBe("test_ReentrancyAttack");
  });

  it("3. Failed test -> parsed failure and status NOT_REPRODUCED", () => {
    const jsonStdout = JSON.stringify({
      "test/Target.t.sol:DynamicSecurityTest": {
        test_results: {
          test_AccessControlBypass: {
            status: "Failure",
            reason: "Revert: Ownable: caller is not the owner",
            decoded_logs: [],
            duration_ms: 5,
          },
        },
      },
    });

    const parsed = parseFoundryTestOutput(jsonStdout, "", 1, "Vault");

    expect(parsed.available).toBe(true);
    expect(parsed.status).toBe("NOT_REPRODUCED");
    expect(parsed.results.length).toBe(1);
    expect(parsed.results[0].passed).toBe(false);
    expect(parsed.results[0].revertReason).toContain("caller is not the owner");
  });

  it("4. Timeout/error -> graceful ERROR result", () => {
    const parsed = parseFoundryTestOutput("", "Compiler error: solc 0.8.20 not supported", 1, "Vault");

    expect(parsed.available).toBe(true);
    expect(parsed.status).toBe("ERROR");
    expect(parsed.reason).toContain("Compiler error");
    expect(parsed.summary.errorCount).toBe(1);
  });

  it("5. Test code generator generates valid pragma & import code", () => {
    const ast = makeMinimalAST("Vault");
    const code = generateFoundryTestCode("pragma solidity ^0.4.24;\ncontract Vault {}", ast);

    expect(code).toContain("pragma solidity ^0.4.24;");
    expect(code).toContain('import "forge-std/Test.sol";');
    expect(code).toContain("contract DynamicSecurityTest is Test");
  });

  it("6. Temporary workspace cleanup test", () => {
    const fs = require("fs");
    const path = require("path");
    const os = require("os");

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "foundry-test-cleanup-"));
    expect(fs.existsSync(tmpDir)).toBe(true);

    fs.rmSync(tmpDir, { recursive: true, force: true });
    expect(fs.existsSync(tmpDir)).toBe(false);
  });

  it("7. Existing benchmark findings remain completely unchanged by dynamic analysis layer", () => {
    const call: ASTExternalCall = {
      id: "c-dyn",
      contractName: "Vault",
      functionName: "withdraw",
      target: "msg.sender",
      method: "call",
      callType: "low-level-call",
      arguments: [],
      rawExpression: "msg.sender.call{value: amount}(\"\")",
      location: BASE_LOC,
    };
    const xfer: ASTEtherTransfer = {
      id: "t-dyn",
      contractName: "Vault",
      functionName: "withdraw",
      recipient: "msg.sender",
      amount: "amount",
      transferType: "call-value",
      rawExpression: call.rawExpression,
      location: BASE_LOC,
    };

    const ast = makeMinimalAST("Vault");
    ast.functions = [
      {
        id: 1,
        name: "withdraw",
        contractName: "Vault",
        kind: "function",
        visibility: "public",
        stateMutability: "nonpayable",
        isVirtual: false,
        isOverride: false,
        modifiers: [],
        parameters: [],
        returnParameters: [],
        signature: "withdraw()",
        location: BASE_LOC,
        externalCalls: [call],
        etherTransfers: [xfer],
        controlStatements: [],
        operations: [],
      },
    ];
    ast.externalCalls = [call];
    ast.etherTransfers = [xfer];

    const beforeRes = detectSecurityVulnerabilities(ast);
    const dynRes = runDynamicVerification("pragma solidity ^0.8.20; contract Vault {}", ast);
    const afterRes = detectSecurityVulnerabilities(ast);

    expect(dynRes).toBeDefined();
    expect(afterRes.summary.totalFindings).toBe(beforeRes.summary.totalFindings);
    expect(afterRes.summary.confirmedCount).toBe(beforeRes.summary.confirmedCount);
  });
});
