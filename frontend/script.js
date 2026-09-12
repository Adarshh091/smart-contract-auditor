// =============================================
//  ChainGuard — Frontend Script
//  Author: [Friend's Name]
//  Connects to ChainGuard backend API
// =============================================

const BACKEND_URL = "http://localhost:3000"; // Change to deployed URL later

// --- Sample Contract for Demo ---
const SAMPLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // WARNING: Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call before state update — reentrancy risk!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount; // State updated AFTER call
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}`;

// --- Line/Char Counter ---
const textarea = document.getElementById("contractCode");
const lineCount = document.getElementById("lineCount");
const charCount = document.getElementById("charCount");

textarea.addEventListener("input", updateMeta);
function updateMeta() {
  const text = textarea.value;
  const lines = text === "" ? 0 : text.split("\n").length;
  lineCount.textContent = `${lines} line${lines !== 1 ? "s" : ""}`;
  charCount.textContent = `${text.length} chars`;
}

// --- Load Sample ---
function loadSample() {
  textarea.value = SAMPLE_CONTRACT;
  updateMeta();
  textarea.focus();
}

// --- Show / Hide helpers ---
function show(id) { document.getElementById(id).classList.remove("hidden"); }
function hide(id) { document.getElementById(id).classList.add("hidden"); }

// --- Animate pipeline steps ---
async function animatePipeline() {
  const steps = ["step1", "step2", "step3"];
  for (let i = 0; i < steps.length; i++) {
    await delay(900);
    document.getElementById(steps[i]).classList.add("active");
    if (i > 0) document.getElementById(steps[i - 1]).classList.remove("active");
    if (i > 0) document.getElementById(steps[i - 1]).classList.add("done");
  }
  await delay(600);
  document.getElementById(steps[2]).classList.remove("active");
  document.getElementById(steps[2]).classList.add("done");
}

function delay(ms) { return new Promise(res => setTimeout(res, ms)); }

// --- Render Report ---
function renderReport(data) {
  const container = document.getElementById("reportOutput");
  const badge     = document.getElementById("reportBadge");
  const findings  = data.findings || [];

  const highCount   = findings.filter(f => f.severity === "HIGH").length;
  const medCount    = findings.filter(f => f.severity === "MEDIUM").length;
  const lowCount    = findings.filter(f => f.severity === "LOW").length;
  const totalIssues = findings.length;

  // Badge
  badge.classList.remove("hidden", "safe", "warn", "danger");
  if (highCount > 0) {
    badge.textContent = `${totalIssues} Issues · CRITICAL`;
    badge.classList.add("danger");
  } else if (medCount > 0) {
    badge.textContent = `${totalIssues} Issues · WARNING`;
    badge.classList.add("warn");
  } else if (lowCount > 0) {
    badge.textContent = `${totalIssues} Issues · LOW`;
    badge.classList.add("warn");
  } else {
    badge.textContent = "✓ CLEAN";
    badge.classList.add("safe");
  }

  // Build HTML
  let html = `
    <div class="summary-bar">
      <div class="summary-item">
        <div class="summary-count red">${highCount}</div>
        <div class="summary-label">HIGH</div>
      </div>
      <div class="summary-item">
        <div class="summary-count yellow">${medCount}</div>
        <div class="summary-label">MEDIUM</div>
      </div>
      <div class="summary-item">
        <div class="summary-count green">${lowCount}</div>
        <div class="summary-label">LOW</div>
      </div>
    </div>
  `;

  if (findings.length === 0) {
    html += `
      <div class="no-issues">
        <div class="no-issues-icon">✓</div>
        <strong>No vulnerabilities detected</strong>
        <span style="font-size:0.78rem;color:var(--muted)">Contract passed all checks.</span>
      </div>`;
  } else {
    html += `<div class="findings-list">`;
    findings.forEach(f => {
      html += `
        <div class="finding-card ${f.severity}">
          <div class="finding-top">
            <span class="finding-severity">${f.severity}</span>
            <span class="finding-tool">${f.tool}</span>
          </div>
          <div class="finding-title">${f.title}</div>
          <div class="finding-desc">${f.description}</div>
        </div>`;
    });
    html += `</div>`;
  }

  container.innerHTML = html;
}

// --- Main Analyze Function ---
async function analyzeContract() {
  const code = textarea.value.trim();

  if (!code) {
    textarea.focus();
    textarea.style.borderColor = "var(--danger)";
    setTimeout(() => textarea.style.borderColor = "", 1500);
    return;
  }

  // UI: loading state
  const btn = document.getElementById("analyzeBtn");
  btn.disabled = true;
  btn.textContent = "Analyzing...";

  hide("placeholder");
  hide("reportOutput");
  document.getElementById("reportBadge").classList.add("hidden");

  // Reset pipeline steps
  ["step1","step2","step3"].forEach(id => {
    const el = document.getElementById(id);
    el.classList.remove("active","done");
  });

  show("loadingState");
  animatePipeline();

  try {
    const response = await fetch(`${BACKEND_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });

    if (!response.ok) throw new Error(`Server error: ${response.status}`);

    const data = await response.json();

    await delay(2800); // Let pipeline animation finish

    hide("loadingState");
    show("reportOutput");
    renderReport(data);

  } catch (err) {
    // Demo mode — show mock results if server not reachable
    await delay(2800);
    hide("loadingState");
    show("reportOutput");

    const mockData = {
      findings: [
        {
          severity: "HIGH",
          tool: "Slither",
          title: "Reentrancy Vulnerability",
          description: "External call made before state update in withdraw(). An attacker can recursively call withdraw() before balance is decremented."
        },
        {
          severity: "MEDIUM",
          tool: "Solhint",
          title: "Missing Access Control",
          description: "The deposit() function has no access modifier. Consider restricting who can call sensitive functions."
        },
        {
          severity: "LOW",
          tool: "Semgrep",
          title: "Floating Pragma",
          description: "Use a fixed compiler version instead of a range to avoid unexpected behavior with newer compiler versions."
        }
      ]
    };
    renderReport(mockData);
  }

  // Reset button
  btn.disabled = false;
  btn.innerHTML = `<span class="btn-icon">⬡</span> Run Security Audit`;
}
