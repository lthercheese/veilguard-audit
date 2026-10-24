"use strict";

const byId = (id) => document.getElementById(id);
const source = byId("source");
const state = { scan: null, review: null, fileName: "Contract.sol", revision: 0 };
const demo = [
  "// 示例仅用于演示风险线索，不可部署",
  "pragma solidity ^0.8.20;",
  "",
  "contract Vault {",
  "    mapping(address => uint256) public balances;",
  "    address public owner;",
  "",
  "    constructor() { owner = msg.sender; }",
  "",
  "    function withdraw() external {",
  "        require(tx.origin == owner, \"only owner\");",
  "        uint256 amount = balances[msg.sender];",
  "        (bool ok, ) = msg.sender.call{value: amount}(\"\");",
  "        require(ok, \"transfer failed\");",
  "        balances[msg.sender] = 0;",
  "    }",
  "}"
].join("\n");

function setMessage(id, value, error = false) {
  const node = byId(id);
  node.textContent = value;
  node.classList.toggle("error", error);
}

function appendText(parent, tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = value;
  parent.append(element);
  return element;
}

function resetResults() {
  state.scan = null;
  state.review = null;
  byId("ai-btn").disabled = true;
  byId("export-btn").disabled = true;
  byId("total-count").textContent = "—";
  for (const id of ["high-count", "medium-count", "low-count"]) byId(id).textContent = "0";
  byId("ai-output").hidden = true;
  byId("ai-output").textContent = "";
  const list = byId("findings");
  list.replaceChildren();
  const empty = document.createElement("div");
  empty.className = "empty-state";
  appendText(empty, "strong", "", "等待分析");
  appendText(empty, "p", "", "输入合约源码后点击“开始安全分析”。");
  list.append(empty);
  setMessage("slither-message", "");
  setMessage("ai-message", "先完成规则扫描，再手动请求 AI 复核。");
}

function sourceChanged() {
  state.revision += 1;
  byId("char-count").textContent = source.value.length.toLocaleString() + " 字符";
  resetResults();
  setMessage("scan-message", "");
}

async function api(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store"
  });
  let result;
  try { result = await response.json(); }
  catch { throw new Error("服务返回了无效响应。"); }
  if (!response.ok) throw new Error(result.error || "请求失败 (" + response.status + ")");
  return result;
}

function makeFinding(item, origin) {
  const row = document.createElement("article");
  row.className = "finding";
  const severity = ["high", "medium", "low"].includes(item.severity) ? item.severity : "informational";
  const label = { high: "高风险", medium: "中风险", low: "低风险", informational: "提示" }[severity];
  appendText(row, "span", "severity-tag " + severity, label);
  const body = document.createElement("div");
  appendText(body, "h3", "", item.title || item.rule_id);
  appendText(body, "div", "finding-meta", origin + " · " + (item.line ? "第 " + item.line + " 行" : "行号未提供") + " · " + item.rule_id);
  if (item.explanation) appendText(body, "p", "", item.explanation);
  if (item.evidence) appendText(body, "code", "", item.evidence);
  if (item.remediation) appendText(body, "p", "", "建议：" + item.remediation);
  row.append(body);
  return row;
}

function renderResults(scan) {
  const list = byId("findings");
  list.replaceChildren();
  const builtIn = scan.findings || [];
  const slither = (scan.slither && scan.slither.findings) || [];
  const all = builtIn.concat(slither);
  if (!all.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    appendText(empty, "strong", "", "当前规则未命中风险线索");
    appendText(empty, "p", "", "这不代表合约安全。仍需测试、人工审查与更深入的工具分析。");
    list.append(empty);
  } else {
    for (const item of builtIn) list.append(makeFinding(item, "内置规则"));
    for (const item of slither) list.append(makeFinding(item, "Slither"));
  }
  byId("total-count").textContent = String(all.length);
  byId("high-count").textContent = String(all.filter((f) => f.severity === "high").length);
  byId("medium-count").textContent = String(all.filter((f) => f.severity === "medium").length);
  byId("low-count").textContent = String(all.filter((f) => !["high", "medium"].includes(f.severity)).length);
  const slitherState = (scan.slither && scan.slither.status) || "skipped";
  const toolMessages = {
    skipped: "Slither 未运行。勾选后可在本机执行编译器级静态分析。",
    unavailable: "Slither 未安装；内置规则结果仍可使用。",
    error: (scan.slither && scan.slither.message) || "Slither 分析失败。",
    ok: "Slither 完成，返回 " + slither.length + " 条线索。"
  };
  setMessage("slither-message", toolMessages[slitherState] || "Slither 状态未知。");
}

async function runScan() {
  const revision = state.revision;
  byId("scan-btn").disabled = true;
  setMessage("scan-message", "正在分析源码…");
  try {
    const result = await api("/api/scan", { source: source.value, with_slither: byId("slither-check").checked });
    if (revision !== state.revision) return;
    state.scan = result;
    state.review = null;
    renderResults(result);
    byId("ai-btn").disabled = false;
    byId("export-btn").disabled = false;
    setMessage("scan-message", "分析完成：" + (result.findings.length + ((result.slither && result.slither.findings && result.slither.findings.length) || 0)) + " 条待复核线索。");
    setMessage("ai-message", "如需进一步解释，请手动请求本地 AI 分析。");
  } catch (error) {
    if (revision === state.revision) setMessage("scan-message", error.message, true);
  } finally {
    byId("scan-btn").disabled = false;
  }
}

async function runAi() {
  if (!state.scan) return;
  const revision = state.revision;
  byId("ai-btn").disabled = true;
  setMessage("ai-message", "正在请求本机 Ollama；模型首次加载可能需要一些时间。");
  try {
    const result = await api("/api/ai", { source: source.value, model: byId("model").value.trim() });
    if (revision !== state.revision) return;
    state.review = result.review;
    byId("ai-output").textContent = result.review;
    byId("ai-output").hidden = false;
    setMessage("ai-message", "以下内容由本地模型生成，未经验证。请逐项复核源码和测试。");
  } catch (error) {
    if (revision === state.revision) setMessage("ai-message", error.message, true);
  } finally {
    byId("ai-btn").disabled = !state.scan;
  }
}

function exportReport() {
  if (!state.scan) return;
  const report = {
    tool: "VeilGuard Audit",
    version: "0.1.0",
    generated_at: new Date().toISOString(),
    file_name: state.fileName,
    source_bytes: new TextEncoder().encode(source.value).length,
    source_included: false,
    note: "Rule findings and AI suggestions require independent verification.",
    rule_findings: state.scan.findings,
    slither: state.scan.slither,
    ai_review_unverified: state.review
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "veilguard-report.json";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

source.addEventListener("input", sourceChanged);
byId("scan-btn").addEventListener("click", runScan);
byId("ai-btn").addEventListener("click", runAi);
byId("export-btn").addEventListener("click", exportReport);
byId("clear-btn").addEventListener("click", () => {
  source.value = "";
  byId("file-input").value = "";
  byId("file-name").textContent = "或直接在下方粘贴源码";
  byId("editor-title").textContent = "Contract.sol";
  state.fileName = "Contract.sol";
  sourceChanged();
  setMessage("scan-message", "");
});
byId("demo-btn").addEventListener("click", () => {
  source.value = demo;
  state.fileName = "VulnerableVault.sol";
  byId("file-name").textContent = "示例合约";
  byId("editor-title").textContent = state.fileName;
  sourceChanged();
});
byId("file-input").addEventListener("change", async (event) => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".sol") || file.size > 256 * 1024) {
    setMessage("scan-message", "请选择不超过 256 KiB 的 .sol 文件。", true);
    return;
  }
  source.value = await file.text();
  state.fileName = file.name;
  byId("file-name").textContent = file.name;
  byId("editor-title").textContent = file.name;
  sourceChanged();
  setMessage("scan-message", "文件已载入本地编辑器。");
});

fetch("/api/status", { cache: "no-store" })
  .then((response) => response.json())
  .then((status) => {
    byId("slither-check").disabled = !status.slither;
    byId("slither-hint").textContent = status.slither ? "Slither 已就绪" : "未安装 Slither；可使用内置规则";
  })
  .catch(() => { byId("slither-hint").textContent = "无法读取本机工具状态"; });
