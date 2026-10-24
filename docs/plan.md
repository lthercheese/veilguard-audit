# VeilGuard Audit Implementation Plan

**Goal:** Deliver a runnable local Solidity review app with rule findings, optional local AI, and exportable reports.

**Architecture:** Python standard-library HTTP server serves a static browser UI and JSON API. Independent scanner and Ollama adapters keep security boundaries testable. The project uses no required third-party Python packages.

**Tech Stack:** Python 3.10+, HTML/CSS/JavaScript, unittest; optional Slither and Ollama.

**Spec:** `docs/design.md`

## Global constraints

- Loopback only, source <= 256 KiB, request <= 512 KiB.
- No source persistence or automatic AI requests.
- Clear distinction between rule evidence and AI suggestions.

## Review focus

- Empty or oversized source receives an error.
- Comments and strings do not produce rule matches.
- AI unavailable returns a bounded, useful error without sending to another host.
- Slither unavailable or failing is visible to the user.
- Malformed HTTP JSON and unknown paths return controlled responses.

## Task 1: Rule scanner

**Files:** `scanner.py`, `tests/test_scanner.py`

**Interface:** `scan_source(source: str) -> list[dict]`; each finding has `rule_id`, `title`, `severity`, `line`, `evidence`, `explanation`, and `remediation`.

- [ ] Write tests for `tx.origin`, `selfdestruct`, and unchecked low-level call, plus comments/strings and size validation.
- [ ] Confirm tests fail before implementation.
- [ ] Implement source masking and conservative rules.
- [ ] Confirm all tests pass.

## Task 2: Optional tools

**Files:** `integrations.py`, `tests/test_integrations.py`

**Interface:** `run_slither(source: str) -> dict`; `ask_ollama(source: str, findings: list[dict], model: str) -> str`.

- [ ] Write tests for Slither availability/error mapping and Ollama response parsing/validation.
- [ ] Confirm tests fail before implementation.
- [ ] Implement bounded subprocess and fixed loopback HTTP request.
- [ ] Confirm all tests pass.

## Task 3: API and UI

**Files:** `server.py`, `web/index.html`, `web/app.js`, `web/styles.css`, `tests/test_server.py`

**Interface:** `POST /api/scan`, `POST /api/ai`, `GET /api/status`, static assets.

- [ ] Write HTTP tests for valid scan, invalid inputs, status, and AI opt-in route.
- [ ] Confirm tests fail before implementation.
- [ ] Implement server and browser workflow.
- [ ] Confirm full test suite and manual browser smoke test pass.

## Task 4: Open-source packaging

**Files:** `README.md`, `LICENSE`, `.gitignore`, `examples/VulnerableVault.sol`.

- [ ] Document setup, security limits, privacy model, and optional tool installation.
- [ ] Run full tests and verify example output.
- [ ] Commit source and prepare GitHub publication.
