# VeilGuard Audit — design

## Intent

A local-first, open-source assistant for an initial review of Solidity source. A developer can paste or load one `.sol` file, inspect traceable rule findings, and explicitly ask a locally running AI model for a second opinion. This helps teams share a review without sending unpublished contract code to a hosted service.

## Scope

- Single-file Solidity input, up to 256 KiB, analyzed in memory.
- Built-in conservative pattern rules with line numbers, severity, evidence, and remediation. These are leads, not confirmed vulnerabilities.
- Optional Slither results when the user has installed Slither and a compatible compiler. Slither failure is reported, never silently replaced.
- Optional Ollama review on `127.0.0.1:11434`, invoked only by the user. Model output is labeled unverified and kept separate from rule results.
- Local HTTP UI and JSON API, bound to loopback. No accounts, database, telemetry, or cloud API calls.
- Export a report as JSON from the browser.

## Boundaries

No automatic contract deployment, execution, formal verification, repository import, or claim of a complete security audit. Imported Solidity dependencies are not resolved by the built-in rules. Source is never written by this application except to a temporary file for the optional Slither subprocess, which is removed after analysis.

## Approaches considered

1. Hosted audit service: convenient collaboration, but conflicts with the sensitive-code privacy goal.
2. CLI-only local tool: simple and scriptable, but harder to inspect and share findings interactively.
3. Local web app: keeps code on the developer's machine while making findings and AI suggestions easy to review. Chosen as the default product shape pending user feedback.

## Main flow

Paste or load Solidity → run local rules → optionally run Slither → inspect evidence → optionally invoke local AI → export JSON. The AI receives the source and rule findings only after the explicit click. Its output is untrusted advice, not a finding verified by tooling.

## Security decisions

- Bind to `127.0.0.1` by default and reject non-loopback host configuration.
- Cap request and source sizes; validate JSON and fields; reject path input.
- Do not log source bodies or persist them.
- Invoke Slither without a shell, in a temporary directory, with a timeout.
- Use a fixed loopback AI endpoint; never accept arbitrary URLs from API clients.
- Render all source and AI output as text, never as HTML.
