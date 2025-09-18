SecureScan — Frontend (single-file) README

SecureScan is a self-contained browser UI for client-side static code scanning.
This repository (or file) contains a single HTML file that implements a polished UI, simple client-side scanners (regex + JavaScript AST via Esprima), and a mock AI progress console. It is intended to run entirely in the browser — no backend required to use the scanner UI.

What this code is / does (short)

Provides a drag-and-drop / browse file UI to upload source files.

Performs client-side vulnerability heuristics:

Regex checks for secrets, AWS keys, PEM blocks, hardcoded passwords.

SQL-like concatenation heuristics.

XSS-like DOM-write heuristics.

Generic eval / exec detections.

JavaScript AST checks (Esprima) for eval(), innerHTML assignment, document.write, etc.

Displays a mock AI console (client-side simulated messages) while scanning.

Renders scan results: per-finding type, severity, file, line, description and remediation.

Shows summary counters (critical/high/medium/low).

Files

index.html — the full frontend implementation (HTML, CSS, JS). Open this file in a modern browser to run the UI.

How to run

Save index.html locally (if not already).

Open it in a modern browser (Chrome/Edge/Firefox):

Double-click index.html or drag it into a browser window.

For best results and to test file uploads reliably, serve it via a static host (optional):

# simple Python static server (optional)
python -m http.server 8080
# then open http://localhost:8080/index.html


Use BROWSE FILES or drag-and-drop one or more source files (supported: .js, .java, .py, .php, .html, .css, .xml, .json, .txt).

Click INITIATE SECURITY SCAN. Results appear in the results panel.

What the scanner flags (detection summary)

The UI implements the following checks (client-side):

Secrets

Hardcoded API keys, client secrets, secret_key patterns.

AWS access key pattern (AKIA...).

Private key PEM blocks (-----BEGIN ... KEY-----).

Hardcoded password-like assignments.

SQL-like

Concatenated SQL or execute() usages that include string concatenation / formatting (possible SQL injection).

XSS / DOM

document.write, innerHTML / outerHTML assignments, insertAdjacentHTML (unsafe DOM writes).

Generic dangerous exec

eval, exec, execfile detection.

JavaScript AST checks (Esprima)

eval() CallExpression → flagged as critical.

Assignment to .innerHTML → flagged high.

document.write(...) usage → flagged high.

If Esprima fails to parse, a low-severity "JS parse error" finding may be emitted.

HTML-specific

Inline event handlers (onclick, onmouseover, etc.) are flagged as medium severity.

Result format (how findings are presented)

Each finding shown in the UI contains:

type — human-readable finding name (e.g., “Hardcoded API Key”).

severity — one of critical, high, medium, low.

file — filename uploaded.

line — best-effort line number.

description — short explanation of the issue.

remediation — brief suggested fix.

Summary counters in the header show counts by severity.

Mock AI behavior

The "AI console" simulates an AI assistant (messages like "Sentinel: extracting tokens...").

This is a client-side simulation to show staged progress — it does not call external AI services or change detection logic. The scanner's findings come from the local heuristics and AST checks.

Limitations & notes (important)

This is a client-side demo using heuristics. It is intended for triage and demo purposes only.

The scanner can produce false positives and false negatives; do not treat results as definitive.

The UI reads files as text (via FileReader) — do not upload real secrets or private keys to public demos.

No execution of uploaded code is performed by the UI; however, uploaded files may contain patterns that look like secrets — treat test files accordingly.

Line numbers are best-effort (based on match index).

Quick troubleshooting

If drag-and-drop or file reading fails, try serving the file via python -m http.server and open http://localhost:8080.

If Esprima fails to parse certain modern JS syntax, the UI will surface a JS parse error finding for that file.

License & attribution

The UI uses Esprima (client-side JS parser) — included via CDN in the code.

You may reuse or modify this frontend code in your projects. (Add a license file to the repo if you want an explicit license.)

