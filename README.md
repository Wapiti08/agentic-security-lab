# Agentic Security Lab

Agentic Security Lab is a defensive security workbench for running controlled
attack simulations against AI agents and MCP tools. It is designed to test
preventive controls, runtime detection, event correlation, risk scoring, and
report generation without targeting real systems or data.

The project is currently in its initial design and scaffolding phase. The first
milestone focuses on filesystem path traversal. Shell execution and HTTP/SSRF
scenarios will be added only after the filesystem workflow is stable.

## Safety and Intended Use

This project is intended only for authorized, isolated, and non-destructive
security testing.

- Use synthetic files, credentials, services, and exfiltration markers only.
- Keep test execution inside a dedicated per-run workspace.
- Do not access real credentials, user directories, public targets, or unrelated
  repository paths.
- Deny outbound internet and host-network access by default.
- Do not use destructive commands, persistence, malware, denial of service, or
  uncontrolled recursive operations.

See [SECURITY.md](SECURITY.md), [DISCLAIMER.md](DISCLAIMER.md), and the
[threat model](docs/threat-model.md) before adding or running attack scenarios.

## How a Test Run Works

1. The attack runner loads an attack case containing controlled input,
   authorization scope, and expected results.
2. The vulnerable agent interprets the input and may propose a tool call.
3. The policy layer evaluates the tool and its normalized arguments.
4. An allowed request is executed by the relevant MCP server; a blocked request
   must not reach execution.
5. Components emit immutable events describing decisions and observed effects.
6. Detectors identify security-relevant behavior, and the correlator connects
   related events into an attack chain.
7. Scoring assigns an explainable risk level.
8. The runner compares actual behavior with the attack case expectations.
9. Reporters produce machine-readable JSON and human-readable HTML results.

Attack outcome and test verdict are intentionally separate. A blocked attack can
mean the test passed, while a successful attack against an intentionally
vulnerable configuration can also mean the test passed when the expected impact
was reproduced and detected.

## Project Structure

| Path | Responsibility |
| --- | --- |
| `apps/vulnerable_agent/` | Converts controlled inputs into potentially unsafe tool requests for testing. |
| `mcp_servers/filesystem_server/` | Exposes controlled filesystem operations to the test agent. |
| `mcp_servers/shell_server/` | Exposes constrained command-execution operations for later scenarios. |
| `mcp_servers/web_server/` | Exposes constrained HTTP operations for later SSRF scenarios. |
| `attack_runner/` | Loads attack cases, orchestrates components, collects results, and evaluates test verdicts. |
| `attack_runner/attacks/` | Stores declarative attack cases and their expected outcomes. |
| `attack_runner/payloads/` | Stores safe, non-destructive test inputs and fixtures. |
| `detectors/rules/` | Contains focused detection rules such as `FS_PATH_TRAVERSAL`. |
| `detectors/correlator.py` | Connects related events and findings into complete attack chains. |
| `detectors/scoring.py` | Calculates explainable risk scores from findings and confirmed impact. |
| `sandbox/sandscope_adapter/` | Integrates the existing Rust SandScope enforcement and telemetry layer. |
| `binary_analysis/` | Extracts binary metadata and applies binary-specific risk rules. |
| `reports/` | Renders canonical run results as JSON and HTML reports. |
| `tests/attacks/` | Verifies attack-case definitions and expected outcomes. |
| `tests/detectors/` | Unit-tests individual detection rules and scoring behavior. |
| `tests/integration/` | Verifies complete runner-to-report attack flows. |
| `docs/` | Documents architecture, trust boundaries, threats, and the attack catalogue. |
| `examples/` | Provides safe example configurations and completed test runs. |

## Core Design Boundaries

- The **runner** orchestrates the experiment; it does not implement detection or
  access files directly.
- The **agent** proposes tool calls; its decisions are untrusted.
- The **policy layer** decides whether a normalized operation is authorized.
- The **MCP server** executes only operations that passed authorization.
- The **sandbox** limits real effects even if an earlier control fails.
- A **detector** identifies and explains suspicious behavior; it does not enforce
  policy.
- The **scorer** estimates risk; it does not decide whether a test passed.
- The **runner** produces the final test verdict by comparing actual behavior
  with the attack case expectations.

## First Milestone: Filesystem Path Traversal

The initial vertical slice will cover four safe cases:

1. A normal read inside an authorized fixture directory.
2. A direct request for a synthetic file outside the authorized directory.
3. A `..` path traversal attempt.
4. A symbolic-link escape attempt.

The first detection rule, `FS_PATH_TRAVERSAL`, will compare the normalized target
path with the authorized filesystem root. The original path, policy decision,
execution result, and synthetic-data markers provide evidence and severity
context, but no single one of them is sufficient by itself.

A blocked traversal case passes only when all expected conditions hold:

- the policy decision is `blocked`;
- no tool execution starts;
- the expected detector rule is emitted;
- no synthetic protected content is returned;
- the event chain completes without infrastructure errors.

## Event and Result Model

Every run uses stable run, trace, event, and parent identifiers so the complete
causal chain can be reconstructed. Original and normalized tool arguments remain
separate, and sensitive evidence is bounded and redacted at its source.

Run results keep these dimensions independent:

- run status;
- policy outcome;
- execution outcome;
- detection outcome;
- actual impact;
- test verdict.

The detailed event contract and completeness invariants are defined in
[docs/architecture.md](docs/architecture.md).

## Optional Observability

Langfuse integration is planned as an optional adapter for visualizing model
calls, tool activity, traces, and evaluation scores. The lab's unified event
model remains the canonical source of security evidence, and all core tests must
run without Langfuse or any other external observability service.

## Documentation

- [Architecture and unified event model](docs/architecture.md)
- [Threat model and safety constraints](docs/threat-model.md)
- [Attack catalogue](docs/attack-catalogue.md)
- [Security policy](SECURITY.md)
- [Disclaimer](DISCLAIMER.md)
