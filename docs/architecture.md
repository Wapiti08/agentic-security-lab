# Architecture

## Processing Flow

Each test follows one traceable flow:

1. The attack runner creates a run and submits a safe test case.
2. The vulnerable agent interprets the input and may propose a tool call.
3. Policy and sandbox layers allow or block the requested operation.
4. MCP servers execute allowed operations against synthetic fixtures.
5. Every component emits events using the unified event model.
6. Detectors create findings; the correlator joins related events.
7. Scoring assigns an explainable risk level.
8. Reporters render the same findings as JSON or HTML.

The JSON report is the canonical machine-readable output. The HTML report is a
presentation of that data and must not introduce different scoring logic.

## Unified Event Model

Events are immutable observations. A later component may emit a finding or
correlation event, but it must not rewrite the event that it evaluated.

### Required Fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Version of the event contract used by producers and consumers. |
| `event_id` | Unique identifier for this event. |
| `run_id` | Identifier shared by all events in one test execution. |
| `trace_id` | Identifier shared by one end-to-end attack path within the run. |
| `parent_event_id` | Immediate causal parent; absent only for a root event. |
| `sequence` | Monotonically increasing number within a trace. |
| `timestamp` | UTC timestamp assigned when the event is emitted. |
| `event_type` | Stable category such as input, tool request, policy decision, execution, or finding. |
| `source` | Component that emitted the event. |
| `outcome` | Observed state: proposed, allowed, blocked, executed, failed, or detected. |
| `summary` | Short human-readable description without sensitive raw content. |
| `data` | Event-type-specific structured fields. |

### Context Fields

The following belong in `data` when relevant:

| Field | Meaning |
| --- | --- |
| `actor` | User, agent, MCP server, policy engine, sandbox, or detector. |
| `tool_name` | Stable name of the requested tool. |
| `original_arguments` | Arguments proposed by the agent, subject to redaction. |
| `normalized_arguments` | Canonical values used for authorization and execution. |
| `authorized_scope` | Tools, paths, commands, hosts, ports, and limits granted to the run. |
| `policy_decision` | Allow or deny, including the policy or rule identifier and reason. |
| `execution_result` | Exit state, bounded metadata, and side-effect summary. |
| `evidence` | Minimal redacted evidence required to support a finding. |
| `rule_id` | Stable identifier of a matched detection rule. |
| `risk_score` | Numeric score produced after detection or correlation. |
| `risk_level` | Human-readable severity derived from the score. |

`original_arguments` and `normalized_arguments` must remain distinct. Detectors
need both to identify traversal, redirect, encoding, and normalization bypasses.

## Event Types

The initial event vocabulary is:

- `run.started` and `run.completed`;
- `input.received`;
- `agent.tool_proposed`;
- `policy.decision`;
- `tool.execution_started` and `tool.execution_completed`;
- `sandbox.violation`;
- `detector.finding`;
- `correlator.finding`;
- `report.generated`.

New event types may be added without changing existing meanings. Breaking field
or semantic changes require a new `schema_version`.

## Causality and Correlation

- `run_id` groups everything created by a single runner invocation.
- `trace_id` groups one attack path, including retries and its resulting tool
  activity.
- `parent_event_id` expresses direct causality.
- `sequence` resolves ordering when timestamps are equal or clocks differ.
- A detector finding references the event that supplied its evidence.
- A correlator finding references all contributing event IDs and explains the
  relationship between them.

Missing parents, duplicate identifiers, sequence regressions, or an execution
without a preceding policy decision are themselves integrity findings.

## Authorization Model

Authorization is declared per run and defaults to deny. It may grant a bounded
set of:

- tool names;
- canonical filesystem roots and permitted operations;
- executable names and argument patterns;
- URL schemes, hosts, resolved address ranges, ports, and redirect behavior;
- resource limits such as duration, output size, process count, and request
  count.

Policy decisions are made against normalized arguments. The exact normalized
values must be passed to execution so that authorization and execution cannot
interpret different resources.

## Evidence and Data Handling

- Store metadata or a digest instead of full content whenever possible.
- Synthetic secrets should contain unique markers so disclosure can be proven
  without relying on real sensitive data.
- Apply redaction before events leave their source component.
- Bound captured stdout, stderr, HTTP bodies, and file excerpts.
- Reports must distinguish absent data from data removed by redaction.
- Reports must not embed active remote resources or executable content.

## Event Completeness Invariants

A completed run is valid only when:

- it contains exactly one start event and one terminal run event;
- every non-root event has a valid causal parent;
- every execution has a preceding tool proposal and policy decision;
- a blocked decision has no corresponding execution event;
- an allowed execution has a terminal success or failure event;
- every reported finding references existing evidence events;
- scoring can be reproduced from the recorded findings and rule versions.

These invariants allow integration tests to distinguish a safe block from
missing telemetry or an incomplete run.

