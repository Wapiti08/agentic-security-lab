# Runner input

Run from the project root with Python 3.11 or later. These are synthetic
filesystem read events, not natural-language attacks. Target files are never
opened. Only the explicitly supplied JSON input file is read. Paths represent
upstream-resolved evidence; the CLI does not resolve symlinks.

Single or multiple paths sharing the same authorized roots:

```sh
python -m attack_runner.runner --path /lab/public/a --allowed-root /lab/public
python -m attack_runner.runner --path /lab/public/a /lab/secret/b --allowed-root /lab/public
```

Both `--path` and `--allowed-root` can be repeated. Omitting roots means an empty
allowlist (deny all). Paths containing spaces must be quoted.

For per-event authorization use a UTF-8 JSON object or non-empty list of objects:

```sh
python -m attack_runner.runner --input-file examples/file-events.json
```

Each object requires a string `path` and a string list `authorized_roots`.
An explicit empty list means deny all; missing roots are rejected. Optional
`event_id` must be a non-empty unique string; omitted IDs are generated as UUIDs.
Unknown fields are rejected to catch typos. JSON mode cannot be combined with
CLI paths or roots. All records are validated before detection starts.
Malformed paths are evaluated as `not_evaluated` by the rule, allowing the rest
of the batch to proceed. Results retain their event IDs and input order.

Programmatic callers can pass a dictionary or list to `load_events`, then pass
the returned events and one reusable Detector to `run_batch`.

Exit codes: 0 means every event was evaluated (including `detected`); 1 means
some event was not evaluated, errored, or had no applicable rules; 2 means CLI,
file, or input schema error. These are not attack success or test verdicts.
