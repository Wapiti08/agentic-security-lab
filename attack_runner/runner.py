"""Detect synthetic file-access events supplied through CLI or JSON."""

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
import json
from pathlib import Path
from uuid import uuid4

from detectors import engine
from detectors.rules.fs_path_traversal import FilePathOutsideScopeRule


@dataclass(frozen=True)
class EventResults:
    event_id: str
    results: tuple[engine.DetectionResult, ...]


def running(event: engine.SecurityEvent, detector: engine.Detector) -> tuple[engine.DetectionResult, ...]:
    return detector.detect(event)


def run_batch(events: Sequence[engine.SecurityEvent], detector: engine.Detector) -> tuple[EventResults, ...]:
    """Keep results grouped by event, even when no rules apply."""
    return tuple(EventResults(event.event_id, running(event, detector)) for event in events)


def load_events(payload: object) -> tuple[engine.SecurityEvent, ...]:
    """Validate the entire input batch before detection starts."""
    records = [payload] if isinstance(payload, dict) else payload
    if not isinstance(records, list) or not records:
        raise ValueError("Expected an event object or a non-empty list of objects.")
    events = []
    seen_ids: set[str] = set()
    for index, record in enumerate(records):
        prefix = f"Record {index + 1}"
        if not isinstance(record, dict):
            raise ValueError(f"{prefix}: expected an object.")
        if set(record) - {"event_id", "path", "authorized_roots"}:
            raise ValueError(f"{prefix}: unknown fields.")
        if not isinstance(record.get("path"), str):
            raise ValueError(f"{prefix}: path must be a string.")
        roots = record.get("authorized_roots")
        if not isinstance(roots, list) or not all(isinstance(root, str) for root in roots):
            raise ValueError(f"{prefix}: authorized_roots must be a list of strings; [] means deny all.")
        event_id = record.get("event_id", str(uuid4()))
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError(f"{prefix}: event_id must be a non-empty string.")
        if event_id in seen_ids:
            raise ValueError(f"{prefix}: duplicate event_id.")
        seen_ids.add(event_id)
        events.append(engine.SecurityEvent(
            event_id, "filesystem", "read",
            engine.FileAccessData(record["path"], tuple(roots)),
        ))
    return tuple(events)


def print_results(batches: tuple[EventResults, ...]) -> None:
    for batch in batches:
        label = json.dumps(batch.event_id, ensure_ascii=True)
        if not batch.results:
            print(f"Event {label}: no applicable rules; safety is unknown.")
        for result in batch.results:
            print(f"Event {label}: {result.rule_id} | {result.status.value} | {result.reason}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--path", nargs="+", action="extend", help="Synthetic paths; repeatable.")
    source.add_argument("--input-file", type=Path, help="UTF-8 JSON object or list of objects.")
    parser.add_argument("--allowed-root", action="append", help="Repeatable CLI root; omit to deny all.")
    args = parser.parse_args(argv)
    if args.input_file is not None and args.allowed_root is not None:
        parser.error("--allowed-root cannot accompany --input-file; specify roots in each record.")
    try:
        if args.input_file is not None:
            payload = json.loads(args.input_file.read_text(encoding="utf-8"))
        else:
            payload = [{"path": path, "authorized_roots": args.allowed_root or []} for path in args.path]
        events = load_events(payload)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))

    detector = engine.Detector([FilePathOutsideScopeRule()])
    batches = run_batch(events, detector)
    print_results(batches)
    incomplete = any(
        not batch.results or any(result.status in (
            engine.DetectionStatus.ERROR, engine.DetectionStatus.NOT_EVALUATED,
        ) for result in batch.results)
        for batch in batches
    )
    return 1 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
