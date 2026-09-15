from dataclasses import dataclass


@dataclass(frozen=True)
class FileServiceConfig:
    workspace_root: str
    authorized_roots: tuple[str, ...]
    max_read_bytes: int


@dataclass(frozen=True)
class ReadRequest:
    request_id: str
    original_path: str


@dataclass(frozen=True)
class ReadResult:
    request_id: str
    original_path: str
    resolved_path: str | None
    policy_decision: str
    execution_status: str
