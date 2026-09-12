"""Shared event types and detection rule contract.

Concrete rules import this module; it must not import concrete rules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class DetectionStatus(str, Enum):
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    NOT_EVALUATED = "not_evaluated"
    ERROR = "error"


@dataclass(frozen=True)
class FileAccessData:
    # None means missing; an empty tuple means no authorized directories.
    resolved_path: str | None
    authorized_roots: tuple[str, ...] | None


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    resource_type: str
    operation: str
    data: FileAccessData | None = None


@dataclass(frozen=True)
class DetectionResult:
    event_id: str
    status: DetectionStatus
    rule_id: str
    reason: str
    target_path: str | None = None
    authorized_roots: tuple[str, ...] | None = None


class DetectionRule(ABC):
    rule_id: str
    description: str

    @abstractmethod
    def supports(self, event: SecurityEvent) -> bool:
        """Check if the rule supports the given event."""
        raise NotImplementedError

    @abstractmethod
    def evaluate(self, event: SecurityEvent) -> DetectionResult:
        """Evaluate the given event and return a DetectionResult."""
        raise NotImplementedError
