"""Shared event types and detection rule contract.

Concrete rules import this module; it must not import concrete rules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from collections.abc import Iterable

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


class Detector:
    def __init__(self, rules: Iterable[DetectionRule]) -> None:
        registered_rules = tuple(rules)
        seen_ids: set[str] = set()

        for rule in registered_rules:
            if not isinstance(rule, DetectionRule):
                raise TypeError("Each rule must inherit from DetectionRule.")
            
            rule_id = getattr(rule, "rule_id", None)

            if not isinstance(rule_id, str) or not rule_id.strip():
                raise ValueError("Each rule must have a non-empty rule_id.")
            
            if rule_id in seen_ids:
                raise ValueError(f"Duplicate rule_id detected: {rule_id}")
            
            seen_ids.add(rule_id)
        
        self._rules = registered_rules

    def detect(
        self,
        event: SecurityEvent, 
    ) -> tuple[DetectionResult, ...]:
        '''
        entrypoint for detection rules. Returns a tuple of DetectionResult objects for the given event.
        '''

        if not isinstance(event, SecurityEvent):
            raise TypeError("The event must be an instance of SecurityEvent.")
        
        results: list[DetectionResult] = []

        # iter rules to check matched results
        for rule in self._rules:
            rule_id = rule.rule_id
            stage = "supports"

            try:
                supported = rule.supports(event)

                if not isinstance(supported, bool):
                    raise TypeError("supports must return bool.")
                
                if not supported:
                    continue

                stage = "evaluate"
                result = rule.evaluate(event)

                stage = "validate_result"
                self._validate_result(result, event, rule_id)

            except Exception as exc:
                result = DetectionResult(
                    event_id=event.event_id,
                    rule_id=rule_id,
                    status=DetectionStatus.ERROR,
                    reason=(
                        f"Rule failed during {stage}: "
                        f"{type(exc).__name__}."
                    ),
                )

            results.append(result)

        return tuple(results)
    
    @staticmethod
    def _validate_result(
        result: object,
        event: SecurityEvent,
        rule_id: str,
    ) -> None:
        if not isinstance(result, DetectionResult):
            raise TypeError("evaluate must return DetectionResult.")

        if result.event_id != event.event_id:
            raise ValueError("Result event_id does not match the input event.")

        if result.rule_id != rule_id:
            raise ValueError("Result rule_id does not match the current rule.")

        if not isinstance(result.status, DetectionStatus):
            raise TypeError("Result status must be DetectionStatus.")

        if not isinstance(result.reason, str) or not result.reason.strip():
            raise ValueError("Result reason must be a non-empty string.")