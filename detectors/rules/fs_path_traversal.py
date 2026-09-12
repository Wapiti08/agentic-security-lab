from pathlib import PurePosixPath

from detectors.engine import (
    DetectionResult,
    DetectionRule,
    DetectionStatus,
    FileAccessData,
    SecurityEvent,
)


def _is_valid_resolved_path(value: object) -> bool:
    """Check if the given value is a valid resolved path."""
    if not isinstance(value, str) or not value:
        return False
    
    if "\x00" in value:
        return False
    
    try:
        path = PurePosixPath(value)
        return path.is_absolute() and ".." not in path.parts
    except Exception:
        return False


def _normalize_posix_path(path: str) -> PurePosixPath:
    """Normalize separators under the lab's POSIX contract without filesystem IO."""
    if not _is_valid_resolved_path(path):
        raise ValueError("Expected an absolute POSIX path without '..'.")
    return PurePosixPath("/" + path.lstrip("/"))


def _is_within_any_root(path: str, roots: tuple[str, ...]) -> bool:
    """Check if the given path is within any of the authorized roots."""
    target = _normalize_posix_path(path)
    return any(target.is_relative_to(_normalize_posix_path(root)) for root in roots)


class FilePathOutsideScopeRule(DetectionRule):
    rule_id = "FS_PATH_OUTSIDE_SCOPE"
    description = "Detect file access outside authorized roots."

    def supports(self, event: SecurityEvent) -> bool:
        return (
            event.resource_type == "filesystem"
            and event.operation == "read"
        )
    
    def evaluate(self, event: SecurityEvent) -> DetectionResult:
        if not self.supports(event):
            return DetectionResult(
                rule_id=self.rule_id,
                event_id=event.event_id,
                status=DetectionStatus.NOT_EVALUATED,
                reason="Event is not supported by this rule.",
            )

        data = event.data

        if not isinstance(data, FileAccessData):
            return DetectionResult(
                event_id=event.event_id,
                rule_id=self.rule_id,
                status=DetectionStatus.NOT_EVALUATED,
                reason="File access data is missing or invalid.",
            )

        if not _is_valid_resolved_path(data.resolved_path):
            return DetectionResult(
                event_id=event.event_id,
                rule_id=self.rule_id,
                status=DetectionStatus.NOT_EVALUATED,
                reason="Target must be an absolute POSIX path without '..'.",
            )
        
        target = data.resolved_path
        assert isinstance(target, str)

        roots = data.authorized_roots

        if roots is None:
            return DetectionResult(
                event_id=event.event_id,
                rule_id=self.rule_id,
                status=DetectionStatus.NOT_EVALUATED,
                reason="Authorized roots are missing.",
                target_path=target,
            )

        if not isinstance(roots, tuple):
            return DetectionResult(
                event_id=event.event_id,
                rule_id=self.rule_id,
                status=DetectionStatus.NOT_EVALUATED,
                reason="Authorized roots must be a tuple.",
                target_path=target,
            )
        
        # check all roots, avoid hidding useless remaining roots
        if not all(_is_valid_resolved_path(root) for root in roots):
            return DetectionResult(
                event_id=event.event_id,
                rule_id=self.rule_id,
                status=DetectionStatus.NOT_EVALUATED,
                reason="An authorized root is not a valid absolute POSIX path.",
                target_path=target,
            )

        if not roots:
            return DetectionResult(
                event_id=event.event_id,
                rule_id=self.rule_id,
                status=DetectionStatus.DETECTED,
                reason="No filesystem roots are authorized.",
                target_path=target,
                authorized_roots=roots,
            )
        
        within_scope = _is_within_any_root(target, roots)

        return DetectionResult(
            event_id=event.event_id,
            rule_id=self.rule_id,
            status=(
                DetectionStatus.NOT_DETECTED
                if within_scope
                else DetectionStatus.DETECTED
            ),
            reason=(
                "Resolved target path is within authorized roots."
                if within_scope
                else "Resolved target path is outside authorized roots."
            ),
            target_path=target,
            authorized_roots=roots,
        )
