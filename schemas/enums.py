from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Supported severity levels across scenarios, events, and findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Status(str, Enum):
    """Execution/result status for a canonical event."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class ScenarioStage(str, Enum):
    """High-level stage of a scenario or event in the attack lifecycle."""

    BENIGN = "benign"
    PRE_IMPACT = "pre-impact"
    IMPACT = "impact"
    POST_IMPACT = "post-impact"


class EventType(str, Enum):
    """V1 normalized event taxonomy used by the project."""

    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_RENAME = "file_rename"
    FILE_DELETE = "file_delete"
    NETWORK_CONNECT = "network_connect"
    BACKUP_DELETE_ATTEMPT = "backup_delete_attempt"
    COMMAND_EXEC = "command_exec"
