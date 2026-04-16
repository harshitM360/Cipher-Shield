from __future__ import annotations

import json
from collections import Counter, deque
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterable, Sequence

from pydantic import BaseModel, ConfigDict, Field

from schemas import CanonicalEvent, EventType


_FILE_EVENT_TYPES = {
    EventType.FILE_CREATE,
    EventType.FILE_MODIFY,
    EventType.FILE_RENAME,
    EventType.FILE_DELETE,
}

_SUSPICIOUS_PARENT_CHILD_PAIRS = {
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("acrord32.exe", "powershell.exe"),
    ("explorer.exe", "payload.exe"),
}

_SUSPICIOUS_COMMAND_PATTERNS = (
    "delete shadows",
    "shadowcopy delete",
    "invoke-webrequest",
    "executionpolicy bypass",
    "-enc",
    "frombase64string",
)

_SENSITIVE_USER_DIR_MARKERS = (
    "/documents/",
    "/desktop/",
    "/pictures/",
    "/downloads/",
)


class FeatureSummary(BaseModel):
    """Behavior summary derived from a canonical event stream."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    scenario_id: str
    hostname: str
    labels: list[str] = Field(default_factory=list)

    total_events: int
    time_span_seconds: float

    process_create_count: int
    process_terminate_count: int
    command_exec_count: int
    network_connection_count: int
    backup_delete_attempt_count: int
    file_create_count: int
    file_modify_count: int
    file_rename_count: int
    file_delete_count: int
    file_activity_count: int

    unique_process_count: int
    unique_processes: list[str] = Field(default_factory=list)
    unique_files_touched: int
    unique_directories_touched: int
    sensitive_directory_touch_count: int
    extension_change_count: int

    suspicious_parent_child_count: int
    suspicious_parent_child: bool
    suspicious_command_count: int
    suspicious_command: bool
    backup_delete_attempt: bool

    max_events_in_10s: int
    max_file_events_in_10s: int
    burst_activity_score: float

    stage_counts: dict[str, int] = Field(default_factory=dict)
    event_type_counts: dict[str, int] = Field(default_factory=dict)


class FeatureExtractor:
    """Extract simple, explainable behavioral features from canonical events."""

    def extract(self, events: Sequence[CanonicalEvent]) -> FeatureSummary:
        if not events:
            raise ValueError("Feature extraction requires at least one canonical event.")

        ordered_events = sorted(events, key=lambda event: event.time)
        scenario_id = ordered_events[0].scenario.scenario_id
        hostname = ordered_events[0].device.hostname
        labels = list(ordered_events[0].labels)

        event_type_counts = Counter(
            event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
            for event in ordered_events
            if event.event_type is not None
        )
        stage_counts = Counter(event.scenario.stage.value for event in ordered_events)

        unique_processes = sorted(
            {
                event.actor.process.name
                for event in ordered_events
                if event.actor.process.name
            }
        )

        file_paths: set[str] = set()
        directories: set[str] = set()
        sensitive_directories: set[str] = set()
        extension_change_count = 0
        suspicious_parent_child_count = 0
        suspicious_command_count = 0

        for event in ordered_events:
            process_name = (event.actor.process.name or "").lower()
            parent_name = (
                event.process.parent_process.name.lower()
                if event.process is not None and event.process.parent_process is not None and event.process.parent_process.name
                else ""
            )
            if process_name and parent_name and (parent_name, process_name) in _SUSPICIOUS_PARENT_CHILD_PAIRS:
                suspicious_parent_child_count += 1

            command_line = (event.actor.process.command_line or "").lower()
            if any(pattern in command_line for pattern in _SUSPICIOUS_COMMAND_PATTERNS):
                suspicious_command_count += 1

            if event.file is not None:
                for candidate in (event.file.path, event.file.new_path):
                    if candidate:
                        file_paths.add(candidate)
                        parent_dir = _parent_directory(candidate)
                        if parent_dir:
                            directories.add(parent_dir)
                            normalized_parent = parent_dir.replace('\\', '/').lower()
                            if any(marker in normalized_parent for marker in _SENSITIVE_USER_DIR_MARKERS):
                                sensitive_directories.add(parent_dir)
                if event.file.path and event.file.new_path:
                    if _file_extension(event.file.path) != _file_extension(event.file.new_path):
                        extension_change_count += 1

        max_events_in_10s = _max_events_in_window(ordered_events, window_seconds=10)
        max_file_events_in_10s = _max_events_in_window(
            [event for event in ordered_events if event.event_type in _FILE_EVENT_TYPES],
            window_seconds=10,
        )

        first_time = ordered_events[0].time
        last_time = ordered_events[-1].time
        time_span_seconds = max((last_time - first_time).total_seconds(), 0.0)
        if time_span_seconds <= 0:
            burst_activity_score = float(len(ordered_events))
        else:
            burst_activity_score = round((len(ordered_events) / max(time_span_seconds, 1.0)) * 10.0, 3)

        return FeatureSummary(
            scenario_id=scenario_id,
            hostname=hostname,
            labels=labels,
            total_events=len(ordered_events),
            time_span_seconds=time_span_seconds,
            process_create_count=event_type_counts.get(EventType.PROCESS_CREATE.value, 0),
            process_terminate_count=event_type_counts.get(EventType.PROCESS_TERMINATE.value, 0),
            command_exec_count=event_type_counts.get(EventType.COMMAND_EXEC.value, 0),
            network_connection_count=event_type_counts.get(EventType.NETWORK_CONNECT.value, 0),
            backup_delete_attempt_count=event_type_counts.get(EventType.BACKUP_DELETE_ATTEMPT.value, 0),
            file_create_count=event_type_counts.get(EventType.FILE_CREATE.value, 0),
            file_modify_count=event_type_counts.get(EventType.FILE_MODIFY.value, 0),
            file_rename_count=event_type_counts.get(EventType.FILE_RENAME.value, 0),
            file_delete_count=event_type_counts.get(EventType.FILE_DELETE.value, 0),
            file_activity_count=sum(event_type_counts.get(event_type.value, 0) for event_type in _FILE_EVENT_TYPES),
            unique_process_count=len(unique_processes),
            unique_processes=unique_processes,
            unique_files_touched=len(file_paths),
            unique_directories_touched=len(directories),
            sensitive_directory_touch_count=len(sensitive_directories),
            extension_change_count=extension_change_count,
            suspicious_parent_child_count=suspicious_parent_child_count,
            suspicious_parent_child=suspicious_parent_child_count > 0,
            suspicious_command_count=suspicious_command_count,
            suspicious_command=suspicious_command_count > 0,
            backup_delete_attempt=event_type_counts.get(EventType.BACKUP_DELETE_ATTEMPT.value, 0) > 0,
            max_events_in_10s=max_events_in_10s,
            max_file_events_in_10s=max_file_events_in_10s,
            burst_activity_score=burst_activity_score,
            stage_counts=dict(stage_counts),
            event_type_counts=dict(event_type_counts),
        )

    def load_events(self, input_path: str | Path) -> list[CanonicalEvent]:
        payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
        return [CanonicalEvent.model_validate(item) for item in payload]

    def extract_from_path(self, input_path: str | Path) -> FeatureSummary:
        return self.extract(self.load_events(input_path))

    def save_summary(self, summary: FeatureSummary, output_path: str | Path, *, indent: int = 2) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary.model_dump(mode="json"), indent=indent), encoding="utf-8")
        return output

    def extract_and_save(self, input_path: str | Path, output_path: str | Path, *, indent: int = 2) -> FeatureSummary:
        summary = self.extract_from_path(input_path)
        self.save_summary(summary, output_path, indent=indent)
        return summary



def extract_all_event_streams(input_dir: str | Path, output_dir: str | Path) -> list[Path]:
    """Extract feature summaries for every generated event stream in a directory."""

    extractor = FeatureExtractor()
    input_root = Path(input_dir)
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    saved_paths: list[Path] = []
    for input_path in sorted(input_root.glob("*_events.json")):
        output_path = output_root / input_path.name.replace("_events.json", "_features.json")
        extractor.extract_and_save(input_path, output_path)
        saved_paths.append(output_path)
    return saved_paths



def _max_events_in_window(events: Sequence[CanonicalEvent], *, window_seconds: int) -> int:
    if not events:
        return 0

    window: deque[datetime] = deque()
    max_count = 0
    for event in sorted(events, key=lambda item: item.time):
        window.append(event.time)
        while window and (event.time - window[0]).total_seconds() > window_seconds:
            window.popleft()
        if len(window) > max_count:
            max_count = len(window)
    return max_count



def _parent_directory(path_str: str) -> str:
    path = _pure_path(path_str)
    parent = str(path.parent)
    return "" if parent == "." else parent



def _file_extension(path_str: str) -> str:
    return _pure_path(path_str).suffix.lower()



def _pure_path(path_str: str):
    normalized = path_str.replace('\\', '/')
    if ":/" in normalized:
        return PureWindowsPath(path_str)
    return PurePosixPath(path_str)
