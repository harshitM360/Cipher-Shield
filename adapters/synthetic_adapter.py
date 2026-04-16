from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Optional

from schemas import (
    Actor,
    ActorProcess,
    ActorUser,
    CanonicalEvent,
    Device,
    EventType,
    FileContext,
    Metadata,
    NetworkContext,
    OSInfo,
    ParentProcess,
    ProcessContext,
    ScenarioBundle,
    ScenarioContext,
    ScenarioEvent,
    ScenarioStage,
    Severity,
    Status,
)


_EVENT_CLASS_NAME: dict[EventType, str] = {
    EventType.PROCESS_CREATE: "Process Activity",
    EventType.PROCESS_TERMINATE: "Process Activity",
    EventType.COMMAND_EXEC: "Process Activity",
    EventType.FILE_CREATE: "File Activity",
    EventType.FILE_MODIFY: "File Activity",
    EventType.FILE_RENAME: "File Activity",
    EventType.FILE_DELETE: "File Activity",
    EventType.NETWORK_CONNECT: "Network Activity",
    EventType.BACKUP_DELETE_ATTEMPT: "Process Activity",
}

_EVENT_CATEGORY_NAME: dict[EventType, str] = {
    event_type: "System Activity" for event_type in EventType
}
_EVENT_CATEGORY_NAME[EventType.NETWORK_CONNECT] = "Network Activity"

_PROCESS_LIKE_EVENTS = {
    EventType.PROCESS_CREATE,
    EventType.PROCESS_TERMINATE,
    EventType.COMMAND_EXEC,
    EventType.BACKUP_DELETE_ATTEMPT,
}

_FILE_LIKE_EVENTS = {
    EventType.FILE_CREATE,
    EventType.FILE_MODIFY,
    EventType.FILE_RENAME,
    EventType.FILE_DELETE,
}


@dataclass
class ProcessTracker:
    """Keeps lightweight synthetic PIDs stable across a generated scenario."""

    next_pid: int = 4000
    pid_by_name: dict[str, int] = field(default_factory=dict)

    def pid_for(self, process_name: Optional[str]) -> Optional[int]:
        if not process_name:
            return None
        if process_name not in self.pid_by_name:
            self.pid_by_name[process_name] = self.next_pid
            self.next_pid += 1
        return self.pid_by_name[process_name]


class SyntheticScenarioAdapter:
    """Converts a synthetic scenario bundle into canonical OCSF-aligned events."""

    def __init__(self, product_name: str = "synthetic-generator", version: str = "0.1.0") -> None:
        self.product_name = product_name
        self.version = version

    def load_bundle(self, scenario_path: str | Path) -> ScenarioBundle:
        path = Path(scenario_path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        return ScenarioBundle.model_validate(payload)

    def generate_events(self, bundle: ScenarioBundle) -> list[CanonicalEvent]:
        tracker = ProcessTracker()
        events: list[CanonicalEvent] = []

        for index, timeline_entry in enumerate(sorted(bundle.timeline, key=lambda entry: entry.offset_seconds), start=1):
            scenario_event = bundle.event_lookup[timeline_entry.event_ref]
            event_time = bundle.created + timedelta(seconds=timeline_entry.offset_seconds)
            stage = self._resolve_stage(bundle, scenario_event)
            severity = self._resolve_severity(bundle, scenario_event, stage)
            username = self._extract_user_name(scenario_event)

            process_name = scenario_event.process_name
            parent_name = scenario_event.parent_process_name
            process_pid = tracker.pid_for(process_name)
            parent_pid = tracker.pid_for(parent_name) if parent_name else None

            canonical_event = CanonicalEvent(
                time=event_time,
                activity_name=CanonicalEvent.activity_name_for_event_type(scenario_event.event_type),
                class_name=_EVENT_CLASS_NAME[scenario_event.event_type],
                category_name=_EVENT_CATEGORY_NAME[scenario_event.event_type],
                severity=severity,
                status=Status.SUCCESS,
                metadata=Metadata(
                    product_name=self.product_name,
                    version=self.version,
                    source_name="synthetic-scenario",
                    source_event_id=f"{bundle.id}:{scenario_event.id}:{index}",
                ),
                device=Device(
                    hostname=bundle.host_profile.hostname,
                    os=OSInfo(name=bundle.host_profile.os),
                ),
                actor=Actor(
                    user=ActorUser(name=username),
                    process=ActorProcess(
                        name=process_name,
                        pid=process_pid,
                        command_line=scenario_event.command_line,
                    ),
                ),
                process=self._build_process_context(parent_name, parent_pid),
                file=self._build_file_context(scenario_event),
                network=self._build_network_context(scenario_event),
                labels=list(bundle.labels),
                scenario=ScenarioContext(
                    scenario_id=bundle.id,
                    stage=stage,
                ),
                event_type=scenario_event.event_type,
            )
            events.append(canonical_event)

        return events

    def save_generated_events(
        self,
        bundle: ScenarioBundle,
        output_path: str | Path,
        *,
        indent: int = 2,
    ) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        events = self.generate_events(bundle)
        payload = [event.model_dump(mode="json") for event in events]
        output.write_text(json.dumps(payload, indent=indent), encoding="utf-8")
        return output

    def generate_from_path(self, scenario_path: str | Path, output_path: Optional[str | Path] = None) -> list[CanonicalEvent]:
        bundle = self.load_bundle(scenario_path)
        events = self.generate_events(bundle)
        if output_path is not None:
            self.save_generated_events(bundle, output_path)
        return events

    @staticmethod
    def _build_process_context(parent_name: Optional[str], parent_pid: Optional[int]) -> Optional[ProcessContext]:
        if not parent_name and parent_pid is None:
            return None
        return ProcessContext(parent_process=ParentProcess(name=parent_name, pid=parent_pid))

    @staticmethod
    def _build_file_context(scenario_event: ScenarioEvent) -> Optional[FileContext]:
        if scenario_event.event_type not in _FILE_LIKE_EVENTS:
            return None
        return FileContext(path=scenario_event.file_path, new_path=scenario_event.target_file_path)

    @staticmethod
    def _build_network_context(scenario_event: ScenarioEvent) -> Optional[NetworkContext]:
        if scenario_event.event_type != EventType.NETWORK_CONNECT:
            return None
        return NetworkContext(
            dst_ip=scenario_event.network_destination_ip,
            dst_port=scenario_event.network_destination_port,
        )

    @staticmethod
    def _extract_user_name(scenario_event: ScenarioEvent) -> Optional[str]:
        candidates = [scenario_event.file_path, scenario_event.target_file_path, scenario_event.command_line]
        for candidate in candidates:
            if not candidate:
                continue
            normalized = candidate.replace('\\', '/')
            match = re.search(r"Users/([^/]+)", normalized)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _resolve_stage(bundle: ScenarioBundle, scenario_event: ScenarioEvent) -> ScenarioStage:
        if scenario_event.stage is not None:
            return scenario_event.stage
        if "benign" in {label.lower() for label in bundle.labels}:
            return ScenarioStage.BENIGN
        if scenario_event.event_type in _FILE_LIKE_EVENTS:
            return ScenarioStage.IMPACT
        if scenario_event.event_type in _PROCESS_LIKE_EVENTS or scenario_event.event_type == EventType.NETWORK_CONNECT:
            return ScenarioStage.PRE_IMPACT
        return ScenarioStage.POST_IMPACT

    @staticmethod
    def _resolve_severity(
        bundle: ScenarioBundle,
        scenario_event: ScenarioEvent,
        stage: ScenarioStage,
    ) -> Severity:
        labels = {label.lower() for label in bundle.labels}
        if "benign" in labels:
            if scenario_event.event_type == EventType.FILE_RENAME:
                return Severity.MEDIUM
            return Severity.LOW

        if stage == ScenarioStage.IMPACT:
            return Severity.CRITICAL if scenario_event.event_type == EventType.FILE_RENAME else Severity.HIGH
        if scenario_event.event_type in {EventType.BACKUP_DELETE_ATTEMPT, EventType.NETWORK_CONNECT}:
            return Severity.HIGH
        if stage == ScenarioStage.PRE_IMPACT:
            return Severity.MEDIUM
        return bundle.expected_findings.severity


def generate_all_scenarios(
    scenario_dir: str | Path,
    output_dir: str | Path,
) -> list[Path]:
    """Generate canonical event streams for every scenario JSON in a directory."""

    adapter = SyntheticScenarioAdapter()
    scenario_root = Path(scenario_dir)
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    generated_paths: list[Path] = []
    for scenario_path in sorted(scenario_root.glob("*.json")):
        bundle = adapter.load_bundle(scenario_path)
        output_path = output_root / f"{scenario_path.stem}_events.json"
        generated_paths.append(adapter.save_generated_events(bundle, output_path))
    return generated_paths
