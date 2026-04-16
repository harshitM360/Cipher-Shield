from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .enums import EventType, Severity, ScenarioStage


class HostProfile(BaseModel):
    """Host metadata for a synthetic scenario."""

    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(..., examples=["finance-laptop-01"])
    os: str = Field(..., examples=["Windows 11"])
    department: str = Field(..., examples=["finance"])


class TimelineEntry(BaseModel):
    """Timeline entry that points to an event and says when it occurs."""

    model_config = ConfigDict(extra="forbid")

    offset_seconds: int = Field(..., ge=0, examples=[10])
    event_ref: str = Field(..., examples=["event--003"])


class ScenarioEvent(BaseModel):
    """Simplified source event used inside a synthetic scenario bundle."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    id: str = Field(..., examples=["event--003"])
    event_type: EventType
    process_name: Optional[str] = Field(default=None, examples=["vssadmin.exe"])
    parent_process_name: Optional[str] = Field(default=None, examples=["powershell.exe"])
    command_line: Optional[str] = Field(
        default=None,
        examples=["vssadmin delete shadows /all /quiet"],
    )
    file_path: Optional[str] = Field(default=None, examples=[r"C:/Users/Alice/Documents/report1.docx"])
    target_file_path: Optional[str] = Field(
        default=None,
        examples=[r"C:/Users/Alice/Documents/report1.locked"],
    )
    network_destination_ip: Optional[str] = Field(default=None, examples=["198.51.100.10"])
    network_destination_port: Optional[int] = Field(default=None, ge=0, le=65535, examples=[443])
    stage: Optional[ScenarioStage] = Field(
        default=None,
        description="Optional per-event stage override. If omitted, stage can be inferred later.",
    )


class ExpectedFindings(BaseModel):
    """Ground-truth style expectations for test and demo validation."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    rules_triggered: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)


class ScenarioBundle(BaseModel):
    """STIX-inspired synthetic scenario container for Phase 1 and beyond."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., pattern=r"^scenario-bundle$")
    id: str = Field(..., examples=["scenario-bundle--ransomware-001"])
    spec_version: str = Field(..., examples=["1.0"])
    name: str = Field(..., examples=["Word to PowerShell to file encryption simulation"])
    created: datetime
    modified: datetime
    labels: list[str] = Field(default_factory=list)
    objective: str
    host_profile: HostProfile
    timeline: list[TimelineEntry] = Field(default_factory=list)
    events: list[ScenarioEvent] = Field(default_factory=list)
    expected_findings: ExpectedFindings

    @model_validator(mode="after")
    def validate_event_references(self) -> "ScenarioBundle":
        """Ensure every timeline entry points to a real event exactly once or more."""

        event_ids = {event.id for event in self.events}
        missing_refs = [entry.event_ref for entry in self.timeline if entry.event_ref not in event_ids]
        if missing_refs:
            raise ValueError(f"Timeline contains unknown event references: {missing_refs}")
        return self

    @property
    def event_lookup(self) -> dict[str, ScenarioEvent]:
        """Convenience accessor for adapters and generators."""

        return {event.id: event for event in self.events}

    @property
    def is_malicious(self) -> bool:
        return "malicious" in {label.lower() for label in self.labels}
