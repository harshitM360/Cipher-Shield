from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .enums import EventType, ScenarioStage, Severity, Status


_ACTIVITY_NAME_TO_EVENT_TYPE: dict[str, EventType] = {
    "Process Launch": EventType.PROCESS_CREATE,
    "Process Terminate": EventType.PROCESS_TERMINATE,
    "File Create": EventType.FILE_CREATE,
    "File Modify": EventType.FILE_MODIFY,
    "File Rename": EventType.FILE_RENAME,
    "File Delete": EventType.FILE_DELETE,
    "Network Connect": EventType.NETWORK_CONNECT,
    "Backup Delete Attempt": EventType.BACKUP_DELETE_ATTEMPT,
    "Command Execution": EventType.COMMAND_EXEC,
}

_EVENT_TYPE_TO_ACTIVITY_NAME: dict[EventType, str] = {
    value: key for key, value in _ACTIVITY_NAME_TO_EVENT_TYPE.items()
}


class Metadata(BaseModel):
    """Source metadata for a normalized security event."""

    model_config = ConfigDict(extra="forbid")

    product_name: str = Field(..., examples=["synthetic-generator"])
    version: str = Field(..., examples=["0.1.0"])
    source_name: str = Field(..., examples=["lab-simulation"])
    source_event_id: Optional[str] = Field(default=None, examples=["evt-001"])


class OSInfo(BaseModel):
    """Operating system details for the reporting device."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., examples=["Windows 11"])


class Device(BaseModel):
    """Host/device information."""

    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(..., examples=["finance-laptop-01"])
    os: OSInfo


class ActorUser(BaseModel):
    """User associated with the event, if known."""

    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, examples=["alice"])


class ActorProcess(BaseModel):
    """Process directly responsible for the event."""

    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, examples=["powershell.exe"])
    pid: Optional[int] = Field(default=None, ge=0, examples=[4321])
    command_line: Optional[str] = Field(
        default=None,
        examples=["powershell.exe -ExecutionPolicy Bypass -File loader.ps1"],
    )


class Actor(BaseModel):
    """Actor context for the event."""

    model_config = ConfigDict(extra="forbid")

    user: ActorUser
    process: ActorProcess


class ParentProcess(BaseModel):
    """Parent process information."""

    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, examples=["winword.exe"])
    pid: Optional[int] = Field(default=None, ge=0, examples=[4210])


class ProcessContext(BaseModel):
    """Additional process context beyond the direct actor."""

    model_config = ConfigDict(extra="forbid")

    parent_process: Optional[ParentProcess] = None


class FileContext(BaseModel):
    """File target/source information when the event touches files."""

    model_config = ConfigDict(extra="forbid")

    path: Optional[str] = Field(default=None, examples=[r"C:/Users/Alice/Documents/report1.docx"])
    new_path: Optional[str] = Field(default=None, examples=[r"C:/Users/Alice/Documents/report1.locked"])


class NetworkContext(BaseModel):
    """Network destination information when the event involves a connection."""

    model_config = ConfigDict(extra="forbid")

    dst_ip: Optional[str] = Field(default=None, examples=["198.51.100.10"])
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535, examples=[443])


class ScenarioContext(BaseModel):
    """Scenario metadata carried alongside each normalized event."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(..., examples=["scenario-ransom-01"])
    stage: ScenarioStage


class CanonicalEvent(BaseModel):
    """OCSF-aligned normalized security event used throughout the project.

    Notes:
        - This model keeps the frozen event fields from Phase 0.
        - `event_type` is an internal normalized field added to simplify downstream
          feature extraction and rule logic while remaining compatible with the
          frozen OCSF-aligned structure.
    """

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    time: datetime
    activity_name: str = Field(..., examples=["Process Launch"])
    class_name: str = Field(..., examples=["Process Activity"])
    category_name: str = Field(..., examples=["System Activity"])
    severity: Severity
    status: Status
    metadata: Metadata
    device: Device
    actor: Actor
    process: Optional[ProcessContext] = None
    file: Optional[FileContext] = None
    network: Optional[NetworkContext] = None
    labels: list[str] = Field(default_factory=list)
    scenario: ScenarioContext
    event_type: Optional[EventType] = Field(
        default=None,
        description="Normalized internal taxonomy used by detection modules.",
    )

    @model_validator(mode="after")
    def infer_and_validate_event_type(self) -> "CanonicalEvent":
        """Infer event_type from activity_name when omitted, and cross-check when set."""

        inferred = _ACTIVITY_NAME_TO_EVENT_TYPE.get(self.activity_name)
        if self.event_type is None and inferred is not None:
            self.event_type = inferred
        elif self.event_type is not None and inferred is not None and self.event_type != inferred:
            raise ValueError(
                f"event_type '{self.event_type}' does not match activity_name '{self.activity_name}'."
            )
        return self

    @property
    def is_file_event(self) -> bool:
        return self.event_type in {
            EventType.FILE_CREATE,
            EventType.FILE_MODIFY,
            EventType.FILE_RENAME,
            EventType.FILE_DELETE,
        }

    @property
    def is_process_event(self) -> bool:
        return self.event_type in {
            EventType.PROCESS_CREATE,
            EventType.PROCESS_TERMINATE,
            EventType.COMMAND_EXEC,
        }

    @classmethod
    def activity_name_for_event_type(cls, event_type: EventType) -> str:
        """Return the default activity_name for a normalized taxonomy value."""

        return _EVENT_TYPE_TO_ACTIVITY_NAME[event_type]
