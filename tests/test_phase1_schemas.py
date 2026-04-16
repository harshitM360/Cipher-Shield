from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from schemas import (  # noqa: E402
    Actor,
    ActorProcess,
    ActorUser,
    CanonicalEvent,
    Device,
    EventType,
    ExpectedFindings,
    HostProfile,
    Metadata,
    OSInfo,
    ParentProcess,
    ProcessContext,
    ScenarioBundle,
    ScenarioContext,
    ScenarioEvent,
    Severity,
    Status,
    TimelineEntry,
)


def test_canonical_event_infers_event_type() -> None:
    event = CanonicalEvent(
        time='2026-04-16T10:00:03Z',
        activity_name='Process Launch',
        class_name='Process Activity',
        category_name='System Activity',
        severity=Severity.HIGH,
        status=Status.SUCCESS,
        metadata=Metadata(product_name='synthetic-generator', version='0.1.0', source_name='lab-simulation'),
        device=Device(hostname='finance-laptop-01', os=OSInfo(name='Windows 11')),
        actor=Actor(
            user=ActorUser(name='alice'),
            process=ActorProcess(name='powershell.exe', pid=4321, command_line='powershell.exe -File loader.ps1'),
        ),
        process=ProcessContext(parent_process=ParentProcess(name='winword.exe', pid=4210)),
        labels=['synthetic', 'malicious', 'ransomware'],
        scenario=ScenarioContext(scenario_id='scenario-ransom-01', stage='pre-impact'),
    )

    assert event.event_type == EventType.PROCESS_CREATE
    assert event.is_process_event is True


def test_scenario_bundle_validates_timeline_references() -> None:
    bundle = ScenarioBundle(
        type='scenario-bundle',
        id='scenario-bundle--ransomware-001',
        spec_version='1.0',
        name='Word to PowerShell',
        created='2026-04-16T09:59:00Z',
        modified='2026-04-16T09:59:00Z',
        labels=['synthetic', 'malicious', 'ransomware'],
        objective='Simulate early ransomware execution.',
        host_profile=HostProfile(hostname='finance-laptop-01', os='Windows 11', department='finance'),
        timeline=[
            TimelineEntry(offset_seconds=0, event_ref='event--001'),
            TimelineEntry(offset_seconds=3, event_ref='event--002'),
        ],
        events=[
            ScenarioEvent(id='event--001', event_type=EventType.PROCESS_CREATE, process_name='winword.exe'),
            ScenarioEvent(id='event--002', event_type=EventType.PROCESS_CREATE, process_name='powershell.exe', parent_process_name='winword.exe'),
        ],
        expected_findings=ExpectedFindings(
            severity=Severity.HIGH,
            rules_triggered=['suspicious_parent_child'],
            attack_techniques=['T1059'],
        ),
    )

    assert bundle.event_lookup['event--002'].parent_process_name == 'winword.exe'
    assert bundle.is_malicious is True
