"""The truncation notice must come back from `_run_model_planning`.

`tests/test_oversized_lists_are_truncated_not_rejected.py::test_the_notice_reaches_a_consumer_outside_this_module`
only greps for a consumer of `truncated_fields`. That stays green if the field is read and then
dropped. This test drives the planning seam with nine `alternatives` (bound 8) and requires the
returned `limitations` to name the dropped items.

It does not render a report revision. The return value is the seam the wiring owns.
"""
from __future__ import annotations

import json
from dataclasses import replace

import httpx

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.model_gateway import ModelGateway
from threat_report_agent.models import (
    AnalysisTask,
    Artifact,
    CaseRecord,
    ContentBlob,
    Evidence,
    ToolRun,
)
from threat_report_agent.service import AnalysisService


def test_overlong_alternatives_are_named_in_planning_limitations(test_settings) -> None:
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    service = AnalysisService(
        settings,
        Database(settings.database_url),
        LocalContentStore(settings.content_store_path),
    )
    service.database.create_schema()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "objective": "inspect",
                                    "actions": [
                                        {
                                            "tool_name": "pe-parser",
                                            "target_artifact_id": "artifact-truncation",
                                            "priority": 1,
                                            "reason": "baseline",
                                            "alternatives": [f"alt-{index}" for index in range(9)],
                                        }
                                    ],
                                }
                            )
                        }
                    }
                ]
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    with service.database.session_factory.begin() as session:
        case = CaseRecord(title="truncation notice")
        session.add(case)
        session.flush()
        blob = ContentBlob(
            sha256="c" * 64,
            size=2,
            media_type="application/octet-stream",
            storage_key="sha256/c",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-truncation",
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="sample.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="pe-parser",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        session.add(
            Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="pe_structure",
                nature="STATIC_OBSERVED",
                value={"format": "PE"},
                anchor={"function_entry": "0x1000"},
                id="truncation-evidence",
            )
        )
        task_id = task.id
        artifact_id = artifact.id

    with service.database.session_factory() as session:
        artifact = session.get(Artifact, artifact_id)
    _actions, limitations = service._run_model_planning(
        task_id,
        [artifact],
        [artifact_id],
        phase="truncation-notice",
    )
    assert any(
        "dropped and are not represented" in item and "alternatives:8/1" in item
        for item in limitations
    ), limitations
