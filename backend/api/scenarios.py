from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db

from backend.models.user import User

from backend.scenarios.enterprise_scenarios import (
    SCENARIOS,
    run_scenario,
)

from backend.services.scenario_detection_service import (
    detect_event,
)

from backend.services.audit_service import write_audit_log


router = APIRouter(
    prefix="/api/scenarios",
    tags=["Controlled Scenarios"],
)


@router.get("")
def list_scenarios(
    current_user: User = Depends(get_current_user),
):
    return {
        "count": len(SCENARIOS),
        "scenarios": [
            {
                "name": name,
                "description": name.replace(
                    "_",
                    " ",
                ).title(),
            }
            for name in SCENARIOS
        ],
        "controlled_environment": True,
        "destructive_actions": False,
    }


@router.post("/{scenario_name}/run")
def execute_scenario(
    scenario_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead")
    ),
):
    if scenario_name not in SCENARIOS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario: {scenario_name}",
        )

    try:
        events = run_scenario(
            db,
            scenario_name,
        )

        all_detections = []

        for event in events:
            detections = detect_event(
                db,
                event.id,
            )

            all_detections.extend(
                detections
            )

        write_audit_log(
            db,
            action="controlled_scenario_executed",
            user_id=current_user.id,
            resource_type="scenario",
            resource_id=scenario_name,
            description=(
                f"Executed controlled PHOENIX "
                f"scenario: {scenario_name}"
            ),
            metadata={
                "scenario": scenario_name,
                "event_count": len(events),
                "detection_count": len(
                    all_detections
                ),
                "controlled": True,
            },
        )

        db.commit()

        return {
            "scenario": scenario_name,
            "executed": True,
            "controlled": True,
            "event_count": len(events),
            "detection_count": len(
                all_detections
            ),
            "events": [
                {
                    "id": event.id,
                    "event_uid": event.event_uid,
                }
                for event in events
            ],
            "detections": all_detections,
        }

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
