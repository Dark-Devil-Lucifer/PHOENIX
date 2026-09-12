from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user
from backend.core.database import get_db

from backend.services.metrics_service import (
    get_soc_metrics,
)


router = APIRouter(
    prefix="/api/reports",
    tags=["Security Reports"],
)


@router.get(
    "/executive",
)
def executive_report(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    metrics = get_soc_metrics(db)

    top_incidents = db.execute(
        text(
            """
            SELECT
                id,
                incident_uid,
                title,
                severity,
                status,
                priority,
                detected_at
            FROM incidents
            ORDER BY priority DESC, detected_at DESC
            LIMIT 10
            """
        )
    ).mappings().all()

    top_vulnerabilities = db.execute(
        text(
            """
            SELECT
                id,
                uid,
                cve,
                title,
                severity,
                cvss,
                status
            FROM vulnerabilities
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 4
                    WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0
                END DESC,
                cvss DESC
            LIMIT 10
            """
        )
    ).mappings().all()

    return {
        "report": "PHOENIX Executive Security Report",
        "generated_by": current_user.username,
        "metrics": metrics,
        "priority_incidents": [
            dict(row)
            for row in top_incidents
        ],
        "priority_vulnerabilities": [
            dict(row)
            for row in top_vulnerabilities
        ],
    }
