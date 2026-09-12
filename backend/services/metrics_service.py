from sqlalchemy import text
from sqlalchemy.orm import Session


def _count(
    db: Session,
    table: str,
    where: str = "",
):
    query = f"SELECT COUNT(*) FROM {table}"

    if where:
        query += f" WHERE {where}"

    return int(
        db.execute(text(query)).scalar() or 0
    )


def get_soc_metrics(
    db: Session,
):
    return {
        "assets": {
            "total": _count(db, "assets"),
            "active": _count(
                db,
                "assets",
                "status = 'active'",
            ),
        },
        "events": {
            "total": _count(
                db,
                "security_events",
            ),
            "critical": _count(
                db,
                "security_events",
                "severity = 'critical'",
            ),
            "high": _count(
                db,
                "security_events",
                "severity = 'high'",
            ),
        },
        "alerts": {
            "total": _count(
                db,
                "alerts",
            ),
            "open": _count(
                db,
                "alerts",
                "status = 'open'",
            ),
            "critical": _count(
                db,
                "alerts",
                "severity = 'critical'",
            ),
            "high": _count(
                db,
                "alerts",
                "severity = 'high'",
            ),
        },
        "incidents": {
            "total": _count(
                db,
                "incidents",
            ),
            "open": _count(
                db,
                "incidents",
                "status = 'open'",
            ),
            "contained": _count(
                db,
                "incidents",
                "status = 'contained'",
            ),
            "resolved": _count(
                db,
                "incidents",
                "status = 'resolved'",
            ),
            "critical": _count(
                db,
                "incidents",
                "severity = 'critical'",
            ),
        },
        "vulnerabilities": {
            "total": _count(
                db,
                "vulnerabilities",
            ),
            "open": _count(
                db,
                "vulnerabilities",
                "status = 'open'",
            ),
            "critical": _count(
                db,
                "vulnerabilities",
                "severity = 'critical'",
            ),
        },
        "endpoints": {
            "total": _count(
                db,
                "endpoints",
            ),
            "isolated": _count(
                db,
                "endpoints",
                "isolation_status = 'isolated'",
            ),
        },
        "cloud": {
            "accounts": _count(
                db,
                "cloud_accounts",
            ),
            "assets": _count(
                db,
                "cloud_assets",
            ),
            "findings": _count(
                db,
                "cloud_security_findings",
            ),
        },
        "kubernetes": {
            "clusters": _count(
                db,
                "kubernetes_clusters",
            ),
            "images": _count(
                db,
                "container_images",
            ),
            "findings": _count(
                db,
                "container_findings",
            ),
            "workloads": _count(
                db,
                "kubernetes_workloads",
            ),
        },
        "threat_intelligence": {
            "indicators": _count(
                db,
                "threat_indicators",
            ),
            "matches": _count(
                db,
                "indicator_matches",
            ),
        },
        "response": {
            "executions": _count(
                db,
                "response_executions",
            ),
            "completed": _count(
                db,
                "response_executions",
                "status = 'completed'",
            ),
        },
    }


def get_security_health(
    db: Session,
):
    checks = []

    tables = [
        "assets",
        "security_events",
        "alerts",
        "incidents",
        "threat_indicators",
        "response_executions",
        "vulnerabilities",
        "audit_logs",
    ]

    for table in tables:
        try:
            db.execute(
                text(
                    f"SELECT 1 FROM {table} LIMIT 1"
                )
            )

            checks.append(
                {
                    "component": table,
                    "status": "healthy",
                }
            )

        except Exception as exc:
            checks.append(
                {
                    "component": table,
                    "status": "unhealthy",
                    "error": str(exc),
                }
            )

    healthy = sum(
        1
        for check in checks
        if check["status"] == "healthy"
    )

    return {
        "status": (
            "healthy"
            if healthy == len(checks)
            else "degraded"
        ),
        "healthy_components": healthy,
        "total_components": len(checks),
        "components": checks,
    }
