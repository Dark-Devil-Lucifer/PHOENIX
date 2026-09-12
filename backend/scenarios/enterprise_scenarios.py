from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from backend.services.event_service import ingest_event
from backend.schemas.security_event import SecurityEventCreate


def _timestamp(minutes_ago: int = 0):
    return datetime.utcnow() - timedelta(minutes=minutes_ago)


def _event(
    *,
    uid: str,
    event_type: str,
    category: str,
    action: str,
    severity: str = "medium",
    source_ip: str | None = None,
    destination_ip: str | None = None,
    username: str | None = None,
    hostname: str | None = None,
    process_name: str | None = None,
    outcome: str | None = None,
    message: str = "",
    scenario: str = "",
    extra: dict | None = None,
):
    normalized = {
        "timestamp": _timestamp().isoformat(),
        "source": "PHOENIX-CONTROLLED-LAB",
        "event_type": event_type,
        "category": category,
        "action": action,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "hostname": hostname,
        "process_name": process_name,
        "outcome": outcome,
        "controlled_test": True,
        "scenario": scenario,
    }

    if extra:
        normalized.update(extra)

    return SecurityEventCreate(
        event_uid=uid,
        source_type="PHOENIX-CONTROLLED-LAB",
        event_type=event_type,
        timestamp=_timestamp(),
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        hostname=hostname,
        action=action,
        outcome=outcome,
        severity=severity,
        raw_event={
            "controlled_test": True,
            "scenario": scenario,
            "message": message,
        },
        normalized_data=normalized,
    )


def run_authentication_attack(db: Session):
    events = []

    for i in range(1, 4):
        events.append(
            _event(
                uid=f"PHX-AUTH-FAIL-{i:03d}",
                event_type="authentication",
                category="authentication",
                action="login",
                severity="medium",
                source_ip="192.168.10.50",
                username="test-admin",
                hostname="phoenix-admin-01",
                outcome="failure",
                message="Controlled failed authentication attempt",
                scenario="controlled_credential_attack",
            )
        )

    events.append(
        _event(
            uid="PHX-AUTH-SUCCESS-001",
            event_type="authentication",
            category="authentication",
            action="login",
            severity="high",
            source_ip="192.168.10.50",
            username="test-admin",
            hostname="phoenix-admin-01",
            outcome="success",
            message="Controlled successful authentication after failures",
            scenario="suspicious_success_after_failures",
        )
    )

    return [ingest_event(db, event) for event in events]


def run_privilege_modification(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-PRIV-001",
                event_type="identity",
                category="identity",
                action="add_role",
                severity="high",
                source_ip="192.168.10.50",
                username="phoenix-analyst",
                hostname="phoenix-admin-01",
                outcome="success",
                message="Controlled administrator role modification",
                scenario="unauthorized_privilege_modification",
                extra={"role_added": "administrator"},
            ),
        )
    ]


def run_suspicious_process(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-ENDPOINT-001",
                event_type="endpoint",
                category="process",
                action="process_start",
                severity="high",
                source_ip="192.168.20.10",
                username="test-user",
                hostname="phoenix-endpoint-01",
                process_name="powershell.exe",
                outcome="success",
                message="Controlled suspicious process execution",
                scenario="suspicious_process",
                extra={
                    "process_path": "/controlled-lab/powershell.exe",
                    "persistence": True,
                },
            ),
        )
    ]


def run_unexpected_outbound(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-NET-001",
                event_type="network",
                category="network",
                action="outbound_connection",
                severity="high",
                source_ip="10.10.20.15",
                destination_ip="203.0.113.77",
                hostname="phoenix-protected-workload",
                outcome="success",
                message="Controlled unexpected outbound connection",
                scenario="unexpected_outbound",
            ),
        )
    ]


def run_web_anomaly(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-WEB-001",
                event_type="web",
                category="web",
                action="request",
                severity="high",
                source_ip="192.168.10.60",
                destination_ip="192.168.10.20",
                username="web-test-user",
                hostname="phoenix-web-01",
                outcome="blocked",
                message="Controlled SQL injection test request",
                scenario="web_anomaly",
                extra={
                    "attack_type": "sql_injection",
                    "path": "/api/search",
                },
            ),
        )
    ]


def run_sensitive_access(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-DATA-001",
                event_type="data_access",
                category="data",
                action="sensitive_resource_access",
                severity="high",
                source_ip="192.168.10.70",
                username="test-user",
                hostname="phoenix-workstation-01",
                outcome="success",
                message="Controlled access to sensitive resource",
                scenario="sensitive_resource_access_anomaly",
                extra={
                    "resource_classification": "confidential",
                    "resource": "customer-records",
                },
            ),
        )
    ]


def run_cloud_config_change(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-CLOUD-001",
                event_type="cloud_audit",
                category="cloud",
                action="security_group_modified",
                severity="critical",
                source_ip="192.168.10.80",
                username="cloud-admin",
                hostname="phoenix-cloud-control",
                outcome="success",
                message="Controlled cloud security configuration change",
                scenario="cloud_admin_config_change",
                extra={
                    "cloud_account": "PHX-CLOUD-LAB",
                    "resource": "security-group",
                },
            ),
        )
    ]


def run_prohibited_segment_access(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-ZT-001",
                event_type="network",
                category="zero_trust",
                action="segment_access",
                severity="critical",
                source_ip="10.10.30.15",
                destination_ip="10.10.10.20",
                username="test-user",
                hostname="phoenix-workstation-01",
                outcome="denied",
                message="Controlled prohibited segment access attempt",
                scenario="prohibited_segment_access",
                extra={
                    "source_segment": "user",
                    "destination_segment": "restricted",
                    "policy_decision": "deny",
                },
            ),
        )
    ]


def run_container_vulnerability(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-CONTAINER-001",
                event_type="container",
                category="container_security",
                action="image_scan",
                severity="critical",
                hostname="phoenix-k8s-node-01",
                outcome="detected",
                message="Controlled container image vulnerability finding",
                scenario="container_image_known_test_vulnerability",
                extra={
                    "image": "phoenix/test-web:1.0",
                    "cve": "CVE-TEST-PHOENIX-001",
                    "cvss": 9.8,
                },
            ),
        )
    ]


def run_kubernetes_baseline_violation(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-K8S-001",
                event_type="kubernetes",
                category="kubernetes_security",
                action="workload_state_change",
                severity="high",
                hostname="phoenix-k8s-node-01",
                outcome="anomalous",
                message="Controlled Kubernetes workload baseline deviation",
                scenario="kubernetes_workload_outside_baseline",
                extra={
                    "namespace": "phoenix-prod",
                    "workload": "phoenix-api",
                    "baseline_replicas": 2,
                    "observed_replicas": 5,
                    "baseline_image": "phoenix/api:stable",
                    "observed_image": "phoenix/api:test",
                },
            ),
        )
    ]


def run_auto_enrichment_investigation(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-ENRICH-001",
                event_type="network",
                category="threat_intelligence",
                action="indicator_match",
                severity="high",
                source_ip="203.0.113.77",
                destination_ip="203.0.113.77",
                hostname="phoenix-web-01",
                outcome="matched",
                message="Controlled threat-intelligence indicator match",
                scenario="auto_enrichment_analyst_investigation",
                extra={
                    "indicator_type": "ip",
                    "indicator_value": "203.0.113.77",
                },
            ),
        )
    ]


def run_containment_recovery(db: Session):
    return [
        ingest_event(
            db,
            _event(
                uid="PHX-RECOVERY-001",
                event_type="incident",
                category="incident_response",
                action="containment_required",
                severity="critical",
                hostname="phoenix-endpoint-01",
                username="test-user",
                outcome="detected",
                message="Controlled incident requiring containment and recovery",
                scenario="controlled_containment_recovery",
                extra={
                    "containment_required": True,
                    "recovery_required": True,
                    "test_asset": True,
                },
            ),
        )
    ]


SCENARIOS = {
    "credential_attack": run_authentication_attack,
    "suspicious_success_after_failures": run_authentication_attack,
    "privilege_modification": run_privilege_modification,
    "suspicious_process": run_suspicious_process,
    "unexpected_outbound": run_unexpected_outbound,
    "web_anomaly": run_web_anomaly,
    "sensitive_access": run_sensitive_access,
    "cloud_config_change": run_cloud_config_change,
    "prohibited_segment_access": run_prohibited_segment_access,
    "container_vulnerability": run_container_vulnerability,
    "kubernetes_baseline_violation": run_kubernetes_baseline_violation,
    "auto_enrichment_investigation": run_auto_enrichment_investigation,
    "containment_recovery": run_containment_recovery,
}


def run_scenario(db: Session, scenario_name: str):
    scenario = SCENARIOS.get(scenario_name)

    if not scenario:
        raise ValueError(
            f"Unknown scenario: {scenario_name}. "
            f"Available: {', '.join(SCENARIOS.keys())}"
        )

    return scenario(db)
