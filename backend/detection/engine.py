from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.security_event import SecurityEvent


FAILED_AUTH_THRESHOLD = 3
DETECTION_WINDOW_MINUTES = 10


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------

def _outcome(event: SecurityEvent) -> str | None:
    if event.normalized_data:
        return event.normalized_data.get("outcome")
    return None


def _detection(
    *,
    detection_id: str,
    rule_name: str,
    severity: str,
    confidence: str,
    description: str,
    evidence_event_ids: list[int],
    recommended_response: str,
    **context,
):
    return {
        "detection_id": detection_id,
        "rule_name": rule_name,
        "severity": severity,
        "confidence": confidence,
        "description": description,
        "evidence_event_ids": evidence_event_ids,
        "recommended_response": recommended_response,
        **context,
    }


# ---------------------------------------------------------------------------
# DET-AUTH-001
# Repeated authentication failures followed by success
# ---------------------------------------------------------------------------

def detect_failed_then_success(
    db: Session,
    username: str,
    source_ip: str,
    success_event_time: datetime,
):
    """
    Detect repeated authentication failures followed by
    a successful authentication from the same user/source.
    """

    window_start = success_event_time - timedelta(
        minutes=DETECTION_WINDOW_MINUTES
    )

    events = db.scalars(
        select(SecurityEvent)
        .where(
            SecurityEvent.username == username,
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.event_type == "authentication",
            SecurityEvent.action == "login",
            SecurityEvent.event_time >= window_start,
            SecurityEvent.event_time <= success_event_time,
        )
        .order_by(SecurityEvent.event_time.asc())
    ).all()

    failures = [
        event
        for event in events
        if _outcome(event) == "failure"
    ]

    if len(failures) < FAILED_AUTH_THRESHOLD:
        return None

    return _detection(
        detection_id="DET-AUTH-001",
        rule_name="Repeated Authentication Failures Followed By Success",
        severity="high",
        confidence="high",
        description=(
            f"User '{username}' successfully authenticated from "
            f"{source_ip} after {len(failures)} failed attempts."
        ),
        evidence_event_ids=[
            event.id for event in failures
        ],
        recommended_response=(
            "Investigate source IP, validate user activity, "
            "and consider temporary account/session containment."
        ),
        username=username,
        source_ip=source_ip,
        failure_count=len(failures),
        window_minutes=DETECTION_WINDOW_MINUTES,
        success_event_time=success_event_time.isoformat(),
        first_failure=failures[0].event_time.isoformat(),
        last_failure=failures[-1].event_time.isoformat(),
    )


# ---------------------------------------------------------------------------
# DET-PRIV-001
# Unauthorized privilege modification
# ---------------------------------------------------------------------------

def detect_privilege_modification(
    event: SecurityEvent,
):
    """
    Detect privilege/role/group modifications.
    """

    privilege_actions = {
        "grant_privilege",
        "add_role",
        "add_group",
        "modify_role",
        "modify_privilege",
        "elevate_privilege",
    }

    if event.action not in privilege_actions:
        return None

    return _detection(
        detection_id="DET-PRIV-001",
        rule_name="Unauthorized Privilege Modification",
        severity="critical",
        confidence="high",
        description=(
            f"Privilege modification detected for user "
            f"'{event.username or 'unknown'}'."
        ),
        evidence_event_ids=[event.id],
        recommended_response=(
            "Validate authorization, review affected identity, "
            "and revert unauthorized privilege changes."
        ),
        username=event.username,
        asset_id=event.asset_id,
    )


# ---------------------------------------------------------------------------
# DET-ADMIN-001
# Unusual administrative activity
# ---------------------------------------------------------------------------

def detect_unusual_admin_activity(
    event: SecurityEvent,
):
    """
    Detect administrative actions occurring outside expected
    administrative activity patterns.
    """

    admin_actions = {
        "admin_login",
        "administrator_login",
        "create_admin",
        "delete_admin",
        "modify_admin",
        "disable_security_control",
    }

    if event.action not in admin_actions:
        return None

    return _detection(
        detection_id="DET-ADMIN-001",
        rule_name="Unusual Administrative Activity",
        severity="high",
        confidence="medium",
        description=(
            f"Administrative activity detected for "
            f"'{event.username or 'unknown'}'."
        ),
        evidence_event_ids=[event.id],
        recommended_response=(
            "Validate administrator identity and review "
            "the associated administrative actions."
        ),
        username=event.username,
        source_ip=event.source_ip,
        asset_id=event.asset_id,
    )


# ---------------------------------------------------------------------------
# DET-NET-001
# Unexpected outbound connection
# ---------------------------------------------------------------------------

def detect_unexpected_outbound(
    event: SecurityEvent,
):
    """
    Detect outbound connections from protected workloads.
    """

    if event.event_type not in {
        "network_connection",
        "firewall",
        "network",
    }:
        return None

    if event.action not in {
        "outbound_connection",
        "connection",
        "egress",
        "allowed",
    }:
        return None

    # Controlled PHOENIX lab considers documentation/example
    # ranges as test destinations unless explicitly allowed.
    suspicious_ranges = (
        "203.0.113.",
        "198.51.100.",
        "192.0.2.",
    )

    destination = event.destination_ip or ""

    if not destination.startswith(suspicious_ranges):
        return None

    return _detection(
        detection_id="DET-NET-001",
        rule_name="Unexpected Outbound Connection",
        severity="high",
        confidence="high",
        description=(
            f"Protected workload generated an outbound connection "
            f"to {destination}."
        ),
        evidence_event_ids=[event.id],
        recommended_response=(
            "Enrich destination IOC, investigate workload origin, "
            "and apply approved egress containment if required."
        ),
        source_ip=event.source_ip,
        destination_ip=destination,
        asset_id=event.asset_id,
    )


# ---------------------------------------------------------------------------
# DET-DATA-001
# Sensitive resource access anomaly
# ---------------------------------------------------------------------------

def detect_sensitive_resource_access(
    event: SecurityEvent,
):
    """
    Detect access to sensitive resources.
    """

    sensitive_actions = {
        "sensitive_access",
        "sensitive_resource_access",
        "read_sensitive",
        "download_sensitive",
        "export_sensitive",
        "access_secret",
    }

    if event.action not in sensitive_actions:
        return None

    return _detection(
        detection_id="DET-DATA-001",
        rule_name="Sensitive Resource Access Anomaly",
        severity="high",
        confidence="medium",
        description=(
            f"Sensitive resource access detected by "
            f"'{event.username or 'unknown'}'."
        ),
        evidence_event_ids=[event.id],
        recommended_response=(
            "Validate user authorization and investigate "
            "resource access and data movement."
        ),
        username=event.username,
        asset_id=event.asset_id,
    )


# ---------------------------------------------------------------------------
# DET-CONFIG-001
# Critical configuration change
# ---------------------------------------------------------------------------

def detect_critical_config_change(
    event: SecurityEvent,
):
    """
    Detect changes to security-critical configuration.
    """

    config_actions = {
        "config_change",
        "security_config_change",
        "firewall_rule_change",
        "audit_config_change",
        "logging_disabled",
        "security_control_modified",
    }

    if event.action not in config_actions:
        return None

    return _detection(
        detection_id="DET-CONFIG-001",
        rule_name="Critical Security Configuration Change",
        severity="critical",
        confidence="high",
        description=(
            f"Security-critical configuration change detected "
            f"on asset {event.asset_id or 'unknown'}."
        ),
        evidence_event_ids=[event.id],
        recommended_response=(
            "Validate change authorization and preserve the "
            "previous configuration for recovery."
        ),
        username=event.username,
        asset_id=event.asset_id,
    )


# ---------------------------------------------------------------------------
# DET-WEB-001
# Web/API anomaly
# ---------------------------------------------------------------------------

def detect_web_api_anomaly(
    event: SecurityEvent,
):
    """
    Detect suspicious web/API activity.
    """

    suspicious_actions = {
        "sql_injection",
        "xss_attempt",
        "path_traversal",
        "command_injection",
        "ssrf_attempt",
        "auth_bypass",
        "rate_limit_exceeded",
        "malicious_request",
    }

    event_data = event.normalized_data or {}

    if (
        event.action not in suspicious_actions
        and event_data.get("attack_type") not in suspicious_actions
    ):
        return None

    return _detection(
        detection_id="DET-WEB-001",
        rule_name="Suspicious Web or API Activity",
        severity="high",
        confidence="high",
        description=(
            f"Suspicious web/API activity detected: "
            f"{event.action}."
        ),
        evidence_event_ids=[event.id],
        recommended_response=(
            "Investigate request source, affected endpoint, "
            "and associated application security telemetry."
        ),
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        asset_id=event.asset_id,
    )


# ---------------------------------------------------------------------------
# DET-ENDPOINT-001
# Suspicious process / persistence
# ---------------------------------------------------------------------------

def detect_suspicious_process(
    event: SecurityEvent,
):
    """
    Detect suspicious endpoint process or persistence activity.
    """

    suspicious_actions = {
        "suspicious_process",
        "process_execution",
        "process_start",
        "persistence",
        "startup_modification",
        "scheduled_task_created",
        "service_created",
    }

    if event.action not in suspicious_actions:
        return None

    return _detection(
        detection_id="DET-ENDPOINT-001",
        rule_name="Suspicious Process or Persistence Activity",
        severity="high",
        confidence="high",
        description=(
            f"Suspicious endpoint activity detected: "
            f"{event.process_name or event.action}."
        ),
        evidence_event_ids=[event.id],
        recommended_response=(
            "Collect endpoint evidence, investigate process lineage, "
            "and isolate the authorized test endpoint if required."
        ),
        username=event.username,
        process_name=event.process_name,
        asset_id=event.asset_id,
    )


# ---------------------------------------------------------------------------
# DET-ZT-001
# Prohibited segment access
# ---------------------------------------------------------------------------

def detect_prohibited_segment_access(
    event: SecurityEvent,
):
    """
    Detect network access that violates the expected segment policy.
    """

    if event.action not in {
        "prohibited_segment_access",
        "segment_access",
        "segment_policy_violation",
        "network_policy_violation",
    }:
        return None

    return _detection(
        detection_id="DET-ZT-001",
        rule_name="Prohibited Network Segment Access",
        severity="critical",
        confidence="high",
        description=(
            f"Network segment policy violation detected from "
            f"{event.source_ip or 'unknown source'}."
        ),
        evidence_event_ids=[event.id],
        recommended_response=(
            "Deny unauthorized communication and investigate "
            "the originating identity and workload."
        ),
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        asset_id=event.asset_id,
    )


# ---------------------------------------------------------------------------
# Additional PHOENIX controlled-lab detectors
# ---------------------------------------------------------------------------

def detect_container_vulnerability(event: SecurityEvent):
    if event.event_type != "container" or event.action != "image_scan":
        return None

    data = event.normalized_data or {}

    if not data.get("cve"):
        return None

    return _detection(
        detection_id="DET-CONTAINER-001",
        rule_name="Container Image Vulnerability Detected",
        severity="critical",
        confidence="high",
        description=f"Container image vulnerability detected: {data.get('cve')}.",
        evidence_event_ids=[event.id],
        recommended_response="Quarantine affected image, assess exposure, and deploy an approved patched image.",
        asset_id=event.asset_id,
    )


def detect_kubernetes_baseline_violation(event: SecurityEvent):
    if event.event_type != "kubernetes":
        return None

    data = event.normalized_data or {}

    if not (
        data.get("baseline_replicas") is not None
        or data.get("observed_replicas") is not None
    ):
        return None

    return _detection(
        detection_id="DET-K8S-001",
        rule_name="Kubernetes Workload Baseline Violation",
        severity="high",
        confidence="high",
        description="Kubernetes workload deviated from the approved security baseline.",
        evidence_event_ids=[event.id],
        recommended_response="Investigate workload changes and restore the approved Kubernetes baseline.",
        asset_id=event.asset_id,
    )


def detect_cloud_config_change(event: SecurityEvent):
    if event.event_type != "cloud_audit":
        return None

    if event.action not in {
        "security_group_modified",
        "iam_policy_modified",
        "cloud_config_changed",
    }:
        return None

    return _detection(
        detection_id="DET-CLOUD-001",
        rule_name="Cloud Security Configuration Change",
        severity="critical",
        confidence="high",
        description="Security-sensitive cloud configuration change detected.",
        evidence_event_ids=[event.id],
        recommended_response="Validate change authorization and restore the approved cloud security configuration if unauthorized.",
        username=event.username,
        asset_id=event.asset_id,
    )


def detect_ti_indicator_match(event: SecurityEvent):
    if event.event_type != "network":
        return None

    data = event.normalized_data or {}

    if event.action != "indicator_match" and data.get("indicator_type") is None:
        return None

    return _detection(
        detection_id="DET-TI-001",
        rule_name="Threat Intelligence Indicator Match",
        severity="high",
        confidence="high",
        description=f"Threat intelligence indicator matched network activity: {event.destination_ip or event.source_ip or 'unknown'}.",
        evidence_event_ids=[event.id],
        recommended_response="Enrich the indicator, investigate related telemetry, and determine whether containment is required.",
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        asset_id=event.asset_id,
    )


def detect_containment_recovery(event: SecurityEvent):
    if event.event_type != "incident":
        return None

    data = event.normalized_data or {}

    if not data.get("containment_required"):
        return None

    return _detection(
        detection_id="DET-IR-001",
        rule_name="Containment and Recovery Required",
        severity="critical",
        confidence="high",
        description="Controlled incident requires containment and recovery actions.",
        evidence_event_ids=[event.id],
        recommended_response="Initiate approved containment, preserve evidence, and execute the documented recovery procedure.",
        username=event.username,
        asset_id=event.asset_id,
    )
