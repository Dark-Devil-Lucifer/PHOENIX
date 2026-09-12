from backend.scenarios.enterprise_scenarios import SCENARIOS


REQUIRED_SCENARIOS = {
    "credential_attack",
    "privilege_modification",
    "suspicious_process",
    "unexpected_outbound",
    "web_anomaly",
    "sensitive_access",
    "cloud_config_change",
    "prohibited_segment_access",
    "container_vulnerability",
    "kubernetes_baseline_violation",
    "auto_enrichment_investigation",
    "containment_recovery",
}


def test_required_scenarios_exist():
    assert REQUIRED_SCENARIOS.issubset(set(SCENARIOS.keys()))


def test_scenario_count():
    assert len(SCENARIOS) >= 12
