from backend.services.risk_service import calculate_risk


def test_critical_risk():
    score, severity = calculate_risk(
        5,
        5,
    )

    assert score == 100
    assert severity == "critical"


def test_low_risk():
    score, severity = calculate_risk(
        1,
        1,
    )

    assert score == 4
    assert severity == "low"
