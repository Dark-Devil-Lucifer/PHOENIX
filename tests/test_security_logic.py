from backend.detection.engine import (
    FAILED_AUTH_THRESHOLD,
    DETECTION_WINDOW_MINUTES,
)


def test_failed_auth_configuration():
    assert FAILED_AUTH_THRESHOLD >= 3
    assert DETECTION_WINDOW_MINUTES >= 5


def test_detection_configuration():
    assert isinstance(
        FAILED_AUTH_THRESHOLD,
        int,
    )

    assert isinstance(
        DETECTION_WINDOW_MINUTES,
        int,
    )
