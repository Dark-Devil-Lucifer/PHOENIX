from backend.services.dlp_service import (
    CLASSIFICATION_SCORE,
    ACTION_SCORE,
)


def test_sensitive_classification_scores():
    assert CLASSIFICATION_SCORE["restricted"] > 50
    assert CLASSIFICATION_SCORE["secret"] > 80


def test_data_movement_scores():
    assert ACTION_SCORE["export"] > ACTION_SCORE["read"]
    assert ACTION_SCORE["transfer"] > ACTION_SCORE["download"]
