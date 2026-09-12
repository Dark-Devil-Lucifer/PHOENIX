from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.intelligence.normalizer import normalize_indicator
from backend.models.indicator_match import IndicatorMatch
from backend.models.threat_indicator import ThreatIndicator


def lookup_indicator(
    db: Session,
    *,
    indicator_type: str,
    value: str,
):
    normalized = normalize_indicator(
        indicator_type,
        value,
    )

    indicator = db.scalar(
        select(ThreatIndicator).where(
            ThreatIndicator.indicator_type
            == indicator_type.lower(),
            ThreatIndicator.normalized_value
            == normalized,
            ThreatIndicator.status == "active",
        )
    )

    if not indicator:
        return {
            "matched": False,
            "indicator_type": indicator_type.lower(),
            "original_value": value,
            "normalized_value": normalized,
        }

    if (
        indicator.expires_at
        and indicator.expires_at < datetime.utcnow()
    ):
        return {
            "matched": False,
            "indicator_type": indicator_type.lower(),
            "original_value": value,
            "normalized_value": normalized,
            "reason": "indicator_expired",
        }

    return {
        "matched": True,
        "indicator_id": indicator.id,
        "indicator_uid": indicator.indicator_uid,
        "indicator_type": indicator.indicator_type,
        "original_value": value,
        "normalized_value": indicator.normalized_value,
        "threat_type": indicator.threat_type,
        "malware_family": indicator.malware_family,
        "confidence": indicator.confidence,
        "severity": indicator.severity,
        "status": indicator.status,
        "source_id": indicator.source_id,
    }


def enrich_event(
    db: Session,
    event,
):
    from backend.intelligence.extractor import (
        extract_indicators_from_event,
    )

    candidates = extract_indicators_from_event(event)

    results = []

    for candidate in candidates:
        result = lookup_indicator(
            db,
            indicator_type=candidate["indicator_type"],
            value=candidate["value"],
        )

        result["field"] = candidate["field"]

        if result["matched"]:
            existing_match = db.scalar(
                select(IndicatorMatch).where(
                    IndicatorMatch.indicator_id
                    == result["indicator_id"],
                    IndicatorMatch.event_id
                    == event.id,
                )
            )

            if not existing_match:
                match = IndicatorMatch(
                    indicator_id=result["indicator_id"],
                    event_id=event.id,
                    matched_value=candidate["value"],
                    match_type=f"exact_{candidate['field']}",
                    confidence=result["confidence"],
                    matched_at=datetime.utcnow(),
                    match_metadata={
                        "indicator_type": candidate[
                            "indicator_type"
                        ],
                        "normalized_value": candidate[
                            "normalized_value"
                        ],
                        "source_id": result["source_id"],
                    },
                )

                db.add(match)

        results.append(result)

    db.commit()

    return {
        "event_id": event.id,
        "event_uid": event.event_uid,
        "indicators_checked": len(candidates),
        "matches": [
            result
            for result in results
            if result["matched"]
        ],
        "unmatched": [
            result
            for result in results
            if not result["matched"]
        ],
    }
