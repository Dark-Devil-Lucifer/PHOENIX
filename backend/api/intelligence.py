from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user
from backend.core.database import get_db

from backend.models.security_event import SecurityEvent
from backend.models.indicator_match import IndicatorMatch
from backend.models.threat_indicator import ThreatIndicator
from backend.models.threat_intelligence_source import ThreatIntelligenceSource

from backend.services.threat_intelligence_service import (
    enrich_event,
    lookup_indicator,
)


router = APIRouter(
    prefix="/api/intelligence",
    tags=["Threat Intelligence"],
)


# ---------------------------------------------------------------------------
# IOC INVENTORY
# ---------------------------------------------------------------------------

@router.get("/indicators")
def get_indicators(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Return the PHOENIX threat-intelligence inventory.

    Includes source information and observed match counts so the
    SOC frontend can display real intelligence state.
    """

    match_counts = (
        select(
            IndicatorMatch.indicator_id.label("indicator_id"),
            func.count(IndicatorMatch.id).label("match_count"),
        )
        .group_by(IndicatorMatch.indicator_id)
        .subquery()
    )

    stmt = (
        select(
            ThreatIndicator,
            ThreatIntelligenceSource,
            func.coalesce(
                match_counts.c.match_count,
                0,
            ).label("match_count"),
        )
        .outerjoin(
            ThreatIntelligenceSource,
            ThreatIntelligenceSource.id
            == ThreatIndicator.source_id,
        )
        .outerjoin(
            match_counts,
            match_counts.c.indicator_id
            == ThreatIndicator.id,
        )
        .order_by(
            ThreatIndicator.last_seen_at.desc(),
            ThreatIndicator.id.desc(),
        )
    )

    rows = db.execute(stmt).all()

    indicators = []

    for indicator, source, match_count in rows:

        indicators.append(
            {
                "id": indicator.id,
                "indicator_uid": indicator.indicator_uid,

                "indicator_type": indicator.indicator_type,
                "indicator_value": indicator.indicator_value,
                "value": indicator.indicator_value,
                "normalized_value": indicator.normalized_value,

                "threat_type": indicator.threat_type,
                "malware_family": indicator.malware_family,

                "confidence": indicator.confidence,
                "severity": indicator.severity,

                "status": indicator.status,

                "first_seen_at": indicator.first_seen_at,
                "last_seen_at": indicator.last_seen_at,
                "expires_at": indicator.expires_at,

                "source_id": indicator.source_id,

                "source_name": (
                    source.name
                    if source
                    else "Unknown Source"
                ),

                "source_uid": (
                    source.source_uid
                    if source
                    else None
                ),

                "source_type": (
                    source.source_type
                    if source
                    else None
                ),

                "match_count": int(match_count or 0),

                "description": (
                    (
                        indicator.indicator_metadata or {}
                    ).get("description")
                    if indicator.indicator_metadata
                    else None
                ),
            }
        )

    return {
        "count": len(indicators),
        "indicators": indicators,
    }


# ---------------------------------------------------------------------------
# INTELLIGENCE SOURCES
# ---------------------------------------------------------------------------

@router.get("/sources")
def get_sources(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Return configured threat-intelligence sources with inventory counts.
    """

    indicator_counts = (
        select(
            ThreatIndicator.source_id.label("source_id"),
            func.count(ThreatIndicator.id).label(
                "indicator_count"
            ),
        )
        .group_by(ThreatIndicator.source_id)
        .subquery()
    )

    match_counts = (
        select(
            ThreatIndicator.source_id.label("source_id"),
            func.count(IndicatorMatch.id).label(
                "match_count"
            ),
        )
        .join(
            IndicatorMatch,
            IndicatorMatch.indicator_id
            == ThreatIndicator.id,
        )
        .group_by(ThreatIndicator.source_id)
        .subquery()
    )

    stmt = (
        select(
            ThreatIntelligenceSource,
            func.coalesce(
                indicator_counts.c.indicator_count,
                0,
            ).label("indicator_count"),
            func.coalesce(
                match_counts.c.match_count,
                0,
            ).label("match_count"),
        )
        .outerjoin(
            indicator_counts,
            indicator_counts.c.source_id
            == ThreatIntelligenceSource.id,
        )
        .outerjoin(
            match_counts,
            match_counts.c.source_id
            == ThreatIntelligenceSource.id,
        )
        .order_by(
            ThreatIntelligenceSource.enabled.desc(),
            ThreatIntelligenceSource.name.asc(),
        )
    )

    rows = db.execute(stmt).all()

    sources = []

    for source, indicator_count, match_count in rows:

        sources.append(
            {
                "id": source.id,
                "source_uid": source.source_uid,
                "name": source.name,
                "source_name": source.name,
                "source_type": source.source_type,

                "reliability": source.reliability,
                "confidence": source.confidence,

                "feed_url": source.feed_url,
                "enabled": source.enabled,

                "last_updated_at": source.last_updated_at,
                "created_at": source.created_at,
                "updated_at": source.updated_at,

                "indicator_count": int(
                    indicator_count or 0
                ),

                "match_count": int(
                    match_count or 0
                ),
            }
        )

    return {
        "count": len(sources),
        "sources": sources,
    }


# ---------------------------------------------------------------------------
# IOC LOOKUP
# ---------------------------------------------------------------------------

@router.get("/lookup")
def lookup(
    indicator_type: str,
    value: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return lookup_indicator(
            db,
            indicator_type=indicator_type,
            value=value,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ---------------------------------------------------------------------------
# EVENT ENRICHMENT
# ---------------------------------------------------------------------------

@router.post("/enrich/event/{event_id}")
def enrich_security_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    event = db.get(
        SecurityEvent,
        event_id,
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Security event not found",
        )

    return enrich_event(
        db,
        event,
    )
