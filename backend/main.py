from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.api.assets import router as assets_router
from backend.api.system import router as system_router
from backend.api.events import router as events_router
from backend.api.detections import router as detections_router
from backend.api.alerts import router as alerts_router
from backend.api.incidents import router as incidents_router
from backend.api.intelligence import router as intelligence_router
from backend.api.soar import router as soar_router
from backend.api.auth import router as auth_router
from backend.api.vulnerabilities import router as vulnerabilities_router
from backend.api.zero_trust import router as zero_trust_router
from backend.api.endpoints import router as endpoints_router
from backend.api.cloud import router as cloud_router
from backend.api.kubernetes import router as kubernetes_router
from backend.api.hunting import router as hunting_router
from backend.api.dlp import router as dlp_router
from backend.api.recovery import router as recovery_router
from backend.api.risk import router as risk_router
from backend.api.compliance import router as compliance_router
from backend.api.siem import router as siem_router
from backend.api.detection_rules import router as detection_rules_router
from backend.api.alert_enrichment import router as alert_enrichment_router
from backend.api.alert_incidents import router as alert_incidents_router
from backend.api.cases import router as cases_router
from backend.api.scenarios import router as scenarios_router
from backend.api.forensics import router as forensics_router
from backend.api.metrics import router as metrics_router
from backend.api.reports import router as reports_router
from backend.core.database import check_database_connection

from fastapi.staticfiles import StaticFiles


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"


app = FastAPI(
    title="PHOENIX",
    description="Autonomous Enterprise Cyber Defense Platform",
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# API ROUTES
# ============================================================

app.include_router(system_router)
app.include_router(assets_router)
app.include_router(events_router)
app.include_router(detections_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(intelligence_router)
app.include_router(soar_router)
app.include_router(auth_router)
app.include_router(vulnerabilities_router)
app.include_router(zero_trust_router)
app.include_router(endpoints_router)
app.include_router(cloud_router)
app.include_router(kubernetes_router)
app.include_router(hunting_router)
app.include_router(dlp_router)
app.include_router(recovery_router)
app.include_router(risk_router)
app.include_router(compliance_router)
app.include_router(siem_router)
app.include_router(detection_rules_router)
app.include_router(alert_enrichment_router)
app.include_router(alert_incidents_router)
app.include_router(cases_router)
app.include_router(scenarios_router)
app.include_router(forensics_router)
app.include_router(metrics_router)
app.include_router(reports_router)


# ============================================================
# FRONTEND STATIC FILES
# ============================================================

if not FRONTEND_DIR.exists():
    raise RuntimeError(
        f"PHOENIX frontend directory not found: {FRONTEND_DIR}"
    )


# Static assets
app.mount(
    "/frontend",
    StaticFiles(
        directory=str(FRONTEND_DIR),
        html=True,
    ),
    name="frontend",
)


# ============================================================
# FRONTEND ENTRY POINT
# ============================================================

@app.get("/", include_in_schema=False)
def frontend_root():
    return FileResponse(
        FRONTEND_DIR / "index.html"
    )


# ============================================================
# API ROOT
# ============================================================

@app.get("/api/health")
def health():
    database_status = check_database_connection()

    return {
        "service": "phoenix-api",
        "status": "healthy" if database_status else "degraded",
        "database": (
            "connected"
            if database_status
            else "unavailable"
        ),
    }


@app.get("/api")
def api_root():
    return {
        "product": "PHOENIX",
        "description": (
            "Autonomous Enterprise Cyber Defense Platform"
        ),
        "status": "operational",
        "version": "0.1.0",
        "frontend": "/frontend/",
        "documentation": "/docs",
        "health": "/api/health",
    }
