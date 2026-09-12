from fastapi import APIRouter
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.core.database import SessionLocal

router = APIRouter(
    prefix="/api/system",
    tags=["System"],
)


@router.get("/database")
def database_status():
    db: Session = SessionLocal()

    try:
        result = db.execute(
            text("SELECT DATABASE() AS database_name")
        ).mappings().first()

        return {
            "status": "connected",
            "database": result["database_name"],
        }

    except Exception as exc:
        return {
            "status": "error",
            "database": None,
            "error": str(exc),
        }

    finally:
        db.close()
