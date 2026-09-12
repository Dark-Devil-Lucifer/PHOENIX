from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db

from backend.schemas.recovery import (
    BackupJobCreate,
    BackupJobResponse,
    RecoveryTestCreate,
    RecoveryTestResponse,
    RecoveryTestUpdate,
)

from backend.services.audit_service import write_audit_log

from backend.services.recovery_service import (
    RecoveryError,
    create_backup_job,
    create_recovery_test,
    get_backup_job,
    get_recovery_test,
    list_backup_jobs,
    list_recovery_tests,
    record_backup_run,
    update_recovery_test,
)


router = APIRouter(
    prefix="/api/recovery",
    tags=["Backup & Recovery"],
)


@router.post(
    "/backups",
    response_model=BackupJobResponse,
)
def create_backup(
    payload: BackupJobCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        job = create_backup_job(
            db,
            payload,
        )

        write_audit_log(
            db,
            action="backup_job_created",
            user_id=current_user.id,
            resource_type="backup_job",
            resource_id=job.id,
            description=(
                f"Created backup job {job.job_uid}"
            ),
        )

        db.commit()

        return job

    except RecoveryError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "/backups",
    response_model=list[BackupJobResponse],
)
def get_backups(
    status: str | None = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_backup_jobs(
        db,
        status=status,
    )


@router.get(
    "/backups/{job_id}",
    response_model=BackupJobResponse,
)
def get_backup(
    job_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_backup_job(
            db,
            job_id,
        )

    except RecoveryError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.post(
    "/backups/{job_id}/run",
    response_model=BackupJobResponse,
)
def record_backup(
    job_id: int,
    success: bool = Query(...),
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        job = record_backup_run(
            db,
            job_id,
            success,
        )

        write_audit_log(
            db,
            action="backup_run_recorded",
            user_id=current_user.id,
            resource_type="backup_job",
            resource_id=job.id,
            description=(
                f"Recorded backup execution for "
                f"{job.job_uid}; success={success}"
            ),
            metadata={
                "success": success,
            },
        )

        db.commit()

        return job

    except RecoveryError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.post(
    "/tests",
    response_model=RecoveryTestResponse,
)
def create_test(
    payload: RecoveryTestCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        test = create_recovery_test(
            db,
            payload,
        )

        write_audit_log(
            db,
            action="recovery_test_created",
            user_id=current_user.id,
            resource_type="recovery_test",
            resource_id=test.id,
            description=(
                f"Created recovery test {test.test_uid}"
            ),
        )

        db.commit()

        return test

    except RecoveryError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "/tests",
    response_model=list[RecoveryTestResponse],
)
def get_tests(
    status: str | None = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_recovery_tests(
        db,
        status=status,
    )


@router.get(
    "/tests/{test_id}",
    response_model=RecoveryTestResponse,
)
def get_test(
    test_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_recovery_test(
            db,
            test_id,
        )

    except RecoveryError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.patch(
    "/tests/{test_id}",
    response_model=RecoveryTestResponse,
)
def update_test(
    test_id: int,
    payload: RecoveryTestUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        test = update_recovery_test(
            db,
            test_id,
            payload,
        )

        write_audit_log(
            db,
            action="recovery_test_updated",
            user_id=current_user.id,
            resource_type="recovery_test",
            resource_id=test.id,
            description=(
                f"Updated recovery test "
                f"{test.test_uid} to {test.status}"
            ),
            metadata={
                "status": test.status,
                "findings": test.findings,
            },
        )

        db.commit()

        return test

    except RecoveryError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
