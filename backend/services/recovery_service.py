from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.recovery import BackupJob, RecoveryTest


class RecoveryError(Exception):
    pass


VALID_BACKUP_TYPES = {
    "full",
    "incremental",
    "differential",
    "snapshot",
}


VALID_RECOVERY_STATUSES = {
    "planned",
    "running",
    "passed",
    "failed",
    "cancelled",
}


def create_backup_job(db: Session, data):
    existing = db.scalar(
        select(BackupJob).where(
            BackupJob.job_uid == data.job_uid
        )
    )

    if existing:
        raise RecoveryError(
            "Backup job UID already exists"
        )

    if data.backup_type not in VALID_BACKUP_TYPES:
        raise RecoveryError(
            "Unsupported backup type"
        )

    job = BackupJob(
        job_uid=data.job_uid,
        name=data.name,
        target_type=data.target_type,
        target_reference=data.target_reference,
        schedule=data.schedule,
        backup_type=data.backup_type,
        retention_days=data.retention_days,
        status="configured",
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    return job


def list_backup_jobs(
    db: Session,
    status: str | None = None,
):
    stmt = select(BackupJob).order_by(
        BackupJob.created_at.desc()
    )

    if status:
        stmt = stmt.where(
            BackupJob.status == status
        )

    return list(db.scalars(stmt).all())


def get_backup_job(
    db: Session,
    job_id: int,
):
    job = db.get(
        BackupJob,
        job_id,
    )

    if not job:
        raise RecoveryError(
            "Backup job not found"
        )

    return job


def record_backup_run(
    db: Session,
    job_id: int,
    success: bool,
):
    job = get_backup_job(
        db,
        job_id,
    )

    now = datetime.utcnow()

    job.last_run_at = now

    if success:
        job.status = "healthy"
        job.last_success_at = now
    else:
        job.status = "failed"

    db.commit()
    db.refresh(job)

    return job


def create_recovery_test(
    db: Session,
    data,
):
    existing = db.scalar(
        select(RecoveryTest).where(
            RecoveryTest.test_uid == data.test_uid
        )
    )

    if existing:
        raise RecoveryError(
            "Recovery test UID already exists"
        )

    if data.backup_job_id:
        get_backup_job(
            db,
            data.backup_job_id,
        )

    test = RecoveryTest(
        test_uid=data.test_uid,
        backup_job_id=data.backup_job_id,
        name=data.name,
        recovery_type=data.recovery_type,
        target_reference=data.target_reference,
        status="planned",
        rto_minutes=data.rto_minutes,
        rpo_minutes=data.rpo_minutes,
        notes=data.notes,
    )

    db.add(test)
    db.commit()
    db.refresh(test)

    return test


def list_recovery_tests(
    db: Session,
    status: str | None = None,
):
    stmt = select(RecoveryTest).order_by(
        RecoveryTest.created_at.desc()
    )

    if status:
        stmt = stmt.where(
            RecoveryTest.status == status
        )

    return list(db.scalars(stmt).all())


def get_recovery_test(
    db: Session,
    test_id: int,
):
    test = db.get(
        RecoveryTest,
        test_id,
    )

    if not test:
        raise RecoveryError(
            "Recovery test not found"
        )

    return test


def update_recovery_test(
    db: Session,
    test_id: int,
    data,
):
    test = get_recovery_test(
        db,
        test_id,
    )

    if data.status not in VALID_RECOVERY_STATUSES:
        raise RecoveryError(
            "Invalid recovery test status"
        )

    if data.status == "running" and not test.started_at:
        test.started_at = datetime.utcnow()

    if data.status in {
        "passed",
        "failed",
        "cancelled",
    }:
        test.completed_at = datetime.utcnow()

    test.status = data.status

    if data.findings is not None:
        test.findings = data.findings

    if data.notes is not None:
        test.notes = data.notes

    if data.rto_minutes is not None:
        test.rto_minutes = data.rto_minutes

    if data.rpo_minutes is not None:
        test.rpo_minutes = data.rpo_minutes

    db.commit()
    db.refresh(test)

    return test
