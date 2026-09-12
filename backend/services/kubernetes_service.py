from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.kubernetes import (
    ContainerFinding,
    ContainerImage,
    KubernetesCluster,
    KubernetesWorkload,
)


def create_cluster(
    db: Session,
    *,
    cluster_uid: str,
    name: str,
    environment: str | None = None,
    version: str | None = None,
    api_endpoint: str | None = None,
):
    existing = db.scalar(
        select(KubernetesCluster).where(
            KubernetesCluster.cluster_uid == cluster_uid
        )
    )

    if existing:
        return existing

    cluster = KubernetesCluster(
        cluster_uid=cluster_uid,
        name=name,
        environment=environment,
        version=version,
        api_endpoint=api_endpoint,
        status="active",
        created_at=datetime.utcnow(),
    )

    db.add(cluster)
    db.flush()

    return cluster


def list_clusters(db: Session):
    return list(
        db.scalars(
            select(KubernetesCluster).order_by(
                KubernetesCluster.created_at.desc()
            )
        ).all()
    )


def create_image(
    db: Session,
    *,
    image_uid: str,
    repository: str,
    tag: str | None = None,
    digest: str | None = None,
    registry: str | None = None,
):
    existing = db.scalar(
        select(ContainerImage).where(
            ContainerImage.image_uid == image_uid
        )
    )

    if existing:
        return existing

    image = ContainerImage(
        image_uid=image_uid,
        repository=repository,
        tag=tag,
        digest=digest,
        registry=registry,
        created_at=datetime.utcnow(),
    )

    db.add(image)
    db.flush()

    return image


def list_images(db: Session):
    return list(
        db.scalars(
            select(ContainerImage).order_by(
                ContainerImage.created_at.desc()
            )
        ).all()
    )


def create_container_finding(
    db: Session,
    *,
    finding_uid: str,
    image_id: int,
    title: str,
    severity: str,
    cve_id: str | None = None,
    cvss_score: float | None = None,
    remediation: str | None = None,
):
    image = db.get(ContainerImage, image_id)

    if not image:
        raise ValueError("Container image not found")

    existing = db.scalar(
        select(ContainerFinding).where(
            ContainerFinding.finding_uid == finding_uid
        )
    )

    if existing:
        return existing

    finding = ContainerFinding(
        finding_uid=finding_uid,
        image_id=image_id,
        cve_id=cve_id,
        title=title,
        severity=severity.lower(),
        cvss_score=cvss_score,
        remediation=remediation,
        status="open",
        detected_at=datetime.utcnow(),
    )

    db.add(finding)
    db.flush()

    return finding


def list_container_findings(
    db: Session,
    *,
    severity: str | None = None,
    status: str | None = None,
):
    query = select(ContainerFinding).order_by(
        ContainerFinding.detected_at.desc()
    )

    if severity:
        query = query.where(
            ContainerFinding.severity == severity.lower()
        )

    if status:
        query = query.where(
            ContainerFinding.status == status
        )

    return list(db.scalars(query).all())


def resolve_container_finding(
    db: Session,
    finding_id: int,
):
    finding = db.get(ContainerFinding, finding_id)

    if not finding:
        raise ValueError("Container finding not found")

    finding.status = "resolved"
    finding.resolved_at = datetime.utcnow()

    db.flush()

    return finding


def create_workload(
    db: Session,
    *,
    workload_uid: str,
    cluster_id: int,
    namespace: str,
    workload_name: str,
    workload_type: str | None = None,
    image_id: int | None = None,
    baseline: dict[str, Any] | None = None,
    observed_state: dict[str, Any] | None = None,
):
    cluster = db.get(KubernetesCluster, cluster_id)

    if not cluster:
        raise ValueError("Kubernetes cluster not found")

    if image_id is not None:
        image = db.get(ContainerImage, image_id)

        if not image:
            raise ValueError("Container image not found")

    existing = db.scalar(
        select(KubernetesWorkload).where(
            KubernetesWorkload.workload_uid == workload_uid
        )
    )

    if existing:
        return existing

    workload = KubernetesWorkload(
        workload_uid=workload_uid,
        cluster_id=cluster_id,
        namespace=namespace,
        workload_name=workload_name,
        workload_type=workload_type,
        image_id=image_id,
        baseline=baseline,
        observed_state=observed_state,
        status="running",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    db.add(workload)
    db.flush()

    return workload


def list_workloads(
    db: Session,
    cluster_id: int | None = None,
):
    query = select(KubernetesWorkload).order_by(
        KubernetesWorkload.created_at.desc()
    )

    if cluster_id:
        query = query.where(
            KubernetesWorkload.cluster_id == cluster_id
        )

    return list(db.scalars(query).all())


def evaluate_workload_baseline(
    db: Session,
    workload_id: int,
):
    workload = db.get(
        KubernetesWorkload,
        workload_id,
    )

    if not workload:
        raise ValueError("Kubernetes workload not found")

    baseline = workload.baseline or {}
    observed = workload.observed_state or {}

    differences = {}

    for key, expected_value in baseline.items():
        actual_value = observed.get(key)

        if actual_value != expected_value:
            differences[key] = {
                "expected": expected_value,
                "observed": actual_value,
            }

    compliant = len(differences) == 0

    return {
        "workload_id": workload.id,
        "workload_uid": workload.workload_uid,
        "compliant": compliant,
        "drift_detected": not compliant,
        "differences": differences,
    }


def update_workload_state(
    db: Session,
    *,
    workload_id: int,
    observed_state: dict[str, Any],
):
    workload = db.get(
        KubernetesWorkload,
        workload_id,
    )

    if not workload:
        raise ValueError("Kubernetes workload not found")

    workload.observed_state = observed_state
    workload.updated_at = datetime.utcnow()

    db.flush()

    return workload
