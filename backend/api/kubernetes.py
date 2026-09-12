from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db
from backend.models.user import User
from backend.schemas.kubernetes import (
    ContainerFindingCreate,
    ContainerImageCreate,
    KubernetesClusterCreate,
    KubernetesWorkloadCreate,
)
from backend.services.audit_service import write_audit_log
from backend.services.kubernetes_service import (
    create_cluster,
    create_container_finding,
    create_image,
    create_workload,
    evaluate_workload_baseline,
    list_clusters,
    list_container_findings,
    list_images,
    list_workloads,
    resolve_container_finding,
    update_workload_state,
)


router = APIRouter(
    prefix="/api/kubernetes",
    tags=["Kubernetes / Container Security"],
)


def get_source_ip(request: Request):
    return request.client.host if request.client else None


@router.post("/clusters")
def create_kubernetes_cluster(
    payload: KubernetesClusterCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead", "soc_analyst")
    ),
):
    cluster = create_cluster(
        db,
        **payload.model_dump(),
    )

    write_audit_log(
        db,
        action="kubernetes_cluster_registered",
        user_id=current_user.id,
        resource_type="kubernetes_cluster",
        resource_id=str(cluster.id),
        description=f"Registered Kubernetes cluster {cluster.name}",
        source_ip=get_source_ip(request),
    )

    db.commit()
    db.refresh(cluster)

    return cluster


@router.get("/clusters")
def clusters(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_clusters(db)


@router.post("/images")
def create_container_image(
    payload: ContainerImageCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead", "soc_analyst")
    ),
):
    image = create_image(
        db,
        **payload.model_dump(),
    )

    write_audit_log(
        db,
        action="container_image_registered",
        user_id=current_user.id,
        resource_type="container_image",
        resource_id=str(image.id),
        description=f"Registered container image {image.repository}",
        source_ip=get_source_ip(request),
    )

    db.commit()
    db.refresh(image)

    return image


@router.get("/images")
def images(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_images(db)


@router.post("/findings")
def create_finding(
    payload: ContainerFindingCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead", "soc_analyst")
    ),
):
    try:
        finding = create_container_finding(
            db,
            **payload.model_dump(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="container_security_finding_created",
        user_id=current_user.id,
        resource_type="container_finding",
        resource_id=str(finding.id),
        description=finding.title,
        source_ip=get_source_ip(request),
    )

    db.commit()
    db.refresh(finding)

    return finding


@router.get("/findings")
def findings(
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_container_findings(
        db,
        severity=severity,
        status=status,
    )


@router.post("/findings/{finding_id}/resolve")
def resolve_finding(
    finding_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead")
    ),
):
    try:
        finding = resolve_container_finding(
            db,
            finding_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="container_security_finding_resolved",
        user_id=current_user.id,
        resource_type="container_finding",
        resource_id=str(finding.id),
        description="Resolved container security finding",
        source_ip=get_source_ip(request),
    )

    db.commit()

    return {
        "success": True,
        "finding_id": finding.id,
        "status": finding.status,
        "resolved_at": finding.resolved_at,
    }


@router.post("/workloads")
def create_kubernetes_workload(
    payload: KubernetesWorkloadCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead", "soc_analyst")
    ),
):
    try:
        workload = create_workload(
            db,
            **payload.model_dump(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="kubernetes_workload_registered",
        user_id=current_user.id,
        resource_type="kubernetes_workload",
        resource_id=str(workload.id),
        description=f"Registered workload {workload.workload_name}",
        source_ip=get_source_ip(request),
    )

    db.commit()
    db.refresh(workload)

    return workload


@router.get("/workloads")
def workloads(
    cluster_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_workloads(
        db,
        cluster_id=cluster_id,
    )


@router.post("/workloads/{workload_id}/evaluate")
def evaluate_workload(
    workload_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        result = evaluate_workload_baseline(
            db,
            workload_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="kubernetes_baseline_evaluated",
        user_id=current_user.id,
        resource_type="kubernetes_workload",
        resource_id=str(workload_id),
        description="Evaluated Kubernetes workload against security baseline",
        source_ip=get_source_ip(request),
        metadata=result,
    )

    db.commit()

    return result


@router.post("/workloads/{workload_id}/state")
def update_state(
    workload_id: int,
    observed_state: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead", "soc_analyst")
    ),
):
    try:
        workload = update_workload_state(
            db,
            workload_id=workload_id,
            observed_state=observed_state,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="kubernetes_workload_state_updated",
        user_id=current_user.id,
        resource_type="kubernetes_workload",
        resource_id=str(workload.id),
        description="Updated observed Kubernetes workload state",
        source_ip=get_source_ip(request),
    )

    db.commit()

    return workload
