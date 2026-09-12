from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class KubernetesCluster(Base):
    __tablename__ = "kubernetes_clusters"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    cluster_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    environment: Mapped[str | None] = mapped_column(
        String(50)
    )

    version: Mapped[str | None] = mapped_column(
        String(100)
    )

    api_endpoint: Mapped[str | None] = mapped_column(
        String(255)
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="active",
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )


class ContainerImage(Base):
    __tablename__ = "container_images"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    image_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    repository: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    tag: Mapped[str | None] = mapped_column(
        String(100)
    )

    digest: Mapped[str | None] = mapped_column(
        String(255)
    )

    registry: Mapped[str | None] = mapped_column(
        String(255)
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )


class ContainerFinding(Base):
    __tablename__ = "container_findings"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    finding_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    image_id: Mapped[int] = mapped_column(
        ForeignKey(
            "container_images.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    cve_id: Mapped[str | None] = mapped_column(
        String(30)
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    cvss_score: Mapped[float | None] = mapped_column(
        Numeric(4, 1)
    )

    remediation: Mapped[str | None] = mapped_column(
        Text
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="open",
    )

    detected_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )

    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )


class KubernetesWorkload(Base):
    __tablename__ = "kubernetes_workloads"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    workload_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    cluster_id: Mapped[int] = mapped_column(
        ForeignKey(
            "kubernetes_clusters.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    namespace: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    workload_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    workload_type: Mapped[str | None] = mapped_column(
        String(100)
    )

    image_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "container_images.id",
            ondelete="SET NULL",
        )
    )

    baseline: Mapped[dict | None] = mapped_column(JSON)
    observed_state: Mapped[dict | None] = mapped_column(JSON)

    status: Mapped[str] = mapped_column(
        String(30),
        default="running",
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )
