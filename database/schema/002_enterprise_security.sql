USE phoenix;

-- ============================================================
-- VULNERABILITY MANAGEMENT
-- ============================================================

CREATE TABLE vulnerabilities (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    vulnerability_uid VARCHAR(100) NOT NULL UNIQUE,
    cve_id VARCHAR(30),
    title VARCHAR(255) NOT NULL,
    description TEXT,

    severity VARCHAR(20) NOT NULL,
    cvss_score DECIMAL(4,1),

    affected_product VARCHAR(255),
    affected_version VARCHAR(255),

    remediation TEXT,

    status VARCHAR(30) DEFAULT 'open',

    first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    fixed_at DATETIME NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_vuln_severity (severity),
    INDEX idx_vuln_status (status),
    INDEX idx_vuln_cve (cve_id)
);


CREATE TABLE asset_vulnerabilities (
    asset_id BIGINT NOT NULL,
    vulnerability_id BIGINT NOT NULL,

    status VARCHAR(30) DEFAULT 'open',

    risk_score INT DEFAULT 50,

    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    remediated_at DATETIME NULL,

    evidence JSON NULL,

    PRIMARY KEY (asset_id, vulnerability_id),

    FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE CASCADE,

    FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(id)
        ON DELETE CASCADE,

    INDEX idx_asset_vuln_status (status),
    INDEX idx_asset_vuln_risk (risk_score)
);


CREATE TABLE vulnerability_exceptions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    asset_id BIGINT NOT NULL,
    vulnerability_id BIGINT NOT NULL,

    reason TEXT NOT NULL,
    approved_by BIGINT NULL,

    expires_at DATETIME NULL,

    status VARCHAR(30) DEFAULT 'approved',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE CASCADE,

    FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(id)
        ON DELETE CASCADE,

    FOREIGN KEY (approved_by)
        REFERENCES users(id)
        ON DELETE SET NULL
);


-- ============================================================
-- ZERO TRUST / NETWORK ACCESS
-- ============================================================

CREATE TABLE zero_trust_policies (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    policy_uid VARCHAR(100) NOT NULL UNIQUE,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    source_segment VARCHAR(100),
    destination_segment VARCHAR(100),

    action VARCHAR(30) NOT NULL,

    required_role VARCHAR(100),
    required_device_state VARCHAR(100),

    enabled BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_zt_enabled (enabled)
);


CREATE TABLE zero_trust_decisions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    decision_uid VARCHAR(100) NOT NULL UNIQUE,

    policy_id BIGINT NULL,
    user_id BIGINT NULL,
    asset_id BIGINT NULL,

    source_segment VARCHAR(100),
    destination_segment VARCHAR(100),

    decision VARCHAR(30) NOT NULL,
    reason TEXT,

    evaluated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (policy_id)
        REFERENCES zero_trust_policies(id)
        ON DELETE SET NULL,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,

    FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE SET NULL,

    INDEX idx_zt_decision (decision),
    INDEX idx_zt_time (evaluated_at)
);


-- ============================================================
-- ENDPOINT / EDR
-- ============================================================

CREATE TABLE endpoints (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    endpoint_uid VARCHAR(100) NOT NULL UNIQUE,
    asset_id BIGINT NOT NULL,

    hostname VARCHAR(255) NOT NULL,
    operating_system VARCHAR(255),

    agent_version VARCHAR(100),

    isolation_status VARCHAR(30) DEFAULT 'connected',
    protection_status VARCHAR(30) DEFAULT 'protected',

    last_seen_at DATETIME,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE CASCADE,

    INDEX idx_endpoint_status (isolation_status),
    INDEX idx_endpoint_asset (asset_id)
);


CREATE TABLE endpoint_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    endpoint_id BIGINT NOT NULL,

    event_type VARCHAR(100) NOT NULL,
    process_name VARCHAR(255),
    process_path VARCHAR(1024),

    command_line TEXT,

    username VARCHAR(255),

    parent_process VARCHAR(255),

    hash_sha256 VARCHAR(64),

    severity VARCHAR(20) DEFAULT 'informational',

    event_time DATETIME NOT NULL,

    metadata JSON NULL,

    FOREIGN KEY (endpoint_id)
        REFERENCES endpoints(id)
        ON DELETE CASCADE,

    INDEX idx_endpoint_event_time (event_time),
    INDEX idx_endpoint_event_type (event_type),
    INDEX idx_endpoint_hash (hash_sha256)
);


-- ============================================================
-- CLOUD SECURITY
-- ============================================================

CREATE TABLE cloud_accounts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    account_uid VARCHAR(100) NOT NULL UNIQUE,

    provider VARCHAR(50) NOT NULL,
    account_name VARCHAR(255) NOT NULL,
    account_identifier VARCHAR(255),

    environment VARCHAR(50) DEFAULT 'production',

    status VARCHAR(30) DEFAULT 'active',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
);


CREATE TABLE cloud_assets (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    cloud_asset_uid VARCHAR(100) NOT NULL UNIQUE,

    cloud_account_id BIGINT NOT NULL,

    resource_type VARCHAR(100) NOT NULL,
    resource_name VARCHAR(255),

    region VARCHAR(100),

    criticality VARCHAR(20) DEFAULT 'medium',

    configuration JSON NULL,

    status VARCHAR(30) DEFAULT 'active',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (cloud_account_id)
        REFERENCES cloud_accounts(id)
        ON DELETE CASCADE,

    INDEX idx_cloud_resource (resource_type),
    INDEX idx_cloud_region (region)
);


CREATE TABLE cloud_security_findings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    finding_uid VARCHAR(100) NOT NULL UNIQUE,

    cloud_asset_id BIGINT NOT NULL,

    title VARCHAR(255) NOT NULL,
    description TEXT,

    severity VARCHAR(20) NOT NULL,

    control_id VARCHAR(100),

    status VARCHAR(30) DEFAULT 'open',

    remediation TEXT,

    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME NULL,

    FOREIGN KEY (cloud_asset_id)
        REFERENCES cloud_assets(id)
        ON DELETE CASCADE,

    INDEX idx_cloud_finding_severity (severity),
    INDEX idx_cloud_finding_status (status)
);


-- ============================================================
-- KUBERNETES / CONTAINER SECURITY
-- ============================================================

CREATE TABLE kubernetes_clusters (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    cluster_uid VARCHAR(100) NOT NULL UNIQUE,

    name VARCHAR(255) NOT NULL,
    environment VARCHAR(50),

    version VARCHAR(100),

    api_endpoint VARCHAR(255),

    status VARCHAR(30) DEFAULT 'active',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE container_images (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    image_uid VARCHAR(100) NOT NULL UNIQUE,

    repository VARCHAR(255) NOT NULL,
    tag VARCHAR(100),

    digest VARCHAR(255),

    registry VARCHAR(255),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE container_findings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    finding_uid VARCHAR(100) NOT NULL UNIQUE,

    image_id BIGINT NOT NULL,

    cve_id VARCHAR(30),
    title VARCHAR(255) NOT NULL,

    severity VARCHAR(20) NOT NULL,

    cvss_score DECIMAL(4,1),

    remediation TEXT,

    status VARCHAR(30) DEFAULT 'open',

    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME NULL,

    FOREIGN KEY (image_id)
        REFERENCES container_images(id)
        ON DELETE CASCADE
);


CREATE TABLE kubernetes_workloads (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    workload_uid VARCHAR(100) NOT NULL UNIQUE,

    cluster_id BIGINT NOT NULL,

    namespace VARCHAR(255) NOT NULL,
    workload_name VARCHAR(255) NOT NULL,
    workload_type VARCHAR(100),

    image_id BIGINT NULL,

    baseline JSON NULL,
    observed_state JSON NULL,

    status VARCHAR(30) DEFAULT 'running',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (cluster_id)
        REFERENCES kubernetes_clusters(id)
        ON DELETE CASCADE,

    FOREIGN KEY (image_id)
        REFERENCES container_images(id)
        ON DELETE SET NULL
);


-- ============================================================
-- CASES / DIGITAL FORENSICS
-- ============================================================

CREATE TABLE cases (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    case_uid VARCHAR(100) NOT NULL UNIQUE,

    incident_id BIGINT NULL,

    title VARCHAR(255) NOT NULL,
    description TEXT,

    status VARCHAR(30) DEFAULT 'open',
    priority INT DEFAULT 50,

    assigned_to BIGINT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE SET NULL,

    FOREIGN KEY (assigned_to)
        REFERENCES users(id)
        ON DELETE SET NULL
);


CREATE TABLE forensic_artifacts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    artifact_uid VARCHAR(100) NOT NULL UNIQUE,

    case_id BIGINT NOT NULL,

    artifact_type VARCHAR(100) NOT NULL,
    source VARCHAR(255),

    hash_sha256 VARCHAR(64),

    collected_by BIGINT NULL,

    collected_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    evidence JSON NULL,

    FOREIGN KEY (case_id)
        REFERENCES cases(id)
        ON DELETE CASCADE,

    FOREIGN KEY (collected_by)
        REFERENCES users(id)
        ON DELETE SET NULL,

    INDEX idx_forensic_case (case_id),
    INDEX idx_forensic_hash (hash_sha256)
);


CREATE TABLE case_evidence (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    case_id BIGINT NOT NULL,

    evidence_type VARCHAR(100) NOT NULL,
    reference_type VARCHAR(100),
    reference_id VARCHAR(100),

    description TEXT,

    added_by BIGINT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (case_id)
        REFERENCES cases(id)
        ON DELETE CASCADE,

    FOREIGN KEY (added_by)
        REFERENCES users(id)
        ON DELETE SET NULL
);


-- ============================================================
-- THREAT HUNTING
-- ============================================================

CREATE TABLE hunting_queries (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    query_uid VARCHAR(100) NOT NULL UNIQUE,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    query_definition JSON NOT NULL,

    created_by BIGINT NULL,

    enabled BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (created_by)
        REFERENCES users(id)
        ON DELETE SET NULL
);


CREATE TABLE hunting_runs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    run_uid VARCHAR(100) NOT NULL UNIQUE,

    query_id BIGINT NOT NULL,

    started_by BIGINT NULL,

    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME NULL,

    events_scanned INT DEFAULT 0,
    matches_found INT DEFAULT 0,

    status VARCHAR(30) DEFAULT 'running',

    results JSON NULL,

    FOREIGN KEY (query_id)
        REFERENCES hunting_queries(id)
        ON DELETE CASCADE,

    FOREIGN KEY (started_by)
        REFERENCES users(id)
        ON DELETE SET NULL
);


-- ============================================================
-- DLP / SENSITIVE DATA
-- ============================================================

CREATE TABLE sensitive_resources (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    resource_uid VARCHAR(100) NOT NULL UNIQUE,

    name VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100),

    classification VARCHAR(50) NOT NULL,

    owner VARCHAR(255),

    location VARCHAR(500),

    enabled BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE dlp_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    event_uid VARCHAR(100) NOT NULL UNIQUE,

    resource_id BIGINT NULL,

    asset_id BIGINT NULL,

    user_id BIGINT NULL,

    action VARCHAR(100) NOT NULL,

    destination VARCHAR(500),

    data_classification VARCHAR(50),

    policy_result VARCHAR(30),

    severity VARCHAR(20) DEFAULT 'medium',

    event_time DATETIME DEFAULT CURRENT_TIMESTAMP,

    metadata JSON NULL,

    FOREIGN KEY (resource_id)
        REFERENCES sensitive_resources(id)
        ON DELETE SET NULL,

    FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE SET NULL,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);


-- ============================================================
-- BACKUP / RECOVERY
-- ============================================================

CREATE TABLE backup_jobs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    job_uid VARCHAR(100) NOT NULL UNIQUE,

    asset_id BIGINT NULL,

    backup_type VARCHAR(50) NOT NULL,

    status VARCHAR(30) DEFAULT 'completed',

    started_at DATETIME,
    completed_at DATETIME,

    integrity_verified BOOLEAN DEFAULT FALSE,

    recovery_point VARCHAR(255),

    metadata JSON NULL,

    FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE SET NULL
);


CREATE TABLE recovery_tests (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    test_uid VARCHAR(100) NOT NULL UNIQUE,

    asset_id BIGINT NULL,

    test_type VARCHAR(100) NOT NULL,

    status VARCHAR(30) DEFAULT 'planned',

    started_at DATETIME,
    completed_at DATETIME,

    recovery_time_seconds INT,

    result JSON NULL,

    FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE SET NULL
);


-- ============================================================
-- RISK / COMPLIANCE
-- ============================================================

CREATE TABLE risk_register (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    risk_uid VARCHAR(100) NOT NULL UNIQUE,

    title VARCHAR(255) NOT NULL,
    description TEXT,

    category VARCHAR(100),

    likelihood INT DEFAULT 3,
    impact INT DEFAULT 3,

    risk_score INT DEFAULT 9,

    treatment VARCHAR(100),

    owner VARCHAR(255),

    status VARCHAR(30) DEFAULT 'open',

    due_date DATE NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
);


CREATE TABLE compliance_controls (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    control_uid VARCHAR(100) NOT NULL UNIQUE,

    framework VARCHAR(100) NOT NULL,
    control_id VARCHAR(100) NOT NULL,

    title VARCHAR(255) NOT NULL,
    description TEXT,

    status VARCHAR(30) DEFAULT 'not_assessed',

    evidence_reference VARCHAR(500),

    last_assessed_at DATETIME NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uq_framework_control (framework, control_id)
);

