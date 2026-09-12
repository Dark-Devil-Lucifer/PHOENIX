CREATE DATABASE IF NOT EXISTS phoenix
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE phoenix;


-- ============================================================
-- ROLES
-- ============================================================

CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- ============================================================
-- USERS
-- ============================================================

CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
);


CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role_id INT NOT NULL,

    PRIMARY KEY (user_id, role_id),

    CONSTRAINT fk_user_roles_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_user_roles_role
        FOREIGN KEY (role_id)
        REFERENCES roles(id)
        ON DELETE CASCADE
);


-- ============================================================
-- ASSETS
-- ============================================================

CREATE TABLE assets (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    asset_uid VARCHAR(100) NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50) NOT NULL,

    ip_address VARCHAR(45),
    operating_system VARCHAR(255),

    environment VARCHAR(50) DEFAULT 'production',
    criticality VARCHAR(20) DEFAULT 'medium',

    owner VARCHAR(255),
    location VARCHAR(255),

    status VARCHAR(30) DEFAULT 'active',

    first_seen_at DATETIME,
    last_seen_at DATETIME,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_assets_hostname (hostname),
    INDEX idx_assets_ip (ip_address),
    INDEX idx_assets_type (asset_type),
    INDEX idx_assets_status (status)
);


-- ============================================================
-- EVENT SOURCES
-- ============================================================

CREATE TABLE event_sources (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    name VARCHAR(255) NOT NULL,
    source_type VARCHAR(100) NOT NULL,

    hostname VARCHAR(255),
    ip_address VARCHAR(45),

    status VARCHAR(30) DEFAULT 'active',

    last_event_at DATETIME NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uq_event_source_name (name)
);


-- ============================================================
-- SECURITY EVENTS / SIEM
-- ============================================================

CREATE TABLE security_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    event_uid VARCHAR(100) NOT NULL UNIQUE,

    source_id BIGINT NULL,
    asset_id BIGINT NULL,

    event_time DATETIME NOT NULL,

    event_type VARCHAR(100) NOT NULL,
    category VARCHAR(100),
    action VARCHAR(100),

    severity VARCHAR(20) DEFAULT 'informational',

    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),

    source_port INT,
    destination_port INT,

    username VARCHAR(255),
    process_name VARCHAR(255),

    message TEXT,

    raw_event JSON NULL,
    normalized_data JSON NULL,

    ingestion_time DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (source_id)
        REFERENCES event_sources(id)
        ON DELETE SET NULL,

    FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE SET NULL,

    INDEX idx_events_time (event_time),
    INDEX idx_events_type (event_type),
    INDEX idx_events_severity (severity),
    INDEX idx_events_source_ip (source_ip),
    INDEX idx_events_username (username),
    INDEX idx_events_asset (asset_id)
);


-- ============================================================
-- DETECTION RULES
-- ============================================================

CREATE TABLE detection_rules (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    rule_uid VARCHAR(100) NOT NULL UNIQUE,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    rule_type VARCHAR(50) NOT NULL,

    severity VARCHAR(20) NOT NULL,
    confidence INT DEFAULT 50,

    enabled BOOLEAN DEFAULT TRUE,

    mitre_tactic VARCHAR(100),
    mitre_technique VARCHAR(100),

    rule_definition JSON NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_detection_enabled (enabled),
    INDEX idx_detection_severity (severity)
);


-- ============================================================
-- DETECTION EXECUTIONS
-- ============================================================

CREATE TABLE detection_executions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    rule_id BIGINT NOT NULL,

    execution_time DATETIME DEFAULT CURRENT_TIMESTAMP,

    events_evaluated INT DEFAULT 0,
    matches_found INT DEFAULT 0,

    execution_status VARCHAR(30) DEFAULT 'success',

    execution_time_ms INT,

    FOREIGN KEY (rule_id)
        REFERENCES detection_rules(id)
        ON DELETE CASCADE
);


-- ============================================================
-- ALERTS
-- ============================================================

CREATE TABLE alerts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    alert_uid VARCHAR(100) NOT NULL UNIQUE,

    detection_rule_id BIGINT NULL,
    asset_id BIGINT NULL,

    title VARCHAR(255) NOT NULL,
    description TEXT,

    severity VARCHAR(20) NOT NULL,
    confidence INT DEFAULT 50,

    status VARCHAR(30) DEFAULT 'new',

    first_seen_at DATETIME,
    last_seen_at DATETIME,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (detection_rule_id)
        REFERENCES detection_rules(id)
        ON DELETE SET NULL,

    FOREIGN KEY (asset_id)
        REFERENCES assets(id)
        ON DELETE SET NULL,

    INDEX idx_alert_status (status),
    INDEX idx_alert_severity (severity),
    INDEX idx_alert_created (created_at)
);


-- ============================================================
-- ALERT ↔ EVENT
-- ============================================================

CREATE TABLE alert_events (
    alert_id BIGINT NOT NULL,
    event_id BIGINT NOT NULL,

    PRIMARY KEY (alert_id, event_id),

    FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE CASCADE,

    FOREIGN KEY (event_id)
        REFERENCES security_events(id)
        ON DELETE CASCADE
);


-- ============================================================
-- INCIDENTS
-- ============================================================

CREATE TABLE incidents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    incident_uid VARCHAR(100) NOT NULL UNIQUE,

    title VARCHAR(255) NOT NULL,
    description TEXT,

    severity VARCHAR(20) NOT NULL,

    status VARCHAR(30) DEFAULT 'open',

    priority INT DEFAULT 50,

    assigned_to BIGINT NULL,

    detected_at DATETIME,
    contained_at DATETIME NULL,
    resolved_at DATETIME NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (assigned_to)
        REFERENCES users(id)
        ON DELETE SET NULL,

    INDEX idx_incident_status (status),
    INDEX idx_incident_severity (severity),
    INDEX idx_incident_priority (priority)
);


-- ============================================================
-- INCIDENT ↔ ALERT
-- ============================================================

CREATE TABLE incident_alerts (
    incident_id BIGINT NOT NULL,
    alert_id BIGINT NOT NULL,

    PRIMARY KEY (incident_id, alert_id),

    FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE CASCADE,

    FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE CASCADE
);


-- ============================================================
-- INCIDENT TIMELINE
-- ============================================================

CREATE TABLE incident_timeline (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    incident_id BIGINT NOT NULL,

    event_type VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,

    actor_type VARCHAR(50),
    actor_id BIGINT NULL,

    occurred_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    metadata JSON NULL,

    FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE CASCADE,

    INDEX idx_timeline_incident (incident_id),
    INDEX idx_timeline_time (occurred_at)
);


-- ============================================================
-- RESPONSE PLAYBOOKS
-- ============================================================

CREATE TABLE response_playbooks (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    playbook_uid VARCHAR(100) NOT NULL UNIQUE,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    trigger_type VARCHAR(100),

    requires_approval BOOLEAN DEFAULT TRUE,
    enabled BOOLEAN DEFAULT TRUE,

    definition JSON NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- ============================================================
-- RESPONSE EXECUTIONS
-- ============================================================

CREATE TABLE response_executions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    playbook_id BIGINT NOT NULL,
    incident_id BIGINT NULL,

    execution_uid VARCHAR(100) NOT NULL UNIQUE,

    status VARCHAR(30) DEFAULT 'pending',

    requested_by BIGINT NULL,
    approved_by BIGINT NULL,

    started_at DATETIME NULL,
    completed_at DATETIME NULL,

    result JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (playbook_id)
        REFERENCES response_playbooks(id),

    FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE SET NULL,

    FOREIGN KEY (requested_by)
        REFERENCES users(id)
        ON DELETE SET NULL,

    FOREIGN KEY (approved_by)
        REFERENCES users(id)
        ON DELETE SET NULL
);


-- ============================================================
-- AUDIT LOG
-- ============================================================

CREATE TABLE audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    user_id BIGINT NULL,

    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(100),

    description TEXT,

    source_ip VARCHAR(45),

    metadata JSON NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,

    INDEX idx_audit_time (created_at),
    INDEX idx_audit_action (action),
    INDEX idx_audit_user (user_id)
);
