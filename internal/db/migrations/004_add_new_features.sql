-- Migration: 004_add_new_features.sql
-- Description: Tables for exposure monitoring, approvals, risk, evidence, knowledge graph, validation, purple team, ASM, compliance builder, collaboration

CREATE TABLE IF NOT EXISTS exposure_findings (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    source VARCHAR(500),
    target VARCHAR(500),
    details TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'open',
    remediation TEXT
);

CREATE INDEX idx_exposure_type ON exposure_findings(type);
CREATE INDEX idx_exposure_severity ON exposure_findings(severity);
CREATE INDEX idx_exposure_status ON exposure_findings(status);

CREATE TABLE IF NOT EXISTS approval_requests (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    requester VARCHAR(255),
    target VARCHAR(500),
    reason TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    approved_by VARCHAR(255),
    approved_at TIMESTAMP,
    denied_by VARCHAR(255),
    denied_at TIMESTAMP,
    deny_reason TEXT
);

CREATE INDEX idx_approval_status ON approval_requests(status);
CREATE INDEX idx_approval_type ON approval_requests(type);

CREATE TABLE IF NOT EXISTS risk_assets (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(500) NOT NULL,
    type VARCHAR(100),
    criticality VARCHAR(20),
    business_value DECIMAL(10,2) DEFAULT 0,
    owner VARCHAR(255),
    compliance TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS business_impacts (
    asset_id VARCHAR(255) PRIMARY KEY,
    impact_score DECIMAL(5,2),
    financial_impact DECIMAL(10,2),
    reputational DECIMAL(10,2),
    regulatory DECIMAL(10,2),
    operational DECIMAL(10,2),
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS risk_trends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE NOT NULL,
    avg_score DECIMAL(5,2),
    max_score DECIMAL(5,2),
    total_open INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sla_entries (
    id VARCHAR(255) PRIMARY KEY,
    finding_id VARCHAR(255) NOT NULL,
    policy_id VARCHAR(255),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    remediated_at TIMESTAMP,
    due_by TIMESTAMP NOT NULL,
    overdue BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS evidence_records (
    id VARCHAR(255) PRIMARY KEY,
    finding_id VARCHAR(255),
    content_hash VARCHAR(255),
    signing_key_id VARCHAR(255),
    signature TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    previous_id VARCHAR(255),
    chain_root VARCHAR(255),
    created_by VARCHAR(255),
    action VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS chain_of_custody (
    id VARCHAR(255) PRIMARY KEY,
    evidence_id VARCHAR(255),
    action VARCHAR(100),
    performed_by VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    previous_hash VARCHAR(255),
    hash VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS immutable_audit_log (
    id VARCHAR(255) PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    level VARCHAR(20),
    message TEXT,
    previous_hash VARCHAR(255),
    hash VARCHAR(255),
    data TEXT
);

CREATE TABLE IF NOT EXISTS knowledge_graph_entities (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    name VARCHAR(500) NOT NULL,
    properties TEXT,
    risk_score DECIMAL(5,2) DEFAULT 0,
    criticality VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_kg_entity_type ON knowledge_graph_entities(type);

CREATE TABLE IF NOT EXISTS knowledge_graph_relationships (
    id VARCHAR(255) PRIMARY KEY,
    source_id VARCHAR(255) NOT NULL,
    target_id VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    properties TEXT,
    weight DECIMAL(5,2) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_kg_rel_source ON knowledge_graph_relationships(source_id);
CREATE INDEX idx_kg_rel_target ON knowledge_graph_relationships(target_id);

CREATE TABLE IF NOT EXISTS validation_tasks (
    id VARCHAR(255) PRIMARY KEY,
    finding_id VARCHAR(255),
    target VARCHAR(500),
    vulnerability_type VARCHAR(255),
    original_evidence TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    last_result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_checked_at TIMESTAMP,
    resolved_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS purple_team_simulations (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(50),
    name VARCHAR(500),
    status VARCHAR(50) DEFAULT 'pending',
    target VARCHAR(500),
    techniques TEXT,
    detection_sources TEXT,
    results TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS asm_assets (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    name VARCHAR(500) NOT NULL,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exposure VARCHAR(20),
    services TEXT,
    cloud_provider VARCHAR(100),
    region VARCHAR(100),
    tags TEXT
);

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id VARCHAR(255) PRIMARY KEY,
    framework_id VARCHAR(255) NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_id VARCHAR(100),
    title VARCHAR(500),
    description TEXT,
    category VARCHAR(100),
    severity VARCHAR(20),
    mapping TEXT,
    tests TEXT
);

CREATE TABLE IF NOT EXISTS collaboration_comments (
    id VARCHAR(255) PRIMARY KEY,
    target_id VARCHAR(255) NOT NULL,
    target_type VARCHAR(50),
    author VARCHAR(255),
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_comments_target ON collaboration_comments(target_id);

CREATE TABLE IF NOT EXISTS collaboration_assignments (
    id VARCHAR(255) PRIMARY KEY,
    target_id VARCHAR(255) NOT NULL,
    target_type VARCHAR(50),
    assignee VARCHAR(255),
    assigned_by VARCHAR(255),
    status VARCHAR(50) DEFAULT 'open',
    due_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX idx_assignments_assignee ON collaboration_assignments(assignee);

CREATE TABLE IF NOT EXISTS evidence_reviews (
    id VARCHAR(255) PRIMARY KEY,
    finding_id VARCHAR(255),
    reviewer VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP
);
