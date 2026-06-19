-- Migration: 001_initial_schema.sql
-- Description: Create initial tables for ARES strategic memory
-- Created: 2024-01-15

CREATE TABLE IF NOT EXISTS scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id VARCHAR(255) NOT NULL,
    target VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    phase VARCHAR(50) NOT NULL DEFAULT 'recon',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    findings_count INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scan_results(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_score DECIMAL(3,1),
    status VARCHAR(50) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'accepted', 'false-positive')),
    endpoint VARCHAR(1000),
    evidence_path VARCHAR(1000),
    remediation TEXT,
    mitre_attack JSONB DEFAULT '[]',
    compliance_controls JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);

CREATE TABLE IF NOT EXISTS strategic_memory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target VARCHAR(255) NOT NULL,
    technique VARCHAR(255) NOT NULL,
    success BOOLEAN NOT NULL,
    confidence DECIMAL(3,2),
    context JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_memory_target ON strategic_memory(target);
CREATE INDEX idx_memory_technique ON strategic_memory(technique);

CREATE TABLE IF NOT EXISTS checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id VARCHAR(255) NOT NULL,
    phase VARCHAR(50) NOT NULL,
    iteration INTEGER DEFAULT 0,
    state JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_checkpoints_scan_id ON checkpoints(scan_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    level VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    fields JSONB DEFAULT '{}',
    scan_id VARCHAR(255)
);

CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_scan_id ON audit_log(scan_id);
