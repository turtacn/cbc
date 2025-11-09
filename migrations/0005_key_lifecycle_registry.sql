-- migrations/0005_key_lifecycle_registry.sql

-- Key Lifecycle Registry (KLR) Table
CREATE TABLE IF NOT EXISTS key_lifecycle_registry (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB,
    version INT NOT NULL DEFAULT 1
);

-- Add compliance_class to tenant_configs table
ALTER TABLE tenant_configs ADD COLUMN IF NOT EXISTS compliance_class VARCHAR(16) DEFAULT 'L1';

-- Add sig to audit_logs table
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS sig VARCHAR(256);
