-- key_rotation_history table
CREATE TABLE key_rotation_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_id VARCHAR(255) NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    rotated_at TIMESTAMPTZ,
    deprecated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, key_id)
);
CREATE INDEX idx_key_rotation_tenant_id ON key_rotation_history(tenant_id);
CREATE INDEX idx_key_rotation_status ON key_rotation_history(status);

-- Add current_key_id to tenants table
ALTER TABLE tenants ADD COLUMN current_key_id VARCHAR(255);
ALTER TABLE tenants ADD COLUMN key_algorithm VARCHAR(50) DEFAULT 'RS256';

--Personal.AI order the ending