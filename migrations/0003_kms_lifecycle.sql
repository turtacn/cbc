-- This migration introduces tables to support a full key lifecycle management system.

-- The tenant_keys table stores metadata about cryptographic keys for each tenant.
-- It includes the key's status (active, deprecated, revoked, compromised), the provider type (vault, pkcs11),
-- a reference to the key in the provider, and the public key in PEM format.
-- Private keys are never stored in the database.
ALTER TABLE tenant_keys
ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'active',
ADD COLUMN IF NOT EXISTS provider_type VARCHAR(32) DEFAULT 'vault',
ADD COLUMN IF NOT EXISTS provider_ref TEXT,
ADD COLUMN IF NOT EXISTS public_key_pem TEXT,
ADD COLUMN IF NOT EXISTS compromised_at TIMESTAMPTZ;

-- The key_backups table stores encrypted backups of private keys.
-- The encrypted_blob is the private key encrypted with a master backup key (MBK).
CREATE TABLE IF NOT EXISTS key_backups (
    backup_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    kid VARCHAR(255) NOT NULL,
    encrypted_blob BYTEA NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
