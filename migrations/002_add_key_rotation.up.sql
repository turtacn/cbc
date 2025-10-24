-- migrations/002_add_key_rotation.up.sql
-- 添加密钥轮换相关表和字段

-- 创建密钥轮换历史表
CREATE TABLE IF NOT EXISTS key_rotation_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_id VARCHAR(255) NOT NULL,
    algorithm VARCHAR(50) NOT NULL DEFAULT 'RS256' CHECK (algorithm IN ('RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512')),
    key_size INTEGER NOT NULL DEFAULT 4096 CHECK (key_size IN (2048, 4096)),
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deprecated', 'revoked')),
    activated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deprecated_at TIMESTAMP,
    revoked_at TIMESTAMP,
    revoke_reason VARCHAR(255),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, key_id),
    CHECK (
        (deprecated_at IS NULL OR deprecated_at > activated_at) AND
        (revoked_at IS NULL OR revoked_at > activated_at)
    )
);

CREATE INDEX idx_key_rotation_tenant_id ON key_rotation_history(tenant_id);
CREATE INDEX idx_key_rotation_status ON key_rotation_history(status);
CREATE INDEX idx_key_rotation_created_at ON key_rotation_history(created_at DESC);
CREATE INDEX idx_key_rotation_activated_at ON key_rotation_history(activated_at DESC);

COMMENT ON TABLE key_rotation_history IS '密钥轮换历史记录表';
COMMENT ON COLUMN key_rotation_history.key_id IS '密钥唯一标识符（与 Vault 中的 key_id 对应）';
COMMENT ON COLUMN key_rotation_history.algorithm IS 'JWT 签名算法';
COMMENT ON COLUMN key_rotation_history.key_size IS '密钥长度（位）';

-- 为租户表添加当前密钥相关字段
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS current_key_id VARCHAR(255);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS key_algorithm VARCHAR(50) DEFAULT 'RS256';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS key_rotation_interval_days INTEGER DEFAULT 90 CHECK (key_rotation_interval_days > 0);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS last_key_rotation_at TIMESTAMP;

CREATE INDEX idx_tenants_current_key_id ON tenants(current_key_id);

COMMENT ON COLUMN tenants.current_key_id IS '当前激活的密钥 ID';
COMMENT ON COLUMN tenants.key_algorithm IS '密钥签名算法';
COMMENT ON COLUMN tenants.key_rotation_interval_days IS '密钥轮换间隔（天）';
COMMENT ON COLUMN tenants.last_key_rotation_at IS '上次密钥轮换时间';

-- 为默认租户插入初始密钥记录
INSERT INTO key_rotation_history (tenant_id, key_id, algorithm, key_size, status, activated_at)
VALUES (
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'default-tenant-key-001',
    'RS256',
    4096,
    'active',
    NOW()
) ON CONFLICT DO NOTHING;

-- 更新默认租户的当前密钥 ID
UPDATE tenants
SET
    current_key_id = 'default-tenant-key-001',
    key_algorithm = 'RS256',
    last_key_rotation_at = NOW()
WHERE id = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11';

-- 创建函数：检查密钥是否需要轮换
CREATE OR REPLACE FUNCTION should_rotate_key(p_tenant_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_last_rotation TIMESTAMP;
    v_rotation_interval INTEGER;
BEGIN
    SELECT last_key_rotation_at, key_rotation_interval_days
    INTO v_last_rotation, v_rotation_interval
    FROM tenants
    WHERE id = p_tenant_id;

    IF v_last_rotation IS NULL THEN
        RETURN TRUE;
    END IF;

    RETURN (NOW() - v_last_rotation) > (v_rotation_interval * INTERVAL '1 day');
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION should_rotate_key IS '检查租户密钥是否需要轮换';

--Personal.AI order the ending
