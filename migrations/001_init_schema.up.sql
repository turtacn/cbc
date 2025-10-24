-- migrations/001_init_schema.up.sql
-- 初始化数据库表结构
-- 使用 UUID 扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 创建租户表
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'deleted')),
    access_token_ttl INTEGER NOT NULL DEFAULT 3600 CHECK (access_token_ttl > 0),
    refresh_token_ttl INTEGER NOT NULL DEFAULT 2592000 CHECK (refresh_token_ttl > 0),
    rate_limit_config JSONB DEFAULT '{"global": 10000, "device": 100}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_status ON tenants(status);
CREATE INDEX idx_tenants_created_at ON tenants(created_at DESC);

COMMENT ON TABLE tenants IS '租户配置表';
COMMENT ON COLUMN tenants.access_token_ttl IS 'Access Token 生命周期（秒）';
COMMENT ON COLUMN tenants.refresh_token_ttl IS 'Refresh Token 生命周期（秒）';
COMMENT ON COLUMN tenants.rate_limit_config IS '限流配置（JSON）';

-- 创建设备表
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    device_type VARCHAR(50) NOT NULL CHECK (device_type IN ('mobile', 'desktop', 'iot', 'server')),
    device_name VARCHAR(255),
    fingerprint TEXT NOT NULL,
    trust_level VARCHAR(50) DEFAULT 'medium' CHECK (trust_level IN ('high', 'medium', 'low', 'untrusted')),
    last_seen_at TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, device_id)
);

CREATE INDEX idx_devices_tenant_id ON devices(tenant_id);
CREATE INDEX idx_devices_device_id ON devices(device_id);
CREATE INDEX idx_devices_fingerprint ON devices(fingerprint);
CREATE INDEX idx_devices_last_seen ON devices(last_seen_at DESC);
CREATE INDEX idx_devices_trust_level ON devices(trust_level);

COMMENT ON TABLE devices IS '设备注册表';
COMMENT ON COLUMN devices.fingerprint IS '设备指纹哈希';
COMMENT ON COLUMN devices.trust_level IS '设备信任等级';

-- 创建令牌元数据表
CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    jti VARCHAR(255) NOT NULL UNIQUE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_type VARCHAR(50) NOT NULL CHECK (token_type IN ('access_token', 'refresh_token')),
    scope TEXT DEFAULT 'agent:read',
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    revoke_reason VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CHECK (expires_at > issued_at)
);

CREATE UNIQUE INDEX idx_tokens_jti ON tokens(jti);
CREATE INDEX idx_tokens_tenant_device ON tokens(tenant_id, device_id);
CREATE INDEX idx_tokens_expires_at ON tokens(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_tokens_revoked_at ON tokens(revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX idx_tokens_token_type ON tokens(token_type);

COMMENT ON TABLE tokens IS '令牌元数据表';
COMMENT ON COLUMN tokens.jti IS 'JWT ID（唯一标识符）';
COMMENT ON COLUMN tokens.scope IS '权限范围';
COMMENT ON COLUMN tokens.revoke_reason IS '撤销原因';

-- 创建审计日志表
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    result VARCHAR(50) NOT NULL CHECK (result IN ('success', 'failure')),
    error_code VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    trace_id VARCHAR(255),
    span_id VARCHAR(255),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_device_id ON audit_logs(device_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_result ON audit_logs(result);
CREATE INDEX idx_audit_logs_trace_id ON audit_logs(trace_id);

COMMENT ON TABLE audit_logs IS '审计日志表';
COMMENT ON COLUMN audit_logs.action IS '操作类型（如：issue_token, revoke_token）';
COMMENT ON COLUMN audit_logs.resource_type IS '资源类型（如：token, device）';
COMMENT ON COLUMN audit_logs.trace_id IS '分布式追踪 ID';

-- 创建触发器函数：自动更新 updated_at 字段
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 为需要的表添加触发器
CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_devices_updated_at BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 插入默认租户（用于开发和测试）
INSERT INTO tenants (id, name, status, access_token_ttl, refresh_token_ttl, rate_limit_config)
VALUES (
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'Default Tenant',
    'active',
    900,
    2592000,
    '{"global": 100000, "device": 10}'::jsonb
) ON CONFLICT DO NOTHING;

--Personal.AI order the ending
