-- migrations/001_init_schema.down.sql
-- 数据库表结构回滚

-- 删除触发器
DROP TRIGGER IF EXISTS update_devices_updated_at ON devices;
DROP TRIGGER IF EXISTS update_tenants_updated_at ON tenants;

-- 删除触发器函数
DROP FUNCTION IF EXISTS update_updated_at_column();

-- 按照依赖关系逆序删除表
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS tokens;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS tenants;

-- 删除 UUID 扩展（如果不再需要）
-- DROP EXTENSION IF EXISTS "uuid-ossp";

--Personal.AI order the ending
