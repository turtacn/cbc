-- migrations/002_add_key_rotation.down.sql
-- 回滚密钥轮换相关更改

-- 删除函数
DROP FUNCTION IF EXISTS should_rotate_key(UUID);

-- 删除租户表中添加的密钥相关字段
ALTER TABLE tenants DROP COLUMN IF EXISTS last_key_rotation_at;
ALTER TABLE tenants DROP COLUMN IF EXISTS key_rotation_interval_days;
ALTER TABLE tenants DROP COLUMN IF EXISTS key_algorithm;
ALTER TABLE tenants DROP COLUMN IF EXISTS current_key_id;

-- 删除密钥轮换历史表
DROP TABLE IF EXISTS key_rotation_history;

--Personal.AI order the ending
