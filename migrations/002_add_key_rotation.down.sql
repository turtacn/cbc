ALTER TABLE tenants DROP COLUMN IF EXISTS current_key_id;
ALTER TABLE tenants DROP COLUMN IF EXISTS key_algorithm;
DROP TABLE IF EXISTS key_rotation_history;

--Personal.AI order the ending