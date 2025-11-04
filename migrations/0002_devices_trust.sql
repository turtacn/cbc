-- ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_fingerprint VARCHAR(256);
-- ALTER TABLE devices ADD COLUMN IF NOT EXISTS trust_level VARCHAR(32) DEFAULT 'low';
-- ALTER TABLE token_metadata ADD COLUMN IF NOT EXISTS device_fingerprint VARCHAR(256);

ALTER TABLE devices ADD COLUMN device_fingerprint VARCHAR(256);
ALTER TABLE devices ADD COLUMN trust_level VARCHAR(32) DEFAULT 'low';
ALTER TABLE token_metadata ADD COLUMN device_fingerprint VARCHAR(256);
