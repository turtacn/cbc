CREATE TABLE IF NOT EXISTS devices (
  tenant_id  TEXT NOT NULL,
  device_id  TEXT NOT NULL,
  display_name TEXT,
  platform   TEXT,
  agent_ver  TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_devices_updated_at ON devices(updated_at DESC);
