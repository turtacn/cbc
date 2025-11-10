-- +goose Up
-- +goose StatementBegin
CREATE TABLE tenant_risk_scores (
    tenant_id VARCHAR(64) PRIMARY KEY,
    anomaly_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0,
    predicted_threat VARCHAR(32) NOT NULL DEFAULT 'low',
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_tenant_id FOREIGN KEY (tenant_id) REFERENCES tenant_configs(tenant_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS tenant_risk_scores;
-- +goose StatementEnd
