CREATE TABLE IF NOT EXISTS pipeline_audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event VARCHAR(100) NOT NULL,
    details JSONB NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS detections (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    source_ip VARCHAR(50),
    attack_category VARCHAR(50),
    confidence FLOAT,
    features JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_event ON pipeline_audit_log(event);
CREATE INDEX idx_detections_category ON detections(attack_category);
