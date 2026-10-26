CREATE TABLE lab_targets (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL,
 address text NOT NULL CHECK(length(address) BETWEEN 7 AND 15), name text NOT NULL,
 created_by uuid NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,id,asset_id), UNIQUE(organization_id,asset_id,address),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id)
);
CREATE INDEX lab_targets_org ON lab_targets(organization_id,created_at);
CREATE TRIGGER lab_targets_immutable BEFORE UPDATE OR DELETE ON lab_targets FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();

CREATE TABLE lab_scans (
 id uuid PRIMARY KEY REFERENCES jobs(id), organization_id uuid NOT NULL, asset_id uuid NOT NULL,
 target_id uuid NOT NULL, ports jsonb NOT NULL CHECK(jsonb_typeof(ports)='array' AND jsonb_array_length(ports) BETWEEN 1 AND 16),
 evidence_id uuid, analysis_id uuid REFERENCES artifact_analyses(id), error_code text,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,target_id,asset_id) REFERENCES lab_targets(organization_id,id,asset_id),
 FOREIGN KEY(organization_id,evidence_id) REFERENCES evidence(organization_id,id)
);
CREATE INDEX lab_scans_org ON lab_scans(organization_id,created_at);

CREATE TABLE lab_execution_lock (
 slot integer PRIMARY KEY CHECK(slot=1), job_id uuid NOT NULL UNIQUE REFERENCES jobs(id),
 expires_at timestamptz NOT NULL
);
