CREATE TABLE import_runs (
 id uuid PRIMARY KEY REFERENCES jobs(id), organization_id uuid NOT NULL,
 asset_id uuid NOT NULL, project_id uuid, evidence_id uuid NOT NULL,
 format text NOT NULL CHECK(format='zip'), report jsonb, error_code text,
 quarantine_only boolean NOT NULL DEFAULT true CHECK(quarantine_only),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id),
 FOREIGN KEY(organization_id,project_id) REFERENCES projects(organization_id,id),
 FOREIGN KEY(organization_id,evidence_id) REFERENCES evidence(organization_id,id)
);
CREATE INDEX import_runs_org ON import_runs(organization_id,created_at);
CREATE TABLE import_execution_lock (
 slot integer PRIMARY KEY CHECK(slot=1), job_id uuid NOT NULL UNIQUE REFERENCES jobs(id)
);
