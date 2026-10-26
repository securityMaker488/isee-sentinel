CREATE TABLE forensic_runs (
 id uuid PRIMARY KEY REFERENCES jobs(id), organization_id uuid NOT NULL, asset_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('pcap','sqlite','plist')),
 evidence_id uuid NOT NULL, report jsonb, error_code text,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id),
 FOREIGN KEY(organization_id,evidence_id) REFERENCES evidence(organization_id,id)
);
CREATE INDEX forensic_runs_org ON forensic_runs(organization_id,created_at);
CREATE TABLE forensic_execution_lock (
 slot integer PRIMARY KEY CHECK(slot=1), job_id uuid NOT NULL UNIQUE REFERENCES jobs(id)
);
