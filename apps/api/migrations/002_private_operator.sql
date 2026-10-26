CREATE TABLE private_operator (
 slot integer PRIMARY KEY CHECK(slot=1), user_id uuid NOT NULL UNIQUE REFERENCES users(id),
 recovery_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE operator_organizations (
 operator_id uuid NOT NULL REFERENCES users(id), organization_id uuid NOT NULL REFERENCES organizations(id),
 PRIMARY KEY(operator_id,organization_id)
);
INSERT INTO operator_organizations(operator_id,organization_id) SELECT id,organization_id FROM users;
ALTER TABLE sessions ADD COLUMN active_organization_id uuid REFERENCES organizations(id);
CREATE TABLE projects (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id), name text NOT NULL,
 contract_ref text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,id)
);
ALTER TABLE assets ADD COLUMN project_id uuid;
ALTER TABLE assets ADD CONSTRAINT assets_project_org_fk FOREIGN KEY(organization_id,project_id) REFERENCES projects(organization_id,id);
ALTER TABLE authorizations DROP CONSTRAINT authorizations_organization_id_created_by_fkey;
ALTER TABLE authorizations ADD CONSTRAINT authorization_operator_org_fk FOREIGN KEY(created_by,organization_id) REFERENCES operator_organizations(operator_id,organization_id);
ALTER TABLE evidence DROP CONSTRAINT evidence_organization_id_created_by_fkey;
ALTER TABLE evidence ADD CONSTRAINT evidence_operator_org_fk FOREIGN KEY(created_by,organization_id) REFERENCES operator_organizations(operator_id,organization_id);
ALTER TABLE security_events ADD COLUMN external_id uuid;
CREATE UNIQUE INDEX security_event_dedup ON security_events(organization_id,asset_id,source,external_id) WHERE external_id IS NOT NULL;
CREATE TABLE alerts (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL,
 incident_id uuid NOT NULL REFERENCES incidents(id), rule_id text NOT NULL, rule_version text NOT NULL,
 title text NOT NULL, severity text NOT NULL, confidence text NOT NULL,
 status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','false_positive','closed')),
 synthetic boolean NOT NULL, event_ids jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id)
);
CREATE INDEX alerts_org ON alerts(organization_id,created_at);
