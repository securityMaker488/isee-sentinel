-- Append-only assessment plans refer to reviewed authorization identities.
ALTER TABLE assets ADD CONSTRAINT assets_project_identity UNIQUE(organization_id,id,project_id);
ALTER TABLE authorization_mandates ADD CONSTRAINT authorization_project_identity UNIQUE(organization_id,id,project_id);
ALTER TABLE jobs ADD CONSTRAINT jobs_asset_identity UNIQUE(organization_id,id,asset_id);
ALTER TABLE evidence ADD CONSTRAINT evidence_asset_identity UNIQUE(organization_id,id,asset_id);

CREATE TABLE assessment_plans (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, project_id uuid NOT NULL,
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 120), created_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,id), UNIQUE(organization_id,id,project_id),
 FOREIGN KEY(organization_id,project_id) REFERENCES projects(organization_id,id),
 FOREIGN KEY(created_by,organization_id) REFERENCES operator_organizations(operator_id,organization_id)
);
CREATE TABLE assessment_plan_revisions (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, plan_id uuid NOT NULL, project_id uuid NOT NULL,
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 100), schema_version integer NOT NULL CHECK(schema_version=1),
 parent_hash text, revision_hash text NOT NULL CHECK(revision_hash ~ '^[0-9a-f]{64}$'),
 mandate_id uuid NOT NULL, authorization_request_hash text NOT NULL,
 objective text NOT NULL CHECK(length(objective) BETWEEN 1 AND 2000), created_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK((revision=1 AND parent_hash IS NULL) OR (revision>1 AND parent_hash IS NOT NULL AND parent_hash ~ '^[0-9a-f]{64}$')),
 UNIQUE(organization_id,id), UNIQUE(organization_id,plan_id,revision), UNIQUE(organization_id,id,revision_hash),
 UNIQUE(organization_id,plan_id,revision_hash), UNIQUE(organization_id,id,mandate_id,project_id),
 FOREIGN KEY(organization_id,plan_id,project_id) REFERENCES assessment_plans(organization_id,id,project_id),
 FOREIGN KEY(organization_id,plan_id,parent_hash) REFERENCES assessment_plan_revisions(organization_id,plan_id,revision_hash),
 FOREIGN KEY(organization_id,mandate_id,authorization_request_hash) REFERENCES authorization_mandates(organization_id,id,request_hash),
 FOREIGN KEY(organization_id,mandate_id,project_id) REFERENCES authorization_mandates(organization_id,id,project_id),
 FOREIGN KEY(created_by,organization_id) REFERENCES operator_organizations(operator_id,organization_id)
);
CREATE TABLE assessment_plan_steps (
 organization_id uuid NOT NULL, revision_id uuid NOT NULL, project_id uuid NOT NULL, mandate_id uuid NOT NULL,
 step_id text NOT NULL CHECK(step_id ~ '^[A-Za-z0-9_-]{1,64}$'), position integer NOT NULL CHECK(position BETWEEN 0 AND 24),
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 160), asset_id uuid NOT NULL,
 profile text NOT NULL CHECK(profile IN ('static.scan','artifact.analyze','archive.inspect','forensic.analyze','evidence.import','events.ingest','agent.observe','lab.inventory','lab.remediate')),
 address text, ports jsonb,
 PRIMARY KEY(organization_id,revision_id,step_id), UNIQUE(organization_id,revision_id,position),
 UNIQUE(organization_id,revision_id,step_id,asset_id),
 CHECK((profile='lab.inventory' AND address IS NOT NULL AND ports IS NOT NULL AND jsonb_typeof(ports)='array') OR (profile<>'lab.inventory' AND address IS NULL AND ports IS NULL)),
 FOREIGN KEY(organization_id,revision_id,mandate_id,project_id) REFERENCES assessment_plan_revisions(organization_id,id,mandate_id,project_id),
 FOREIGN KEY(organization_id,asset_id,project_id) REFERENCES assets(organization_id,id,project_id),
 FOREIGN KEY(mandate_id,asset_id) REFERENCES authorization_mandate_assets(mandate_id,asset_id)
);
CREATE TABLE assessment_executions (
 job_id uuid PRIMARY KEY, organization_id uuid NOT NULL, revision_id uuid NOT NULL, revision_hash text NOT NULL,
 step_id text NOT NULL, asset_id uuid NOT NULL, created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,job_id,asset_id),
 FOREIGN KEY(organization_id,job_id,asset_id) REFERENCES jobs(organization_id,id,asset_id),
 FOREIGN KEY(organization_id,revision_id,revision_hash) REFERENCES assessment_plan_revisions(organization_id,id,revision_hash),
 FOREIGN KEY(organization_id,revision_id,step_id,asset_id) REFERENCES assessment_plan_steps(organization_id,revision_id,step_id,asset_id),
 FOREIGN KEY(created_by,organization_id) REFERENCES operator_organizations(operator_id,organization_id)
);
CREATE TABLE assessment_execution_evidence (
 organization_id uuid NOT NULL, job_id uuid NOT NULL, asset_id uuid NOT NULL, evidence_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(organization_id,job_id,evidence_id),
 FOREIGN KEY(organization_id,job_id,asset_id) REFERENCES assessment_executions(organization_id,job_id,asset_id),
 FOREIGN KEY(organization_id,evidence_id,asset_id) REFERENCES evidence(organization_id,id,asset_id)
);
CREATE INDEX assessment_plans_org ON assessment_plans(organization_id,created_at);
CREATE INDEX assessment_executions_revision ON assessment_executions(organization_id,revision_id,created_at);
CREATE TRIGGER assessment_plans_immutable BEFORE UPDATE OR DELETE ON assessment_plans FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
CREATE TRIGGER assessment_revisions_immutable BEFORE UPDATE OR DELETE ON assessment_plan_revisions FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
CREATE TRIGGER assessment_steps_immutable BEFORE UPDATE OR DELETE ON assessment_plan_steps FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
CREATE TRIGGER assessment_executions_immutable BEFORE UPDATE OR DELETE ON assessment_executions FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
CREATE TRIGGER assessment_execution_evidence_immutable BEFORE UPDATE OR DELETE ON assessment_execution_evidence FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
