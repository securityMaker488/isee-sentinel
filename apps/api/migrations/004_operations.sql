ALTER TABLE incidents ADD CONSTRAINT incidents_org_id_unique UNIQUE(organization_id,id);
CREATE TABLE incident_notes (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, incident_id uuid NOT NULL,
 actor_id uuid NOT NULL, body_cipher text NOT NULL, sha256 text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,incident_id) REFERENCES incidents(organization_id,id),
 FOREIGN KEY(actor_id,organization_id) REFERENCES operator_organizations(operator_id,organization_id)
);
CREATE TABLE incident_evidence (
 organization_id uuid NOT NULL, incident_id uuid NOT NULL, evidence_id uuid NOT NULL,
 actor_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,incident_id,evidence_id),
 FOREIGN KEY(organization_id,incident_id) REFERENCES incidents(organization_id,id),
 FOREIGN KEY(organization_id,evidence_id) REFERENCES evidence(organization_id,id),
 FOREIGN KEY(actor_id,organization_id) REFERENCES operator_organizations(operator_id,organization_id)
);
CREATE TABLE remediation_plans (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL, name text NOT NULL,
 status text NOT NULL CHECK(status IN ('manual_review','no_change','proposed','approved','applied','verified','rolled_back')),
 original_evidence_id uuid NOT NULL, proposed_evidence_id uuid NOT NULL,
 original_hash text NOT NULL, proposed_hash text NOT NULL, changes jsonb NOT NULL,
 reasons jsonb NOT NULL, current_revision integer NOT NULL DEFAULT 1,
 created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,id),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id),
 FOREIGN KEY(organization_id,original_evidence_id) REFERENCES evidence(organization_id,id),
 FOREIGN KEY(organization_id,proposed_evidence_id) REFERENCES evidence(organization_id,id),
 FOREIGN KEY(created_by,organization_id) REFERENCES operator_organizations(operator_id,organization_id)
);
CREATE TABLE remediation_revisions (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, plan_id uuid NOT NULL, revision integer NOT NULL,
 action text NOT NULL CHECK(action IN ('import','apply','rollback')), sha256 text NOT NULL,
 content_cipher text NOT NULL, actor_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,plan_id,revision),
 FOREIGN KEY(organization_id,plan_id) REFERENCES remediation_plans(organization_id,id),
 FOREIGN KEY(actor_id,organization_id) REFERENCES operator_organizations(operator_id,organization_id)
);
CREATE INDEX incident_notes_case ON incident_notes(organization_id,incident_id,created_at);
CREATE INDEX remediation_plans_org ON remediation_plans(organization_id,created_at);
CREATE TRIGGER incident_notes_immutable BEFORE UPDATE OR DELETE ON incident_notes FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
CREATE TRIGGER incident_evidence_immutable BEFORE UPDATE OR DELETE ON incident_evidence FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
CREATE TRIGGER remediation_revisions_immutable BEFORE UPDATE OR DELETE ON remediation_revisions FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
