CREATE TABLE artifact_analyses (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL,
 kind text NOT NULL, evidence_id uuid NOT NULL, report jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id),
 FOREIGN KEY(organization_id,evidence_id) REFERENCES evidence(organization_id,id)
);
CREATE INDEX artifact_analyses_org ON artifact_analyses(organization_id,created_at);
CREATE TRIGGER artifact_analyses_immutable BEFORE UPDATE OR DELETE ON artifact_analyses FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
