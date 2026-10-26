CREATE TABLE authorization_mandates (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, project_id uuid NOT NULL,
 mode text NOT NULL CHECK(mode IN ('lab','assessment')),
 risk text NOT NULL CHECK(risk IN ('low','moderate')),
 profiles jsonb NOT NULL, limits jsonb NOT NULL,
 not_before timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK(expires_at>not_before),
 status text NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved','revoked')),
 details_cipher text NOT NULL, details_hash text NOT NULL CHECK(length(details_hash)=64),
 request_hash text NOT NULL CHECK(length(request_hash)=64),
 authority_evidence_id uuid NOT NULL, authority_evidence_hash text NOT NULL CHECK(length(authority_evidence_hash)=64),
 created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 approved_by uuid, approved_at timestamptz, revoked_at timestamptz, revocation_cipher text,
 UNIQUE(organization_id,id),
 FOREIGN KEY(organization_id,project_id) REFERENCES projects(organization_id,id),
 FOREIGN KEY(organization_id,authority_evidence_id) REFERENCES evidence(organization_id,id),
 FOREIGN KEY(created_by,organization_id) REFERENCES operator_organizations(operator_id,organization_id),
 FOREIGN KEY(approved_by,organization_id) REFERENCES operator_organizations(operator_id,organization_id),
 CHECK((status='draft' AND approved_at IS NULL AND revoked_at IS NULL) OR
       (status='approved' AND approved_at IS NOT NULL AND approved_by IS NOT NULL AND revoked_at IS NULL) OR
       (status='revoked' AND revoked_at IS NOT NULL AND revocation_cipher IS NOT NULL))
);
CREATE INDEX authorization_mandates_org ON authorization_mandates(organization_id,created_at);
CREATE TABLE authorization_mandate_assets (
 mandate_id uuid NOT NULL, organization_id uuid NOT NULL, asset_id uuid NOT NULL,
 environment text NOT NULL CHECK(environment IN ('lab','staging','production')),
 PRIMARY KEY(mandate_id,asset_id),
 FOREIGN KEY(organization_id,mandate_id) REFERENCES authorization_mandates(organization_id,id),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id)
);
ALTER TABLE assets ADD COLUMN authorization_mode text NOT NULL DEFAULT 'legacy' CHECK(authorization_mode IN ('legacy','managed'));
ALTER TABLE authorizations ADD COLUMN mandate_id uuid;
ALTER TABLE authorizations ADD CONSTRAINT authorizations_mandate_org_fk FOREIGN KEY(organization_id,mandate_id) REFERENCES authorization_mandates(organization_id,id);
CREATE INDEX authorizations_mandate ON authorizations(mandate_id);
CREATE FUNCTION protect_authorization_mandate() RETURNS trigger AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['status','approved_by','approved_at','revoked_at','revocation_cipher']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['status','approved_by','approved_at','revoked_at','revocation_cipher']) THEN
  RAISE EXCEPTION 'Authorization request is immutable';
 END IF;
 IF NOT ((OLD.status='draft' AND NEW.status IN ('approved','revoked')) OR
         (OLD.status='approved' AND NEW.status='revoked')) THEN
  RAISE EXCEPTION 'Invalid authorization transition';
 END IF;
 IF NEW.status='revoked' AND (NEW.approved_by IS DISTINCT FROM OLD.approved_by OR NEW.approved_at IS DISTINCT FROM OLD.approved_at) THEN
  RAISE EXCEPTION 'Approval history is immutable';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER authorization_mandate_immutable BEFORE UPDATE ON authorization_mandates FOR EACH ROW EXECUTE FUNCTION protect_authorization_mandate();
