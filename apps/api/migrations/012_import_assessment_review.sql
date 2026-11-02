-- Existing imports remain historical. No retrospective authorization is assigned.
ALTER TABLE import_runs ADD COLUMN mandate_id uuid;
ALTER TABLE import_runs ADD COLUMN authorization_request_hash text;
ALTER TABLE import_runs ADD CONSTRAINT import_review_pair CHECK (
 (mandate_id IS NULL AND authorization_request_hash IS NULL) OR
 (mandate_id IS NOT NULL AND authorization_request_hash IS NOT NULL AND authorization_request_hash ~ '^[0-9a-f]{64}$')
);
ALTER TABLE import_runs ADD CONSTRAINT import_review_fk FOREIGN KEY(organization_id,mandate_id,authorization_request_hash)
 REFERENCES authorization_mandates(organization_id,id,request_hash);
ALTER TABLE import_runs ADD CONSTRAINT import_review_asset_fk FOREIGN KEY(mandate_id,asset_id)
 REFERENCES authorization_mandate_assets(mandate_id,asset_id);
ALTER TABLE import_runs ADD CONSTRAINT import_job_asset_fk FOREIGN KEY(organization_id,id,asset_id)
 REFERENCES jobs(organization_id,id,asset_id);
ALTER TABLE import_runs ADD CONSTRAINT import_evidence_asset_fk FOREIGN KEY(organization_id,evidence_id,asset_id)
 REFERENCES evidence(organization_id,id,asset_id);
CREATE FUNCTION protect_import_identity() RETURNS trigger AS $$
BEGIN
 IF (to_jsonb(NEW) - 'report' - 'error_code') IS DISTINCT FROM (to_jsonb(OLD) - 'report' - 'error_code') THEN
  RAISE EXCEPTION 'Import identity and reviewed authorization are immutable';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER import_identity_immutable BEFORE UPDATE ON import_runs FOR EACH ROW EXECUTE FUNCTION protect_import_identity();
CREATE TRIGGER import_no_delete BEFORE DELETE ON import_runs FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
