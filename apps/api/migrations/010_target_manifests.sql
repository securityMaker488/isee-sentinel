-- Existing records retain their original hash and never acquire retroactive consent.
ALTER TABLE authorization_mandates ADD COLUMN target_manifest jsonb;
ALTER TABLE authorization_mandates ADD COLUMN request_schema_version smallint NOT NULL DEFAULT 1;
ALTER TABLE authorization_mandates ADD CONSTRAINT authorization_manifest_version CHECK (
 (request_schema_version=1 AND target_manifest IS NULL) OR
 (request_schema_version=2 AND target_manifest IS NOT NULL AND jsonb_typeof(target_manifest)='object' AND COALESCE(target_manifest->>'version'='1',false))
);
ALTER TABLE authorization_mandates ADD CONSTRAINT authorization_review_identity UNIQUE(organization_id,id,request_hash);

ALTER TABLE lab_scans ADD COLUMN mandate_id uuid;
ALTER TABLE lab_scans ADD COLUMN authorization_request_hash text;
ALTER TABLE lab_scans ADD CONSTRAINT lab_scan_review_pair CHECK (
 (mandate_id IS NULL AND authorization_request_hash IS NULL) OR
 (mandate_id IS NOT NULL AND authorization_request_hash IS NOT NULL AND authorization_request_hash ~ '^[0-9a-f]{64}$')
);
ALTER TABLE lab_scans ADD CONSTRAINT lab_scan_review_fk FOREIGN KEY(organization_id,mandate_id,authorization_request_hash)
 REFERENCES authorization_mandates(organization_id,id,request_hash);
ALTER TABLE lab_scans ADD CONSTRAINT lab_scan_review_asset_fk FOREIGN KEY(mandate_id,asset_id)
 REFERENCES authorization_mandate_assets(mandate_id,asset_id);
CREATE INDEX lab_scans_mandate ON lab_scans(organization_id,mandate_id);

CREATE FUNCTION protect_lab_scan_review() RETURNS trigger AS $$
BEGIN
 IF NEW.mandate_id IS DISTINCT FROM OLD.mandate_id OR NEW.authorization_request_hash IS DISTINCT FROM OLD.authorization_request_hash THEN
  RAISE EXCEPTION 'Lab scan authorization history is immutable';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER lab_scan_review_immutable BEFORE UPDATE ON lab_scans FOR EACH ROW EXECUTE FUNCTION protect_lab_scan_review();
