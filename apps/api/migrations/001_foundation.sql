CREATE TABLE organizations (id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE users (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id), email text NOT NULL UNIQUE,
 role text NOT NULL CHECK(role IN ('admin','analyst','viewer')), password_hash text NOT NULL,
 totp_cipher text NOT NULL, last_totp_counter bigint NOT NULL DEFAULT -1, disabled boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,id)
);
CREATE TABLE sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), csrf_token text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL
);
CREATE TABLE login_attempts (key text PRIMARY KEY, failures integer NOT NULL DEFAULT 0, window_start timestamptz NOT NULL);
CREATE TABLE assets (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id), name text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('application','server','repository')),
 environment text NOT NULL CHECK(environment IN ('lab','staging','production')),
 criticality integer NOT NULL CHECK(criticality BETWEEN 1 AND 5), created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,id)
);
CREATE TABLE authorizations (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL, environment text NOT NULL,
 operations jsonb NOT NULL, authorization_ref text NOT NULL, not_before timestamptz NOT NULL,
 expires_at timestamptz NOT NULL, created_by uuid NOT NULL, revoked_at timestamptz,
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id),
 FOREIGN KEY(organization_id,created_by) REFERENCES users(organization_id,id), CHECK(expires_at>not_before)
);
CREATE TABLE jobs (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL, kind text NOT NULL,
 status text NOT NULL CHECK(status IN ('running','completed','failed','interrupted')),
 created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id)
);
CREATE TABLE scans (
 id uuid PRIMARY KEY REFERENCES jobs(id), organization_id uuid NOT NULL, asset_id uuid NOT NULL,
 result jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,id),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id)
);
CREATE TABLE evidence (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL, name text NOT NULL,
 media_type text NOT NULL, sha256 text NOT NULL CHECK(length(sha256)=64), size_bytes integer NOT NULL,
 content_cipher text NOT NULL, created_by uuid NOT NULL, source text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,id),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id),
 FOREIGN KEY(organization_id,created_by) REFERENCES users(organization_id,id)
);
CREATE TABLE findings (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL, scan_id uuid NOT NULL,
 evidence_id uuid NOT NULL, details jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id),
 FOREIGN KEY(organization_id,scan_id) REFERENCES scans(organization_id,id),
 FOREIGN KEY(organization_id,evidence_id) REFERENCES evidence(organization_id,id)
);
CREATE TABLE security_events (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL, schema_version integer NOT NULL CHECK(schema_version=1),
 type text NOT NULL, source text NOT NULL, occurred_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
 data jsonb NOT NULL, FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id)
);
CREATE TABLE incidents (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL, rule_id text NOT NULL,
 title text NOT NULL, status text NOT NULL DEFAULT 'open', event_ids jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id)
);
CREATE TABLE audit_events (
 sequence bigserial PRIMARY KEY, id uuid NOT NULL UNIQUE, organization_id uuid NOT NULL REFERENCES organizations(id),
 actor_id uuid, action text NOT NULL, resource_id text, details jsonb NOT NULL,
 created_at timestamptz NOT NULL, previous_hash text NOT NULL, hash text NOT NULL
);
CREATE INDEX assets_org ON assets(organization_id);
CREATE INDEX scopes_asset ON authorizations(organization_id,asset_id);
CREATE INDEX scans_org ON scans(organization_id,created_at);
CREATE INDEX evidence_org ON evidence(organization_id,created_at);
CREATE INDEX findings_org ON findings(organization_id,scan_id);
CREATE INDEX events_correlation ON security_events(organization_id,asset_id,type,received_at);
CREATE INDEX audit_org ON audit_events(organization_id,sequence);
CREATE FUNCTION sentinel_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'append-only record'; END $$;
CREATE TRIGGER evidence_immutable BEFORE UPDATE OR DELETE ON evidence FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
