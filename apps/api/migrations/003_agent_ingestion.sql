CREATE TABLE endpoint_agents (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, asset_id uuid NOT NULL,
 name text NOT NULL, secret_cipher text NOT NULL, created_by uuid NOT NULL,
 expires_at timestamptz NOT NULL, revoked_at timestamptz, last_seen_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,id),
 FOREIGN KEY(organization_id,asset_id) REFERENCES assets(organization_id,id),
 FOREIGN KEY(created_by,organization_id) REFERENCES operator_organizations(operator_id,organization_id)
);
CREATE TABLE agent_nonces (
 agent_id uuid NOT NULL REFERENCES endpoint_agents(id), nonce uuid NOT NULL,
 received_at timestamptz NOT NULL, PRIMARY KEY(agent_id,nonce)
);
CREATE TABLE agent_observations (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, agent_id uuid NOT NULL,
 observation_id text NOT NULL, payload_hash text NOT NULL, payload jsonb NOT NULL,
 evidence_id uuid NOT NULL, result text NOT NULL CHECK(result IN ('unbaselined','unchanged','changed')),
 incident_id uuid REFERENCES incidents(id), received_at timestamptz NOT NULL,
 UNIQUE(agent_id,observation_id), UNIQUE(organization_id,id),
 FOREIGN KEY(organization_id,agent_id) REFERENCES endpoint_agents(organization_id,id),
 FOREIGN KEY(organization_id,evidence_id) REFERENCES evidence(organization_id,id)
);
CREATE TABLE integrity_baselines (
 agent_id uuid NOT NULL, organization_id uuid NOT NULL, path_id text NOT NULL,
 path_label text NOT NULL, sha256 text NOT NULL, observation_id uuid NOT NULL,
 approved_by uuid NOT NULL, approved_at timestamptz NOT NULL,
 PRIMARY KEY(agent_id,path_id),
 FOREIGN KEY(organization_id,agent_id) REFERENCES endpoint_agents(organization_id,id),
 FOREIGN KEY(organization_id,observation_id) REFERENCES agent_observations(organization_id,id),
 FOREIGN KEY(approved_by,organization_id) REFERENCES operator_organizations(operator_id,organization_id)
);
CREATE INDEX agent_observations_org ON agent_observations(organization_id,received_at);
CREATE TRIGGER agent_observations_immutable BEFORE UPDATE OR DELETE ON agent_observations FOR EACH ROW EXECUTE FUNCTION sentinel_immutable();
