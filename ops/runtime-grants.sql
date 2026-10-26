-- Execute como identidade de migração no banco EXCLUSIVO do Sentinel, após migrar.
-- O administrador do PostgreSQL deve criar previamente o papel sentinel_runtime
-- com LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION e senha própria.
-- Não execute em bancos de terceiros ou com usuários de outros sistemas.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO sentinel_runtime;
GRANT SELECT ON schema_migrations TO sentinel_runtime;
GRANT SELECT ON private_operator TO sentinel_runtime;
GRANT SELECT ON users TO sentinel_runtime;
GRANT UPDATE(last_totp_counter) ON users TO sentinel_runtime;
GRANT SELECT, INSERT, DELETE ON sessions, login_attempts TO sentinel_runtime;
GRANT UPDATE(active_organization_id,csrf_token) ON sessions TO sentinel_runtime;
GRANT UPDATE(failures,window_start) ON login_attempts TO sentinel_runtime;
GRANT SELECT, INSERT ON organizations, operator_organizations, projects, assets TO sentinel_runtime;
GRANT UPDATE(id) ON organizations, assets TO sentinel_runtime;
GRANT SELECT, INSERT ON authorizations TO sentinel_runtime;
GRANT UPDATE(revoked_at) ON authorizations TO sentinel_runtime;
GRANT SELECT, INSERT ON jobs TO sentinel_runtime;
GRANT UPDATE(status,completed_at) ON jobs TO sentinel_runtime;
GRANT SELECT, INSERT ON scans, evidence, findings, security_events, incidents, audit_events, alerts TO sentinel_runtime;
GRANT UPDATE(status) ON alerts TO sentinel_runtime;
GRANT USAGE, SELECT ON SEQUENCE audit_events_sequence_seq TO sentinel_runtime;
GRANT SELECT, INSERT ON endpoint_agents, agent_observations, integrity_baselines TO sentinel_runtime;
GRANT UPDATE(last_seen_at,revoked_at) ON endpoint_agents TO sentinel_runtime;
GRANT UPDATE(sha256,path_label,observation_id,approved_by,approved_at) ON integrity_baselines TO sentinel_runtime;
GRANT SELECT, INSERT, DELETE ON agent_nonces TO sentinel_runtime;
GRANT SELECT, INSERT ON incident_notes, incident_evidence, remediation_revisions, remediation_plans TO sentinel_runtime;
GRANT UPDATE(status,current_revision,updated_at) ON remediation_plans TO sentinel_runtime;
GRANT UPDATE(status) ON incidents TO sentinel_runtime;
GRANT SELECT, INSERT ON artifact_analyses TO sentinel_runtime;
GRANT SELECT, INSERT ON lab_targets, lab_scans TO sentinel_runtime;
GRANT UPDATE(evidence_id,analysis_id,error_code) ON lab_scans TO sentinel_runtime;
GRANT SELECT, INSERT, DELETE ON lab_execution_lock TO sentinel_runtime;
GRANT UPDATE(slot) ON lab_execution_lock TO sentinel_runtime;
GRANT SELECT, INSERT ON forensic_runs TO sentinel_runtime;
GRANT UPDATE(report,error_code) ON forensic_runs TO sentinel_runtime;
GRANT SELECT, INSERT, DELETE ON forensic_execution_lock TO sentinel_runtime;
GRANT UPDATE(slot) ON forensic_execution_lock TO sentinel_runtime;
GRANT SELECT, INSERT ON import_runs TO sentinel_runtime;
GRANT UPDATE(report,error_code) ON import_runs TO sentinel_runtime;
GRANT SELECT, INSERT, DELETE ON import_execution_lock TO sentinel_runtime;
GRANT UPDATE(slot) ON import_execution_lock TO sentinel_runtime;
