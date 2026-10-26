-- Modelo manual para um administrador PostgreSQL, somente em instância autorizada.
-- Não executado automaticamente. Falha se papéis/banco já existirem; não os altera.
-- Execute com: psql -h 127.0.0.1 -U postgres -d postgres -f ops/provision-postgres.sql
\set ON_ERROR_STOP on
CREATE ROLE sentinel_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
\password sentinel_migrator
CREATE ROLE sentinel_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
\password sentinel_runtime
CREATE DATABASE sentinel OWNER sentinel_migrator;
REVOKE ALL ON DATABASE sentinel FROM PUBLIC;
GRANT CONNECT ON DATABASE sentinel TO sentinel_migrator, sentinel_runtime;
\connect sentinel
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO sentinel_migrator;
GRANT USAGE ON SCHEMA public TO sentinel_runtime;
-- Depois: bootstrap com sentinel_migrator, runtime-grants.sql com migrator,
-- e inicialização do servidor com sentinel_runtime. Guarde as senhas fora do repo.
