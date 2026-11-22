#!/bin/sh
# Creates the database and its two roles. Runs once, when the Postgres data volume is empty.
#   crm_owner: owns the schema, used only by Flyway migrations.
#   crm_app:   used by the running app; cannot bypass Row-Level Security or change the schema.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$CRM_DB_OWNER_PASSWORD" -v app_pw="$CRM_DB_APP_PASSWORD" <<'EOSQL'
CREATE ROLE crm_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE crm_app   LOGIN PASSWORD :'app_pw'   NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE crm OWNER crm_owner;
REVOKE CONNECT ON DATABASE crm FROM PUBLIC;
GRANT CONNECT ON DATABASE crm TO crm_owner, crm_app;
\connect crm
ALTER SCHEMA public OWNER TO crm_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
EOSQL
