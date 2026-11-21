-- Reference bootstrap requiring independent DBA approval. NEVER run automatically from CI.
-- First-generation 0001..0063 contains CREATE ROLE statements and is NOT
-- executable solely by this no-CREATEROLE migration executor.
-- No LOGIN is enabled; independent identity/credential issuance is mandatory.
BEGIN;
CREATE ROLE vv_production_schema_owner
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE vv_production_migration_executor
 NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- On PostgreSQL 16+, grant an explicit SET-only membership without inheritance.
GRANT vv_production_schema_owner TO vv_production_migration_executor
 WITH INHERIT FALSE, SET TRUE;
-- The owner must own only the separately scoped, approved application schema.
-- Future privileged CREATE ROLE/ALTER ROLE/extension work requires a distinct
-- reviewed bootstrap principal. No PUBLIC, app role or CI principal is granted
-- this membership. Do not enable LOGIN without an external identity review.
COMMIT;
