\set ON_ERROR_STOP on
-- Ephemeral CI database ONLY. Never execute in production or use these fixture credentials.
CREATE ROLE vv_test_runtime LOGIN PASSWORD 'vv-ci-runtime-only' NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;
CREATE ROLE vv_test_signer LOGIN PASSWORD 'vv-ci-signer-only' NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;
CREATE ROLE vv_test_worker LOGIN PASSWORD 'vv-ci-worker-only' NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;
GRANT verivaro_runtime TO vv_test_runtime;
GRANT verivaro_signer TO vv_test_signer;
GRANT verivaro_ingest_worker TO vv_test_worker;
UPDATE vv_private.identity SET issuer='https://issuer.invalid' WHERE issuer='synthetic';

CREATE ROLE vv_test_parser LOGIN PASSWORD 'vv-ci-parser-only' NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;
GRANT verivaro_parse_worker TO vv_test_parser;

CREATE ROLE vv_test_capability LOGIN PASSWORD 'vv-ci-capability-only' NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;
GRANT verivaro_capability TO vv_test_capability;

CREATE ROLE vv_test_portability LOGIN PASSWORD 'vv-ci-portability-only' NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;
GRANT verivaro_portability_operator TO vv_test_portability;
