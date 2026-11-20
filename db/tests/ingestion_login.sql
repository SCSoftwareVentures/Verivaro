\getenv password VV_INGEST_PASSWORD
CREATE ROLE vv_ci_ingest LOGIN NOINHERIT PASSWORD :'password';
GRANT verivaro_evidence_ingestor TO vv_ci_ingest;
\unset password
