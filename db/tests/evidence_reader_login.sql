\getenv password VV_EVIDENCE_READER_PASSWORD
CREATE ROLE vv_ci_evidence_reader LOGIN NOINHERIT PASSWORD :'password';
GRANT verivaro_evidence_reader TO vv_ci_evidence_reader;
\unset password
