\getenv password VV_EVIDENCE_AUDITOR_PASSWORD
CREATE ROLE vv_ci_evidence_auditor LOGIN NOINHERIT PASSWORD :'password';
GRANT verivaro_evidence_auditor TO vv_ci_evidence_auditor;
\unset password
