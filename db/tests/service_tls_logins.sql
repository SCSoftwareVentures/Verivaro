\getenv old_password VV_TLS_OLD_PASSWORD
\getenv new_password VV_TLS_NEW_PASSWORD
SET password_encryption='scram-sha-256';
CREATE ROLE vv_ci_tls_old LOGIN NOINHERIT PASSWORD :'old_password';
CREATE ROLE vv_ci_tls_new LOGIN NOINHERIT PASSWORD :'new_password';
GRANT verivaro_monitor_reader TO vv_ci_tls_old,vv_ci_tls_new;
\unset old_password
\unset new_password
