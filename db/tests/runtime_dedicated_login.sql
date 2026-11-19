\getenv runtime_password VV_RUNTIME_PASSWORD
ALTER ROLE verivaro_runtime NOLOGIN PASSWORD NULL;
CREATE ROLE vv_ci_runtime LOGIN NOINHERIT PASSWORD :'runtime_password';
GRANT verivaro_runtime TO vv_ci_runtime;
\unset runtime_password
