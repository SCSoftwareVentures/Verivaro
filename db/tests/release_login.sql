\getenv password VV_RELEASE_PASSWORD
CREATE ROLE vv_ci_release LOGIN NOINHERIT PASSWORD :'password';
GRANT verivaro_release_service TO vv_ci_release;
\unset password
