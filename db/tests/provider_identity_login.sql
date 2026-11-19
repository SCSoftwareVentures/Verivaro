\getenv identity_password VV_IDENTITY_PASSWORD
CREATE ROLE vv_ci_identity LOGIN NOINHERIT PASSWORD :'identity_password';
GRANT verivaro_identity_service TO vv_ci_identity;
\unset identity_password
