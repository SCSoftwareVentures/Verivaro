\getenv gateway_password VV_SHARE_PASSWORD
CREATE ROLE vv_ci_share LOGIN NOINHERIT PASSWORD :'gateway_password';
GRANT verivaro_share_gateway TO vv_ci_share;
\unset gateway_password
