\getenv recipient_password VV_RECIPIENT_PASSWORD
CREATE ROLE vv_ci_recipient LOGIN NOINHERIT PASSWORD :'recipient_password';
GRANT verivaro_recipient_gateway TO vv_ci_recipient;
\unset recipient_password
