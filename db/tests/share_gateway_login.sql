\getenv gateway_password VV_SHARE_PASSWORD
ALTER ROLE verivaro_share_gateway LOGIN PASSWORD :'gateway_password';
\unset gateway_password
