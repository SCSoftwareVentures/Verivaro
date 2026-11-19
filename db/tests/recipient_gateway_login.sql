\getenv recipient_password VV_RECIPIENT_PASSWORD
ALTER ROLE verivaro_recipient_gateway LOGIN PASSWORD :'recipient_password';
\unset recipient_password
