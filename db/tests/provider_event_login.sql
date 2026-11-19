\getenv event_password VV_IDENTITY_EVENTS_PASSWORD
CREATE ROLE vv_ci_identity_events LOGIN NOINHERIT PASSWORD :'event_password';
GRANT verivaro_identity_events TO vv_ci_identity_events;
\unset event_password
