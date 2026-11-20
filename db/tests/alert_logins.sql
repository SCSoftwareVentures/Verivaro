\getenv alert_a VV_ALERT_A_PASSWORD
\getenv alert_b VV_ALERT_B_PASSWORD
CREATE ROLE vv_ci_alert_a LOGIN NOINHERIT PASSWORD :'alert_a';
CREATE ROLE vv_ci_alert_b LOGIN NOINHERIT PASSWORD :'alert_b';
GRANT verivaro_alert_sender TO vv_ci_alert_a,vv_ci_alert_b;
\unset alert_a
\unset alert_b
