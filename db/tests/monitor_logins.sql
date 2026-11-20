\getenv worker_password VV_MONITOR_WORKER_PASSWORD
\getenv reader_password VV_MONITOR_READER_PASSWORD
CREATE ROLE vv_ci_monitor_worker LOGIN NOINHERIT PASSWORD :'worker_password';
GRANT verivaro_monitor_worker TO vv_ci_monitor_worker;
CREATE ROLE vv_ci_monitor_reader LOGIN NOINHERIT PASSWORD :'reader_password';
GRANT verivaro_monitor_reader TO vv_ci_monitor_reader;
\unset worker_password
\unset reader_password
