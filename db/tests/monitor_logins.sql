\getenv worker_password VV_MONITOR_WORKER_PASSWORD
\getenv reader_password VV_MONITOR_READER_PASSWORD
ALTER ROLE verivaro_monitor_worker LOGIN PASSWORD :'worker_password';
ALTER ROLE verivaro_monitor_reader LOGIN PASSWORD :'reader_password';
\unset worker_password
\unset reader_password
