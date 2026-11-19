\getenv a VV_API_A_PASSWORD
\getenv b VV_API_B_PASSWORD
CREATE ROLE vv_ci_api_a LOGIN NOINHERIT PASSWORD :'a';
CREATE ROLE vv_ci_api_b LOGIN NOINHERIT PASSWORD :'b';
GRANT verivaro_api_admission TO vv_ci_api_a,vv_ci_api_b;
\unset a
\unset b
