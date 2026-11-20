\getenv password VV_TENANT_OPERATOR_PASSWORD
CREATE ROLE vv_ci_tenant_operator LOGIN NOINHERIT PASSWORD :'password';
GRANT verivaro_tenant_operator TO vv_ci_tenant_operator;
\unset password
