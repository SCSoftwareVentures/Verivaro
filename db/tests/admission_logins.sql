\getenv admission_a VV_ADMISSION_PASSWORD
\getenv admission_b VV_ADMISSION_B_PASSWORD
CREATE ROLE vv_ci_admission_a LOGIN NOINHERIT PASSWORD :'admission_a';
CREATE ROLE vv_ci_admission_b LOGIN NOINHERIT PASSWORD :'admission_b';
GRANT verivaro_admission_service TO vv_ci_admission_a,vv_ci_admission_b;
\unset admission_a
\unset admission_b
