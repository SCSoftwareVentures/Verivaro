-- Fresh PostgreSQL 16 migration. Run as privileged migration operator, never runtime.
BEGIN;
CREATE ROLE verivaro_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE verivaro_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE SCHEMA vv_private AUTHORIZATION verivaro_owner;
CREATE SCHEMA vv_app AUTHORIZATION verivaro_owner;
CREATE SCHEMA vv_crypto;
REVOKE ALL ON SCHEMA vv_private,vv_app,vv_crypto FROM PUBLIC;
CREATE EXTENSION pgcrypto WITH SCHEMA vv_crypto;
GRANT USAGE ON SCHEMA vv_crypto TO verivaro_owner;
SET LOCAL ROLE verivaro_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE vv_private.tenant (
 id uuid PRIMARY KEY, name text NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 200),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE vv_private.identity (
 id uuid PRIMARY KEY, issuer text NOT NULL CHECK(length(issuer)>0),
 subject text NOT NULL CHECK(length(subject)>0), UNIQUE(issuer,subject)
);
CREATE TABLE vv_private.membership (
 tenant_id uuid NOT NULL REFERENCES vv_private.tenant(id), actor_id uuid NOT NULL REFERENCES vv_private.identity(id),
 active boolean NOT NULL DEFAULT false, version integer NOT NULL DEFAULT 1 CHECK(version>0),
 tenant_role text NOT NULL CHECK(tenant_role IN ('owner','admin','member')),
 PRIMARY KEY(tenant_id,actor_id)
);
CREATE TABLE vv_app.project (
 tenant_id uuid NOT NULL REFERENCES vv_private.tenant(id), id uuid NOT NULL,
 name text NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 200),
 timezone text NOT NULL, created_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,created_by) REFERENCES vv_private.membership(tenant_id,actor_id)
);
CREATE TABLE vv_private.project_member (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, actor_id uuid NOT NULL,
 role text NOT NULL CHECK(role IN ('owner','manager','reviewer','contributor','viewer')),
 active boolean NOT NULL DEFAULT false, version integer NOT NULL DEFAULT 1 CHECK(version>0),
 PRIMARY KEY(tenant_id,project_id,actor_id),
 FOREIGN KEY(tenant_id,project_id) REFERENCES vv_app.project(tenant_id,id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES vv_private.membership(tenant_id,actor_id)
);
-- Provision random independent key through an authorised management path, not migration.
CREATE TABLE vv_private.context_key (
 id uuid PRIMARY KEY, secret bytea NOT NULL CHECK(octet_length(secret)>=32), active boolean NOT NULL DEFAULT false
);
CREATE TABLE vv_app.document (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, id uuid NOT NULL,
 title text NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 250),
 created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id) REFERENCES vv_app.project(tenant_id,id),
 FOREIGN KEY(tenant_id,project_id,created_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
CREATE TABLE vv_app.document_version (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, id uuid NOT NULL, document_id uuid NOT NULL,
 revision integer NOT NULL CHECK(revision>0), content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[0-9a-f]{64}$'),
 extracted_text text, scan_state text NOT NULL CHECK(scan_state IN ('quarantined','clean','rejected')),
 reviewed_by uuid, supersedes_id uuid, created_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),
 UNIQUE(tenant_id,project_id,document_id,revision),
 UNIQUE(tenant_id,project_id,document_id,id),
 FOREIGN KEY(tenant_id,project_id,document_id) REFERENCES vv_app.document(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,document_id,supersedes_id) REFERENCES vv_app.document_version(tenant_id,project_id,document_id,id),
 FOREIGN KEY(tenant_id,project_id,created_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 FOREIGN KEY(tenant_id,project_id,reviewed_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK((revision=1 AND supersedes_id IS NULL) OR (revision>1 AND supersedes_id IS NOT NULL)),
 CHECK(supersedes_id IS DISTINCT FROM id),
 CHECK(scan_state='clean' OR (extracted_text IS NULL AND reviewed_by IS NULL)),
 CHECK(reviewed_by IS NULL OR extracted_text IS NOT NULL)
);
CREATE TABLE vv_app.source_span (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, id uuid NOT NULL, document_version_id uuid NOT NULL,
 start_cp integer NOT NULL CHECK(start_cp>=0), end_cp integer NOT NULL CHECK(end_cp>start_cp),
 quote text NOT NULL CHECK(length(quote)>0),
 created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,document_version_id) REFERENCES vv_app.document_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,created_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK(length(quote)=end_cp-start_cp)
);
-- DB offsets are Unicode code points; domain UTF-16 offsets must be translated and tested at the API.
CREATE TABLE vv_app.requirement (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, id uuid NOT NULL,
 created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id) REFERENCES vv_app.project(tenant_id,id),
 FOREIGN KEY(tenant_id,project_id,created_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
CREATE TABLE vv_app.requirement_version (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, id uuid NOT NULL, requirement_id uuid NOT NULL,
 revision integer NOT NULL CHECK(revision>0), source_span_id uuid NOT NULL,
 mandatory boolean NOT NULL, applicability text NOT NULL CHECK(applicability IN ('unknown','applicable','not-applicable')),
 criterion_kind text NOT NULL CHECK(length(trim(criterion_kind))>0), expected text NOT NULL CHECK(length(trim(expected))>0),
 approved_by uuid, supersedes_id uuid, created_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id), UNIQUE(tenant_id,project_id,requirement_id,revision),
 UNIQUE(tenant_id,project_id,requirement_id,id),
 FOREIGN KEY(tenant_id,project_id,requirement_id) REFERENCES vv_app.requirement(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,source_span_id) REFERENCES vv_app.source_span(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,requirement_id,supersedes_id) REFERENCES vv_app.requirement_version(tenant_id,project_id,requirement_id,id),
 FOREIGN KEY(tenant_id,project_id,created_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 FOREIGN KEY(tenant_id,project_id,approved_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK((revision=1 AND supersedes_id IS NULL) OR (revision>1 AND supersedes_id IS NOT NULL)),
 CHECK(supersedes_id IS DISTINCT FROM id),
 CHECK(approved_by IS NULL OR applicability<>'unknown')
);
CREATE TABLE vv_app.evidence_link (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, id uuid NOT NULL,
 requirement_version_id uuid NOT NULL, source_span_id uuid NOT NULL,
 kind text NOT NULL CHECK(length(trim(kind))>0), asserted_value text NOT NULL CHECK(length(trim(asserted_value))>0),
 review_state text NOT NULL CHECK(review_state IN ('pending','approved','rejected')), reviewed_by uuid,
 created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,requirement_version_id) REFERENCES vv_app.requirement_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,source_span_id) REFERENCES vv_app.source_span(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,created_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 FOREIGN KEY(tenant_id,project_id,reviewed_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK((review_state='pending')=(reviewed_by IS NULL))
);
CREATE INDEX evidence_req ON vv_app.evidence_link(tenant_id,project_id,requirement_version_id);
CREATE INDEX evidence_span ON vv_app.evidence_link(tenant_id,project_id,source_span_id);
CREATE INDEX requirement_span ON vv_app.requirement_version(tenant_id,project_id,source_span_id);
CREATE INDEX span_document ON vv_app.source_span(tenant_id,project_id,document_version_id);
-- Force RLS on every business/identity table. Owner-only administrative policy for controlled migrations.
DO $$
DECLARE t regclass;
BEGIN
 FOR t IN SELECT c.oid::regclass FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN ('vv_private','vv_app') AND c.relkind='r'
 LOOP
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY owner_only ON %s TO verivaro_owner USING (true) WITH CHECK (true)',t);
 END LOOP;
END $$;
-- Verify exact raw payload bytes with a private HMAC key; bind short-lived claims to transaction.
-- Gateway signer is not implemented. Runtime must have no access to signing keys.
CREATE FUNCTION vv_private.allowed_project(want_tenant uuid,want_project uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,vv_private,vv_crypto AS $$
DECLARE raw text; sig text; j jsonb; k bytea; actor uuid; expiry bigint; now_s bigint; mv integer; pv integer;
BEGIN
 raw:=current_setting('verivaro.context',true); sig:=current_setting('verivaro.signature',true);
 IF raw IS NULL OR length(raw)>2048 OR sig IS NULL OR sig !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
 j:=raw::jsonb;
 IF jsonb_typeof(j)<>'object' OR j->>'tx' IS DISTINCT FROM pg_current_xact_id_if_assigned()::text
 OR pg_current_xact_id_if_assigned() IS NULL OR j->>'tenant' IS DISTINCT FROM want_tenant::text
 OR j->>'project' IS DISTINCT FROM want_project::text THEN RETURN false; END IF;
 SELECT secret INTO k FROM vv_private.context_key WHERE id=(j->>'key')::uuid AND active;
 IF k IS NULL OR vv_crypto.hmac(convert_to(raw,'UTF8'),k,'sha256') IS DISTINCT FROM decode(sig,'hex') THEN RETURN false; END IF;
 expiry:=(j->>'exp')::bigint; now_s:=extract(epoch FROM statement_timestamp())::bigint;
 IF expiry IS NULL OR expiry<=now_s OR expiry>now_s+120 THEN RETURN false; END IF;
 actor:=(j->>'actor')::uuid; mv:=(j->>'member_version')::integer; pv:=(j->>'project_version')::integer;
 RETURN EXISTS(SELECT 1 FROM vv_private.membership m JOIN vv_private.project_member p
 ON p.tenant_id=m.tenant_id AND p.actor_id=m.actor_id
 WHERE m.tenant_id=want_tenant AND p.project_id=want_project AND m.actor_id=actor
 AND m.active AND p.active AND m.version=mv AND p.version=pv);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_parameter_value THEN
 RETURN false;
END $$;
REVOKE ALL ON FUNCTION vv_private.allowed_project(uuid,uuid) FROM PUBLIC;
GRANT USAGE ON SCHEMA vv_private,vv_app TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION vv_private.allowed_project(uuid,uuid) TO verivaro_runtime;
-- Deliberately no writes, no raw identity/membership/key reads, and no extracted text access.
-- Evidence and document payload access will be mediated by an authenticated API with narrower roles.
CREATE POLICY scoped_read ON vv_app.project FOR SELECT TO verivaro_runtime USING(vv_private.allowed_project(tenant_id,id));
GRANT SELECT ON vv_app.project TO verivaro_runtime;
RESET ROLE;
COMMIT;
