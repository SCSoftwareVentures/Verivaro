BEGIN;
CREATE TABLE verivaro_private.customer_package_grants(
 grant_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,
 submission_id uuid NOT NULL REFERENCES verivaro_private.submission_snapshots(submission_id),sha256 text NOT NULL CHECK(sha256~'^[0-9a-f]{64}$'),
 owner_id uuid NOT NULL,recipient_id uuid NOT NULL,recipient_generation uuid[] NOT NULL CHECK(cardinality(recipient_generation)=2),
 session_id uuid NOT NULL,graph_stamp text NOT NULL CHECK(graph_stamp~'^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),CHECK(expires_at>created_at));
CREATE TABLE verivaro_private.customer_package_revocations(grant_id uuid PRIMARY KEY REFERENCES verivaro_private.customer_package_grants(grant_id),actor_id uuid NOT NULL,session_id uuid NOT NULL,revoked_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE verivaro_private.customer_package_reads(read_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),grant_id uuid NOT NULL REFERENCES verivaro_private.customer_package_grants(grant_id),actor_id uuid NOT NULL,session_id uuid NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON verivaro_private.customer_package_grants,verivaro_private.customer_package_revocations,verivaro_private.customer_package_reads FROM PUBLIC;
DO $immutable$
DECLARE n text;
BEGIN
 FOREACH n IN ARRAY ARRAY['customer_package_grants','customer_package_revocations','customer_package_reads'] LOOP
 EXECUTE format('CREATE TRIGGER immutable_record BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.%I FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable()',n);
 END LOOP;
END $immutable$;
CREATE TRIGGER customer_package_archive_guard BEFORE INSERT ON verivaro_private.customer_package_grants FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
-- Tenant-only viewer: no current active project membership. Never upgrades a
-- user to a general project viewer in order to share a single package.
CREATE FUNCTION verivaro_private.customer_generation(t uuid,p uuid,a uuid) RETURNS uuid[]
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $generation$
DECLARE tg uuid;ag uuid;
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 SELECT m.share_generation INTO tg FROM verivaro.memberships m WHERE m.tenant_id=t AND m.actor_id=a AND m.role='viewer' AND m.revoked_at IS NULL FOR SHARE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a) OR EXISTS(SELECT 1 FROM verivaro.project_members m WHERE m.tenant_id=t AND m.project_id=p AND m.actor_id=a AND m.revoked_at IS NULL AND (m.expires_at IS NULL OR m.expires_at>clock_timestamp())) THEN RETURN NULL;END IF;
 SELECT generation INTO ag FROM verivaro_private.actor_share_generations WHERE actor_id=a;
 RETURN ARRAY[tg,COALESCE(ag,'00000000-0000-0000-0000-000000000000'::uuid)];
END $generation$;
-- The owner validates the full current canonical manifest at grant creation.
-- This conservative fingerprint detects subsequent changes in all source
-- graph records, without giving the recipient project-wide assessment access.
CREATE FUNCTION verivaro_private.customer_graph_stamp(t uuid,p uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private SET TimeZone='UTC' AS $stamp$
 SELECT encode(verivaro_private.digest(convert_to(jsonb_build_array(
 (SELECT jsonb_build_array(q.revision,q.name,q.archived_at) FROM verivaro.projects q WHERE q.tenant_id=t AND q.id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.version_id),'[]'::jsonb) FROM verivaro_private.requirement_versions x WHERE x.tenant_id=t AND x.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.version_id),'[]'::jsonb) FROM verivaro_private.requirement_reviews x JOIN verivaro_private.requirement_versions q USING(version_id) WHERE q.tenant_id=t AND q.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.link_id),'[]'::jsonb) FROM verivaro_private.requirement_evidence_links x JOIN verivaro_private.requirement_versions v USING(version_id) WHERE v.tenant_id=t AND v.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.link_id),'[]'::jsonb) FROM verivaro_private.requirement_link_reviews x JOIN verivaro_private.requirement_evidence_links q USING(link_id) JOIN verivaro_private.requirement_versions v USING(version_id) WHERE v.tenant_id=t AND v.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.version_id),'[]'::jsonb) FROM verivaro_private.requirement_sources x WHERE x.tenant_id=t AND x.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.edge_id),'[]'::jsonb) FROM verivaro_private.requirement_dependencies x WHERE x.tenant_id=t AND x.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.edge_id),'[]'::jsonb) FROM verivaro_private.requirement_dependency_reviews x JOIN verivaro_private.requirement_dependencies q USING(edge_id) WHERE q.tenant_id=t AND q.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.removal_id),'[]'::jsonb) FROM verivaro_private.requirement_dependency_removals x WHERE x.tenant_id=t AND x.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.removal_id),'[]'::jsonb) FROM verivaro_private.requirement_dependency_removal_reviews x JOIN verivaro_private.requirement_dependency_removals q USING(removal_id) WHERE q.tenant_id=t AND q.project_id=p)
 )::text,'UTF8'),'sha256'),'hex')
$stamp$;
CREATE FUNCTION verivaro_verification.grant_customer_package(t uuid,p uuid,r uuid,s uuid,h text,a uuid,minutes integer) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $grant$
DECLARE c text[];checked jsonb;g uuid[];prior verivaro_private.customer_package_grants%ROWTYPE;now_at timestamptz;until_at timestamptz;stamp text;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'owner');
 IF r IS NULL OR s IS NULL OR a IS NULL OR a=c[2]::uuid OR h IS NULL OR minutes IS NULL OR minutes NOT BETWEEN 1 AND 60 THEN RAISE EXCEPTION 'package share denied' USING ERRCODE='42501';END IF;
 checked:=verivaro_verification.read_submission(t,p,s,h);
 g:=verivaro_private.customer_generation(t,p,a);IF g IS NULL THEN RAISE EXCEPTION 'package share denied' USING ERRCODE='42501';END IF;
 stamp:=verivaro_private.customer_graph_stamp(t,p);
 SELECT * INTO prior FROM verivaro_private.customer_package_grants x WHERE x.grant_id=r;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.submission_id<>s OR prior.sha256<>h OR prior.owner_id<>c[2]::uuid OR prior.recipient_id<>a OR prior.recipient_generation<>g OR prior.graph_stamp<>stamp OR prior.expires_at<>LEAST(prior.created_at+make_interval(mins=>minutes),(checked->>'authorizedAt')::timestamptz+interval '1 hour') THEN RAISE EXCEPTION 'package share conflict' USING ERRCODE='23505';END IF;RETURN r;END IF;
 now_at:=clock_timestamp();until_at:=LEAST(now_at+make_interval(mins=>minutes),(checked->>'authorizedAt')::timestamptz+interval '1 hour');
 IF until_at<=now_at THEN RAISE EXCEPTION 'package share expired' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(740129816168::bigint);
 IF (SELECT count(*) FROM verivaro_private.customer_package_grants)>=32768 OR (SELECT count(*) FROM verivaro_private.customer_package_grants x WHERE x.tenant_id=t AND x.project_id=p)>=128 THEN RAISE EXCEPTION 'package share capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.customer_package_grants(grant_id,tenant_id,project_id,submission_id,sha256,owner_id,recipient_id,recipient_generation,session_id,graph_stamp,created_at,expires_at)
 VALUES(r,t,p,s,h,c[2]::uuid,a,g,c[3]::uuid,stamp,now_at,until_at);RETURN r;
END $grant$;
CREATE FUNCTION verivaro_verification.revoke_customer_package(t uuid,p uuid,r uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $revoke$
DECLARE c text[];
BEGIN
 c:=verivaro_private.graph_actor(t,p,'owner');
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.customer_package_grants x WHERE x.tenant_id=t AND x.project_id=p AND x.grant_id=r) THEN RAISE EXCEPTION 'package share denied' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro_private.customer_package_revocations(grant_id,actor_id,session_id) VALUES(r,c[2]::uuid,c[3]::uuid) ON CONFLICT DO NOTHING;RETURN true;
END $revoke$;
CREATE FUNCTION verivaro_private.customer_package_receipt(t uuid,p uuid,r uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $receipt$
DECLARE c text[];g verivaro_private.customer_package_grants%ROWTYPE;q verivaro_private.submission_snapshots%ROWTYPE;v verivaro_private.submission_reviews%ROWTYPE;z verivaro_private.submission_authorizations%ROWTYPE;
BEGIN
 c:=verivaro.bound_context();
 IF current_setting('transaction_isolation')<>'read committed' OR c IS NULL OR c[1]<>t::text OR NOT verivaro.active_identity() THEN RAISE EXCEPTION 'package share denied' USING ERRCODE='42501';END IF;
 SELECT * INTO g FROM verivaro_private.customer_package_grants x WHERE x.tenant_id=t AND x.project_id=p AND x.grant_id=r AND x.recipient_id=c[2]::uuid;
 IF NOT FOUND OR g.expires_at<=clock_timestamp() OR g.recipient_generation IS DISTINCT FROM verivaro_private.customer_generation(t,p,c[2]::uuid) THEN RAISE EXCEPTION 'package share denied' USING ERRCODE='42501';END IF;
 PERFORM 1 FROM verivaro.projects x WHERE x.tenant_id=t AND x.id=p AND x.archived_at IS NULL FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM verivaro_private.customer_package_revocations x WHERE x.grant_id=r) OR NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions i WHERE i.actor_id=c[2]::uuid AND i.session_id=c[3]::uuid AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp()) THEN RAISE EXCEPTION 'package share denied' USING ERRCODE='42501';END IF;
 SELECT * INTO q FROM verivaro_private.submission_snapshots WHERE submission_id=g.submission_id AND tenant_id=t AND project_id=p;
 SELECT * INTO v FROM verivaro_private.submission_reviews WHERE submission_id=g.submission_id;
 SELECT * INTO z FROM verivaro_private.submission_authorizations WHERE submission_id=g.submission_id;
 IF q.submission_id IS NULL OR v.submission_id IS NULL OR z.submission_id IS NULL OR z.owner_id<>g.owner_id OR v.decision<>'approved' OR q.sha256<>g.sha256 OR encode(verivaro_private.digest(convert_to(q.manifest,'UTF8'),'sha256'),'hex')<>g.sha256
 OR q.created_at<clock_timestamp()-interval '7 days' OR v.reviewed_at<clock_timestamp()-interval '24 hours' OR z.authorized_at<clock_timestamp()-interval '1 hour'
 OR z.owner_generation IS DISTINCT FROM verivaro_private.release_generation(t,p,z.owner_id,'owner') OR v.reviewer_generation IS DISTINCT FROM verivaro_private.release_generation(t,p,v.reviewer_id,'reviewer') OR q.preparer_generation IS DISTINCT FROM verivaro_private.release_generation(t,p,q.preparer_id,'submitter')
 OR g.graph_stamp IS DISTINCT FROM verivaro_private.customer_graph_stamp(t,p) THEN RAISE EXCEPTION 'package share stale' USING ERRCODE='42501';END IF;
 -- Recheck object metadata and stored ciphertext without exposing any other inventory.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(q.manifest::jsonb->'evidence') e LEFT JOIN verivaro_private.evidence_objects o ON o.evidence_id=(e->>'id')::uuid AND o.tenant_id=t AND o.project_id=p WHERE o.evidence_id IS NULL OR o.sha256<>e->>'sha256' OR o.bytes<>(e->>'bytes')::integer OR o.media_type<>e->>'mediaType' OR o.cipher_digest<>verivaro_private.digest(o.envelope,'sha256')) THEN RAISE EXCEPTION 'package share integrity denied' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('submissionId',q.submission_id,'sha256',q.sha256,'manifest',q.manifest,'preparedAt',q.created_at,'reviewedAt',v.reviewed_at,'authorizedAt',z.authorized_at,'reviewReason',v.reason,'authorization','authenticated scoped recipient download only','grantId',r,'expiresAt',g.expires_at);
END $receipt$;
CREATE FUNCTION verivaro_verification.preview_customer_package(t uuid,p uuid,r uuid) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $preview$
DECLARE q jsonb;
BEGIN
 q:=verivaro_private.customer_package_receipt(t,p,r);
 RETURN (q-'manifest'-'reviewReason')||jsonb_build_object('evidenceCount',(SELECT count(*) FROM jsonb_array_elements((q->>'manifest')::jsonb->'evidence')),'projectName',(q->>'manifest')::jsonb->>'projectName');
END $preview$;
CREATE FUNCTION verivaro_verification.read_customer_package(t uuid,p uuid,r uuid,s uuid,h text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $read$
DECLARE q jsonb;c text[];
BEGIN
 q:=verivaro_private.customer_package_receipt(t,p,r);c:=verivaro.bound_context();
 IF q->>'submissionId' IS DISTINCT FROM s::text OR q->>'sha256' IS DISTINCT FROM h THEN RAISE EXCEPTION 'package share denied' USING ERRCODE='42501';END IF;
 IF (SELECT count(*) FROM verivaro_private.customer_package_reads x WHERE x.grant_id=r)>=128 THEN RAISE EXCEPTION 'package share read limit' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.customer_package_reads(grant_id,actor_id,session_id) VALUES(r,c[2]::uuid,c[3]::uuid);
 RETURN q;
END $read$;
CREATE FUNCTION verivaro_ingestion.fetch_customer_package_object(t uuid,p uuid,r uuid,e uuid)
RETURNS TABLE(id uuid,sha256 text,bytes integer,key_id text,media_type text,envelope bytea,cipher_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $fetch$
DECLARE q jsonb;c text[];obj verivaro_private.evidence_objects%ROWTYPE;
BEGIN
 q:=verivaro_private.customer_package_receipt(t,p,r);c:=verivaro.bound_context();
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements((q->>'manifest')::jsonb->'evidence') x WHERE x->>'id'=e::text) THEN RAISE EXCEPTION 'package object denied' USING ERRCODE='42501';END IF;
 SELECT o.* INTO obj FROM verivaro_private.evidence_objects o JOIN verivaro.evidence v ON v.id=o.evidence_id AND v.tenant_id=o.tenant_id AND v.project_id=o.project_id AND v.sha256=o.sha256 WHERE o.evidence_id=e AND o.tenant_id=t AND o.project_id=p AND v.storage_ref='db-encrypted-v1';
 IF NOT FOUND THEN RAISE EXCEPTION 'package object denied' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro_private.evidence_access_events(evidence_id,tenant_id,project_id,actor_id,session_id) VALUES(e,t,p,c[2]::uuid,c[3]::uuid);
 RETURN QUERY SELECT obj.evidence_id,obj.sha256,obj.bytes,obj.key_id,obj.media_type,obj.envelope,encode(obj.cipher_digest,'hex');
END $fetch$;
CREATE FUNCTION verivaro_verification.customer_package_list(t uuid,p uuid) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $list$
DECLARE c text[];
BEGIN
 c:=verivaro_private.graph_actor(t,p,'owner');
 RETURN COALESCE((SELECT jsonb_agg(jsonb_build_object('grantId',x.grant_id,'submissionId',x.submission_id,'sha256',x.sha256,'recipientId',x.recipient_id,'expiresAt',x.expires_at,'revoked',z.grant_id IS NOT NULL,'expired',x.expires_at<=clock_timestamp()) ORDER BY x.created_at,x.grant_id) FROM verivaro_private.customer_package_grants x LEFT JOIN verivaro_private.customer_package_revocations z USING(grant_id) WHERE x.tenant_id=t AND x.project_id=p),'[]'::jsonb);
END $list$;
REVOKE ALL ON FUNCTION verivaro_private.customer_generation(uuid,uuid,uuid),verivaro_private.customer_graph_stamp(uuid,uuid),verivaro_private.customer_package_receipt(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION verivaro_verification.grant_customer_package(uuid,uuid,uuid,uuid,text,uuid,integer),verivaro_verification.revoke_customer_package(uuid,uuid,uuid),verivaro_verification.preview_customer_package(uuid,uuid,uuid),verivaro_verification.read_customer_package(uuid,uuid,uuid,uuid,text),verivaro_verification.customer_package_list(uuid,uuid),verivaro_ingestion.fetch_customer_package_object(uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.grant_customer_package(uuid,uuid,uuid,uuid,text,uuid,integer),verivaro_verification.revoke_customer_package(uuid,uuid,uuid),verivaro_verification.preview_customer_package(uuid,uuid,uuid),verivaro_verification.read_customer_package(uuid,uuid,uuid,uuid,text),verivaro_verification.customer_package_list(uuid,uuid) TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION verivaro_ingestion.fetch_customer_package_object(uuid,uuid,uuid,uuid) TO verivaro_evidence_reader;
COMMIT;
