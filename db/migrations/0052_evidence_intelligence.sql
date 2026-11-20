BEGIN;
CREATE TABLE verivaro_private.evidence_metadata_versions(
 version_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,evidence_id uuid NOT NULL REFERENCES verivaro_private.evidence_objects(evidence_id),
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 16),sha256 text NOT NULL CHECK(sha256~'^[a-f0-9]{64}$'),
 kind text NOT NULL CHECK(kind IN ('certificate','warranty','inspection','manual','photo','other')),
 identifier text NOT NULL CHECK(char_length(identifier) BETWEEN 1 AND 128 AND octet_length(identifier)<=512),
 equipment text NOT NULL CHECK(char_length(equipment) BETWEEN 1 AND 128 AND octet_length(equipment)<=512),
 issuer text NOT NULL CHECK(char_length(issuer) BETWEEN 1 AND 128 AND octet_length(issuer)<=512),
 issued_on date,expires_on date,reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 actor_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(evidence_id,revision),FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),
 CHECK(expires_on IS NULL OR issued_on IS NULL OR expires_on>=issued_on));
CREATE TABLE verivaro_private.evidence_metadata_reviews(
 version_id uuid PRIMARY KEY REFERENCES verivaro_private.evidence_metadata_versions(version_id),
 reviewer_id uuid NOT NULL,session_id uuid NOT NULL,decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON verivaro_private.evidence_metadata_versions,verivaro_private.evidence_metadata_reviews FROM PUBLIC;
CREATE TRIGGER evidence_metadata_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.evidence_metadata_versions FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER evidence_metadata_reviews_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.evidence_metadata_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER evidence_metadata_archive_guard BEFORE INSERT ON verivaro_private.evidence_metadata_versions FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE INDEX evidence_metadata_scope ON verivaro_private.evidence_metadata_versions(tenant_id,project_id,evidence_id,revision DESC);
CREATE FUNCTION verivaro_private.metadata_field(x text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $field$
 SELECT x IS NOT NULL AND char_length(x) BETWEEN 1 AND 128 AND octet_length(x)<=512 AND x=btrim(x) AND x!~'[[:cntrl:]]' AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY[8234,8235,8236,8237,8238,8294,8295,8296,8297]) n WHERE position(chr(n) in x)>0)
$field$;
CREATE FUNCTION verivaro_private.metadata_date(x text) RETURNS date LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $date$
DECLARE d date;
BEGIN
 IF x IS NULL THEN RETURN NULL;END IF;
 IF x!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN RAISE EXCEPTION 'invalid date' USING ERRCODE='22023';END IF;
 d:=x::date;
 IF to_char(d,'YYYY-MM-DD')<>x THEN RAISE EXCEPTION 'invalid date' USING ERRCODE='22023';END IF;
 RETURN d;
END $date$;
CREATE FUNCTION verivaro_verification.write_evidence_metadata(t uuid,p uuid,v uuid,e uuid,h text,expected integer,k text,ident text,equip text,issuer_text text,issued text,expires text,why text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $write$
DECLARE c text[];old verivaro_private.evidence_metadata_versions%ROWTYPE;n integer;d1 date;d2 date;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');
 IF v IS NULL OR e IS NULL OR h IS NULL OR expected IS NULL OR expected NOT BETWEEN 0 AND 15 OR k IS NULL OR k NOT IN ('certificate','warranty','inspection','manual','photo','other') OR NOT verivaro_private.metadata_field(ident) OR NOT verivaro_private.metadata_field(equip) OR NOT verivaro_private.metadata_field(issuer_text) OR NOT verivaro_private.workflow_reason(why) THEN RAISE EXCEPTION 'invalid metadata' USING ERRCODE='22023';END IF;
 d1:=verivaro_private.metadata_date(issued);d2:=verivaro_private.metadata_date(expires);
 IF d1 IS NOT NULL AND d2 IS NOT NULL AND d2<d1 THEN RAISE EXCEPTION 'invalid metadata date order' USING ERRCODE='22023';END IF;
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects x JOIN verivaro.evidence a ON a.id=x.evidence_id AND a.tenant_id=t AND a.project_id=p AND a.sha256=x.sha256 WHERE x.evidence_id=e AND x.tenant_id=t AND x.project_id=p AND x.sha256=h AND x.cipher_digest=verivaro_private.digest(x.envelope,'sha256') AND a.storage_ref='db-encrypted-v1') THEN RAISE EXCEPTION 'metadata source denied' USING ERRCODE='42501';END IF;
 SELECT * INTO old FROM verivaro_private.evidence_metadata_versions x WHERE x.version_id=v;
 IF FOUND THEN
 IF old.tenant_id<>t OR old.project_id<>p OR old.evidence_id<>e OR old.sha256<>h OR old.actor_id<>c[2]::uuid OR old.revision<>expected+1 OR old.kind<>k OR old.identifier<>ident OR old.equipment<>equip OR old.issuer<>issuer_text OR old.issued_on IS DISTINCT FROM d1 OR old.expires_on IS DISTINCT FROM d2 OR old.reason<>why THEN RAISE EXCEPTION 'metadata conflict' USING ERRCODE='23505';END IF;
 RETURN jsonb_build_object('versionId',v,'revision',old.revision);
 END IF;
 SELECT COALESCE(max(x.revision),0) INTO n FROM verivaro_private.evidence_metadata_versions x WHERE x.evidence_id=e;
 IF n<>expected THEN RAISE EXCEPTION 'metadata stale' USING ERRCODE='23505';END IF;
 PERFORM pg_advisory_xact_lock(740129816172::bigint);
 IF (SELECT count(*) FROM verivaro_private.evidence_metadata_versions)>=32768 OR (SELECT count(*) FROM verivaro_private.evidence_metadata_versions x WHERE x.tenant_id=t AND x.project_id=p)>=256 THEN RAISE EXCEPTION 'metadata capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.evidence_metadata_versions(version_id,tenant_id,project_id,evidence_id,revision,sha256,kind,identifier,equipment,issuer,issued_on,expires_on,reason,actor_id,session_id)
 VALUES(v,t,p,e,n+1,h,k,ident,equip,issuer_text,d1,d2,why,c[2]::uuid,c[3]::uuid);
 RETURN jsonb_build_object('versionId',v,'revision',n+1);
END $write$;
CREATE FUNCTION verivaro_verification.review_evidence_metadata(t uuid,p uuid,v uuid,decision_text text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE c text[];q verivaro_private.evidence_metadata_versions%ROWTYPE;old verivaro_private.evidence_metadata_reviews%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');
 SELECT * INTO q FROM verivaro_private.evidence_metadata_versions x WHERE x.tenant_id=t AND x.project_id=p AND x.version_id=v;
 IF NOT FOUND OR q.actor_id=c[2]::uuid OR decision_text IS NULL OR decision_text NOT IN ('approved','rejected') OR NOT verivaro_private.workflow_reason(why) OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects e WHERE e.tenant_id=t AND e.project_id=p AND e.evidence_id=q.evidence_id AND e.actor_id<>c[2]::uuid AND e.sha256=q.sha256 AND e.cipher_digest=verivaro_private.digest(e.envelope,'sha256')) THEN RAISE EXCEPTION 'metadata review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO old FROM verivaro_private.evidence_metadata_reviews x WHERE x.version_id=v;
 IF FOUND THEN IF old.reviewer_id<>c[2]::uuid OR old.decision<>decision_text OR old.reason<>why THEN RAISE EXCEPTION 'metadata review conflict' USING ERRCODE='23505';END IF;RETURN true;END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.evidence_metadata_versions x WHERE x.evidence_id=q.evidence_id AND x.revision>q.revision) THEN RAISE EXCEPTION 'metadata stale' USING ERRCODE='23505';END IF;
 INSERT INTO verivaro_private.evidence_metadata_reviews(version_id,reviewer_id,session_id,decision,reason) VALUES(v,c[2]::uuid,c[3]::uuid,decision_text,why);RETURN true;
END $review$;
CREATE FUNCTION verivaro_verification.evidence_intelligence_records(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $records$
DECLARE g jsonb;c text[];tr text;pr text;items jsonb;history jsonb;inventory jsonb;
BEGIN
 g:=verivaro_verification.assessment(t,p);c:=verivaro.bound_context();
 SELECT m.role,pm.role INTO tr,pr FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id WHERE m.tenant_id=t AND pm.project_id=p AND m.actor_id=c[2]::uuid AND m.revoked_at IS NULL AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp());
 IF NOT FOUND OR NOT ((tr='owner' AND pr='owner') OR (tr='reviewer' AND pr='reviewer')) THEN RAISE EXCEPTION 'intelligence denied' USING ERRCODE='42501';END IF;
 -- Bounded metadata, only current scoped source bytes; no raw file contents.
 SELECT COALESCE(jsonb_agg(jsonb_build_object('evidenceId',x.evidence_id,'versionId',x.version_id,'revision',x.revision,'sha256',x.sha256,'kind',x.kind,'identifier',x.identifier,'equipment',x.equipment,'issuer',x.issuer,'issuedOn',x.issued_on,'expiresOn',x.expires_on,'decision',COALESCE(r.decision,'pending'),'reviewReason',r.reason,'reason',x.reason,
 'sourceIntact',o.sha256=x.sha256 AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256'),'canReview',tr='reviewer' AND NOT(g->>'archived')::boolean AND r.version_id IS NULL AND x.actor_id<>c[2]::uuid AND o.actor_id<>c[2]::uuid,
 'history',(SELECT jsonb_agg(jsonb_build_object('versionId',z.version_id,'revision',z.revision,'decision',COALESCE(rv.decision,'pending'),'kind',z.kind,'identifier',z.identifier,'equipment',z.equipment,'issuer',z.issuer,'issuedOn',z.issued_on,'expiresOn',z.expires_on,'reason',z.reason,'reviewReason',rv.reason) ORDER BY z.revision) FROM verivaro_private.evidence_metadata_versions z LEFT JOIN verivaro_private.evidence_metadata_reviews rv USING(version_id) WHERE z.evidence_id=x.evidence_id AND z.tenant_id=t AND z.project_id=p)) ORDER BY x.evidence_id),'[]'::jsonb)
 INTO items FROM (SELECT DISTINCT ON(evidence_id) * FROM verivaro_private.evidence_metadata_versions WHERE tenant_id=t AND project_id=p ORDER BY evidence_id,revision DESC) x JOIN verivaro_private.evidence_objects o ON o.evidence_id=x.evidence_id LEFT JOIN verivaro_private.evidence_metadata_reviews r USING(version_id);
 IF (SELECT count(*) FROM verivaro.evidence x WHERE x.tenant_id=t AND x.project_id=p)>4096 THEN RAISE EXCEPTION 'inventory capacity' USING ERRCODE='54000';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('evidenceId',x.id,'sha256',x.sha256) ORDER BY x.id),'[]'::jsonb) INTO inventory FROM verivaro.evidence x WHERE x.tenant_id=t AND x.project_id=p;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('requirementId',q.requirement_id,'versionId',q.version_id,'revision',q.revision,'ruleRejected',r.decision='rejected','failedLinks',l.failed,'unknownLinks',l.unknown) ORDER BY q.requirement_id,q.revision),'[]'::jsonb)
 INTO history FROM verivaro_private.requirement_versions q LEFT JOIN verivaro_private.requirement_reviews r USING(version_id) CROSS JOIN LATERAL (SELECT count(*) FILTER(WHERE z.decision='fail') failed,count(*) FILTER(WHERE z.decision='unknown') unknown FROM verivaro_private.requirement_evidence_links b JOIN verivaro_private.requirement_link_reviews z USING(link_id) WHERE b.version_id=q.version_id) l WHERE q.tenant_id=t AND q.project_id=p;
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'asOfDate',to_char(statement_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD'),'assessment',g,'canWrite',tr='owner' AND NOT(g->>'archived')::boolean,'metadata',items,'inventory',inventory,'reviewHistory',history);
END $records$;
REVOKE ALL ON FUNCTION verivaro_private.metadata_field(text),verivaro_private.metadata_date(text),verivaro_verification.write_evidence_metadata(uuid,uuid,uuid,uuid,text,integer,text,text,text,text,text,text,text),verivaro_verification.review_evidence_metadata(uuid,uuid,uuid,text,text),verivaro_verification.evidence_intelligence_records(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.write_evidence_metadata(uuid,uuid,uuid,uuid,text,integer,text,text,text,text,text,text,text),verivaro_verification.review_evidence_metadata(uuid,uuid,uuid,text,text),verivaro_verification.evidence_intelligence_records(uuid,uuid) TO verivaro_runtime;
ALTER TABLE verivaro_private.trustproof_entries DROP CONSTRAINT trustproof_entries_source_type_check;
ALTER TABLE verivaro_private.trustproof_entries ADD CONSTRAINT trustproof_entries_source_type_check CHECK(source_type IN ('requirement_versions','requirement_reviews','requirement_evidence_links','requirement_link_reviews','requirement_sources','requirement_dependencies','requirement_dependency_reviews','requirement_dependency_removals','requirement_dependency_removal_reviews','submission_snapshots','submission_reviews','submission_authorizations','prooflock_milestones','prooflock_windows','prooflock_window_reviews','prooflock_capture_receipts','prooflock_alert_policies','prooflock_recovery_proposals','prooflock_recovery_reviews','financial_records','financial_versions','financial_reviews','project_chronology','project_chronology_reviews','acknowledgement_grants','acknowledgement_revocations','acknowledgement_events','resolution_tasks','resolution_task_events','customer_package_grants','customer_package_revocations','customer_package_reads','export_template_versions','organisation_template_publications','organisation_template_imports','project_lifecycle_events','evidence_metadata_versions','evidence_metadata_reviews'));
CREATE OR REPLACE FUNCTION verivaro_private.trustproof_source(k text,r uuid) RETURNS TABLE(tenant_id uuid,project_id uuid,source_digest text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private SET TimeZone='UTC' AS $source$
BEGIN
 CASE k
 WHEN 'requirement_versions' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_versions x  WHERE x.version_id=r;
 WHEN 'requirement_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_reviews x JOIN verivaro_private.requirement_versions q USING(version_id) WHERE x.version_id=r;
 WHEN 'requirement_evidence_links' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_evidence_links x JOIN verivaro_private.requirement_versions q USING(version_id) WHERE x.link_id=r;
 WHEN 'requirement_link_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_link_reviews x JOIN verivaro_private.requirement_evidence_links l USING(link_id) JOIN verivaro_private.requirement_versions q ON q.version_id=l.version_id WHERE x.link_id=r;
 WHEN 'requirement_sources' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_sources x  WHERE x.version_id=r;
 WHEN 'requirement_dependencies' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_dependencies x  WHERE x.edge_id=r;
 WHEN 'requirement_dependency_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_dependency_reviews x JOIN verivaro_private.requirement_dependencies q USING(edge_id) WHERE x.edge_id=r;
 WHEN 'requirement_dependency_removals' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_dependency_removals x  WHERE x.removal_id=r;
 WHEN 'requirement_dependency_removal_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_dependency_removal_reviews x JOIN verivaro_private.requirement_dependency_removals q USING(removal_id) WHERE x.removal_id=r;
 WHEN 'submission_snapshots' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.submission_snapshots x  WHERE x.submission_id=r;
 WHEN 'submission_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.submission_reviews x JOIN verivaro_private.submission_snapshots q USING(submission_id) WHERE x.submission_id=r;
 WHEN 'submission_authorizations' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.submission_authorizations x JOIN verivaro_private.submission_snapshots q USING(submission_id) WHERE x.submission_id=r;
 WHEN 'prooflock_milestones' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.prooflock_milestones x  WHERE x.revision_id=r;
 WHEN 'prooflock_windows' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.prooflock_windows x  WHERE x.window_id=r;
 WHEN 'prooflock_window_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.prooflock_window_reviews x JOIN verivaro_private.prooflock_windows q USING(window_id) WHERE x.window_id=r;
 WHEN 'prooflock_capture_receipts' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.prooflock_capture_receipts x  WHERE x.link_id=r;
 WHEN 'prooflock_alert_policies' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.prooflock_alert_policies x  WHERE x.policy_id=r;
 WHEN 'prooflock_recovery_proposals' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.prooflock_recovery_proposals x  WHERE x.recovery_id=r;
 WHEN 'prooflock_recovery_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.prooflock_recovery_reviews x JOIN verivaro_private.prooflock_recovery_proposals q USING(recovery_id) WHERE x.recovery_id=r;
 WHEN 'financial_records' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.financial_records x  WHERE x.record_id=r;
 WHEN 'financial_versions' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.financial_versions x JOIN verivaro_private.financial_records q USING(record_id) WHERE x.version_id=r;
 WHEN 'financial_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.financial_reviews x JOIN verivaro_private.financial_versions v USING(version_id) JOIN verivaro_private.financial_records q ON q.record_id=v.record_id WHERE x.version_id=r;
 WHEN 'project_chronology' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.project_chronology x  WHERE x.event_id=r;
 WHEN 'project_chronology_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.project_chronology_reviews x JOIN verivaro_private.project_chronology q USING(event_id) WHERE x.event_id=r;
 WHEN 'acknowledgement_grants' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.acknowledgement_grants x  WHERE x.grant_id=r;
 WHEN 'acknowledgement_revocations' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.acknowledgement_revocations x JOIN verivaro_private.acknowledgement_grants q USING(grant_id) WHERE x.grant_id=r;
 WHEN 'acknowledgement_events' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.acknowledgement_events x JOIN verivaro_private.acknowledgement_grants q USING(grant_id) WHERE x.event_id=r;
 WHEN 'resolution_tasks' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.resolution_tasks x  WHERE x.task_id=r;
 WHEN 'resolution_task_events' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.resolution_task_events x JOIN verivaro_private.resolution_tasks q USING(task_id) WHERE x.event_id=r;
 WHEN 'customer_package_grants' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.customer_package_grants x  WHERE x.grant_id=r;
 WHEN 'customer_package_revocations' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.customer_package_revocations x JOIN verivaro_private.customer_package_grants q USING(grant_id) WHERE x.grant_id=r;
 WHEN 'customer_package_reads' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.customer_package_reads x JOIN verivaro_private.customer_package_grants q USING(grant_id) WHERE x.read_id=r;
 WHEN 'export_template_versions' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.export_template_versions x WHERE x.version_id=r;
 WHEN 'organisation_template_publications' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.organisation_template_publications x WHERE x.event_id=r;
 WHEN 'organisation_template_imports' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.organisation_template_imports x WHERE x.event_id=r;
 WHEN 'project_lifecycle_events' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.project_lifecycle_events x WHERE x.event_id=r;
 WHEN 'evidence_metadata_versions' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.evidence_metadata_versions x  WHERE x.version_id=r;
 WHEN 'evidence_metadata_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.evidence_metadata_reviews x JOIN verivaro_private.evidence_metadata_versions q USING(version_id) WHERE x.version_id=r;
 ELSE RAISE EXCEPTION 'unknown trustproof source' USING ERRCODE='22023';
 END CASE;
 IF FOUND THEN RETURN NEXT;END IF;
END $source$;
CREATE OR REPLACE FUNCTION verivaro_verification.trustproof_page(t uuid,p uuid,after_sequence integer,page_size integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private SET TimeZone='UTC' AS $page$
DECLARE c text[];tr text;pr text;n bigint;head text;before_hash text;items jsonb;source_count bigint;actual_count bigint;
BEGIN
 c:=verivaro.bound_context();
 IF c IS NULL OR c[1]<>t::text OR NOT verivaro.active_identity() OR after_sequence IS NULL OR after_sequence<0 OR page_size IS NULL OR page_size NOT BETWEEN 1 AND 256 THEN RAISE EXCEPTION 'audit denied' USING ERRCODE='42501';END IF;
 SELECT m.role,pm.role INTO tr,pr FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id WHERE m.tenant_id=t AND pm.project_id=p AND m.actor_id=c[2]::uuid AND m.revoked_at IS NULL AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp());
 IF NOT FOUND OR NOT ((tr='owner' AND pr='owner') OR (tr='reviewer' AND pr='reviewer')) THEN RAISE EXCEPTION 'audit denied' USING ERRCODE='42501';END IF;
 SELECT x.sequence,x.entry_hash INTO n,head FROM verivaro_private.trustproof_entries x WHERE x.tenant_id=t AND x.project_id=p ORDER BY x.sequence DESC LIMIT 1;
 n:=COALESCE(n,0);head:=COALESCE(head,repeat('0',64));
 IF after_sequence>n THEN RAISE EXCEPTION 'audit cursor conflict' USING ERRCODE='23505';END IF;
 SELECT x.entry_hash INTO before_hash FROM verivaro_private.trustproof_entries x WHERE x.tenant_id=t AND x.project_id=p AND x.sequence=after_sequence;
 IF after_sequence>0 AND before_hash IS NULL THEN RAISE EXCEPTION 'audit cursor conflict' USING ERRCODE='23505';END IF;
 SELECT (SELECT count(*) FROM verivaro_private.requirement_versions x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.requirement_reviews x JOIN verivaro_private.requirement_versions q USING(version_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.requirement_evidence_links x JOIN verivaro_private.requirement_versions q USING(version_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.requirement_link_reviews x JOIN verivaro_private.requirement_evidence_links l USING(link_id) JOIN verivaro_private.requirement_versions q ON q.version_id=l.version_id WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.requirement_sources x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.requirement_dependencies x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.requirement_dependency_reviews x JOIN verivaro_private.requirement_dependencies q USING(edge_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.requirement_dependency_removals x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.requirement_dependency_removal_reviews x JOIN verivaro_private.requirement_dependency_removals q USING(removal_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.submission_snapshots x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.submission_reviews x JOIN verivaro_private.submission_snapshots q USING(submission_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.submission_authorizations x JOIN verivaro_private.submission_snapshots q USING(submission_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.prooflock_milestones x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.prooflock_windows x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.prooflock_window_reviews x JOIN verivaro_private.prooflock_windows q USING(window_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.prooflock_capture_receipts x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.prooflock_alert_policies x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.prooflock_recovery_proposals x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.prooflock_recovery_reviews x JOIN verivaro_private.prooflock_recovery_proposals q USING(recovery_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.financial_records x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.financial_versions x JOIN verivaro_private.financial_records q USING(record_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.financial_reviews x JOIN verivaro_private.financial_versions v USING(version_id) JOIN verivaro_private.financial_records q ON q.record_id=v.record_id WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.project_chronology x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.project_chronology_reviews x JOIN verivaro_private.project_chronology q USING(event_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.acknowledgement_grants x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.acknowledgement_revocations x JOIN verivaro_private.acknowledgement_grants q USING(grant_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.acknowledgement_events x JOIN verivaro_private.acknowledgement_grants q USING(grant_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.resolution_tasks x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.resolution_task_events x JOIN verivaro_private.resolution_tasks q USING(task_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.customer_package_grants x  WHERE x.tenant_id=t AND x.project_id=p)+
 (SELECT count(*) FROM verivaro_private.customer_package_revocations x JOIN verivaro_private.customer_package_grants q USING(grant_id) WHERE q.tenant_id=t AND q.project_id=p)+
 (SELECT count(*) FROM verivaro_private.customer_package_reads x JOIN verivaro_private.customer_package_grants q USING(grant_id) WHERE q.tenant_id=t AND q.project_id=p)+(SELECT count(*) FROM verivaro_private.export_template_versions x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.organisation_template_publications x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.organisation_template_imports x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.project_lifecycle_events x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.evidence_metadata_versions x  WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.evidence_metadata_reviews x JOIN verivaro_private.evidence_metadata_versions q USING(version_id) WHERE q.tenant_id=t AND q.project_id=p) INTO source_count;
 SELECT count(*) INTO actual_count FROM verivaro_private.trustproof_entries x WHERE x.tenant_id=t AND x.project_id=p;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('sequence',x.sequence,'sourceType',x.source_type,'sourceId',x.source_id,'origin',x.origin,'recordedAt',x.recorded_at,'sourceDigest',x.source_digest,'previousHash',x.previous_hash,'entryHash',x.entry_hash,'sourceIntact',COALESCE(v.tenant_id=t AND v.project_id=p AND v.source_digest=x.source_digest,false)) ORDER BY x.sequence),'[]'::jsonb)
 INTO items FROM (SELECT * FROM verivaro_private.trustproof_entries e WHERE e.tenant_id=t AND e.project_id=p AND e.sequence>after_sequence ORDER BY e.sequence LIMIT page_size) x LEFT JOIN LATERAL verivaro_private.trustproof_source(x.source_type,x.source_id) v ON true;
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'afterSequence',after_sequence,'previousHash',COALESCE(before_hash,repeat('0',64)),'headSequence',n,'headHash',head,'sourceCount',source_count,'ledgerCount',actual_count,'entries',items);
END $page$;
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.evidence_metadata_versions FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('version_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.evidence_metadata_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('version_id');
COMMIT;
