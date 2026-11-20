BEGIN;
CREATE TABLE verivaro_private.export_template_versions(
 version_id uuid PRIMARY KEY,template_id uuid NOT NULL,tenant_id uuid NOT NULL,project_id uuid NOT NULL,
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 16),
 reference text NOT NULL CHECK(reference~'^[a-z0-9][a-z0-9._-]{0,63}$'),
 heading text NOT NULL CHECK(char_length(heading) BETWEEN 1 AND 80 AND octet_length(heading)<=320),
 index_order text NOT NULL CHECK(index_order IN ('requirements_first','evidence_first')),
 include_workbook boolean NOT NULL,active boolean NOT NULL,actor_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),
 UNIQUE(template_id,revision),UNIQUE(tenant_id,project_id,reference,revision));
REVOKE ALL ON verivaro_private.export_template_versions FROM PUBLIC;
CREATE TRIGGER export_template_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.export_template_versions FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER export_template_archive_guard BEFORE INSERT ON verivaro_private.export_template_versions FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE INDEX export_template_scope_idx ON verivaro_private.export_template_versions(tenant_id,project_id,template_id,revision DESC);
CREATE FUNCTION verivaro_verification.write_export_template(t uuid,p uuid,r uuid,v uuid,expected integer,ref text,h text,o text,w boolean,enabled boolean) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $write$
DECLARE c text[];prior verivaro_private.export_template_versions%ROWTYPE;latest verivaro_private.export_template_versions%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'owner');
 IF r IS NULL OR v IS NULL OR expected IS NULL OR expected NOT BETWEEN 0 AND 15 OR ref IS NULL OR ref!~'^[a-z0-9][a-z0-9._-]{0,63}$'
 OR h IS NULL OR char_length(h) NOT BETWEEN 1 AND 80 OR octet_length(h)>320 OR h<>btrim(h) OR h~'[[:cntrl:]]'
 OR EXISTS(SELECT 1 FROM unnest(ARRAY[8234,8235,8236,8237,8238,8294,8295,8296,8297]) n WHERE position(chr(n) in h)>0)
 OR o IS NULL OR o NOT IN ('requirements_first','evidence_first') OR w IS NULL OR enabled IS NULL OR (expected=0 AND NOT enabled)
 THEN RAISE EXCEPTION 'invalid export template' USING ERRCODE='22023';END IF;
 SELECT * INTO prior FROM verivaro_private.export_template_versions x WHERE x.version_id=v;
 IF FOUND THEN
  IF prior.tenant_id<>t OR prior.project_id<>p OR prior.template_id<>r OR prior.actor_id<>c[2]::uuid OR prior.revision<>expected+1 OR prior.reference<>ref OR prior.heading<>h OR prior.index_order<>o OR prior.include_workbook<>w OR prior.active<>enabled THEN RAISE EXCEPTION 'template conflict' USING ERRCODE='23505';END IF;
  RETURN jsonb_build_object('templateId',r,'versionId',v,'revision',prior.revision);
 END IF;
 SELECT * INTO latest FROM verivaro_private.export_template_versions x WHERE x.template_id=r ORDER BY x.revision DESC LIMIT 1;
 IF FOUND THEN
  IF latest.tenant_id<>t OR latest.project_id<>p OR latest.reference<>ref OR latest.revision<>expected THEN RAISE EXCEPTION 'stale template revision' USING ERRCODE='23505';END IF;
 ELSE
  IF expected<>0 OR EXISTS(SELECT 1 FROM verivaro_private.export_template_versions x WHERE x.tenant_id=t AND x.project_id=p AND x.reference=ref) THEN RAISE EXCEPTION 'template reference conflict' USING ERRCODE='23505';END IF;
 END IF;
 PERFORM pg_advisory_xact_lock(740129816169::bigint);
 IF (SELECT count(*) FROM verivaro_private.export_template_versions)>=32768 OR (SELECT count(*) FROM verivaro_private.export_template_versions x WHERE x.tenant_id=t AND x.project_id=p)>=256
 OR (expected=0 AND (SELECT count(*) FROM verivaro_private.export_template_versions x WHERE x.tenant_id=t AND x.project_id=p AND x.revision=1)>=32) THEN RAISE EXCEPTION 'template capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.export_template_versions(version_id,template_id,tenant_id,project_id,revision,reference,heading,index_order,include_workbook,active,actor_id,session_id)
 VALUES(v,r,t,p,expected+1,ref,h,o,w,enabled,c[2]::uuid,c[3]::uuid);
 RETURN jsonb_build_object('templateId',r,'versionId',v,'revision',expected+1);
END $write$;
CREATE FUNCTION verivaro_verification.export_template_list(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $list$
DECLARE c text[];tr text;pr text;archived boolean;items jsonb;
BEGIN
 c:=verivaro.bound_context();
 IF c IS NULL OR c[1]<>t::text OR NOT verivaro.active_identity() THEN RAISE EXCEPTION 'template denied' USING ERRCODE='42501';END IF;
 SELECT m.role,pm.role,q.archived_at IS NOT NULL INTO tr,pr,archived FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id JOIN verivaro.projects q ON q.tenant_id=pm.tenant_id AND q.id=pm.project_id
 WHERE m.tenant_id=t AND pm.project_id=p AND m.actor_id=c[2]::uuid AND m.revoked_at IS NULL AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp());
 IF NOT FOUND OR NOT ((tr='owner' AND pr='owner') OR (tr='reviewer' AND pr='reviewer')) THEN RAISE EXCEPTION 'template denied' USING ERRCODE='42501';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('templateId',x.template_id,'versionId',x.version_id,'revision',x.revision,'reference',x.reference,'active',x.active,
 'configuration',jsonb_build_object('version',1,'heading',x.heading,'order',x.index_order,'includeWorkbook',x.include_workbook),
 'history',(SELECT jsonb_agg(jsonb_build_object('versionId',h.version_id,'revision',h.revision,'active',h.active,'configuration',jsonb_build_object('version',1,'heading',h.heading,'order',h.index_order,'includeWorkbook',h.include_workbook),'recordedAt',h.created_at) ORDER BY h.revision) FROM verivaro_private.export_template_versions h WHERE h.template_id=x.template_id AND h.tenant_id=t AND h.project_id=p)) ORDER BY x.reference),'[]'::jsonb)
 INTO items FROM (SELECT DISTINCT ON(template_id) * FROM verivaro_private.export_template_versions WHERE tenant_id=t AND project_id=p ORDER BY template_id,revision DESC) x;
 RETURN jsonb_build_object('canWrite',tr='owner' AND pr='owner' AND NOT archived,'items',items);
END $list$;
CREATE FUNCTION verivaro_verification.read_export_template(t uuid,p uuid,r uuid,v uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $read$
DECLARE c text[];x verivaro_private.export_template_versions%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'owner');
 SELECT * INTO x FROM verivaro_private.export_template_versions y WHERE y.tenant_id=t AND y.project_id=p AND y.template_id=r ORDER BY y.revision DESC LIMIT 1;
 IF NOT FOUND OR NOT x.active THEN RAISE EXCEPTION 'template denied' USING ERRCODE='42501';END IF;
 IF x.version_id<>v THEN RAISE EXCEPTION 'stale template' USING ERRCODE='23505';END IF;
 RETURN jsonb_build_object('template',jsonb_build_object('templateId',r,'versionId',v,'revision',x.revision,'reference',x.reference),'configuration',jsonb_build_object('version',1,'heading',x.heading,'order',x.index_order,'includeWorkbook',x.include_workbook));
END $read$;
REVOKE ALL ON FUNCTION verivaro_verification.write_export_template(uuid,uuid,uuid,uuid,integer,text,text,text,boolean,boolean),verivaro_verification.export_template_list(uuid,uuid),verivaro_verification.read_export_template(uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.write_export_template(uuid,uuid,uuid,uuid,integer,text,text,text,boolean,boolean),verivaro_verification.export_template_list(uuid,uuid),verivaro_verification.read_export_template(uuid,uuid,uuid,uuid) TO verivaro_runtime;
ALTER TABLE verivaro_private.trustproof_entries DROP CONSTRAINT trustproof_entries_source_type_check;
ALTER TABLE verivaro_private.trustproof_entries ADD CONSTRAINT trustproof_entries_source_type_check CHECK(source_type IN ('requirement_versions','requirement_reviews','requirement_evidence_links','requirement_link_reviews','requirement_sources','requirement_dependencies','requirement_dependency_reviews','requirement_dependency_removals','requirement_dependency_removal_reviews','submission_snapshots','submission_reviews','submission_authorizations','prooflock_milestones','prooflock_windows','prooflock_window_reviews','prooflock_capture_receipts','prooflock_alert_policies','prooflock_recovery_proposals','prooflock_recovery_reviews','financial_records','financial_versions','financial_reviews','project_chronology','project_chronology_reviews','acknowledgement_grants','acknowledgement_revocations','acknowledgement_events','resolution_tasks','resolution_task_events','customer_package_grants','customer_package_revocations','customer_package_reads','export_template_versions'));
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
 (SELECT count(*) FROM verivaro_private.customer_package_reads x JOIN verivaro_private.customer_package_grants q USING(grant_id) WHERE q.tenant_id=t AND q.project_id=p)+(SELECT count(*) FROM verivaro_private.export_template_versions x WHERE x.tenant_id=t AND x.project_id=p) INTO source_count;
 SELECT count(*) INTO actual_count FROM verivaro_private.trustproof_entries x WHERE x.tenant_id=t AND x.project_id=p;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('sequence',x.sequence,'sourceType',x.source_type,'sourceId',x.source_id,'origin',x.origin,'recordedAt',x.recorded_at,'sourceDigest',x.source_digest,'previousHash',x.previous_hash,'entryHash',x.entry_hash,'sourceIntact',COALESCE(v.tenant_id=t AND v.project_id=p AND v.source_digest=x.source_digest,false)) ORDER BY x.sequence),'[]'::jsonb)
 INTO items FROM (SELECT * FROM verivaro_private.trustproof_entries e WHERE e.tenant_id=t AND e.project_id=p AND e.sequence>after_sequence ORDER BY e.sequence LIMIT page_size) x LEFT JOIN LATERAL verivaro_private.trustproof_source(x.source_type,x.source_id) v ON true;
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'afterSequence',after_sequence,'previousHash',COALESCE(before_hash,repeat('0',64)),'headSequence',n,'headHash',head,'sourceCount',source_count,'ledgerCount',actual_count,'entries',items);
END $page$;
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.export_template_versions FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('version_id');
COMMIT;
