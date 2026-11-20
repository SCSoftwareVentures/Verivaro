BEGIN;
CREATE TABLE verivaro_private.project_lifecycle_events(
 event_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,sequence integer NOT NULL CHECK(sequence BETWEEN 1 AND 512),
 kind text NOT NULL CHECK(kind IN ('policy','hold','hold_release_request','hold_release_approved','hold_release_denied','disposal_request','disposal_approved','disposal_denied','disposal_cancelled')),
 parent_id uuid REFERENCES verivaro_private.project_lifecycle_events(event_id),reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 retain_until timestamptz,backup_days integer CHECK(backup_days BETWEEN 7 AND 3650),
 actor_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),UNIQUE(tenant_id,project_id,sequence),
 CHECK((kind='policy' AND retain_until IS NOT NULL AND backup_days IS NOT NULL AND parent_id IS NULL) OR (kind<>'policy' AND retain_until IS NULL AND backup_days IS NULL)),
 CHECK((parent_id IS NULL)=(kind IN ('policy','hold'))));
REVOKE ALL ON verivaro_private.project_lifecycle_events FROM PUBLIC;
CREATE TRIGGER lifecycle_event_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.project_lifecycle_events FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE INDEX lifecycle_event_scope ON verivaro_private.project_lifecycle_events(tenant_id,project_id,kind,sequence);
CREATE INDEX lifecycle_event_parent ON verivaro_private.project_lifecycle_events(parent_id);
-- Unlike ordinary content writes, preservation controls must remain available
-- after project archive. Active identity, both role levels and project lock
-- are required; the archived project itself is never amended.
CREATE FUNCTION verivaro_private.lifecycle_actor(t uuid,p uuid,role_name text) RETURNS text[]
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $actor$
DECLARE c text[];
BEGIN
 c:=verivaro_private.release_actor(t,p,role_name);
 PERFORM 1 FROM verivaro.projects q WHERE q.tenant_id=t AND q.id=p FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'lifecycle denied' USING ERRCODE='42501';END IF;
 RETURN verivaro_private.release_actor(t,p,role_name);
END $actor$;
CREATE FUNCTION verivaro_private.lifecycle_active_holds(t uuid,p uuid) RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $holds$
 SELECT count(*)::integer FROM verivaro_private.project_lifecycle_events h WHERE h.tenant_id=t AND h.project_id=p AND h.kind='hold' AND NOT EXISTS(
 SELECT 1 FROM verivaro_private.project_lifecycle_events r JOIN verivaro_private.project_lifecycle_events a ON a.parent_id=r.event_id AND a.kind='hold_release_approved'
 WHERE r.parent_id=h.event_id AND r.kind='hold_release_request' AND r.tenant_id=t AND r.project_id=p AND a.tenant_id=t AND a.project_id=p)
$holds$;
CREATE FUNCTION verivaro_verification.write_lifecycle_event(t uuid,p uuid,e uuid,expected integer,k text,parent uuid,why text,retain text,days integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $write$
DECLARE c text[];prior verivaro_private.project_lifecycle_events%ROWTYPE;ancestor verivaro_private.project_lifecycle_events%ROWTYPE;pol verivaro_private.project_lifecycle_events%ROWTYPE;hold_row verivaro_private.project_lifecycle_events%ROWTYPE;n integer;until_at timestamptz;closed boolean;
BEGIN
 IF k IS NULL OR k NOT IN ('policy','hold','hold_release_request','hold_release_approved','hold_release_denied','disposal_request','disposal_approved','disposal_denied','disposal_cancelled') OR e IS NULL OR expected IS NULL OR expected NOT BETWEEN 0 AND 511 OR NOT verivaro_private.workflow_reason(why) OR (parent IS NULL)<>(k IN ('policy','hold')) THEN RAISE EXCEPTION 'invalid lifecycle event' USING ERRCODE='22023';END IF;
 c:=verivaro_private.lifecycle_actor(t,p,CASE WHEN k IN ('hold_release_approved','hold_release_denied','disposal_approved','disposal_denied') THEN 'reviewer' ELSE 'owner' END);
 IF k='policy' THEN
 IF retain IS NULL OR retain!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$' OR days IS NULL OR days NOT BETWEEN 7 AND 3650 THEN RAISE EXCEPTION 'invalid retention settings' USING ERRCODE='22023';END IF;
 until_at:=retain::timestamptz;
 IF to_char(until_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')<>retain THEN RAISE EXCEPTION 'invalid retention time' USING ERRCODE='22023';END IF;
 ELSIF retain IS NOT NULL OR days IS NOT NULL THEN RAISE EXCEPTION 'unexpected retention settings' USING ERRCODE='22023';END IF;
 SELECT * INTO prior FROM verivaro_private.project_lifecycle_events x WHERE x.event_id=e;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.actor_id<>c[2]::uuid OR prior.sequence<>expected+1 OR prior.kind<>k OR prior.parent_id IS DISTINCT FROM parent OR prior.reason<>why OR prior.retain_until IS DISTINCT FROM until_at OR prior.backup_days IS DISTINCT FROM days THEN RAISE EXCEPTION 'lifecycle conflict' USING ERRCODE='23505';END IF;
 RETURN jsonb_build_object('eventId',e,'sequence',prior.sequence);
 END IF;
 SELECT COALESCE(max(x.sequence),0) INTO n FROM verivaro_private.project_lifecycle_events x WHERE x.tenant_id=t AND x.project_id=p;
 IF n<>expected THEN RAISE EXCEPTION 'stale lifecycle history' USING ERRCODE='23505';END IF;
 SELECT q.archived_at IS NOT NULL INTO closed FROM verivaro.projects q WHERE q.tenant_id=t AND q.id=p;
 IF parent IS NOT NULL THEN
 SELECT * INTO ancestor FROM verivaro_private.project_lifecycle_events x WHERE x.event_id=parent AND x.tenant_id=t AND x.project_id=p;
 IF NOT FOUND THEN RAISE EXCEPTION 'lifecycle parent denied' USING ERRCODE='42501';END IF;
 END IF;
 SELECT * INTO pol FROM verivaro_private.project_lifecycle_events x WHERE x.tenant_id=t AND x.project_id=p AND x.kind='policy' ORDER BY x.sequence DESC LIMIT 1;
 IF k='hold_release_request' THEN
 IF ancestor.kind<>'hold' OR EXISTS(SELECT 1 FROM verivaro_private.project_lifecycle_events r WHERE r.parent_id=parent AND r.kind='hold_release_request' AND NOT EXISTS(SELECT 1 FROM verivaro_private.project_lifecycle_events a WHERE a.parent_id=r.event_id AND a.kind='hold_release_denied')) THEN RAISE EXCEPTION 'hold release conflict' USING ERRCODE='23505';END IF;
 ELSIF k IN ('hold_release_approved','hold_release_denied') THEN
 IF ancestor.kind<>'hold_release_request' OR ancestor.actor_id=c[2]::uuid OR EXISTS(SELECT 1 FROM verivaro_private.project_lifecycle_events x WHERE x.parent_id=parent) THEN RAISE EXCEPTION 'hold review conflict' USING ERRCODE='23505';END IF;
 SELECT * INTO hold_row FROM verivaro_private.project_lifecycle_events x WHERE x.event_id=ancestor.parent_id AND x.tenant_id=t AND x.project_id=p AND x.kind='hold';
 IF NOT FOUND OR hold_row.actor_id=c[2]::uuid THEN RAISE EXCEPTION 'hold reviewer denied' USING ERRCODE='42501';END IF;
 ELSIF k='disposal_request' THEN
 IF NOT closed OR pol.event_id IS DISTINCT FROM parent OR pol.retain_until>clock_timestamp() OR verivaro_private.lifecycle_active_holds(t,p)>0 OR EXISTS(SELECT 1 FROM verivaro_private.project_lifecycle_events r WHERE r.tenant_id=t AND r.project_id=p AND r.kind='disposal_request' AND r.parent_id=parent AND NOT EXISTS(SELECT 1 FROM verivaro_private.project_lifecycle_events a WHERE a.parent_id=r.event_id AND a.kind IN ('disposal_approved','disposal_denied','disposal_cancelled'))) THEN RAISE EXCEPTION 'disposal not eligible' USING ERRCODE='23505';END IF;
 ELSIF k IN ('disposal_approved','disposal_denied','disposal_cancelled') THEN
 IF ancestor.kind<>'disposal_request' OR EXISTS(SELECT 1 FROM verivaro_private.project_lifecycle_events x WHERE x.parent_id=parent AND x.kind IN ('disposal_approved','disposal_denied','disposal_cancelled')) THEN RAISE EXCEPTION 'disposal review conflict' USING ERRCODE='23505';END IF;
 IF k<>'disposal_cancelled' AND ancestor.actor_id=c[2]::uuid THEN RAISE EXCEPTION 'disposal reviewer denied' USING ERRCODE='42501';END IF;
 IF k='disposal_approved' AND (NOT closed OR pol.event_id IS DISTINCT FROM ancestor.parent_id OR pol.retain_until>clock_timestamp() OR verivaro_private.lifecycle_active_holds(t,p)>0 OR EXISTS(SELECT 1 FROM verivaro_private.project_lifecycle_events x WHERE x.tenant_id=t AND x.project_id=p AND x.sequence>ancestor.sequence AND x.kind IN ('hold','policy'))) THEN RAISE EXCEPTION 'disposal approval stale' USING ERRCODE='23505';END IF;
 END IF;
 PERFORM pg_advisory_xact_lock(740129816171::bigint);
 IF (SELECT count(*) FROM verivaro_private.project_lifecycle_events)>=65536 THEN RAISE EXCEPTION 'lifecycle capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.project_lifecycle_events(event_id,tenant_id,project_id,sequence,kind,parent_id,reason,retain_until,backup_days,actor_id,session_id) VALUES(e,t,p,n+1,k,parent,why,until_at,days,c[2]::uuid,c[3]::uuid);
 RETURN jsonb_build_object('eventId',e,'sequence',n+1);
END $write$;
CREATE FUNCTION verivaro_verification.lifecycle_records(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $list$
DECLARE c text[];tr text;pr text;closed boolean;items jsonb;pol verivaro_private.project_lifecycle_events%ROWTYPE;approved verivaro_private.project_lifecycle_events%ROWTYPE;n integer;holds integer;eligible boolean;
BEGIN
 c:=verivaro.bound_context();
 IF c IS NULL OR c[1]<>t::text OR NOT verivaro.active_identity() THEN RAISE EXCEPTION 'lifecycle denied' USING ERRCODE='42501';END IF;
 SELECT m.role,pm.role,q.archived_at IS NOT NULL INTO tr,pr,closed FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id JOIN verivaro.projects q ON q.tenant_id=pm.tenant_id AND q.id=pm.project_id WHERE m.tenant_id=t AND pm.project_id=p AND m.actor_id=c[2]::uuid AND m.revoked_at IS NULL AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp());
 IF NOT FOUND OR NOT ((tr='owner' AND pr='owner') OR (tr='reviewer' AND pr='reviewer')) THEN RAISE EXCEPTION 'lifecycle denied' USING ERRCODE='42501';END IF;
 SELECT COALESCE(max(x.sequence),0) INTO n FROM verivaro_private.project_lifecycle_events x WHERE x.tenant_id=t AND x.project_id=p;
 SELECT * INTO pol FROM verivaro_private.project_lifecycle_events x WHERE x.tenant_id=t AND x.project_id=p AND x.kind='policy' ORDER BY x.sequence DESC LIMIT 1;
 holds:=verivaro_private.lifecycle_active_holds(t,p);
 eligible:=closed AND pol.event_id IS NOT NULL AND pol.retain_until<=statement_timestamp() AND holds=0;
 SELECT a.* INTO approved FROM verivaro_private.project_lifecycle_events a JOIN verivaro_private.project_lifecycle_events r ON a.parent_id=r.event_id WHERE a.tenant_id=t AND a.project_id=p AND a.kind='disposal_approved' AND r.parent_id=pol.event_id AND NOT EXISTS(SELECT 1 FROM verivaro_private.project_lifecycle_events x WHERE x.tenant_id=t AND x.project_id=p AND x.sequence>r.sequence AND x.kind IN ('hold','policy')) ORDER BY a.sequence DESC LIMIT 1;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('eventId',x.event_id,'sequence',x.sequence,'kind',x.kind,'parentId',x.parent_id,'reason',x.reason,'retainUntil',CASE WHEN x.retain_until IS NULL THEN NULL ELSE to_char(x.retain_until AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,'backupDays',x.backup_days,'recordedAt',x.created_at) ORDER BY x.sequence),'[]'::jsonb) INTO items FROM verivaro_private.project_lifecycle_events x WHERE x.tenant_id=t AND x.project_id=p;
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'sequence',n,'archived',closed,'canWrite',tr='owner' AND pr='owner','canReview',tr='reviewer' AND pr='reviewer','activeHoldCount',holds,'currentPolicyId',pol.event_id,'eligibleForDisposalReview',eligible,'approvalCurrent',eligible AND approved.event_id IS NOT NULL,'executionEnabled',false,'events',items);
END $list$;
-- Restricted portable preservation bundle input. Archived only, no new shares,
-- no secret or session data. Legacy or oversized originals are refused.
CREATE FUNCTION verivaro_verification.portable_archive_inventory(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $inventory$
DECLARE c text[];r jsonb;q jsonb;l jsonb;
BEGIN
 c:=verivaro_private.lifecycle_actor(t,p,'owner');
 IF NOT EXISTS(SELECT 1 FROM verivaro.projects x WHERE x.tenant_id=t AND x.id=p AND x.archived_at IS NOT NULL) THEN RAISE EXCEPTION 'archive export requires archived project' USING ERRCODE='42501';END IF;
 r:=verivaro_mutation.project_report(t,p)-'generatedAt';
 IF jsonb_array_length(r->'evidence')>64 OR (r->'summary'->>'bytes')::bigint>16777216 OR EXISTS(SELECT 1 FROM jsonb_array_elements(r->'evidence') x WHERE x->>'storage'<>'encrypted') THEN RAISE EXCEPTION 'portable archive capacity or legacy storage' USING ERRCODE='54000';END IF;
 q:=verivaro_verification.assessment(t,p);
 l:=verivaro_verification.lifecycle_records(t,p);
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'classification','internal preservation copy; not approval or full database backup','report',r,'assessment',q,'lifecycle',l);
END $inventory$;
REVOKE ALL ON FUNCTION verivaro_private.lifecycle_actor(uuid,uuid,text),verivaro_private.lifecycle_active_holds(uuid,uuid),verivaro_verification.write_lifecycle_event(uuid,uuid,uuid,integer,text,uuid,text,text,integer),verivaro_verification.lifecycle_records(uuid,uuid),verivaro_verification.portable_archive_inventory(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.write_lifecycle_event(uuid,uuid,uuid,integer,text,uuid,text,text,integer),verivaro_verification.lifecycle_records(uuid,uuid),verivaro_verification.portable_archive_inventory(uuid,uuid) TO verivaro_runtime;
ALTER TABLE verivaro_private.trustproof_entries DROP CONSTRAINT trustproof_entries_source_type_check;
ALTER TABLE verivaro_private.trustproof_entries ADD CONSTRAINT trustproof_entries_source_type_check CHECK(source_type IN ('requirement_versions','requirement_reviews','requirement_evidence_links','requirement_link_reviews','requirement_sources','requirement_dependencies','requirement_dependency_reviews','requirement_dependency_removals','requirement_dependency_removal_reviews','submission_snapshots','submission_reviews','submission_authorizations','prooflock_milestones','prooflock_windows','prooflock_window_reviews','prooflock_capture_receipts','prooflock_alert_policies','prooflock_recovery_proposals','prooflock_recovery_reviews','financial_records','financial_versions','financial_reviews','project_chronology','project_chronology_reviews','acknowledgement_grants','acknowledgement_revocations','acknowledgement_events','resolution_tasks','resolution_task_events','customer_package_grants','customer_package_revocations','customer_package_reads','export_template_versions','organisation_template_publications','organisation_template_imports','project_lifecycle_events'));
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
 (SELECT count(*) FROM verivaro_private.customer_package_reads x JOIN verivaro_private.customer_package_grants q USING(grant_id) WHERE q.tenant_id=t AND q.project_id=p)+(SELECT count(*) FROM verivaro_private.export_template_versions x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.organisation_template_publications x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.organisation_template_imports x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.project_lifecycle_events x WHERE x.tenant_id=t AND x.project_id=p) INTO source_count;
 SELECT count(*) INTO actual_count FROM verivaro_private.trustproof_entries x WHERE x.tenant_id=t AND x.project_id=p;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('sequence',x.sequence,'sourceType',x.source_type,'sourceId',x.source_id,'origin',x.origin,'recordedAt',x.recorded_at,'sourceDigest',x.source_digest,'previousHash',x.previous_hash,'entryHash',x.entry_hash,'sourceIntact',COALESCE(v.tenant_id=t AND v.project_id=p AND v.source_digest=x.source_digest,false)) ORDER BY x.sequence),'[]'::jsonb)
 INTO items FROM (SELECT * FROM verivaro_private.trustproof_entries e WHERE e.tenant_id=t AND e.project_id=p AND e.sequence>after_sequence ORDER BY e.sequence LIMIT page_size) x LEFT JOIN LATERAL verivaro_private.trustproof_source(x.source_type,x.source_id) v ON true;
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'afterSequence',after_sequence,'previousHash',COALESCE(before_hash,repeat('0',64)),'headSequence',n,'headHash',head,'sourceCount',source_count,'ledgerCount',actual_count,'entries',items);
END $page$;
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.project_lifecycle_events FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('event_id');
COMMIT;
