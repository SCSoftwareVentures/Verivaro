BEGIN;
SET LOCAL TimeZone='UTC';
-- Locked during initial reconciliation so no insert can fall between the
-- deterministic backfill and installation of the live capture triggers.
LOCK TABLE verivaro_private.requirement_versions, verivaro_private.requirement_reviews, verivaro_private.requirement_evidence_links, verivaro_private.requirement_link_reviews, verivaro_private.requirement_sources, verivaro_private.requirement_dependencies, verivaro_private.requirement_dependency_reviews, verivaro_private.requirement_dependency_removals, verivaro_private.requirement_dependency_removal_reviews, verivaro_private.submission_snapshots, verivaro_private.submission_reviews, verivaro_private.submission_authorizations, verivaro_private.prooflock_milestones, verivaro_private.prooflock_windows, verivaro_private.prooflock_window_reviews, verivaro_private.prooflock_capture_receipts, verivaro_private.prooflock_alert_policies, verivaro_private.prooflock_recovery_proposals, verivaro_private.prooflock_recovery_reviews, verivaro_private.financial_records, verivaro_private.financial_versions, verivaro_private.financial_reviews, verivaro_private.project_chronology, verivaro_private.project_chronology_reviews, verivaro_private.acknowledgement_grants, verivaro_private.acknowledgement_revocations, verivaro_private.acknowledgement_events, verivaro_private.resolution_tasks, verivaro_private.resolution_task_events, verivaro_private.customer_package_grants, verivaro_private.customer_package_revocations, verivaro_private.customer_package_reads IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE verivaro_private.trustproof_entries(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,sequence bigint NOT NULL CHECK(sequence>0),
 source_type text NOT NULL CHECK(source_type IN ('requirement_versions','requirement_reviews','requirement_evidence_links','requirement_link_reviews','requirement_sources','requirement_dependencies','requirement_dependency_reviews','requirement_dependency_removals','requirement_dependency_removal_reviews','submission_snapshots','submission_reviews','submission_authorizations','prooflock_milestones','prooflock_windows','prooflock_window_reviews','prooflock_capture_receipts','prooflock_alert_policies','prooflock_recovery_proposals','prooflock_recovery_reviews','financial_records','financial_versions','financial_reviews','project_chronology','project_chronology_reviews','acknowledgement_grants','acknowledgement_revocations','acknowledgement_events','resolution_tasks','resolution_task_events','customer_package_grants','customer_package_revocations','customer_package_reads')),source_id uuid NOT NULL,
 origin text NOT NULL CHECK(origin IN ('backfill','live')),recorded_at text NOT NULL CHECK(recorded_at~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'),
 source_digest text NOT NULL CHECK(source_digest~'^[a-f0-9]{64}$'),previous_hash text NOT NULL CHECK(previous_hash~'^[a-f0-9]{64}$'),entry_hash text NOT NULL CHECK(entry_hash~'^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,project_id,sequence),UNIQUE(source_type,source_id),FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id));
REVOKE ALL ON verivaro_private.trustproof_entries FROM PUBLIC;
CREATE TRIGGER trustproof_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.trustproof_entries FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE FUNCTION verivaro_private.trustproof_source(k text,r uuid) RETURNS TABLE(tenant_id uuid,project_id uuid,source_digest text)
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
 ELSE RAISE EXCEPTION 'unknown trustproof source' USING ERRCODE='22023';
 END CASE;
 IF FOUND THEN RETURN NEXT;END IF;
END $source$;
CREATE FUNCTION verivaro_private.trustproof_append(t uuid,p uuid,k text,r uuid,origin_value text,h text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $append$
DECLARE seq bigint;prev text;stamp text;entry text;
BEGIN
 IF t IS NULL OR p IS NULL OR r IS NULL OR h IS NULL THEN RAISE EXCEPTION 'missing trustproof scope';END IF;
 -- Serialize only this project's append stream; a hash collision can only
 -- serialize unrelated writers, never mix their records.
 PERFORM pg_advisory_xact_lock(174802413,hashtext(t::text||':'||p::text));
 SELECT x.sequence,x.entry_hash INTO seq,prev FROM verivaro_private.trustproof_entries x WHERE x.tenant_id=t AND x.project_id=p ORDER BY x.sequence DESC LIMIT 1;
 seq:=COALESCE(seq,0)+1;prev:=COALESCE(prev,repeat('0',64));
 stamp:=to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
 entry:=encode(verivaro_private.digest(convert_to(concat_ws('|','trustproof-v1',t,p,seq,k,r,origin_value,stamp,h,prev),'UTF8'),'sha256'),'hex');
 INSERT INTO verivaro_private.trustproof_entries VALUES(t,p,seq,k,r,origin_value,stamp,h,prev,entry);
END $append$;
CREATE FUNCTION verivaro_private.trustproof_capture() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private SET TimeZone='UTC' AS $capture$
DECLARE r uuid;v record;
BEGIN
 r:=(to_jsonb(NEW)->>TG_ARGV[0])::uuid;
 SELECT * INTO v FROM verivaro_private.trustproof_source(TG_TABLE_NAME,r);
 IF NOT FOUND THEN RAISE EXCEPTION 'missing trustproof source';END IF;
 PERFORM verivaro_private.trustproof_append(v.tenant_id,v.project_id,TG_TABLE_NAME,r,'live',v.source_digest);RETURN NEW;
END $capture$;
REVOKE ALL ON FUNCTION verivaro_private.trustproof_source(text,uuid),verivaro_private.trustproof_append(uuid,uuid,text,uuid,text,text),verivaro_private.trustproof_capture() FROM PUBLIC;
-- Backfill order is structural, not an assertion of historical event order.
DO $backfill$
BEGIN
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'requirement_versions',x.version_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.requirement_versions x  ORDER BY x.tenant_id,x.project_id,x.version_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'requirement_reviews',x.version_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.requirement_reviews x JOIN verivaro_private.requirement_versions q USING(version_id) ORDER BY q.tenant_id,q.project_id,x.version_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'requirement_evidence_links',x.link_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.requirement_evidence_links x JOIN verivaro_private.requirement_versions q USING(version_id) ORDER BY q.tenant_id,q.project_id,x.link_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'requirement_link_reviews',x.link_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.requirement_link_reviews x JOIN verivaro_private.requirement_evidence_links l USING(link_id) JOIN verivaro_private.requirement_versions q ON q.version_id=l.version_id ORDER BY q.tenant_id,q.project_id,x.link_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'requirement_sources',x.version_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.requirement_sources x  ORDER BY x.tenant_id,x.project_id,x.version_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'requirement_dependencies',x.edge_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.requirement_dependencies x  ORDER BY x.tenant_id,x.project_id,x.edge_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'requirement_dependency_reviews',x.edge_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.requirement_dependency_reviews x JOIN verivaro_private.requirement_dependencies q USING(edge_id) ORDER BY q.tenant_id,q.project_id,x.edge_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'requirement_dependency_removals',x.removal_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.requirement_dependency_removals x  ORDER BY x.tenant_id,x.project_id,x.removal_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'requirement_dependency_removal_reviews',x.removal_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.requirement_dependency_removal_reviews x JOIN verivaro_private.requirement_dependency_removals q USING(removal_id) ORDER BY q.tenant_id,q.project_id,x.removal_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'submission_snapshots',x.submission_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.submission_snapshots x  ORDER BY x.tenant_id,x.project_id,x.submission_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'submission_reviews',x.submission_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.submission_reviews x JOIN verivaro_private.submission_snapshots q USING(submission_id) ORDER BY q.tenant_id,q.project_id,x.submission_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'submission_authorizations',x.submission_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.submission_authorizations x JOIN verivaro_private.submission_snapshots q USING(submission_id) ORDER BY q.tenant_id,q.project_id,x.submission_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'prooflock_milestones',x.revision_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.prooflock_milestones x  ORDER BY x.tenant_id,x.project_id,x.revision_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'prooflock_windows',x.window_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.prooflock_windows x  ORDER BY x.tenant_id,x.project_id,x.window_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'prooflock_window_reviews',x.window_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.prooflock_window_reviews x JOIN verivaro_private.prooflock_windows q USING(window_id) ORDER BY q.tenant_id,q.project_id,x.window_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'prooflock_capture_receipts',x.link_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.prooflock_capture_receipts x  ORDER BY x.tenant_id,x.project_id,x.link_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'prooflock_alert_policies',x.policy_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.prooflock_alert_policies x  ORDER BY x.tenant_id,x.project_id,x.policy_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'prooflock_recovery_proposals',x.recovery_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.prooflock_recovery_proposals x  ORDER BY x.tenant_id,x.project_id,x.recovery_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'prooflock_recovery_reviews',x.recovery_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.prooflock_recovery_reviews x JOIN verivaro_private.prooflock_recovery_proposals q USING(recovery_id) ORDER BY q.tenant_id,q.project_id,x.recovery_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'financial_records',x.record_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.financial_records x  ORDER BY x.tenant_id,x.project_id,x.record_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'financial_versions',x.version_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.financial_versions x JOIN verivaro_private.financial_records q USING(record_id) ORDER BY q.tenant_id,q.project_id,x.version_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'financial_reviews',x.version_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.financial_reviews x JOIN verivaro_private.financial_versions v USING(version_id) JOIN verivaro_private.financial_records q ON q.record_id=v.record_id ORDER BY q.tenant_id,q.project_id,x.version_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'project_chronology',x.event_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.project_chronology x  ORDER BY x.tenant_id,x.project_id,x.event_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'project_chronology_reviews',x.event_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.project_chronology_reviews x JOIN verivaro_private.project_chronology q USING(event_id) ORDER BY q.tenant_id,q.project_id,x.event_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'acknowledgement_grants',x.grant_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.acknowledgement_grants x  ORDER BY x.tenant_id,x.project_id,x.grant_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'acknowledgement_revocations',x.grant_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.acknowledgement_revocations x JOIN verivaro_private.acknowledgement_grants q USING(grant_id) ORDER BY q.tenant_id,q.project_id,x.grant_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'acknowledgement_events',x.event_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.acknowledgement_events x JOIN verivaro_private.acknowledgement_grants q USING(grant_id) ORDER BY q.tenant_id,q.project_id,x.event_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'resolution_tasks',x.task_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.resolution_tasks x  ORDER BY x.tenant_id,x.project_id,x.task_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'resolution_task_events',x.event_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.resolution_task_events x JOIN verivaro_private.resolution_tasks q USING(task_id) ORDER BY q.tenant_id,q.project_id,x.event_id;
PERFORM verivaro_private.trustproof_append(x.tenant_id,x.project_id,'customer_package_grants',x.grant_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.customer_package_grants x  ORDER BY x.tenant_id,x.project_id,x.grant_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'customer_package_revocations',x.grant_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.customer_package_revocations x JOIN verivaro_private.customer_package_grants q USING(grant_id) ORDER BY q.tenant_id,q.project_id,x.grant_id;
PERFORM verivaro_private.trustproof_append(q.tenant_id,q.project_id,'customer_package_reads',x.read_id,'backfill',encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex')) FROM verivaro_private.customer_package_reads x JOIN verivaro_private.customer_package_grants q USING(grant_id) ORDER BY q.tenant_id,q.project_id,x.read_id;
END $backfill$;
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.requirement_versions FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('version_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.requirement_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('version_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.requirement_evidence_links FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('link_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.requirement_link_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('link_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.requirement_sources FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('version_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.requirement_dependencies FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('edge_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.requirement_dependency_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('edge_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.requirement_dependency_removals FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('removal_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.requirement_dependency_removal_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('removal_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.submission_snapshots FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('submission_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.submission_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('submission_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.submission_authorizations FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('submission_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.prooflock_milestones FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('revision_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.prooflock_windows FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('window_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.prooflock_window_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('window_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.prooflock_capture_receipts FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('link_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.prooflock_alert_policies FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('policy_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.prooflock_recovery_proposals FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('recovery_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.prooflock_recovery_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('recovery_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.financial_records FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('record_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.financial_versions FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('version_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.financial_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('version_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.project_chronology FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('event_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.project_chronology_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('event_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.acknowledgement_grants FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('grant_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.acknowledgement_revocations FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('grant_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.acknowledgement_events FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('event_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.resolution_tasks FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('task_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.resolution_task_events FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('event_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.customer_package_grants FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('grant_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.customer_package_revocations FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('grant_id');
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.customer_package_reads FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('read_id');
CREATE FUNCTION verivaro_verification.trustproof_page(t uuid,p uuid,after_sequence integer,page_size integer) RETURNS jsonb
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
 (SELECT count(*) FROM verivaro_private.customer_package_reads x JOIN verivaro_private.customer_package_grants q USING(grant_id) WHERE q.tenant_id=t AND q.project_id=p) INTO source_count;
 SELECT count(*) INTO actual_count FROM verivaro_private.trustproof_entries x WHERE x.tenant_id=t AND x.project_id=p;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('sequence',x.sequence,'sourceType',x.source_type,'sourceId',x.source_id,'origin',x.origin,'recordedAt',x.recorded_at,'sourceDigest',x.source_digest,'previousHash',x.previous_hash,'entryHash',x.entry_hash,'sourceIntact',COALESCE(v.tenant_id=t AND v.project_id=p AND v.source_digest=x.source_digest,false)) ORDER BY x.sequence),'[]'::jsonb)
 INTO items FROM (SELECT * FROM verivaro_private.trustproof_entries e WHERE e.tenant_id=t AND e.project_id=p AND e.sequence>after_sequence ORDER BY e.sequence LIMIT page_size) x LEFT JOIN LATERAL verivaro_private.trustproof_source(x.source_type,x.source_id) v ON true;
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'afterSequence',after_sequence,'previousHash',COALESCE(before_hash,repeat('0',64)),'headSequence',n,'headHash',head,'sourceCount',source_count,'ledgerCount',actual_count,'entries',items);
END $page$;
REVOKE ALL ON FUNCTION verivaro_verification.trustproof_page(uuid,uuid,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.trustproof_page(uuid,uuid,integer,integer) TO verivaro_runtime;
COMMIT;
