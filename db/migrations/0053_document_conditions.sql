BEGIN;
CREATE TABLE verivaro_private.requirement_document_conditions(
 version_id uuid PRIMARY KEY REFERENCES verivaro_private.requirement_versions(version_id),
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,metadata_version_id uuid NOT NULL REFERENCES verivaro_private.evidence_metadata_versions(version_id),
 kind text NOT NULL CHECK(kind IN ('certificate','warranty','inspection')),identifier text NOT NULL,equipment text NOT NULL,issuer text NOT NULL,
 reason text NOT NULL,actor_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id));
REVOKE ALL ON verivaro_private.requirement_document_conditions FROM PUBLIC;
CREATE TRIGGER document_condition_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.requirement_document_conditions FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER document_condition_archive_guard BEFORE INSERT ON verivaro_private.requirement_document_conditions FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE FUNCTION verivaro_verification.pin_document_condition(t uuid,p uuid,v uuid,m uuid,k text,ident text,equip text,issuer_text text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $pin$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;x verivaro_private.evidence_metadata_versions%ROWTYPE;old verivaro_private.requirement_document_conditions%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');q:=verivaro_private.graph_current(t,p,v);
 IF q.author_id<>c[2]::uuid OR q.applicability NOT IN ('required','optional') OR k IS NULL OR k NOT IN ('certificate','warranty','inspection') OR NOT verivaro_private.metadata_field(ident) OR NOT verivaro_private.metadata_field(equip) OR NOT verivaro_private.metadata_field(issuer_text) OR NOT verivaro_private.workflow_reason(why) THEN RAISE EXCEPTION 'condition denied' USING ERRCODE='42501';END IF;
 SELECT * INTO old FROM verivaro_private.requirement_document_conditions x WHERE x.version_id=v;
 IF FOUND THEN
 IF old.tenant_id<>t OR old.project_id<>p OR old.metadata_version_id<>m OR old.actor_id<>c[2]::uuid OR old.kind<>k OR old.identifier<>ident OR old.equipment<>equip OR old.issuer<>issuer_text OR old.reason<>why THEN RAISE EXCEPTION 'condition conflict' USING ERRCODE='23505';END IF;
 RETURN true;
 END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_reviews x WHERE x.version_id=v) THEN RAISE EXCEPTION 'criterion already reviewed' USING ERRCODE='23505';END IF;
 SELECT * INTO x FROM verivaro_private.evidence_metadata_versions e WHERE e.tenant_id=t AND e.project_id=p AND e.version_id=m;
 IF NOT FOUND OR x.kind<>k OR x.identifier<>ident OR x.equipment<>equip OR x.issuer<>issuer_text
 OR x.issued_on IS NULL OR x.expires_on IS NULL OR x.issued_on>(clock_timestamp() AT TIME ZONE 'UTC')::date OR x.expires_on<(clock_timestamp() AT TIME ZONE 'UTC')::date
 OR EXISTS(SELECT 1 FROM verivaro_private.evidence_metadata_versions n WHERE n.evidence_id=x.evidence_id AND n.revision>x.revision)
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_metadata_reviews r WHERE r.version_id=m AND r.decision='approved')
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t AND o.project_id=p AND o.evidence_id=x.evidence_id AND o.sha256=x.sha256 AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256'))
 THEN RAISE EXCEPTION 'document condition source unavailable' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro_private.requirement_document_conditions(version_id,tenant_id,project_id,metadata_version_id,kind,identifier,equipment,issuer,reason,actor_id,session_id)
 VALUES(v,t,p,m,k,ident,equip,issuer_text,why,c[2]::uuid,c[3]::uuid);
 RETURN true;
END $pin$;
CREATE FUNCTION verivaro_private.document_condition(t uuid,p uuid,v uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $condition$
DECLARE c verivaro_private.requirement_document_conditions%ROWTYPE;m verivaro_private.evidence_metadata_versions%ROWTYPE;s text;today date:=(statement_timestamp() AT TIME ZONE 'UTC')::date;
BEGIN
 SELECT * INTO c FROM verivaro_private.requirement_document_conditions x WHERE x.tenant_id=t AND x.project_id=p AND x.version_id=v;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT * INTO m FROM verivaro_private.evidence_metadata_versions x WHERE x.tenant_id=t AND x.project_id=p AND x.version_id=c.metadata_version_id;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects o JOIN verivaro.evidence e ON e.id=o.evidence_id AND e.tenant_id=t AND e.project_id=p AND e.sha256=o.sha256 AND e.created_by=o.actor_id AND e.storage_ref='db-encrypted-v1' WHERE o.tenant_id=t AND o.project_id=p AND o.evidence_id=m.evidence_id AND o.sha256=m.sha256 AND octet_length(o.envelope)=o.bytes+28 AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256')) THEN s:='integrity_failure';
 ELSIF m.kind<>c.kind OR m.identifier<>c.identifier OR m.equipment<>c.equipment OR m.issuer<>c.issuer THEN s:='field_mismatch';
 ELSIF EXISTS(SELECT 1 FROM verivaro_private.evidence_metadata_versions n WHERE n.evidence_id=m.evidence_id AND n.revision>m.revision) THEN s:='superseded_metadata';
 ELSIF NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_metadata_reviews r WHERE r.version_id=m.version_id AND r.decision='approved') THEN s:='metadata_unapproved';
 ELSIF m.issued_on IS NULL OR m.expires_on IS NULL THEN s:='unknown_dates';
 ELSIF m.issued_on>today THEN s:='future_issue';
 ELSIF m.expires_on<today THEN s:='expired';
 ELSIF NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_evidence_links b JOIN verivaro_private.requirement_link_reviews r USING(link_id) WHERE b.version_id=v AND b.evidence_id=m.evidence_id AND b.sha256=m.sha256 AND r.decision='pass') THEN s:='matching_link_required';
 ELSE s:='satisfied';END IF;
 RETURN jsonb_build_object('metadataVersionId',c.metadata_version_id,'evidenceId',m.evidence_id,'sha256',m.sha256,'kind',c.kind,'identifier',c.identifier,'equipment',c.equipment,'issuer',c.issuer,'issuedOn',m.issued_on,'expiresOn',m.expires_on,'reason',c.reason,'status',s,'issuerVerified',false);
END $condition$;
-- A revised applicable criterion must preserve the explicit documentary
-- constraint. A reviewed not-applicable decision remains an explicit route.
CREATE FUNCTION verivaro_private.document_condition_continuity() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $continuity$
DECLARE q verivaro_private.requirement_versions%ROWTYPE;
BEGIN
 IF NEW.decision<>'approved' THEN RETURN NEW;END IF;
 SELECT * INTO q FROM verivaro_private.requirement_versions WHERE version_id=NEW.version_id;
 IF q.applicability IN ('required','optional') AND EXISTS(SELECT 1 FROM verivaro_private.requirement_versions r JOIN verivaro_private.requirement_document_conditions d USING(version_id) WHERE r.tenant_id=q.tenant_id AND r.project_id=q.project_id AND r.requirement_id=q.requirement_id AND r.revision<q.revision)
 AND NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_document_conditions d WHERE d.version_id=q.version_id) THEN RAISE EXCEPTION 'document condition continuity required' USING ERRCODE='23505';END IF;
 RETURN NEW;
END $continuity$;
CREATE TRIGGER document_condition_continuity BEFORE INSERT ON verivaro_private.requirement_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.document_condition_continuity();
-- Integrate before dependency fingerprints, not in a presentation-only layer.
ALTER FUNCTION verivaro_private.local_assessment(uuid,uuid) RENAME TO base_evidence_assessment;
CREATE FUNCTION verivaro_private.local_assessment(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $local$
DECLARE g jsonb;q jsonb;cond jsonb;items jsonb:='[]'::jsonb;
BEGIN
 g:=verivaro_private.base_evidence_assessment(t,p);
 FOR q IN SELECT value FROM jsonb_array_elements(g->'requirements') LOOP
 cond:=verivaro_private.document_condition(t,p,(q->>'versionId')::uuid);
 IF cond IS NOT NULL THEN
  q:=q||jsonb_build_object('documentCondition',cond);
  IF cond->>'status'='integrity_failure' THEN q:=jsonb_set(q,'{state}','"integrity_failure"'::jsonb);
  ELSIF q->>'state'='satisfied' AND cond->>'status'<>'satisfied' THEN q:=jsonb_set(q,'{state}',CASE WHEN cond->>'status'='matching_link_required' THEN '"missing_evidence"'::jsonb ELSE '"failed"'::jsonb END);END IF;
 END IF;
 items:=items||jsonb_build_array(q);
 END LOOP;
 RETURN jsonb_set(g,'{requirements}',items);
END $local$;
REVOKE ALL ON FUNCTION verivaro_private.local_assessment(uuid,uuid),verivaro_private.document_condition(uuid,uuid,uuid),verivaro_private.document_condition_continuity() FROM PUBLIC;
REVOKE ALL ON FUNCTION verivaro_verification.pin_document_condition(uuid,uuid,uuid,uuid,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.pin_document_condition(uuid,uuid,uuid,uuid,text,text,text,text,text) TO verivaro_runtime;
CREATE OR REPLACE FUNCTION verivaro_private.dependency_assessment(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $evaluate$
DECLARE g jsonb;done jsonb:='{}'::jsonb;outcome jsonb;remaining integer;progress integer;q jsonb;item jsonb;deps jsonb;parent jsonb;d record;failed boolean;local_text jsonb;rid text;fp text;
BEGIN
 g:=verivaro_private.local_assessment(t,p);
 remaining:=jsonb_array_length(g->'requirements');
 WHILE remaining>0 LOOP
  progress:=0;
  FOR q IN SELECT value FROM jsonb_array_elements(g->'requirements') LOOP
   rid:=q->>'requirementId';
   IF done ? rid THEN CONTINUE;END IF;
   IF EXISTS(SELECT 1 FROM verivaro_private.requirement_dependencies e WHERE e.tenant_id=t AND e.project_id=p AND e.dependent_version_id=(q->>'versionId')::uuid AND NOT (done ? e.prerequisite_id::text)) THEN CONTINUE;END IF;
   deps:='[]'::jsonb;failed:=false;
   FOR d IN SELECT e.*,v.decision,v.reason FROM verivaro_private.requirement_dependencies e LEFT JOIN verivaro_private.requirement_dependency_reviews v USING(edge_id)
    WHERE e.tenant_id=t AND e.project_id=p AND e.dependent_version_id=(q->>'versionId')::uuid ORDER BY e.prerequisite_id LOOP
    parent:=done->d.prerequisite_id::text;
    IF parent IS NULL THEN RAISE EXCEPTION 'dependency graph invalid' USING ERRCODE='23505';END IF;
    IF d.decision IS DISTINCT FROM 'approved' OR parent->>'state' IS DISTINCT FROM 'satisfied' OR parent->>'_fingerprint' IS DISTINCT FROM d.prerequisite_fingerprint THEN failed:=true;END IF;
    deps:=deps||jsonb_build_array(jsonb_build_object('edgeId',d.edge_id,'prerequisiteId',d.prerequisite_id,'pinnedFingerprint',d.prerequisite_fingerprint,'currentFingerprint',parent->>'_fingerprint','prerequisiteState',parent->>'state','decision',COALESCE(d.decision,'pending'),'reason',d.reason));
   END LOOP;
   item:=q;
   IF jsonb_array_length(deps)>0 THEN
    item:=item||jsonb_build_object('dependencyPins',deps,'localState',q->>'state');
    IF failed AND q->>'state'<>'integrity_failure' THEN item:=jsonb_set(item,'{state}','"dependency_blocked"'::jsonb);END IF;
   END IF;
   local_text:=(item-'canRevise'-'canReview'-'canLink'-'links')||jsonb_build_object('links',COALESCE((SELECT jsonb_agg(x-'canReview' ORDER BY x->>'linkId') FROM jsonb_array_elements(item->'links') x),'[]'::jsonb));
   fp:=encode(verivaro_private.digest(convert_to(jsonb_build_array(t,p,local_text)::text,'UTF8'),'sha256'),'hex');
   done:=done||jsonb_build_object(rid,item||jsonb_build_object('_fingerprint',fp));
   remaining:=remaining-1;progress:=progress+1;
  END LOOP;
  IF progress=0 THEN RAISE EXCEPTION 'dependency graph invalid' USING ERRCODE='23505';END IF;
 END LOOP;
 SELECT COALESCE(jsonb_agg(value ORDER BY key),'[]'::jsonb) INTO outcome FROM jsonb_each(done);
 RETURN jsonb_set(g,'{requirements}',outcome);
END $evaluate$;
CREATE OR REPLACE FUNCTION verivaro_private.customer_graph_stamp(t uuid,p uuid) RETURNS text
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
,(SELECT COALESCE(jsonb_agg(verivaro_private.document_condition(t,p,x.version_id) ORDER BY x.version_id),'[]'::jsonb) FROM verivaro_private.requirement_document_conditions x JOIN verivaro_private.requirement_versions q USING(version_id) WHERE x.tenant_id=t AND x.project_id=p AND NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_versions n WHERE n.requirement_id=q.requirement_id AND n.tenant_id=t AND n.project_id=p AND n.revision>q.revision))
 )::text,'UTF8'),'sha256'),'hex')
$stamp$;
ALTER TABLE verivaro_private.trustproof_entries DROP CONSTRAINT trustproof_entries_source_type_check;
ALTER TABLE verivaro_private.trustproof_entries ADD CONSTRAINT trustproof_entries_source_type_check CHECK(source_type IN ('requirement_versions','requirement_reviews','requirement_evidence_links','requirement_link_reviews','requirement_sources','requirement_dependencies','requirement_dependency_reviews','requirement_dependency_removals','requirement_dependency_removal_reviews','submission_snapshots','submission_reviews','submission_authorizations','prooflock_milestones','prooflock_windows','prooflock_window_reviews','prooflock_capture_receipts','prooflock_alert_policies','prooflock_recovery_proposals','prooflock_recovery_reviews','financial_records','financial_versions','financial_reviews','project_chronology','project_chronology_reviews','acknowledgement_grants','acknowledgement_revocations','acknowledgement_events','resolution_tasks','resolution_task_events','customer_package_grants','customer_package_revocations','customer_package_reads','export_template_versions','organisation_template_publications','organisation_template_imports','project_lifecycle_events','evidence_metadata_versions','evidence_metadata_reviews','requirement_document_conditions'));
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
 WHEN 'requirement_document_conditions' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_document_conditions x WHERE x.version_id=r;
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
 (SELECT count(*) FROM verivaro_private.customer_package_reads x JOIN verivaro_private.customer_package_grants q USING(grant_id) WHERE q.tenant_id=t AND q.project_id=p)+(SELECT count(*) FROM verivaro_private.export_template_versions x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.organisation_template_publications x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.organisation_template_imports x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.project_lifecycle_events x WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.evidence_metadata_versions x  WHERE x.tenant_id=t AND x.project_id=p)+(SELECT count(*) FROM verivaro_private.evidence_metadata_reviews x JOIN verivaro_private.evidence_metadata_versions q USING(version_id) WHERE q.tenant_id=t AND q.project_id=p)+(SELECT count(*) FROM verivaro_private.requirement_document_conditions x WHERE x.tenant_id=t AND x.project_id=p) INTO source_count;
 SELECT count(*) INTO actual_count FROM verivaro_private.trustproof_entries x WHERE x.tenant_id=t AND x.project_id=p;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('sequence',x.sequence,'sourceType',x.source_type,'sourceId',x.source_id,'origin',x.origin,'recordedAt',x.recorded_at,'sourceDigest',x.source_digest,'previousHash',x.previous_hash,'entryHash',x.entry_hash,'sourceIntact',COALESCE(v.tenant_id=t AND v.project_id=p AND v.source_digest=x.source_digest,false)) ORDER BY x.sequence),'[]'::jsonb)
 INTO items FROM (SELECT * FROM verivaro_private.trustproof_entries e WHERE e.tenant_id=t AND e.project_id=p AND e.sequence>after_sequence ORDER BY e.sequence LIMIT page_size) x LEFT JOIN LATERAL verivaro_private.trustproof_source(x.source_type,x.source_id) v ON true;
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'afterSequence',after_sequence,'previousHash',COALESCE(before_hash,repeat('0',64)),'headSequence',n,'headHash',head,'sourceCount',source_count,'ledgerCount',actual_count,'entries',items);
END $page$;
CREATE TRIGGER trustproof_append AFTER INSERT ON verivaro_private.requirement_document_conditions FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('version_id');
COMMIT;
