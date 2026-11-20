BEGIN;
-- Preserve legacy source digests exactly; location is included only on new rows.
ALTER TABLE verivaro_private.requirement_sources ADD COLUMN office_location jsonb;
ALTER TABLE verivaro_private.requirement_sources DROP CONSTRAINT requirement_sources_algorithm_check;
ALTER TABLE verivaro_private.requirement_sources ADD CONSTRAINT requirement_sources_algorithm_check CHECK(algorithm IN ('modal-line-v1','obligation-line-v2','manual-source-line-v1','office-source-span-v1'));
ALTER TABLE verivaro_private.requirement_sources ADD CONSTRAINT requirement_sources_office_location_check CHECK((algorithm='office-source-span-v1' AND office_location IS NOT NULL AND page_number IS NULL) OR (algorithm<>'office-source-span-v1' AND office_location IS NULL));
CREATE FUNCTION verivaro_private.office_location_valid(media text,l jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $loc$
DECLARE k text;kind text;
BEGIN
 IF jsonb_typeof(l) IS DISTINCT FROM 'object' OR octet_length(l::text)>2048 OR COALESCE(l->>'partSha256','')!~'^[a-f0-9]{64}$' THEN RETURN false;END IF;
 IF media='application/vnd.openxmlformats-officedocument.wordprocessingml.document' THEN
 RETURN (l-ARRAY['part','partSha256','paragraph']='{}'::jsonb AND l->>'part'='word/document.xml' AND jsonb_typeof(l->'paragraph')='number' AND l->>'paragraph'~'^[1-9][0-9]{0,4}$') IS TRUE;
 ELSIF media='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' THEN
 kind:=l->>'valueKind';
 IF NOT COALESCE(l->>'part'~'^xl/worksheets/sheet([1-9]|[1-5][0-9]|6[0-4])\.xml$',false) OR NOT COALESCE(l->>'cell'~'^[A-Z]{1,2}[1-9][0-9]{0,3}$',false) OR NOT COALESCE(char_length(l->>'sheet') BETWEEN 1 AND 31,false) OR NOT COALESCE(jsonb_typeof(l->'sheetId')='number' AND l->>'sheetId'~'^[1-9][0-9]{0,4}$',false) THEN RETURN false;END IF;
 IF kind='s' THEN
 RETURN (l-ARRAY['part','partSha256','sheet','sheetId','cell','valueKind','sharedStringIndex','sharedStringPart','sharedStringPartSha256']='{}'::jsonb AND l->>'sharedStringPart'='xl/sharedStrings.xml' AND l->>'sharedStringPartSha256'~'^[a-f0-9]{64}$' AND jsonb_typeof(l->'sharedStringIndex')='number' AND l->>'sharedStringIndex'~'^(0|[1-9][0-9]{0,3})$') IS TRUE;
 ELSIF kind IN ('inlineStr','n') THEN RETURN (l-ARRAY['part','partSha256','sheet','sheetId','cell','valueKind']='{}'::jsonb) IS TRUE;END IF;
 END IF;
 RETURN false;
END $loc$;
REVOKE ALL ON FUNCTION verivaro_private.office_location_valid(text,jsonb) FROM PUBLIC;
CREATE FUNCTION verivaro_verification.import_office_source(t uuid,p uuid,r uuid,v uuid,e uuid,h text,ln integer,quote_text text,quote_hash text,app text,loc jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $import$
DECLARE prior verivaro_private.requirement_sources%ROWTYPE;outcome jsonb;media text;
BEGIN
 PERFORM verivaro_private.graph_actor(t,p,'submitter');
 IF r IS NULL OR v IS NULL OR e IS NULL OR h IS NULL OR ln IS NULL OR ln NOT BETWEEN 1 AND 8192 OR quote_text IS NULL OR char_length(quote_text) NOT BETWEEN 1 AND 1024 OR octet_length(quote_text)>4096 OR quote_text<>btrim(quote_text) OR quote_text~'[[:cntrl:]]' OR quote_hash IS DISTINCT FROM encode(verivaro_private.digest(convert_to(quote_text,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'office source denied' USING ERRCODE='42501';END IF;
 SELECT o.media_type INTO media FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t AND o.project_id=p AND o.evidence_id=e AND o.sha256=h AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256');
 IF NOT FOUND OR NOT verivaro_private.office_location_valid(media,loc) THEN RAISE EXCEPTION 'office source denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_sources WHERE version_id=v;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.evidence_id<>e OR prior.source_sha256<>h OR prior.line_number<>ln OR prior.page_number IS NOT NULL OR prior.quote_sha256<>quote_hash OR prior.algorithm<>'office-source-span-v1' OR prior.office_location IS DISTINCT FROM loc THEN RAISE EXCEPTION 'source conflict' USING ERRCODE='23505';END IF;
 RETURN verivaro_verification.write_requirement(t,p,r,v,0,'Source line '||ln,quote_text,app);
 END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_versions WHERE version_id=v) THEN RAISE EXCEPTION 'source conflict' USING ERRCODE='23505';END IF;
 outcome:=verivaro_verification.write_requirement(t,p,r,v,0,'Source line '||ln,quote_text,app);
 INSERT INTO verivaro_private.requirement_sources(version_id,tenant_id,project_id,evidence_id,source_sha256,line_number,page_number,quote_sha256,algorithm,office_location)
 VALUES(v,t,p,e,h,ln,NULL,quote_hash,'office-source-span-v1',loc);
 RETURN outcome;
END $import$;
REVOKE ALL ON FUNCTION verivaro_verification.import_office_source(uuid,uuid,uuid,uuid,uuid,text,integer,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.import_office_source(uuid,uuid,uuid,uuid,uuid,text,integer,text,text,text,jsonb) TO verivaro_runtime;
CREATE OR REPLACE FUNCTION verivaro_private.base_evidence_assessment(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $assessment$
DECLARE c text[];a uuid;items jsonb;summary jsonb;blocking integer;required_count integer;verified integer;tr text;pr text;closed boolean;can_write boolean;can_review boolean;
BEGIN
 c:=verivaro.bound_context();
 IF current_setting('transaction_isolation')<>'read committed' OR c IS NULL OR t IS NULL OR p IS NULL OR c[1]<>t::text OR NOT verivaro.active_identity() THEN RAISE EXCEPTION 'graph denied' USING ERRCODE='42501';END IF;
 a:=c[2]::uuid;
 SELECT m.role,pm.role,q.archived_at IS NOT NULL INTO tr,pr,closed FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id JOIN verivaro.projects q ON q.tenant_id=pm.tenant_id AND q.id=pm.project_id
 WHERE m.tenant_id=t AND m.actor_id=a AND m.revoked_at IS NULL AND pm.project_id=p AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp());
 IF NOT FOUND THEN RAISE EXCEPTION 'graph denied' USING ERRCODE='42501';END IF;
 can_write:=NOT closed AND tr IN ('owner','reviewer','contributor') AND pr IN ('owner','reviewer','contributor');
 can_review:=NOT closed AND tr='reviewer' AND pr='reviewer';
 WITH current_versions AS (
 SELECT DISTINCT ON (requirement_id) * FROM verivaro_private.requirement_versions WHERE tenant_id=t AND project_id=p ORDER BY requirement_id,revision DESC
 ),referenced AS (
 SELECT b.evidence_id FROM current_versions q JOIN verivaro_private.requirement_evidence_links b USING(version_id)
 UNION SELECT s.evidence_id FROM current_versions q JOIN verivaro_private.requirement_sources s USING(version_id)
 ),verified_objects AS MATERIALIZED (
 SELECT o.evidence_id,o.sha256,o.actor_id,
 (v.id IS NOT NULL AND v.storage_ref='db-encrypted-v1' AND v.sha256=o.sha256 AND v.created_by=o.actor_id
 AND octet_length(o.envelope)=o.bytes+28 AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256')) IS TRUE AS intact
 FROM referenced r JOIN verivaro_private.evidence_objects o ON o.evidence_id=r.evidence_id AND o.tenant_id=t AND o.project_id=p
 LEFT JOIN verivaro.evidence v ON v.id=o.evidence_id AND v.tenant_id=t AND v.project_id=p
 ),details AS (
 SELECT q.requirement_id AS "requirementId",q.version_id AS "versionId",q.revision,q.title,q.criterion,q.applicability,CASE WHEN src.version_id IS NULL THEN q.provenance ELSE 'source-line-v1' END AS provenance,
 CASE WHEN src.version_id IS NULL THEN NULL ELSE jsonb_build_object('evidenceId',src.evidence_id,'sha256',src.source_sha256,'line',src.line_number,'page',src.page_number,'quoteSha256',src.quote_sha256,'algorithm',src.algorithm)||CASE WHEN src.office_location IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('location',src.office_location) END END AS source,
 COALESCE(rv.decision,'pending') AS "ruleDecision",rv.reason AS "ruleReason",
 (can_write AND q.revision<16) AS "canRevise", (can_review AND q.author_id<>a AND rv.version_id IS NULL) AS "canReview",
 (can_write AND rv.decision='approved' AND q.applicability IN ('required','optional') AND jsonb_array_length(l.links)<8) IS TRUE AS "canLink",
 CASE WHEN l.invalid_count>0 OR (src.version_id IS NOT NULL AND (src.tenant_id<>t OR src.project_id<>p OR so.intact IS DISTINCT FROM true OR so.sha256 IS DISTINCT FROM src.source_sha256 OR src.quote_sha256 IS DISTINCT FROM encode(verivaro_private.digest(convert_to(q.criterion,'UTF8'),'sha256'),'hex'))) THEN 'integrity_failure'
 WHEN rv.decision='rejected' THEN 'rule_rejected'
 WHEN rv.decision IS DISTINCT FROM 'approved' THEN 'awaiting_rule_review'
 WHEN q.applicability='unknown' THEN 'unknown_applicability'
 WHEN q.applicability='not_applicable' THEN 'not_applicable'
 WHEN l.passes>0 AND l.failures>0 THEN 'conflict'
 WHEN l.failures>0 THEN 'failed'
 WHEN l.unresolved>0 THEN 'unresolved_evidence'
 WHEN l.passes>0 THEN 'satisfied' ELSE 'missing_evidence' END AS state,l.links
 FROM current_versions q LEFT JOIN verivaro_private.requirement_reviews rv USING(version_id) LEFT JOIN verivaro_private.requirement_sources src ON src.version_id=q.version_id LEFT JOIN verified_objects so ON so.evidence_id=src.evidence_id
 CROSS JOIN LATERAL (
 SELECT count(*) FILTER(WHERE z.decision='pass') AS passes,count(*) FILTER(WHERE z.decision='fail') AS failures,
 count(*) FILTER(WHERE z.decision IS NULL OR z.decision='unknown') AS unresolved,
 count(*) FILTER(WHERE o.intact IS DISTINCT FROM true OR o.sha256 IS DISTINCT FROM b.sha256) AS invalid_count,
 COALESCE(jsonb_agg(jsonb_build_object('linkId',b.link_id,'evidenceId',b.evidence_id,'sha256',b.sha256,'decision',COALESCE(z.decision,'pending'),'reason',z.reason,'integrity',(o.intact IS TRUE AND o.sha256=b.sha256) IS TRUE,'canReview',(o.intact IS TRUE AND o.sha256=b.sha256 AND can_review AND q.author_id<>a AND b.proposer_id<>a AND o.actor_id<>a AND z.link_id IS NULL)) ORDER BY b.link_id),'[]'::jsonb) AS links
 FROM verivaro_private.requirement_evidence_links b LEFT JOIN verified_objects o ON o.evidence_id=b.evidence_id LEFT JOIN verivaro_private.requirement_link_reviews z USING(link_id) WHERE b.version_id=q.version_id
 ) l
 ) SELECT COALESCE(jsonb_agg(to_jsonb(details) ORDER BY "requirementId"),'[]'::jsonb),
 count(*) FILTER(WHERE state IN ('awaiting_rule_review','rule_rejected','unknown_applicability','integrity_failure') OR (applicability='required' AND state<>'satisfied')),
 count(*) FILTER(WHERE applicability='required'),
 count(*) FILTER(WHERE applicability='required' AND state='satisfied')
 INTO items,blocking,required_count,verified FROM details;
 summary:=jsonb_build_object('requirements',jsonb_array_length(items),'required',required_count,'verifiedRequired',verified,'blockers',blocking,
 'status',CASE WHEN blocking>0 THEN 'blocked' WHEN required_count=0 THEN 'not_assessed' ELSE 'criteria_satisfied' END);
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'evaluatedAt',statement_timestamp(),'summary',summary,'requirements',items,'canWrite',can_write,'archived',closed,
 'scope','reviewed criteria subset only; not release authorization or certification');
END $assessment$;
CREATE OR REPLACE FUNCTION verivaro_private.customer_graph_stamp(t uuid,p uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private SET TimeZone='UTC' AS $stamp$
 SELECT encode(verivaro_private.digest(convert_to(jsonb_build_array(
 (SELECT jsonb_build_array(q.revision,q.name,q.archived_at) FROM verivaro.projects q WHERE q.tenant_id=t AND q.id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.version_id),'[]'::jsonb) FROM verivaro_private.requirement_versions x WHERE x.tenant_id=t AND x.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.version_id),'[]'::jsonb) FROM verivaro_private.requirement_reviews x JOIN verivaro_private.requirement_versions q USING(version_id) WHERE q.tenant_id=t AND q.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.link_id),'[]'::jsonb) FROM verivaro_private.requirement_evidence_links x JOIN verivaro_private.requirement_versions v USING(version_id) WHERE v.tenant_id=t AND v.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.link_id),'[]'::jsonb) FROM verivaro_private.requirement_link_reviews x JOIN verivaro_private.requirement_evidence_links q USING(link_id) JOIN verivaro_private.requirement_versions v USING(version_id) WHERE v.tenant_id=t AND v.project_id=p),
 (SELECT COALESCE(jsonb_agg(CASE WHEN x.office_location IS NULL THEN to_jsonb(x)-'office_location' ELSE to_jsonb(x) END ORDER BY x.version_id),'[]'::jsonb) FROM verivaro_private.requirement_sources x WHERE x.tenant_id=t AND x.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.edge_id),'[]'::jsonb) FROM verivaro_private.requirement_dependencies x WHERE x.tenant_id=t AND x.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.edge_id),'[]'::jsonb) FROM verivaro_private.requirement_dependency_reviews x JOIN verivaro_private.requirement_dependencies q USING(edge_id) WHERE q.tenant_id=t AND q.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.removal_id),'[]'::jsonb) FROM verivaro_private.requirement_dependency_removals x WHERE x.tenant_id=t AND x.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.removal_id),'[]'::jsonb) FROM verivaro_private.requirement_dependency_removal_reviews x JOIN verivaro_private.requirement_dependency_removals q USING(removal_id) WHERE q.tenant_id=t AND q.project_id=p)
,(SELECT COALESCE(jsonb_agg(verivaro_private.document_condition(t,p,x.version_id) ORDER BY x.version_id),'[]'::jsonb) FROM verivaro_private.requirement_document_conditions x JOIN verivaro_private.requirement_versions q USING(version_id) WHERE x.tenant_id=t AND x.project_id=p AND NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_versions n WHERE n.requirement_id=q.requirement_id AND n.tenant_id=t AND n.project_id=p AND n.revision>q.revision))
 )::text,'UTF8'),'sha256'),'hex')
$stamp$;
CREATE OR REPLACE FUNCTION verivaro_private.trustproof_source(k text,r uuid) RETURNS TABLE(tenant_id uuid,project_id uuid,source_digest text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private SET TimeZone='UTC' AS $source$
BEGIN
 CASE k
 WHEN 'requirement_versions' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_versions x  WHERE x.version_id=r;
 WHEN 'requirement_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_reviews x JOIN verivaro_private.requirement_versions q USING(version_id) WHERE x.version_id=r;
 WHEN 'requirement_evidence_links' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_evidence_links x JOIN verivaro_private.requirement_versions q USING(version_id) WHERE x.link_id=r;
 WHEN 'requirement_link_reviews' THEN SELECT q.tenant_id,q.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_link_reviews x JOIN verivaro_private.requirement_evidence_links l USING(link_id) JOIN verivaro_private.requirement_versions q ON q.version_id=l.version_id WHERE x.link_id=r;
 WHEN 'requirement_sources' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to((CASE WHEN x.office_location IS NULL THEN to_jsonb(x)-'office_location' ELSE to_jsonb(x) END)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.requirement_sources x  WHERE x.version_id=r;
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
 WHEN 'evidence_import_lineage' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.evidence_import_lineage x WHERE x.evidence_id=r;
 ELSE RAISE EXCEPTION 'unknown trustproof source' USING ERRCODE='22023';
 END CASE;
 IF FOUND THEN RETURN NEXT;END IF;
END $source$;
COMMIT;
