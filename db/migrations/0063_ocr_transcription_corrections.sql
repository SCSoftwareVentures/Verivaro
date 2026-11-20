BEGIN;
SET LOCAL TimeZone='UTC';
CREATE TABLE verivaro_private.ocr_transcription_corrections(
 correction_id uuid PRIMARY KEY,version_id uuid NOT NULL REFERENCES verivaro_private.requirement_versions(version_id),
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,revision integer NOT NULL CHECK(revision BETWEEN 1 AND 4),
 source_sha256 text NOT NULL CHECK(source_sha256~'^[a-f0-9]{64}$'),
 original_quote_sha256 text NOT NULL CHECK(original_quote_sha256~'^[a-f0-9]{64}$'),
 region_digest text NOT NULL CHECK(region_digest~'^[a-f0-9]{64}$'),
 corrected_text text NOT NULL CHECK(char_length(corrected_text) BETWEEN 1 AND 1024 AND octet_length(corrected_text)<=4096),
 corrected_sha256 text NOT NULL CHECK(corrected_sha256~'^[a-f0-9]{64}$'),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 8 AND 512 AND octet_length(reason)<=2048),
 author_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 UNIQUE(version_id,revision)
);
CREATE TABLE verivaro_private.ocr_transcription_correction_reviews(
 correction_id uuid PRIMARY KEY REFERENCES verivaro_private.ocr_transcription_corrections(correction_id),
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,reviewer_id uuid NOT NULL,session_id uuid NOT NULL,
 decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 8 AND 512 AND octet_length(reason)<=2048),
 reviewed_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
REVOKE ALL ON verivaro_private.ocr_transcription_corrections,verivaro_private.ocr_transcription_correction_reviews FROM PUBLIC;
CREATE TRIGGER correction_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.ocr_transcription_corrections FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER correction_review_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.ocr_transcription_correction_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER correction_archive_guard BEFORE INSERT ON verivaro_private.ocr_transcription_corrections FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE TRIGGER correction_review_archive_guard BEFORE INSERT ON verivaro_private.ocr_transcription_correction_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE FUNCTION verivaro_verification.propose_ocr_correction(t uuid,p uuid,i uuid,v uuid,h text,qh text,rh text,expected integer,corrected text,why text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $propose$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;prior verivaro_private.ocr_transcription_corrections%ROWTYPE;last_version record;next_revision integer;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');q:=verivaro_private.graph_current(t,p,v);
 IF i IS NULL OR q.author_id<>c[2]::uuid OR expected IS NULL OR expected NOT BETWEEN 0 AND 3 OR
 corrected IS NULL OR corrected<>btrim(corrected) OR char_length(corrected) NOT BETWEEN 1 AND 1024 OR octet_length(corrected)>4096 OR corrected~'[[:cntrl:]]' OR
 why IS NULL OR why<>btrim(why) OR char_length(why) NOT BETWEEN 8 AND 512 OR octet_length(why)>2048 OR why~'[[:cntrl:]]' OR
 EXISTS(SELECT 1 FROM verivaro_private.requirement_reviews rv WHERE rv.version_id=v) OR
 NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_sources s JOIN verivaro_private.evidence_objects o ON o.evidence_id=s.evidence_id AND o.tenant_id=s.tenant_id AND o.project_id=s.project_id WHERE s.version_id=v AND s.tenant_id=t AND s.project_id=p AND s.algorithm='ocr-human-source-v1' AND s.source_sha256=h AND s.quote_sha256=qh AND s.office_location->>'regionDigest'=rh AND o.sha256=h AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256') AND qh=encode(verivaro_private.digest(convert_to(q.criterion,'UTF8'),'sha256'),'hex')) OR
 corrected=q.criterion THEN RAISE EXCEPTION 'OCR correction denied' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(174802413,hashtext(t::text||':'||p::text||':'||v::text));
 SELECT * INTO prior FROM verivaro_private.ocr_transcription_corrections WHERE correction_id=i;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.version_id<>v OR prior.source_sha256<>h OR prior.original_quote_sha256<>qh OR prior.region_digest<>rh OR prior.corrected_text<>corrected OR prior.reason<>why OR prior.author_id<>c[2]::uuid OR prior.revision<>expected+1 THEN RAISE EXCEPTION 'OCR correction conflict' USING ERRCODE='23505';END IF;
 RETURN jsonb_build_object('correctionId',i,'revision',prior.revision);
 END IF;
 SELECT z.revision,rv.decision INTO last_version FROM verivaro_private.ocr_transcription_corrections z LEFT JOIN verivaro_private.ocr_transcription_correction_reviews rv USING(correction_id) WHERE z.version_id=v ORDER BY z.revision DESC LIMIT 1;
 next_revision:=COALESCE(last_version.revision,0)+1;
 IF next_revision<>expected+1 OR (next_revision>1 AND last_version.decision IS DISTINCT FROM 'rejected') THEN RAISE EXCEPTION 'OCR correction stale or pending' USING ERRCODE='23505';END IF;
 INSERT INTO verivaro_private.ocr_transcription_corrections(correction_id,version_id,tenant_id,project_id,revision,source_sha256,original_quote_sha256,region_digest,corrected_text,corrected_sha256,reason,author_id,session_id)
 VALUES(i,v,t,p,next_revision,h,qh,rh,corrected,encode(verivaro_private.digest(convert_to(corrected,'UTF8'),'sha256'),'hex'),why,c[2]::uuid,c[3]::uuid);
 RETURN jsonb_build_object('correctionId',i,'revision',next_revision);
END $propose$;
CREATE FUNCTION verivaro_verification.review_ocr_correction(t uuid,p uuid,i uuid,decision text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;proposal verivaro_private.ocr_transcription_corrections%ROWTYPE;prior verivaro_private.ocr_transcription_correction_reviews%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');
 SELECT * INTO proposal FROM verivaro_private.ocr_transcription_corrections WHERE correction_id=i AND tenant_id=t AND project_id=p;
 IF NOT FOUND THEN RAISE EXCEPTION 'OCR correction review denied' USING ERRCODE='42501';END IF;
 q:=verivaro_private.graph_current(t,p,proposal.version_id);
 IF q.author_id=c[2]::uuid OR proposal.author_id=c[2]::uuid OR
 EXISTS(SELECT 1 FROM verivaro_private.requirement_sources s JOIN verivaro_private.evidence_objects o ON o.evidence_id=s.evidence_id AND o.tenant_id=t AND o.project_id=p WHERE s.version_id=q.version_id AND o.actor_id=c[2]::uuid) OR
 EXISTS(SELECT 1 FROM verivaro_private.ocr_transcription_corrections newer WHERE newer.version_id=proposal.version_id AND newer.revision>proposal.revision) OR
 decision IS NULL OR decision NOT IN ('approved','rejected') OR why IS NULL OR why<>btrim(why) OR char_length(why) NOT BETWEEN 8 AND 512 OR octet_length(why)>2048 OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'OCR correction review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.ocr_transcription_correction_reviews WHERE correction_id=i;
 IF FOUND THEN
 IF prior.reviewer_id<>c[2]::uuid OR prior.decision<>decision OR prior.reason<>why THEN RAISE EXCEPTION 'OCR correction review conflict' USING ERRCODE='23505';END IF;
 RETURN true;
 END IF;
 INSERT INTO verivaro_private.ocr_transcription_correction_reviews(correction_id,tenant_id,project_id,reviewer_id,session_id,decision,reason) VALUES(i,t,p,c[2]::uuid,c[3]::uuid,decision,why);
 RETURN true;
END $review$;
REVOKE ALL ON FUNCTION verivaro_verification.propose_ocr_correction(uuid,uuid,uuid,uuid,text,text,text,integer,text,text),verivaro_verification.review_ocr_correction(uuid,uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.propose_ocr_correction(uuid,uuid,uuid,uuid,text,text,text,integer,text,text),verivaro_verification.review_ocr_correction(uuid,uuid,uuid,text,text) TO verivaro_runtime;
ALTER TABLE verivaro_private.trustproof_entries DROP CONSTRAINT trustproof_entries_source_type_check;
ALTER TABLE verivaro_private.trustproof_entries ADD CONSTRAINT trustproof_entries_source_type_check CHECK(source_type IN ('requirement_versions','requirement_reviews','requirement_evidence_links','requirement_link_reviews','requirement_sources','requirement_dependencies','requirement_dependency_reviews','requirement_dependency_removals','requirement_dependency_removal_reviews','submission_snapshots','submission_reviews','submission_authorizations','prooflock_milestones','prooflock_windows','prooflock_window_reviews','prooflock_capture_receipts','prooflock_alert_policies','prooflock_recovery_proposals','prooflock_recovery_reviews','financial_records','financial_versions','financial_reviews','project_chronology','project_chronology_reviews','acknowledgement_grants','acknowledgement_revocations','acknowledgement_events','resolution_tasks','resolution_task_events','customer_package_grants','customer_package_revocations','customer_package_reads','export_template_versions','organisation_template_publications','organisation_template_imports','project_lifecycle_events','evidence_metadata_versions','evidence_metadata_reviews','requirement_document_conditions','evidence_import_lineage','ocr_transcription_corrections','ocr_transcription_correction_reviews'));
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
 SELECT q.requirement_id AS "requirementId",q.version_id AS "versionId",q.revision,q.title,CASE WHEN ocrv.decision='approved' THEN oc.corrected_text ELSE q.criterion END AS criterion,q.applicability,CASE WHEN src.version_id IS NULL THEN q.provenance ELSE 'source-line-v1' END AS provenance,
 CASE WHEN src.version_id IS NULL THEN NULL ELSE jsonb_build_object('evidenceId',src.evidence_id,'sha256',src.source_sha256,'line',src.line_number,'page',src.page_number,'quoteSha256',src.quote_sha256,'algorithm',src.algorithm)||CASE WHEN src.office_location IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('location',src.office_location) END||CASE WHEN oc.correction_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('correction',jsonb_build_object('correctionId',oc.correction_id,'revision',oc.revision,'originalText',q.criterion,'proposedText',oc.corrected_text,'reason',oc.reason,'sha256',oc.corrected_sha256,'status',COALESCE(ocrv.decision,'pending'),'reviewReason',ocrv.reason)) END END AS source,
 COALESCE(rv.decision,'pending') AS "ruleDecision",rv.reason AS "ruleReason",
 (can_write AND q.revision<16) AS "canRevise", (can_review AND q.author_id<>a AND rv.version_id IS NULL) AS "canReview",
 (can_write AND q.author_id=a AND src.algorithm='ocr-human-source-v1' AND rv.version_id IS NULL AND (oc.correction_id IS NULL OR ocrv.decision='rejected')) AS "canProposeOcrCorrection",
 (can_review AND q.author_id<>a AND oc.correction_id IS NOT NULL AND oc.author_id<>a AND so.actor_id<>a AND ocrv.correction_id IS NULL AND so.intact IS TRUE) AS "canReviewOcrCorrection",
 (can_write AND rv.decision='approved' AND q.applicability IN ('required','optional') AND jsonb_array_length(l.links)<8) IS TRUE AS "canLink",
 CASE WHEN l.invalid_count>0 OR (src.version_id IS NOT NULL AND (src.tenant_id<>t OR src.project_id<>p OR so.intact IS DISTINCT FROM true OR so.sha256 IS DISTINCT FROM src.source_sha256 OR src.quote_sha256 IS DISTINCT FROM encode(verivaro_private.digest(convert_to(q.criterion,'UTF8'),'sha256'),'hex'))) THEN 'integrity_failure'
 WHEN oc.correction_id IS NOT NULL AND ocrv.decision IS DISTINCT FROM 'approved' THEN CASE WHEN ocrv.decision='rejected' THEN 'correction_rejected' ELSE 'awaiting_correction_review' END
 WHEN rv.decision='rejected' THEN 'rule_rejected'
 WHEN rv.decision IS DISTINCT FROM 'approved' THEN 'awaiting_rule_review'
 WHEN q.applicability='unknown' THEN 'unknown_applicability'
 WHEN q.applicability='not_applicable' THEN 'not_applicable'
 WHEN l.passes>0 AND l.failures>0 THEN 'conflict'
 WHEN l.failures>0 THEN 'failed'
 WHEN l.unresolved>0 THEN 'unresolved_evidence'
 WHEN l.passes>0 THEN 'satisfied' ELSE 'missing_evidence' END AS state,l.links
 FROM current_versions q LEFT JOIN verivaro_private.requirement_reviews rv USING(version_id) LEFT JOIN verivaro_private.requirement_sources src ON src.version_id=q.version_id LEFT JOIN verified_objects so ON so.evidence_id=src.evidence_id
 LEFT JOIN LATERAL (SELECT c.* FROM verivaro_private.ocr_transcription_corrections c WHERE c.version_id=q.version_id ORDER BY c.revision DESC LIMIT 1) oc ON true
 LEFT JOIN verivaro_private.ocr_transcription_correction_reviews ocrv ON ocrv.correction_id=oc.correction_id
 CROSS JOIN LATERAL (
 SELECT count(*) FILTER(WHERE z.decision='pass') AS passes,count(*) FILTER(WHERE z.decision='fail') AS failures,
 count(*) FILTER(WHERE z.decision IS NULL OR z.decision='unknown') AS unresolved,
 count(*) FILTER(WHERE o.intact IS DISTINCT FROM true OR o.sha256 IS DISTINCT FROM b.sha256) AS invalid_count,
 COALESCE(jsonb_agg(jsonb_build_object('linkId',b.link_id,'evidenceId',b.evidence_id,'sha256',b.sha256,'decision',COALESCE(z.decision,'pending'),'reason',z.reason,'integrity',(o.intact IS TRUE AND o.sha256=b.sha256) IS TRUE,'canReview',(o.intact IS TRUE AND o.sha256=b.sha256 AND can_review AND q.author_id<>a AND b.proposer_id<>a AND o.actor_id<>a AND z.link_id IS NULL)) ORDER BY b.link_id),'[]'::jsonb) AS links
 FROM verivaro_private.requirement_evidence_links b LEFT JOIN verified_objects o ON o.evidence_id=b.evidence_id LEFT JOIN verivaro_private.requirement_link_reviews z USING(link_id) WHERE b.version_id=q.version_id
 ) l
 ) SELECT COALESCE(jsonb_agg(to_jsonb(details) ORDER BY "requirementId"),'[]'::jsonb),
 count(*) FILTER(WHERE state IN ('awaiting_rule_review','rule_rejected','unknown_applicability','integrity_failure','awaiting_correction_review','correction_rejected') OR (applicability='required' AND state<>'satisfied')),
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
 SELECT encode(verivaro_private.digest(convert_to((jsonb_build_array(
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
 )||CASE WHEN EXISTS(SELECT 1 FROM verivaro_private.ocr_transcription_corrections c WHERE c.tenant_id=t AND c.project_id=p) THEN jsonb_build_array(
 (SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.version_id,c.revision),'[]'::jsonb) FROM verivaro_private.ocr_transcription_corrections c WHERE c.tenant_id=t AND c.project_id=p),
 (SELECT COALESCE(jsonb_agg(to_jsonb(z) ORDER BY z.correction_id),'[]'::jsonb) FROM verivaro_private.ocr_transcription_correction_reviews z WHERE z.tenant_id=t AND z.project_id=p)
 ) ELSE '[]'::jsonb END)::text,'UTF8'),'sha256'),'hex')
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
 WHEN 'ocr_transcription_corrections' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.ocr_transcription_corrections x WHERE x.correction_id=r;
 WHEN 'ocr_transcription_correction_reviews' THEN SELECT x.tenant_id,x.project_id,encode(verivaro_private.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256'),'hex') INTO tenant_id,project_id,source_digest FROM verivaro_private.ocr_transcription_correction_reviews x WHERE x.correction_id=r;
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
CREATE OR REPLACE FUNCTION verivaro_verification.review_ocr_source(t uuid,p uuid,v uuid,h text,qh text,rh text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE d text:='approved';c text[];q verivaro_private.requirement_versions%ROWTYPE;prior verivaro_private.requirement_reviews%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');q:=verivaro_private.graph_current(t,p,v);
 IF EXISTS(SELECT 1 FROM verivaro_private.ocr_transcription_corrections correction WHERE correction.version_id=v AND correction.revision=(SELECT max(z.revision) FROM verivaro_private.ocr_transcription_corrections z WHERE z.version_id=v) AND NOT EXISTS(SELECT 1 FROM verivaro_private.ocr_transcription_correction_reviews review WHERE review.correction_id=correction.correction_id AND review.decision='approved')) THEN RAISE EXCEPTION 'independent correction review required' USING ERRCODE='42501';END IF;
 IF why IS NULL OR char_length(why) NOT BETWEEN 1 AND 450 OR why<>btrim(why) OR NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_sources s JOIN verivaro_private.evidence_objects o ON o.evidence_id=s.evidence_id AND o.tenant_id=s.tenant_id AND o.project_id=s.project_id WHERE s.version_id=v AND s.tenant_id=t AND s.project_id=p AND s.algorithm='ocr-human-source-v1' AND s.source_sha256=h AND s.quote_sha256=qh AND s.office_location->>'regionDigest'=rh AND o.sha256=h AND ((o.media_type='image/png' AND NOT(s.office_location ? 'page')) OR (o.media_type='application/pdf' AND s.office_location->>'page'~'^[1-4]$' AND s.office_location->>'rasterSha256'~'^[a-f0-9]{64}$')) AND o.actor_id<>c[2]::uuid AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256') AND qh=encode(verivaro_private.digest(convert_to(q.criterion,'UTF8'),'sha256'),'hex')) THEN RAISE EXCEPTION 'OCR review denied' USING ERRCODE='42501';END IF;
 why:='OCR transcription and criterion independently confirmed: '||why;
 IF q.author_id=c[2]::uuid OR d IS NULL OR d NOT IN ('approved','rejected') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'graph review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_reviews WHERE version_id=v;
 IF FOUND THEN
 IF prior.reviewer_id<>c[2]::uuid OR prior.decision<>d OR prior.reason<>why THEN RAISE EXCEPTION 'graph conflict' USING ERRCODE='23505';END IF;
 RETURN true;END IF;
 INSERT INTO verivaro_private.requirement_reviews(version_id,reviewer_id,session_id,decision,reason) VALUES(v,c[2]::uuid,c[3]::uuid,d,why);
 RETURN true;
END $review$;
CREATE TRIGGER correction_trustproof AFTER INSERT ON verivaro_private.ocr_transcription_corrections FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('correction_id');
CREATE TRIGGER correction_review_trustproof AFTER INSERT ON verivaro_private.ocr_transcription_correction_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.trustproof_capture('correction_id');
COMMIT;
