BEGIN;
CREATE OR REPLACE FUNCTION verivaro_verification.assessment(t uuid,p uuid) RETURNS jsonb
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
 ),details AS (
 SELECT q.requirement_id AS "requirementId",q.version_id AS "versionId",q.revision,q.title,q.criterion,q.applicability,q.provenance,
 COALESCE(rv.decision,'pending') AS "ruleDecision",rv.reason AS "ruleReason",
 (can_write AND q.revision<16) AS "canRevise", (can_review AND q.author_id<>a AND rv.version_id IS NULL) AS "canReview",
 (can_write AND rv.decision='approved' AND q.applicability IN ('required','optional') AND jsonb_array_length(l.links)<8) IS TRUE AS "canLink",
 CASE WHEN rv.decision IS DISTINCT FROM 'approved' THEN 'awaiting_rule_review'
 WHEN q.applicability='unknown' THEN 'unknown_applicability'
 WHEN q.applicability='not_applicable' THEN 'not_applicable'
 WHEN l.passes>0 AND l.failures>0 THEN 'conflict'
 WHEN l.failures>0 THEN 'failed'
 WHEN l.unresolved>0 THEN 'unresolved_evidence'
 WHEN l.passes>0 THEN 'satisfied' ELSE 'missing_evidence' END AS state,l.links
 FROM current_versions q LEFT JOIN verivaro_private.requirement_reviews rv USING(version_id)
 CROSS JOIN LATERAL (
 SELECT count(*) FILTER(WHERE z.decision='pass') AS passes,count(*) FILTER(WHERE z.decision='fail') AS failures,
 count(*) FILTER(WHERE z.decision IS NULL OR z.decision='unknown') AS unresolved,
 COALESCE(jsonb_agg(jsonb_build_object('linkId',b.link_id,'evidenceId',b.evidence_id,'sha256',b.sha256,'decision',COALESCE(z.decision,'pending'),'reason',z.reason,'canReview',(can_review AND q.author_id<>a AND b.proposer_id<>a AND o.actor_id<>a AND z.link_id IS NULL)) ORDER BY b.link_id),'[]'::jsonb) AS links
 FROM verivaro_private.requirement_evidence_links b JOIN verivaro_private.evidence_objects o ON o.evidence_id=b.evidence_id LEFT JOIN verivaro_private.requirement_link_reviews z USING(link_id) WHERE b.version_id=q.version_id
 ) l
 ) SELECT COALESCE(jsonb_agg(to_jsonb(details) ORDER BY "requirementId"),'[]'::jsonb),
 count(*) FILTER(WHERE state IN ('awaiting_rule_review','unknown_applicability') OR (applicability='required' AND state<>'satisfied')),
 count(*) FILTER(WHERE applicability='required'),
 count(*) FILTER(WHERE applicability='required' AND state='satisfied')
 INTO items,blocking,required_count,verified FROM details;
 summary:=jsonb_build_object('requirements',jsonb_array_length(items),'required',required_count,'verifiedRequired',verified,'blockers',blocking,
 'status',CASE WHEN blocking>0 THEN 'blocked' WHEN required_count=0 THEN 'not_assessed' ELSE 'criteria_satisfied' END);
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'evaluatedAt',statement_timestamp(),'summary',summary,'requirements',items,'canWrite',can_write,'archived',closed,
 'scope','manual reviewed criteria only; not release authorization or certification');
END $assessment$;
COMMIT;
