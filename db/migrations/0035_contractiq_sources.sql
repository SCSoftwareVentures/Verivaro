BEGIN;
CREATE TABLE verivaro_private.requirement_sources(
 version_id uuid PRIMARY KEY REFERENCES verivaro_private.requirement_versions(version_id),
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,evidence_id uuid NOT NULL REFERENCES verivaro_private.evidence_objects(evidence_id),
 source_sha256 text NOT NULL CHECK(source_sha256~'^[a-f0-9]{64}$'),
 line_number integer NOT NULL CHECK(line_number BETWEEN 1 AND 262144),page_number integer CHECK(page_number=1),
 quote_sha256 text NOT NULL CHECK(quote_sha256~'^[a-f0-9]{64}$'),
 algorithm text NOT NULL CHECK(algorithm='modal-line-v1'),
 UNIQUE(tenant_id,project_id,evidence_id,line_number)
);
REVOKE ALL ON verivaro_private.requirement_sources FROM PUBLIC;
CREATE TRIGGER requirement_source_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.requirement_sources FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER archive_source_guard BEFORE INSERT ON verivaro_private.requirement_sources FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
-- Trusted extraction adapter derives the quote from authenticated decrypted
-- bytes. SQL binds its claim to the exact immutable source and rule version.
CREATE FUNCTION verivaro_verification.import_source_line(t uuid,p uuid,r uuid,v uuid,e uuid,h text,ln integer,pg integer,quote_text text,quote_hash text,app text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $import$
DECLARE c text[];prior verivaro_private.requirement_sources%ROWTYPE;outcome jsonb;media text;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');
 IF r IS NULL OR v IS NULL OR e IS NULL OR h IS NULL OR ln IS NULL OR ln NOT BETWEEN 1 AND 262144 OR quote_text IS NULL
 OR char_length(quote_text) NOT BETWEEN 1 AND 1024 OR octet_length(quote_text)>4096 OR quote_text<>btrim(quote_text) OR quote_text~'[[:cntrl:]]'
 OR quote_hash IS DISTINCT FROM encode(verivaro_private.digest(convert_to(quote_text,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'source import denied' USING ERRCODE='42501';END IF;
 SELECT o.media_type INTO media FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t AND o.project_id=p AND o.evidence_id=e AND o.sha256=h AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256');
 IF NOT FOUND OR (media='application/pdf' AND (pg IS DISTINCT FROM 1 OR ln>40)) OR (media='text/plain; charset=utf-8' AND pg IS NOT NULL) OR media NOT IN ('application/pdf','text/plain; charset=utf-8') THEN RAISE EXCEPTION 'source import denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_sources WHERE version_id=v;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.evidence_id<>e OR prior.source_sha256<>h OR prior.line_number<>ln OR prior.page_number IS DISTINCT FROM pg OR prior.quote_sha256<>quote_hash THEN RAISE EXCEPTION 'source conflict' USING ERRCODE='23505';END IF;
 RETURN verivaro_verification.write_requirement(t,p,r,v,0,'Source line '||ln,quote_text,app);
 END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_versions WHERE version_id=v) THEN RAISE EXCEPTION 'source conflict' USING ERRCODE='23505';END IF;
 outcome:=verivaro_verification.write_requirement(t,p,r,v,0,'Source line '||ln,quote_text,app);
 INSERT INTO verivaro_private.requirement_sources(version_id,tenant_id,project_id,evidence_id,source_sha256,line_number,page_number,quote_sha256,algorithm)
 VALUES(v,t,p,e,h,ln,pg,quote_hash,'modal-line-v1');
 RETURN outcome;
END $import$;
REVOKE ALL ON FUNCTION verivaro_verification.import_source_line(uuid,uuid,uuid,uuid,uuid,text,integer,integer,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.import_source_line(uuid,uuid,uuid,uuid,uuid,text,integer,integer,text,text,text) TO verivaro_runtime;
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
 SELECT q.requirement_id AS "requirementId",q.version_id AS "versionId",q.revision,q.title,q.criterion,q.applicability,CASE WHEN src.version_id IS NULL THEN q.provenance ELSE 'source-line-v1' END AS provenance,
 CASE WHEN src.version_id IS NULL THEN NULL ELSE jsonb_build_object('evidenceId',src.evidence_id,'sha256',src.source_sha256,'line',src.line_number,'page',src.page_number,'quoteSha256',src.quote_sha256,'algorithm',src.algorithm) END AS source,
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
 FROM current_versions q LEFT JOIN verivaro_private.requirement_reviews rv USING(version_id) LEFT JOIN verivaro_private.requirement_sources src ON src.version_id=q.version_id
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
 'scope','reviewed criteria subset only; not release authorization or certification');
END $assessment$;
COMMIT;
