BEGIN;
CREATE SCHEMA verivaro_verification;
REVOKE ALL ON SCHEMA verivaro_verification FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro_verification TO verivaro_runtime;
CREATE TABLE verivaro_private.requirement_versions(
 version_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,requirement_id uuid NOT NULL,
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 16),
 title text NOT NULL CHECK(char_length(title) BETWEEN 1 AND 128 AND octet_length(title)<=512),
 criterion text NOT NULL CHECK(char_length(criterion) BETWEEN 1 AND 1024 AND octet_length(criterion)<=4096),
 applicability text NOT NULL CHECK(applicability IN ('required','optional','not_applicable','unknown')),
 provenance text NOT NULL CHECK(provenance='manual'),
 author_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),
 UNIQUE(tenant_id,project_id,requirement_id,revision)
);
CREATE TABLE verivaro_private.requirement_reviews(
 version_id uuid PRIMARY KEY REFERENCES verivaro_private.requirement_versions(version_id),
 reviewer_id uuid NOT NULL,session_id uuid NOT NULL,decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE verivaro_private.requirement_evidence_links(
 link_id uuid PRIMARY KEY,version_id uuid NOT NULL REFERENCES verivaro_private.requirement_versions(version_id),
 evidence_id uuid NOT NULL REFERENCES verivaro_private.evidence_objects(evidence_id),
 sha256 text NOT NULL CHECK(sha256~'^[0-9a-f]{64}$'),proposer_id uuid NOT NULL,session_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(version_id,evidence_id)
);
CREATE TABLE verivaro_private.requirement_link_reviews(
 link_id uuid PRIMARY KEY REFERENCES verivaro_private.requirement_evidence_links(link_id),
 reviewer_id uuid NOT NULL,session_id uuid NOT NULL,decision text NOT NULL CHECK(decision IN ('pass','fail','unknown')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON verivaro_private.requirement_versions,verivaro_private.requirement_reviews,verivaro_private.requirement_evidence_links,verivaro_private.requirement_link_reviews FROM PUBLIC;
CREATE TRIGGER requirement_version_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.requirement_versions FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER requirement_review_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.requirement_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER requirement_link_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.requirement_evidence_links FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER requirement_link_review_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.requirement_link_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER archive_requirement_guard BEFORE INSERT ON verivaro_private.requirement_versions FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
-- All graph writes use the same project row lock, serializing versions,
-- decisions, links and archival. Private tables have no service DML grants.
CREATE FUNCTION verivaro_private.graph_actor(t uuid,p uuid,permission text) RETURNS text[]
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $actor$
DECLARE c text[];
BEGIN
 c:=verivaro_private.release_actor(t,p,permission);
 PERFORM 1 FROM verivaro.projects q WHERE q.tenant_id=t AND q.id=p AND q.archived_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'graph denied' USING ERRCODE='42501';END IF;
 RETURN c;
END $actor$;
CREATE FUNCTION verivaro_private.graph_current(t uuid,p uuid,v uuid) RETURNS verivaro_private.requirement_versions
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $current$
DECLARE q verivaro_private.requirement_versions%ROWTYPE;
BEGIN
 SELECT * INTO q FROM verivaro_private.requirement_versions WHERE tenant_id=t AND project_id=p AND version_id=v;
 IF NOT FOUND THEN RAISE EXCEPTION 'graph denied' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_versions n WHERE n.tenant_id=t AND n.project_id=p AND n.requirement_id=q.requirement_id AND n.revision>q.revision) THEN RAISE EXCEPTION 'stale requirement' USING ERRCODE='23505';END IF;
 RETURN q;
END $current$;
REVOKE ALL ON FUNCTION verivaro_private.graph_actor(uuid,uuid,text),verivaro_private.graph_current(uuid,uuid,uuid) FROM PUBLIC;
CREATE FUNCTION verivaro_verification.write_requirement(t uuid,p uuid,r uuid,v uuid,expected integer,n text,criterion_text text,app text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $write$
DECLARE c text[];prior verivaro_private.requirement_versions%ROWTYPE;latest integer;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');
 IF r IS NULL OR v IS NULL OR expected IS NULL OR expected NOT BETWEEN 0 AND 15
 OR n IS NULL OR char_length(n) NOT BETWEEN 1 AND 128 OR octet_length(n)>512 OR n<>btrim(n) OR n~'[[:cntrl:]]'
 OR criterion_text IS NULL OR char_length(criterion_text) NOT BETWEEN 1 AND 1024 OR octet_length(criterion_text)>4096 OR criterion_text<>btrim(criterion_text) OR criterion_text~'[[:cntrl:]]'
 OR app IS NULL OR app NOT IN ('required','optional','not_applicable','unknown') THEN RAISE EXCEPTION 'invalid requirement' USING ERRCODE='22023';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_versions WHERE version_id=v;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.requirement_id<>r OR prior.author_id<>c[2]::uuid OR prior.revision<>expected+1 OR prior.title<>n OR prior.criterion<>criterion_text OR prior.applicability<>app THEN RAISE EXCEPTION 'graph conflict' USING ERRCODE='23505';END IF;
 RETURN jsonb_build_object('requirementId',r,'versionId',v,'revision',prior.revision);END IF;
 SELECT COALESCE(max(revision),0) INTO latest FROM verivaro_private.requirement_versions WHERE tenant_id=t AND project_id=p AND requirement_id=r;
 IF latest<>expected THEN RAISE EXCEPTION 'stale requirement' USING ERRCODE='23505';END IF;
 PERFORM pg_advisory_xact_lock(740129816157::bigint);
 IF (SELECT count(*) FROM verivaro_private.requirement_versions)>=32768 OR (latest=0 AND (SELECT count(*) FROM verivaro_private.requirement_versions WHERE tenant_id=t AND project_id=p AND revision=1)>=128) THEN RAISE EXCEPTION 'graph capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.requirement_versions(version_id,tenant_id,project_id,requirement_id,revision,title,criterion,applicability,provenance,author_id,session_id)
 VALUES(v,t,p,r,expected+1,n,criterion_text,app,'manual',c[2]::uuid,c[3]::uuid);
 RETURN jsonb_build_object('requirementId',r,'versionId',v,'revision',expected+1);
END $write$;
CREATE FUNCTION verivaro_verification.review_requirement(t uuid,p uuid,v uuid,d text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;prior verivaro_private.requirement_reviews%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');q:=verivaro_private.graph_current(t,p,v);
 IF q.author_id=c[2]::uuid OR d IS NULL OR d NOT IN ('approved','rejected') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'graph review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_reviews WHERE version_id=v;
 IF FOUND THEN
 IF prior.reviewer_id<>c[2]::uuid OR prior.decision<>d OR prior.reason<>why THEN RAISE EXCEPTION 'graph conflict' USING ERRCODE='23505';END IF;
 RETURN true;END IF;
 INSERT INTO verivaro_private.requirement_reviews(version_id,reviewer_id,session_id,decision,reason) VALUES(v,c[2]::uuid,c[3]::uuid,d,why);
 RETURN true;
END $review$;
CREATE FUNCTION verivaro_verification.link_evidence(t uuid,p uuid,v uuid,l uuid,e uuid,h text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $link$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;prior verivaro_private.requirement_evidence_links%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');q:=verivaro_private.graph_current(t,p,v);
 IF l IS NULL OR e IS NULL OR h IS NULL OR q.applicability NOT IN ('required','optional')
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_reviews x WHERE x.version_id=v AND x.decision='approved')
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects o WHERE o.evidence_id=e AND o.tenant_id=t AND o.project_id=p AND o.sha256=h AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256'))
 THEN RAISE EXCEPTION 'graph link denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_evidence_links WHERE link_id=l;
 IF FOUND THEN
 IF prior.version_id<>v OR prior.evidence_id<>e OR prior.sha256<>h OR prior.proposer_id<>c[2]::uuid THEN RAISE EXCEPTION 'graph conflict' USING ERRCODE='23505';END IF;
 RETURN l;END IF;
 PERFORM pg_advisory_xact_lock(740129816157::bigint);
 IF (SELECT count(*) FROM verivaro_private.requirement_evidence_links)>=65536 OR (SELECT count(*) FROM verivaro_private.requirement_evidence_links WHERE version_id=v)>=8 THEN RAISE EXCEPTION 'graph capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.requirement_evidence_links(link_id,version_id,evidence_id,sha256,proposer_id,session_id) VALUES(l,v,e,h,c[2]::uuid,c[3]::uuid);
 RETURN l;
END $link$;
CREATE FUNCTION verivaro_verification.review_link(t uuid,p uuid,l uuid,d text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;ln verivaro_private.requirement_evidence_links%ROWTYPE;prior verivaro_private.requirement_link_reviews%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');
 SELECT * INTO ln FROM verivaro_private.requirement_evidence_links WHERE link_id=l;
 IF NOT FOUND THEN RAISE EXCEPTION 'graph review denied' USING ERRCODE='42501';END IF;
 q:=verivaro_private.graph_current(t,p,ln.version_id);
 IF ln.proposer_id=c[2]::uuid OR q.author_id=c[2]::uuid OR d IS NULL OR d NOT IN ('pass','fail','unknown') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]'
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects o WHERE o.evidence_id=ln.evidence_id AND o.tenant_id=t AND o.project_id=p AND o.actor_id<>c[2]::uuid AND o.sha256=ln.sha256 AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256'))
 THEN RAISE EXCEPTION 'graph review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_link_reviews WHERE link_id=l;
 IF FOUND THEN
 IF prior.reviewer_id<>c[2]::uuid OR prior.decision<>d OR prior.reason<>why THEN RAISE EXCEPTION 'graph conflict' USING ERRCODE='23505';END IF;
 RETURN true;END IF;
 INSERT INTO verivaro_private.requirement_link_reviews(link_id,reviewer_id,session_id,decision,reason) VALUES(l,c[2]::uuid,c[3]::uuid,d,why);
 RETURN true;
END $review$;
CREATE FUNCTION verivaro_verification.assessment(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $assessment$
DECLARE c text[];a uuid;items jsonb;summary jsonb;blocking integer;required_count integer;verified integer;
BEGIN
 c:=verivaro.bound_context();
 IF current_setting('transaction_isolation')<>'read committed' OR c IS NULL OR t IS NULL OR p IS NULL OR c[1]<>t::text OR NOT verivaro.active_identity() THEN RAISE EXCEPTION 'graph denied' USING ERRCODE='42501';END IF;
 a:=c[2]::uuid;
 IF NOT EXISTS(SELECT 1 FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id
 WHERE m.tenant_id=t AND m.actor_id=a AND m.revoked_at IS NULL AND pm.project_id=p AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp()))
 THEN RAISE EXCEPTION 'graph denied' USING ERRCODE='42501';END IF;
 WITH current_versions AS (
 SELECT DISTINCT ON (requirement_id) * FROM verivaro_private.requirement_versions WHERE tenant_id=t AND project_id=p ORDER BY requirement_id,revision DESC
 ),details AS (
 SELECT q.requirement_id AS "requirementId",q.version_id AS "versionId",q.revision,q.title,q.criterion,q.applicability,q.provenance,
 COALESCE(rv.decision,'pending') AS "ruleDecision",rv.reason AS "ruleReason",
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
 COALESCE(jsonb_agg(jsonb_build_object('linkId',b.link_id,'evidenceId',b.evidence_id,'sha256',b.sha256,'decision',COALESCE(z.decision,'pending'),'reason',z.reason) ORDER BY b.link_id),'[]'::jsonb) AS links
 FROM verivaro_private.requirement_evidence_links b LEFT JOIN verivaro_private.requirement_link_reviews z USING(link_id) WHERE b.version_id=q.version_id
 ) l
 ) SELECT COALESCE(jsonb_agg(to_jsonb(details) ORDER BY "requirementId"),'[]'::jsonb),
 count(*) FILTER(WHERE state IN ('awaiting_rule_review','unknown_applicability') OR (applicability='required' AND state<>'satisfied')),
 count(*) FILTER(WHERE applicability='required'),
 count(*) FILTER(WHERE applicability='required' AND state='satisfied')
 INTO items,blocking,required_count,verified FROM details;
 summary:=jsonb_build_object('requirements',jsonb_array_length(items),'required',required_count,'verifiedRequired',verified,'blockers',blocking,
 'status',CASE WHEN blocking>0 THEN 'blocked' WHEN required_count=0 THEN 'not_assessed' ELSE 'criteria_satisfied' END);
 RETURN jsonb_build_object('version',1,'tenantId',t,'projectId',p,'evaluatedAt',statement_timestamp(),'summary',summary,'requirements',items,
 'scope','manual reviewed criteria only; not release authorization or certification');
END $assessment$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA verivaro_verification FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.write_requirement(uuid,uuid,uuid,uuid,integer,text,text,text),verivaro_verification.review_requirement(uuid,uuid,uuid,text,text),verivaro_verification.link_evidence(uuid,uuid,uuid,uuid,uuid,text),verivaro_verification.review_link(uuid,uuid,uuid,text,text),verivaro_verification.assessment(uuid,uuid) TO verivaro_runtime;
COMMIT;
