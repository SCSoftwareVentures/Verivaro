BEGIN;
CREATE TABLE verivaro_private.requirement_dependencies(
 edge_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,
 dependent_version_id uuid NOT NULL REFERENCES verivaro_private.requirement_versions(version_id),
 prerequisite_id uuid NOT NULL,prerequisite_fingerprint text NOT NULL CHECK(prerequisite_fingerprint~'^[0-9a-f]{64}$'),
 proposer_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),
 UNIQUE(dependent_version_id,prerequisite_id));
CREATE TABLE verivaro_private.requirement_dependency_reviews(
 edge_id uuid PRIMARY KEY REFERENCES verivaro_private.requirement_dependencies(edge_id),
 reviewer_id uuid NOT NULL,session_id uuid NOT NULL,decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON verivaro_private.requirement_dependencies,verivaro_private.requirement_dependency_reviews FROM PUBLIC;
CREATE TRIGGER dependency_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.requirement_dependencies FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER dependency_review_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.requirement_dependency_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER dependency_archive_guard BEFORE INSERT ON verivaro_private.requirement_dependencies FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
-- Preserve the previous scoped assessment as a private local evaluator.
ALTER FUNCTION verivaro_verification.assessment(uuid,uuid) SET SCHEMA verivaro_private;
ALTER FUNCTION verivaro_private.assessment(uuid,uuid) RENAME TO local_assessment;
REVOKE ALL ON FUNCTION verivaro_private.local_assessment(uuid,uuid) FROM PUBLIC,verivaro_runtime;

CREATE FUNCTION verivaro_private.dependency_assessment(t uuid,p uuid) RETURNS jsonb
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
REVOKE ALL ON FUNCTION verivaro_private.dependency_assessment(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION verivaro_verification.assessment(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $assessment$
DECLARE g jsonb;items jsonb;blocking integer;required_count integer;verified integer;
BEGIN
 g:=verivaro_private.dependency_assessment(t,p);
 SELECT COALESCE(jsonb_agg(x-'_fingerprint' ORDER BY x->>'requirementId'),'[]'::jsonb),
 count(*) FILTER(WHERE x->>'state' IN ('awaiting_rule_review','rule_rejected','unknown_applicability','integrity_failure','dependency_blocked') OR (x->>'applicability'='required' AND x->>'state'<>'satisfied')),
 count(*) FILTER(WHERE x->>'applicability'='required'),
 count(*) FILTER(WHERE x->>'applicability'='required' AND x->>'state'='satisfied')
 INTO items,blocking,required_count,verified FROM jsonb_array_elements(g->'requirements') x;
 RETURN g||jsonb_build_object('requirements',items,'summary',jsonb_build_object('requirements',jsonb_array_length(items),'required',required_count,'verifiedRequired',verified,'blockers',blocking,'status',CASE WHEN blocking>0 THEN 'blocked' WHEN required_count=0 THEN 'not_assessed' ELSE 'criteria_satisfied' END));
END $assessment$;

CREATE FUNCTION verivaro_verification.propose_dependency(t uuid,p uuid,v uuid,e uuid,pr uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $propose$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;prior verivaro_private.requirement_dependencies%ROWTYPE;g jsonb;parent jsonb;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');q:=verivaro_private.graph_current(t,p,v);
 IF e IS NULL OR pr IS NULL OR pr=q.requirement_id OR q.applicability NOT IN ('required','optional') THEN RAISE EXCEPTION 'dependency denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_dependencies WHERE edge_id=e;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.dependent_version_id<>v OR prior.prerequisite_id<>pr OR prior.proposer_id<>c[2]::uuid THEN RAISE EXCEPTION 'dependency conflict' USING ERRCODE='23505';END IF;
 RETURN e;END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_reviews WHERE version_id=v) THEN RAISE EXCEPTION 'dependency version already reviewed' USING ERRCODE='23505';END IF;
 g:=verivaro_private.dependency_assessment(t,p);
 SELECT x INTO parent FROM jsonb_array_elements(g->'requirements') x WHERE x->>'requirementId'=pr::text;
 IF parent IS NULL OR parent->>'state'<>'satisfied' THEN RAISE EXCEPTION 'prerequisite unavailable' USING ERRCODE='23505';END IF;
 PERFORM pg_advisory_xact_lock(740129816159::bigint);
 IF (SELECT count(*) FROM verivaro_private.requirement_dependencies)>=65536 OR (SELECT count(*) FROM verivaro_private.requirement_dependencies WHERE dependent_version_id=v)>=8 THEN RAISE EXCEPTION 'dependency capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.requirement_dependencies(edge_id,tenant_id,project_id,dependent_version_id,prerequisite_id,prerequisite_fingerprint,proposer_id,session_id)
 VALUES(e,t,p,v,pr,parent->>'_fingerprint',c[2]::uuid,c[3]::uuid);
 -- Validate the whole graph including the new edge in the same transaction.
 PERFORM verivaro_private.dependency_assessment(t,p);
 RETURN e;
END $propose$;

CREATE FUNCTION verivaro_verification.review_dependency(t uuid,p uuid,e uuid,decision_text text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;d verivaro_private.requirement_dependencies%ROWTYPE;r verivaro_private.requirement_dependency_reviews%ROWTYPE;g jsonb;parent jsonb;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');
 SELECT * INTO d FROM verivaro_private.requirement_dependencies WHERE edge_id=e AND tenant_id=t AND project_id=p;
 IF NOT FOUND THEN RAISE EXCEPTION 'dependency denied' USING ERRCODE='42501';END IF;
 q:=verivaro_private.graph_current(t,p,d.dependent_version_id);
 IF c[2]::uuid IN(d.proposer_id,q.author_id) OR decision_text IS NULL OR decision_text NOT IN ('approved','rejected') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'dependency review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO r FROM verivaro_private.requirement_dependency_reviews WHERE edge_id=e;
 IF FOUND THEN
 IF r.reviewer_id<>c[2]::uuid OR r.decision<>decision_text OR r.reason<>why THEN RAISE EXCEPTION 'dependency review conflict' USING ERRCODE='23505';END IF;
 RETURN true;END IF;
 IF decision_text='approved' THEN
  g:=verivaro_private.dependency_assessment(t,p);
  SELECT x INTO parent FROM jsonb_array_elements(g->'requirements') x WHERE x->>'requirementId'=d.prerequisite_id::text;
  IF parent IS NULL OR parent->>'state'<>'satisfied' OR parent->>'_fingerprint' IS DISTINCT FROM d.prerequisite_fingerprint THEN RAISE EXCEPTION 'dependency stale' USING ERRCODE='23505';END IF;
 END IF;
 INSERT INTO verivaro_private.requirement_dependency_reviews(edge_id,reviewer_id,session_id,decision,reason) VALUES(e,c[2]::uuid,c[3]::uuid,decision_text,why);
 RETURN true;
END $review$;
-- A revision cannot silently drop a previously declared prerequisite.
CREATE FUNCTION verivaro_private.require_dependency_continuity() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $continuity$
DECLARE q verivaro_private.requirement_versions%ROWTYPE;
BEGIN
 IF NEW.decision<>'approved' THEN RETURN NEW;END IF;
 SELECT * INTO q FROM verivaro_private.requirement_versions WHERE version_id=NEW.version_id;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_versions previous_version JOIN verivaro_private.requirement_dependencies e ON e.dependent_version_id=previous_version.version_id
 WHERE previous_version.tenant_id=q.tenant_id AND previous_version.project_id=q.project_id AND previous_version.requirement_id=q.requirement_id AND previous_version.revision<q.revision
 AND NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_dependencies n WHERE n.dependent_version_id=q.version_id AND n.prerequisite_id=e.prerequisite_id)) THEN RAISE EXCEPTION 'dependency continuity required' USING ERRCODE='23505';END IF;
 RETURN NEW;
END $continuity$;
REVOKE ALL ON FUNCTION verivaro_private.require_dependency_continuity() FROM PUBLIC;
CREATE TRIGGER dependency_continuity BEFORE INSERT ON verivaro_private.requirement_reviews FOR EACH ROW EXECUTE FUNCTION verivaro_private.require_dependency_continuity();
REVOKE ALL ON FUNCTION verivaro_verification.assessment(uuid,uuid),verivaro_verification.propose_dependency(uuid,uuid,uuid,uuid,uuid),verivaro_verification.review_dependency(uuid,uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.assessment(uuid,uuid),verivaro_verification.propose_dependency(uuid,uuid,uuid,uuid,uuid),verivaro_verification.review_dependency(uuid,uuid,uuid,text,text) TO verivaro_runtime;
COMMIT;
