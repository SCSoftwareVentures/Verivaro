BEGIN;
CREATE TABLE verivaro_private.requirement_dependency_removals(
 removal_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,
 version_id uuid NOT NULL REFERENCES verivaro_private.requirement_versions(version_id),
 prerequisite_id uuid NOT NULL,historical_edge_id uuid NOT NULL REFERENCES verivaro_private.requirement_dependencies(edge_id),
 proposer_id uuid NOT NULL,session_id uuid NOT NULL,reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),
 UNIQUE(version_id,prerequisite_id));
CREATE TABLE verivaro_private.requirement_dependency_removal_reviews(
 removal_id uuid PRIMARY KEY REFERENCES verivaro_private.requirement_dependency_removals(removal_id),
 reviewer_id uuid NOT NULL,session_id uuid NOT NULL,decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON verivaro_private.requirement_dependency_removals,verivaro_private.requirement_dependency_removal_reviews FROM PUBLIC;
CREATE TRIGGER removal_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.requirement_dependency_removals FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER removal_review_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.requirement_dependency_removal_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER removal_archive_guard BEFORE INSERT ON verivaro_private.requirement_dependency_removals FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();

CREATE FUNCTION verivaro_private.guard_dependency_removal_conflict() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_dependency_removals m WHERE m.version_id=NEW.dependent_version_id AND m.prerequisite_id=NEW.prerequisite_id)
 THEN RAISE EXCEPTION 'conflicting dependency removal' USING ERRCODE='23505';END IF;
 RETURN NEW;
END $guard$;
REVOKE ALL ON FUNCTION verivaro_private.guard_dependency_removal_conflict() FROM PUBLIC;
CREATE TRIGGER dependency_removal_conflict BEFORE INSERT ON verivaro_private.requirement_dependencies FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_dependency_removal_conflict();

CREATE FUNCTION verivaro_verification.propose_dependency_removal(t uuid,p uuid,v uuid,m uuid,pr uuid,why text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $proposal$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;existing verivaro_private.requirement_dependency_removals%ROWTYPE;old_edge uuid;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');q:=verivaro_private.graph_current(t,p,v);
 IF q.revision<2 OR m IS NULL OR pr IS NULL OR pr=q.requirement_id OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'removal denied' USING ERRCODE='42501';END IF;
 SELECT * INTO existing FROM verivaro_private.requirement_dependency_removals WHERE removal_id=m;
 IF FOUND THEN
  IF existing.tenant_id<>t OR existing.project_id<>p OR existing.version_id<>v OR existing.prerequisite_id<>pr OR existing.proposer_id<>c[2]::uuid OR existing.reason<>why THEN RAISE EXCEPTION 'removal conflict' USING ERRCODE='23505';END IF;
  RETURN m;
 END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_reviews WHERE version_id=v) OR EXISTS(SELECT 1 FROM verivaro_private.requirement_dependencies e WHERE e.dependent_version_id=v AND e.prerequisite_id=pr) THEN RAISE EXCEPTION 'removal conflict' USING ERRCODE='23505';END IF;
 SELECT e.edge_id INTO old_edge FROM verivaro_private.requirement_dependencies e JOIN verivaro_private.requirement_versions prev ON prev.version_id=e.dependent_version_id
 WHERE e.tenant_id=t AND e.project_id=p AND prev.tenant_id=t AND prev.project_id=p AND prev.requirement_id=q.requirement_id AND prev.revision<q.revision AND e.prerequisite_id=pr
 ORDER BY prev.revision DESC LIMIT 1;
 IF old_edge IS NULL THEN RAISE EXCEPTION 'historical dependency unavailable' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(740129816160::bigint);
 IF (SELECT count(*) FROM verivaro_private.requirement_dependency_removals)>=65536 OR (SELECT count(*) FROM verivaro_private.requirement_dependency_removals WHERE version_id=v)>=128 THEN RAISE EXCEPTION 'removal capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.requirement_dependency_removals(removal_id,tenant_id,project_id,version_id,prerequisite_id,historical_edge_id,proposer_id,session_id,reason)
 VALUES(m,t,p,v,pr,old_edge,c[2]::uuid,c[3]::uuid,why);
 RETURN m;
END $proposal$;

CREATE FUNCTION verivaro_verification.review_dependency_removal(t uuid,p uuid,m uuid,decision_text text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;d verivaro_private.requirement_dependency_removals%ROWTYPE;r verivaro_private.requirement_dependency_removal_reviews%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');
 SELECT * INTO d FROM verivaro_private.requirement_dependency_removals WHERE removal_id=m AND tenant_id=t AND project_id=p;
 IF NOT FOUND THEN RAISE EXCEPTION 'removal denied' USING ERRCODE='42501';END IF;
 q:=verivaro_private.graph_current(t,p,d.version_id);
 IF c[2]::uuid IN(d.proposer_id,q.author_id) OR decision_text IS NULL OR decision_text NOT IN ('approved','rejected') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'removal review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO r FROM verivaro_private.requirement_dependency_removal_reviews WHERE removal_id=m;
 IF FOUND THEN
  IF r.reviewer_id<>c[2]::uuid OR r.decision<>decision_text OR r.reason<>why THEN RAISE EXCEPTION 'removal review conflict' USING ERRCODE='23505';END IF;
  RETURN true;
 END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_reviews WHERE version_id=d.version_id) THEN RAISE EXCEPTION 'removal version already reviewed' USING ERRCODE='23505';END IF;
 INSERT INTO verivaro_private.requirement_dependency_removal_reviews(removal_id,reviewer_id,session_id,decision,reason) VALUES(m,c[2]::uuid,c[3]::uuid,decision_text,why);
 RETURN true;
END $review$;

CREATE FUNCTION verivaro_verification.dependency_removal_candidates(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $candidates$
DECLARE g jsonb;items jsonb;
BEGIN
 g:=verivaro_private.local_assessment(t,p);
 IF NOT COALESCE((g->>'canWrite')::boolean,false) THEN RETURN '[]'::jsonb;END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('versionId',v,'prerequisiteId',pr) ORDER BY v,pr),'[]'::jsonb) INTO items FROM (
 SELECT DISTINCT current_version.version_id AS v,e.prerequisite_id AS pr
 FROM jsonb_array_elements(g->'requirements') x
 JOIN verivaro_private.requirement_versions current_version ON current_version.version_id=(x->>'versionId')::uuid AND current_version.tenant_id=t AND current_version.project_id=p
 JOIN verivaro_private.requirement_versions prev ON prev.tenant_id=t AND prev.project_id=p AND prev.requirement_id=current_version.requirement_id AND prev.revision<current_version.revision
 JOIN verivaro_private.requirement_dependencies e ON e.dependent_version_id=prev.version_id AND e.tenant_id=t AND e.project_id=p
 WHERE x->>'ruleDecision'='pending'
 AND NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_dependencies n WHERE n.dependent_version_id=current_version.version_id AND n.prerequisite_id=e.prerequisite_id)
 AND NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_dependency_removals m WHERE m.version_id=current_version.version_id AND m.prerequisite_id=e.prerequisite_id)
 ) candidates;
 RETURN items;
END $candidates$;

CREATE OR REPLACE FUNCTION verivaro_private.dependency_assessment(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $evaluate$
DECLARE g jsonb;done jsonb:='{}'::jsonb;outcome jsonb;remaining integer;progress integer;q jsonb;item jsonb;deps jsonb;removals jsonb;parent jsonb;d record;failed boolean;local_text jsonb;rid text;fp text;
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
   SELECT COALESCE(jsonb_agg(jsonb_build_object('removalId',m.removal_id,'prerequisiteId',m.prerequisite_id,'historicalEdgeId',m.historical_edge_id,'proposalReason',m.reason,'decision',COALESCE(rv.decision,'pending'),'reviewReason',rv.reason) ORDER BY m.prerequisite_id),'[]'::jsonb)
   INTO removals FROM verivaro_private.requirement_dependency_removals m LEFT JOIN verivaro_private.requirement_dependency_removal_reviews rv USING(removal_id)
   WHERE m.tenant_id=t AND m.project_id=p AND m.version_id=(q->>'versionId')::uuid;
   IF jsonb_array_length(removals)>0 THEN
    item:=item||jsonb_build_object('dependencyRemovals',removals,'localState',q->>'state');
    IF EXISTS(SELECT 1 FROM jsonb_array_elements(removals) r WHERE r->>'decision'<>'approved') AND q->>'state'<>'integrity_failure' THEN item:=jsonb_set(item,'{state}','"dependency_blocked"'::jsonb);END IF;
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

CREATE OR REPLACE FUNCTION verivaro_private.require_dependency_continuity() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $continuity$
DECLARE q verivaro_private.requirement_versions%ROWTYPE;
BEGIN
 IF NEW.decision<>'approved' THEN RETURN NEW;END IF;
 SELECT * INTO q FROM verivaro_private.requirement_versions WHERE version_id=NEW.version_id;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_versions previous_version JOIN verivaro_private.requirement_dependencies e ON e.dependent_version_id=previous_version.version_id
 WHERE previous_version.tenant_id=q.tenant_id AND previous_version.project_id=q.project_id AND previous_version.requirement_id=q.requirement_id AND previous_version.revision<q.revision
 AND NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_dependencies n WHERE n.dependent_version_id=q.version_id AND n.prerequisite_id=e.prerequisite_id)
 AND NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_dependency_removals m JOIN verivaro_private.requirement_dependency_removal_reviews rv USING(removal_id) WHERE m.version_id=q.version_id AND m.tenant_id=q.tenant_id AND m.project_id=q.project_id AND m.prerequisite_id=e.prerequisite_id AND rv.decision='approved')) THEN RAISE EXCEPTION 'dependency continuity required' USING ERRCODE='23505';END IF;
 RETURN NEW;
END $continuity$;

REVOKE ALL ON FUNCTION verivaro_verification.propose_dependency_removal(uuid,uuid,uuid,uuid,uuid,text),verivaro_verification.review_dependency_removal(uuid,uuid,uuid,text,text),verivaro_verification.dependency_removal_candidates(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.propose_dependency_removal(uuid,uuid,uuid,uuid,uuid,text),verivaro_verification.review_dependency_removal(uuid,uuid,uuid,text,text),verivaro_verification.dependency_removal_candidates(uuid,uuid) TO verivaro_runtime;
COMMIT;
