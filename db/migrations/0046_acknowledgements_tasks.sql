BEGIN;
CREATE TABLE verivaro_private.acknowledgement_grants(
 grant_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,submission_id uuid NOT NULL REFERENCES verivaro_private.submission_snapshots(submission_id),sha256 text NOT NULL,
 recipient_id uuid NOT NULL,recipient_generation uuid[] NOT NULL CHECK(cardinality(recipient_generation)=3),owner_id uuid NOT NULL,session_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),CHECK(sha256~'^[a-f0-9]{64}$'));
CREATE TABLE verivaro_private.acknowledgement_revocations(grant_id uuid PRIMARY KEY REFERENCES verivaro_private.acknowledgement_grants(grant_id),actor_id uuid NOT NULL,session_id uuid NOT NULL,revoked_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE verivaro_private.acknowledgement_events(
 event_id uuid PRIMARY KEY,grant_id uuid NOT NULL REFERENCES verivaro_private.acknowledgement_grants(grant_id),
 recipient_id uuid NOT NULL,session_id uuid NOT NULL,kind text NOT NULL CHECK(kind IN ('receipt_attested','acceptance_attested','rejection_attested')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(grant_id,kind));
CREATE TABLE verivaro_private.resolution_tasks(
 task_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,version_id uuid NOT NULL REFERENCES verivaro_private.requirement_versions(version_id),
 assignee_id uuid NOT NULL,assignee_generation uuid[] NOT NULL CHECK(cardinality(assignee_generation)=3),creator_id uuid NOT NULL,session_id uuid NOT NULL,reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),UNIQUE(version_id,assignee_id));
CREATE TABLE verivaro_private.resolution_task_events(
 event_id uuid PRIMARY KEY,task_id uuid NOT NULL REFERENCES verivaro_private.resolution_tasks(task_id),revision integer NOT NULL CHECK(revision BETWEEN 1 AND 16),
 kind text NOT NULL CHECK(kind IN ('submitted','returned','closed')),actor_id uuid NOT NULL,session_id uuid NOT NULL,reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(task_id,revision));
DO $triggers$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['acknowledgement_grants','acknowledgement_revocations','acknowledgement_events','resolution_tasks','resolution_task_events'] LOOP
 EXECUTE format('REVOKE ALL ON verivaro_private.%I FROM PUBLIC',name);
 EXECUTE format('CREATE TRIGGER immutable_record BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.%I FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable()',name);
 END LOOP;
END $triggers$;
CREATE TRIGGER acknowledgement_archive_guard BEFORE INSERT ON verivaro_private.acknowledgement_grants FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE TRIGGER resolution_archive_guard BEFORE INSERT ON verivaro_private.resolution_tasks FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE FUNCTION verivaro_private.workflow_reason(v text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $reason$
 SELECT v IS NOT NULL AND char_length(v) BETWEEN 1 AND 512 AND octet_length(v)<=2048 AND v=btrim(v) AND v!~'[[:cntrl:]]'
$reason$;
REVOKE ALL ON FUNCTION verivaro_private.workflow_reason(text) FROM PUBLIC;
CREATE FUNCTION verivaro_verification.grant_acknowledgement(t uuid,p uuid,r uuid,s uuid,h text,a uuid,hours integer) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $grant$
DECLARE c text[];g uuid[];prior verivaro_private.acknowledgement_grants%ROWTYPE;now_at timestamptz:=clock_timestamp();
BEGIN
 c:=verivaro_private.graph_actor(t,p,'owner');
 IF r IS NULL OR s IS NULL OR a IS NULL OR a=c[2]::uuid OR h IS NULL OR hours IS NULL OR hours NOT BETWEEN 1 AND 168 OR NOT EXISTS(
 SELECT 1 FROM verivaro_private.submission_snapshots x JOIN verivaro_private.submission_authorizations z USING(submission_id) WHERE x.tenant_id=t AND x.project_id=p AND x.submission_id=s AND x.sha256=h AND encode(verivaro_private.digest(convert_to(x.manifest,'UTF8'),'sha256'),'hex')=h)
 THEN RAISE EXCEPTION 'acknowledgement grant denied' USING ERRCODE='42501';END IF;
 g:=verivaro_private.release_generation(t,p,a,'viewer');IF g IS NULL THEN RAISE EXCEPTION 'recipient denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.acknowledgement_grants x WHERE x.grant_id=r;
 IF FOUND THEN
  IF prior.tenant_id<>t OR prior.project_id<>p OR prior.submission_id<>s OR prior.sha256<>h OR prior.recipient_id<>a OR prior.recipient_generation<>g OR prior.owner_id<>c[2]::uuid OR prior.expires_at<>prior.created_at+make_interval(hours=>hours) THEN RAISE EXCEPTION 'grant conflict' USING ERRCODE='23505';END IF;RETURN r;
 END IF;
 PERFORM pg_advisory_xact_lock(740129816166::bigint);
 IF (SELECT count(*) FROM verivaro_private.acknowledgement_grants)>=32768 OR (SELECT count(*) FROM verivaro_private.acknowledgement_grants x WHERE x.tenant_id=t AND x.project_id=p)>=128 THEN RAISE EXCEPTION 'grant capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.acknowledgement_grants(grant_id,tenant_id,project_id,submission_id,sha256,recipient_id,recipient_generation,owner_id,session_id,created_at,expires_at) VALUES(r,t,p,s,h,a,g,c[2]::uuid,c[3]::uuid,now_at,now_at+make_interval(hours=>hours));RETURN r;
END $grant$;
CREATE FUNCTION verivaro_verification.revoke_acknowledgement(t uuid,p uuid,r uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $revoke$
DECLARE c text[];
BEGIN
 c:=verivaro_private.graph_actor(t,p,'owner');
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.acknowledgement_grants x WHERE x.tenant_id=t AND x.project_id=p AND x.grant_id=r) THEN RAISE EXCEPTION 'grant denied' USING ERRCODE='42501';END IF;
 INSERT INTO verivaro_private.acknowledgement_revocations(grant_id,actor_id,session_id) VALUES(r,c[2]::uuid,c[3]::uuid) ON CONFLICT DO NOTHING;RETURN true;
END $revoke$;
CREATE FUNCTION verivaro_verification.record_acknowledgement(t uuid,p uuid,r uuid,e uuid,h text,k text,why text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $record$
DECLARE c text[];grant_row verivaro_private.acknowledgement_grants%ROWTYPE;prior verivaro_private.acknowledgement_events%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'viewer');
 SELECT * INTO grant_row FROM verivaro_private.acknowledgement_grants x WHERE x.tenant_id=t AND x.project_id=p AND x.grant_id=r AND x.recipient_id=c[2]::uuid;
 IF NOT FOUND OR e IS NULL OR h IS DISTINCT FROM grant_row.sha256 OR k IS NULL OR k NOT IN ('receipt_attested','acceptance_attested','rejection_attested') OR NOT verivaro_private.workflow_reason(why) OR grant_row.expires_at<=clock_timestamp() OR grant_row.recipient_generation IS DISTINCT FROM verivaro_private.release_generation(t,p,c[2]::uuid,'viewer') OR EXISTS(SELECT 1 FROM verivaro_private.acknowledgement_revocations x WHERE x.grant_id=r) THEN RAISE EXCEPTION 'acknowledgement denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.acknowledgement_events x WHERE x.event_id=e;
 IF FOUND THEN IF prior.grant_id<>r OR prior.recipient_id<>c[2]::uuid OR prior.kind<>k OR prior.reason<>why THEN RAISE EXCEPTION 'acknowledgement conflict' USING ERRCODE='23505';END IF;RETURN e;END IF;
 IF k<>'receipt_attested' AND NOT EXISTS(SELECT 1 FROM verivaro_private.acknowledgement_events x WHERE x.grant_id=r AND x.kind='receipt_attested') THEN RAISE EXCEPTION 'explicit receipt required' USING ERRCODE='23505';END IF;
 INSERT INTO verivaro_private.acknowledgement_events(event_id,grant_id,recipient_id,session_id,kind,reason) VALUES(e,r,c[2]::uuid,c[3]::uuid,k,why);RETURN e;
END $record$;
CREATE FUNCTION verivaro_verification.acknowledgement_list(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $list$
DECLARE g jsonb;c text[];tr text;pr text;owner_view boolean;review_view boolean;
BEGIN
 g:=verivaro_verification.assessment(t,p);c:=verivaro.bound_context();
 SELECT m.role,pm.role INTO tr,pr FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id WHERE m.tenant_id=t AND pm.project_id=p AND m.actor_id=c[2]::uuid AND m.revoked_at IS NULL AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp());
 IF NOT FOUND THEN RAISE EXCEPTION 'acknowledgement denied' USING ERRCODE='42501';END IF;
 owner_view:=tr='owner' AND pr='owner';review_view:=tr='reviewer' AND pr='reviewer';
 RETURN jsonb_build_object('canGrant',owner_view AND NOT (g->>'archived')::boolean,'items',COALESCE((SELECT jsonb_agg(jsonb_build_object('grantId',x.grant_id,'submissionId',x.submission_id,'sha256',x.sha256,'recipientId',x.recipient_id,'expiresAt',x.expires_at,
 'active',z.grant_id IS NULL AND x.expires_at>statement_timestamp() AND NOT (g->>'archived')::boolean AND EXISTS(SELECT 1 FROM verivaro.memberships tm JOIN verivaro.project_members pm ON tm.tenant_id=pm.tenant_id AND tm.actor_id=pm.actor_id LEFT JOIN verivaro_private.actor_share_generations ag ON ag.actor_id=tm.actor_id WHERE tm.tenant_id=t AND pm.project_id=p AND tm.actor_id=x.recipient_id AND tm.role='viewer' AND pm.role='viewer' AND tm.revoked_at IS NULL AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp()) AND ARRAY[tm.share_generation,pm.share_generation,COALESCE(ag.generation,'00000000-0000-0000-0000-000000000000'::uuid)]=x.recipient_generation AND NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors da WHERE da.actor_id=x.recipient_id)),
 'canAttest',tr='viewer' AND pr='viewer' AND x.recipient_id=c[2]::uuid,
 'events',COALESCE((SELECT jsonb_agg(jsonb_build_object('eventId',e.event_id,'kind',e.kind,'reason',e.reason,'recordedAt',e.recorded_at) ORDER BY e.recorded_at,e.event_id) FROM verivaro_private.acknowledgement_events e WHERE e.grant_id=x.grant_id),'[]'::jsonb)) ORDER BY x.created_at,x.grant_id)
 FROM verivaro_private.acknowledgement_grants x LEFT JOIN verivaro_private.acknowledgement_revocations z USING(grant_id) WHERE x.tenant_id=t AND x.project_id=p AND (owner_view OR review_view OR (tr='viewer' AND pr='viewer' AND x.recipient_id=c[2]::uuid))),'[]'::jsonb));
END $list$;
CREATE FUNCTION verivaro_verification.assign_resolution(t uuid,p uuid,r uuid,v uuid,a uuid,why text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $assign$
DECLARE c text[];q verivaro_private.requirement_versions%ROWTYPE;g uuid[];prior verivaro_private.resolution_tasks%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'owner');
 IF r IS NULL OR v IS NULL OR a IS NULL OR NOT verivaro_private.workflow_reason(why) THEN RAISE EXCEPTION 'assignment denied' USING ERRCODE='42501';END IF;
 g:=verivaro_private.release_generation(t,p,a,'submitter');IF g IS NULL THEN RAISE EXCEPTION 'assignee denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.resolution_tasks x WHERE x.task_id=r;
 IF FOUND THEN IF prior.tenant_id<>t OR prior.project_id<>p OR prior.version_id<>v OR prior.assignee_id<>a OR prior.assignee_generation<>g OR prior.creator_id<>c[2]::uuid OR prior.reason<>why THEN RAISE EXCEPTION 'assignment conflict' USING ERRCODE='23505';END IF;RETURN r;END IF;
 q:=verivaro_private.graph_current(t,p,v);
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(verivaro_verification.assessment(t,p)->'requirements') x WHERE x->>'versionId'=v::text AND x->>'state' NOT IN ('satisfied','not_applicable')) THEN RAISE EXCEPTION 'no open deficiency' USING ERRCODE='23505';END IF;
 PERFORM pg_advisory_xact_lock(740129816167::bigint);
 IF (SELECT count(*) FROM verivaro_private.resolution_tasks)>=32768 OR (SELECT count(*) FROM verivaro_private.resolution_tasks x WHERE x.tenant_id=t AND x.project_id=p)>=128 THEN RAISE EXCEPTION 'task capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.resolution_tasks(task_id,tenant_id,project_id,version_id,assignee_id,assignee_generation,creator_id,session_id,reason) VALUES(r,t,p,v,a,g,c[2]::uuid,c[3]::uuid,why);RETURN r;
END $assign$;
CREATE FUNCTION verivaro_verification.advance_resolution(t uuid,p uuid,r uuid,e uuid,expected integer,k text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $advance$
DECLARE c text[];task verivaro_private.resolution_tasks%ROWTYPE;prior verivaro_private.resolution_task_events%ROWTYPE;last_event verivaro_private.resolution_task_events%ROWTYPE;q verivaro_private.requirement_versions%ROWTYPE;
BEGIN
 IF k IS NULL OR k NOT IN ('submitted','returned','closed') OR e IS NULL OR expected IS NULL OR expected NOT BETWEEN 0 AND 15 OR NOT verivaro_private.workflow_reason(why) THEN RAISE EXCEPTION 'task denied' USING ERRCODE='42501';END IF;
 c:=verivaro_private.graph_actor(t,p,CASE WHEN k='submitted' THEN 'submitter' ELSE 'reviewer' END);
 SELECT * INTO task FROM verivaro_private.resolution_tasks x WHERE x.tenant_id=t AND x.project_id=p AND x.task_id=r;
 IF NOT FOUND OR (k='submitted' AND (task.assignee_id<>c[2]::uuid OR task.assignee_generation IS DISTINCT FROM verivaro_private.release_generation(t,p,c[2]::uuid,'submitter'))) OR (k<>'submitted' AND c[2]::uuid IN(task.assignee_id,task.creator_id)) THEN RAISE EXCEPTION 'task denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.resolution_task_events x WHERE x.event_id=e;
 IF FOUND THEN IF prior.task_id<>r OR prior.revision<>expected+1 OR prior.actor_id<>c[2]::uuid OR prior.kind<>k OR prior.reason<>why THEN RAISE EXCEPTION 'task conflict' USING ERRCODE='23505';END IF;RETURN true;END IF;
 q:=verivaro_private.graph_current(t,p,task.version_id);
 SELECT * INTO last_event FROM verivaro_private.resolution_task_events x WHERE x.task_id=r ORDER BY x.revision DESC LIMIT 1;
 IF COALESCE(last_event.revision,0)<>expected OR (k='submitted' AND COALESCE(last_event.kind,'assigned') NOT IN ('assigned','returned')) OR (k<>'submitted' AND last_event.kind IS DISTINCT FROM 'submitted') THEN RAISE EXCEPTION 'task transition conflict' USING ERRCODE='23505';END IF;
 IF k='closed' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(verivaro_verification.assessment(t,p)->'requirements') x WHERE x->>'versionId'=task.version_id::text AND x->>'ruleDecision'='approved' AND x->>'state' IN ('satisfied','not_applicable')) THEN RAISE EXCEPTION 'criterion still blocked' USING ERRCODE='23505';END IF;
 INSERT INTO verivaro_private.resolution_task_events(event_id,task_id,revision,kind,actor_id,session_id,reason) VALUES(e,r,expected+1,k,c[2]::uuid,c[3]::uuid,why);RETURN true;
END $advance$;
CREATE FUNCTION verivaro_verification.resolution_list(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $list$
DECLARE g jsonb;c text[];tr text;pr text;owner_view boolean;review_view boolean;
BEGIN
 g:=verivaro_verification.assessment(t,p);c:=verivaro.bound_context();
 SELECT m.role,pm.role INTO tr,pr FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id WHERE m.tenant_id=t AND pm.project_id=p AND m.actor_id=c[2]::uuid AND m.revoked_at IS NULL AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp());
 IF NOT FOUND THEN RAISE EXCEPTION 'task denied' USING ERRCODE='42501';END IF;
 owner_view:=tr='owner' AND pr='owner';review_view:=tr='reviewer' AND pr='reviewer';
 RETURN jsonb_build_object('canAssign',owner_view AND NOT (g->>'archived')::boolean,'items',COALESCE((SELECT jsonb_agg(jsonb_build_object('taskId',x.task_id,'versionId',x.version_id,'requirementId',q.requirement_id,'title',q.title,'assigneeId',x.assignee_id,'reason',x.reason,'state',COALESCE(z.kind,'assigned'),'revision',COALESCE(z.revision,0),
 'current',EXISTS(SELECT 1 FROM jsonb_array_elements(g->'requirements') a WHERE a->>'versionId'=x.version_id::text),
 'criterionSatisfied',EXISTS(SELECT 1 FROM jsonb_array_elements(g->'requirements') a WHERE a->>'versionId'=x.version_id::text AND a->>'ruleDecision'='approved' AND a->>'state' IN ('satisfied','not_applicable')),
 'canSubmit',c[2]::uuid=x.assignee_id AND (g->>'canWrite')::boolean AND COALESCE(z.kind,'assigned') IN ('assigned','returned'),
 'canReview',review_view AND NOT(g->>'archived')::boolean AND c[2]::uuid NOT IN(x.creator_id,x.assignee_id) AND z.kind='submitted',
 'history',COALESCE((SELECT jsonb_agg(jsonb_build_object('revision',h.revision,'kind',h.kind,'reason',h.reason,'recordedAt',h.recorded_at) ORDER BY h.revision) FROM verivaro_private.resolution_task_events h WHERE h.task_id=x.task_id),'[]'::jsonb)) ORDER BY x.created_at,x.task_id)
 FROM verivaro_private.resolution_tasks x JOIN verivaro_private.requirement_versions q ON q.version_id=x.version_id LEFT JOIN LATERAL(SELECT * FROM verivaro_private.resolution_task_events h WHERE h.task_id=x.task_id ORDER BY h.revision DESC LIMIT 1) z ON true WHERE x.tenant_id=t AND x.project_id=p AND (owner_view OR review_view OR ((g->>'canWrite')::boolean AND x.assignee_id=c[2]::uuid))),'[]'::jsonb));
END $list$;
REVOKE ALL ON FUNCTION verivaro_verification.grant_acknowledgement(uuid,uuid,uuid,uuid,text,uuid,integer),verivaro_verification.revoke_acknowledgement(uuid,uuid,uuid),verivaro_verification.record_acknowledgement(uuid,uuid,uuid,uuid,text,text,text),verivaro_verification.acknowledgement_list(uuid,uuid),verivaro_verification.assign_resolution(uuid,uuid,uuid,uuid,uuid,text),verivaro_verification.advance_resolution(uuid,uuid,uuid,uuid,integer,text,text),verivaro_verification.resolution_list(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.grant_acknowledgement(uuid,uuid,uuid,uuid,text,uuid,integer),verivaro_verification.revoke_acknowledgement(uuid,uuid,uuid),verivaro_verification.record_acknowledgement(uuid,uuid,uuid,uuid,text,text,text),verivaro_verification.acknowledgement_list(uuid,uuid),verivaro_verification.assign_resolution(uuid,uuid,uuid,uuid,uuid,text),verivaro_verification.advance_resolution(uuid,uuid,uuid,uuid,integer,text,text),verivaro_verification.resolution_list(uuid,uuid) TO verivaro_runtime;
COMMIT;
