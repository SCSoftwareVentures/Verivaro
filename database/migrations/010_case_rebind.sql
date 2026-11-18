BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE OR REPLACE FUNCTION vv_api.save_rejection(t uuid,p uuid,c uuid,prior integer,req uuid,new_state text,details text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.rejection_event%ROWTYPE;
BEGIN a:=vv_private.graph_lock(t,p);
 IF c IS NULL OR prior IS NULL OR prior<0 OR prior>=2147483647 OR new_state IS NULL OR new_state NOT IN ('open','resolution-recorded') OR details IS NULL OR length(trim(details)) NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION 'invalid rejection event' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.rejection_event WHERE tenant_id=t AND project_id=p AND id=c ORDER BY revision DESC LIMIT 1;
 IF old.revision=prior+1 AND (old.requirement_version_id,old.state,old.note,old.reviewer_id) IS NOT DISTINCT FROM (req,new_state,details,a) THEN RETURN old.revision;END IF;
 IF coalesce(old.revision,0)<>prior THEN RAISE EXCEPTION 'stale case' USING ERRCODE='23505';END IF;
 IF prior=0 AND (new_state<>'open' OR NOT vv_private.current_requirement(t,p,req)) THEN RAISE EXCEPTION 'new case must reference current requirement' USING ERRCODE='22023';END IF;
 IF prior>0 THEN
  IF req IS NULL OR NOT vv_private.current_requirement(t,p,req) THEN RAISE EXCEPTION 'current requirement required' USING ERRCODE='42501';END IF;
  IF old.requirement_version_id<>req THEN
   IF new_state<>'open' OR NOT EXISTS(SELECT 1 FROM vv_app.requirement_version x JOIN vv_app.requirement_version y ON (y.tenant_id,y.project_id,y.requirement_id)=(x.tenant_id,x.project_id,x.requirement_id) WHERE x.tenant_id=t AND x.project_id=p AND x.id=old.requirement_version_id AND y.id=req AND y.revision>x.revision) THEN
    RAISE EXCEPTION 'case rebind must reopen the same logical requirement on a later revision' USING ERRCODE='22023';END IF;
  ELSIF old.state=new_state THEN RAISE EXCEPTION 'invalid case transition' USING ERRCODE='22023';
  END IF;
 END IF;
 IF (SELECT count(*) FROM vv_app.rejection_event WHERE tenant_id=t AND project_id=p)>=2000 THEN RAISE EXCEPTION 'case limit' USING ERRCODE='54000';END IF;
 INSERT INTO vv_app.rejection_event(tenant_id,project_id,id,revision,requirement_version_id,state,note,reviewer_id) VALUES(t,p,c,prior+1,req,new_state,details,a);
 PERFORM vv_private.bump_graph(t,p);RETURN prior+1;
END $$;
RESET ROLE;
COMMIT;
