BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE TABLE vv_app.native_page_draft(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,intent_id uuid NOT NULL,page integer NOT NULL CHECK(page BETWEEN 1 AND 20),
 source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 method text NOT NULL CHECK(method IN ('pdf-text','ocr')),
 text_value text NOT NULL CHECK(octet_length(text_value)<=1048576),
 text_sha256 text NOT NULL CHECK(text_sha256=encode(vv_crypto.digest(convert_to(text_value,'UTF8'),'sha256'),'hex')),
 extracted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,intent_id,page),
 FOREIGN KEY(tenant_id,project_id,intent_id) REFERENCES vv_private.extract_job(tenant_id,project_id,intent_id)
);
CREATE TABLE vv_app.requirement_decision(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,intent_id uuid NOT NULL,
 page integer NOT NULL CHECK(page BETWEEN 1 AND 20),start_cp integer NOT NULL CHECK(start_cp>=0),
 end_cp integer NOT NULL CHECK(end_cp>start_cp),quote text NOT NULL CHECK(length(quote)=end_cp-start_cp AND length(quote)<=2000),
 text_sha256 text NOT NULL CHECK(text_sha256 ~ '^[0-9a-f]{64}$'),
 decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 criterion_kind text,expected text,mandatory boolean,
 reviewer_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),
 UNIQUE(tenant_id,project_id,intent_id,page,start_cp,end_cp),
 FOREIGN KEY(tenant_id,project_id,intent_id) REFERENCES vv_private.extract_job(tenant_id,project_id,intent_id),
 FOREIGN KEY(tenant_id,project_id,reviewer_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK((decision='approved' AND criterion_kind IS NOT NULL AND expected IS NOT NULL AND mandatory IS NOT NULL) OR
 (decision='rejected' AND criterion_kind IS NULL AND expected IS NULL AND mandatory IS NULL))
);
ALTER TABLE vv_app.native_page_draft ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_app.native_page_draft FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_app.native_page_draft TO verivaro_owner USING(true) WITH CHECK(true);
ALTER TABLE vv_app.requirement_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_app.requirement_decision FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_app.requirement_decision TO verivaro_owner USING(true) WITH CHECK(true);
-- Parser role can stage outputs only for a valid clean-scan extraction lease, not approve them.
CREATE FUNCTION vv_api.finish_native_extract(token uuid,pages jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_crypto AS $$
DECLARE j vv_private.extract_job%ROWTYPE;r vv_app.quarantine_receipt%ROWTYPE;x jsonb;n integer:=0;total integer:=0;nonempty boolean:=false;v text;m text;
BEGIN
 SELECT * INTO j FROM vv_private.extract_job WHERE lease_token=token AND state='leased' AND lease_until>clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'lease unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT r FROM vv_app.quarantine_receipt WHERE (tenant_id,project_id,intent_id)=(j.tenant_id,j.project_id,j.intent_id);
 IF r.media_type NOT IN ('application/pdf','image/png','image/jpeg') OR r.actual_bytes>10485760 OR pages IS NULL OR jsonb_typeof(pages)<>'array' THEN RAISE EXCEPTION 'invalid pages' USING ERRCODE='22023';END IF;
 IF jsonb_array_length(pages) NOT BETWEEN 1 AND 20 OR (r.media_type<>'application/pdf' AND jsonb_array_length(pages)<>1) THEN RAISE EXCEPTION 'invalid page count' USING ERRCODE='22023';END IF;
 FOR x IN SELECT value FROM jsonb_array_elements(pages) LOOP
 n:=n+1;v:=x->>'text';m:=x->>'method';
 IF jsonb_typeof(x)<>'object' OR jsonb_typeof(x->'page') IS DISTINCT FROM 'number' OR x->>'page' IS DISTINCT FROM n::text OR jsonb_typeof(x->'text') IS DISTINCT FROM 'string' OR m IS NULL OR m NOT IN ('pdf-text','ocr') OR (r.media_type<>'application/pdf' AND m<>'ocr') THEN RAISE EXCEPTION 'invalid page' USING ERRCODE='22023';END IF;
 total:=total+octet_length(v);IF total>1048576 THEN RAISE EXCEPTION 'text limit' USING ERRCODE='22023';END IF;
 nonempty:=nonempty OR length(trim(v))>0;
 INSERT INTO vv_app.native_page_draft(tenant_id,project_id,intent_id,page,source_sha256,method,text_value,text_sha256)
 VALUES(j.tenant_id,j.project_id,j.intent_id,n,r.actual_sha256,m,v,encode(vv_crypto.digest(convert_to(v,'UTF8'),'sha256'),'hex'));
 END LOOP;
 IF NOT nonempty THEN RAISE EXCEPTION 'empty extraction' USING ERRCODE='22023';END IF;
 UPDATE vv_private.extract_job SET state='complete',lease_token=NULL,lease_until=NULL WHERE (tenant_id,project_id,intent_id)=(j.tenant_id,j.project_id,j.intent_id);
 RETURN 'complete';
END $$;
CREATE FUNCTION vv_private.review_actor(t uuid,p uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
DECLARE a uuid;
BEGIN
 a:=vv_private.capture_actor(t,p);
 IF NOT EXISTS(SELECT 1 FROM vv_private.project_member WHERE tenant_id=t AND project_id=p AND actor_id=a AND role IN ('owner','reviewer') AND active) THEN RAISE EXCEPTION 'review denied' USING ERRCODE='42501';END IF;
 RETURN a;
END $$;
CREATE FUNCTION vv_api.review_pages(t uuid,p uuid,u uuid)
RETURNS TABLE(page integer,method text,text_value text,text_sha256 text,source_sha256 text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_crypto AS $$
BEGIN
 PERFORM vv_private.review_actor(t,p);
 IF NOT EXISTS(SELECT 1 FROM vv_private.extract_job WHERE tenant_id=t AND project_id=p AND intent_id=u AND state='complete') THEN RAISE EXCEPTION 'draft unavailable' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT 1,'utf8-exact'::text,d.text_value,d.source_sha256,d.source_sha256 FROM vv_app.extracted_text_draft d WHERE d.tenant_id=t AND d.project_id=p AND d.intent_id=u
 UNION ALL SELECT d.page,d.method,d.text_value,d.text_sha256,d.source_sha256 FROM vv_app.native_page_draft d WHERE d.tenant_id=t AND d.project_id=p AND d.intent_id=u ORDER BY 1;
END $$;
CREATE FUNCTION vv_api.decide_requirement(t uuid,p uuid,u uuid,d uuid,pg integer,lo integer,hi integer,q text,digest text,verdict text,kind text,wanted text,must boolean) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_api AS $$
DECLARE a uuid;v record;old vv_app.requirement_decision%ROWTYPE;
BEGIN
 a:=vv_private.review_actor(t,p);
 IF d IS NULL OR pg IS NULL OR lo IS NULL OR hi IS NULL OR lo<0 OR hi<=lo OR hi-lo>2000 OR q IS NULL OR length(q)<>hi-lo OR verdict IS NULL OR verdict NOT IN ('approved','rejected') THEN RAISE EXCEPTION 'invalid review' USING ERRCODE='22023'; END IF;
 SELECT * INTO v FROM vv_api.review_pages(t,p,u) WHERE page=pg;
 IF NOT FOUND OR digest IS DISTINCT FROM v.text_sha256 OR hi>length(v.text_value) OR substring(v.text_value FROM lo+1 FOR hi-lo) IS DISTINCT FROM q THEN RAISE EXCEPTION 'source mismatch' USING ERRCODE='22023';END IF;
 IF verdict='approved' AND (kind IS NULL OR length(trim(kind)) NOT BETWEEN 1 AND 80 OR wanted IS NULL OR length(trim(wanted)) NOT BETWEEN 1 AND 500 OR position(wanted IN q)=0 OR must IS NULL) THEN RAISE EXCEPTION 'invalid criterion' USING ERRCODE='22023';END IF;
 IF verdict='rejected' AND (kind IS NOT NULL OR wanted IS NOT NULL OR must IS NOT NULL) THEN RAISE EXCEPTION 'invalid rejection' USING ERRCODE='22023'; END IF;
 INSERT INTO vv_app.requirement_decision(tenant_id,project_id,id,intent_id,page,start_cp,end_cp,quote,text_sha256,decision,criterion_kind,expected,mandatory,reviewer_id)
 VALUES(t,p,d,u,pg,lo,hi,q,digest,verdict,kind,wanted,must,a) ON CONFLICT DO NOTHING;
 SELECT * INTO old FROM vv_app.requirement_decision WHERE tenant_id=t AND project_id=p AND id=d;
 IF NOT FOUND OR (old.intent_id,old.page,old.start_cp,old.end_cp,old.quote,old.text_sha256,old.decision,old.criterion_kind,old.expected,old.mandatory,old.reviewer_id) IS DISTINCT FROM (u,pg,lo,hi,q,digest,verdict,kind,wanted,must,a) THEN RAISE EXCEPTION 'review conflict' USING ERRCODE='23505';END IF;
 RETURN d;
END $$;
REVOKE ALL ON FUNCTION vv_api.finish_native_extract(uuid,jsonb),vv_private.review_actor(uuid,uuid),vv_api.review_pages(uuid,uuid,uuid),vv_api.decide_requirement(uuid,uuid,uuid,uuid,integer,integer,integer,text,text,text,text,text,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.finish_native_extract(uuid,jsonb) TO verivaro_parse_worker;
GRANT EXECUTE ON FUNCTION vv_api.review_pages(uuid,uuid,uuid),vv_api.decide_requirement(uuid,uuid,uuid,uuid,integer,integer,integer,text,text,text,text,text,boolean) TO verivaro_runtime;
RESET ROLE;
COMMIT;
