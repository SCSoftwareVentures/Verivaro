BEGIN;
-- Extend only OCR location type checks; unchanged historic rows retain exact digests.
CREATE OR REPLACE FUNCTION verivaro_private.ocr_location_valid(l jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $loc$
DECLARE k text;b jsonb;w integer;h integer;x integer;y integer;bw integer;bh integer;
BEGIN
 IF jsonb_typeof(l) IS DISTINCT FROM 'object' OR octet_length(l::text)>2048 OR l-ARRAY['algorithm','width','height','block','paragraph','line','box','confidence','minWordConfidence','wordCount','regionDigest','page','rasterSha256']<>'{}'::jsonb OR l->>'algorithm' IS DISTINCT FROM 'tesseract-eng-psm6-tsv-v1' OR COALESCE(l->>'regionDigest','')!~'^[a-f0-9]{64}$' THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['width','height','block','paragraph','line','wordCount'] LOOP
 IF jsonb_typeof(l->k) IS DISTINCT FROM 'number' OR COALESCE(l->>k,'')!~'^[1-9][0-9]{0,3}$' THEN RETURN false;END IF;
 END LOOP;
 w:=(l->>'width')::integer;h:=(l->>'height')::integer;
 IF w>2048 OR h>2048 OR w*h>1048576 OR (l->>'wordCount')::integer>128 OR (l->>'block')::integer>4096 OR (l->>'paragraph')::integer>4096 OR (l->>'line')::integer>4096 THEN RETURN false;END IF;
 b:=l->'box';
 IF jsonb_typeof(b) IS DISTINCT FROM 'object' OR b-ARRAY['left','top','width','height']<>'{}'::jsonb THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['left','top','width','height'] LOOP
 IF jsonb_typeof(b->k) IS DISTINCT FROM 'number' OR COALESCE(b->>k,'')!~'^(0|[1-9][0-9]{0,3})$' THEN RETURN false;END IF;
 END LOOP;
 x:=(b->>'left')::integer;y:=(b->>'top')::integer;bw:=(b->>'width')::integer;bh:=(b->>'height')::integer;
 IF bw<1 OR bh<1 OR x+bw>w OR y+bh>h THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['confidence','minWordConfidence'] LOOP
 IF jsonb_typeof(l->k) IS DISTINCT FROM 'number' OR COALESCE(l->>k,'')!~'^(0|[1-9][0-9]{0,2})(\.[0-9]{1,2})?$' OR (l->>k)::numeric>100 THEN RETURN false;END IF;
 END LOOP;
 IF (l ? 'page')<>(l ? 'rasterSha256') THEN RETURN false;END IF;
 IF l ? 'page' THEN
  IF jsonb_typeof(l->'page') IS DISTINCT FROM 'number' OR l->>'page'<>'1' OR COALESCE(l->>'rasterSha256','')!~'^[a-f0-9]{64}$' THEN RETURN false;END IF;
 END IF;
 RETURN (l->>'minWordConfidence')::numeric<=(l->>'confidence')::numeric;
END $loc$;
CREATE OR REPLACE FUNCTION verivaro_verification.import_ocr_source(t uuid,p uuid,r uuid,v uuid,e uuid,h text,ln integer,quote_text text,quote_hash text,app text,loc jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $import$
DECLARE prior verivaro_private.requirement_sources%ROWTYPE;outcome jsonb;media text;
BEGIN
 PERFORM verivaro_private.graph_actor(t,p,'submitter');
 IF r IS NULL OR v IS NULL OR e IS NULL OR h IS NULL OR ln IS NULL OR ln NOT BETWEEN 1 AND 512 OR quote_text IS NULL OR char_length(quote_text) NOT BETWEEN 1 AND 1024 OR octet_length(quote_text)>4096 OR quote_text<>btrim(quote_text) OR quote_text~'[[:cntrl:]]' OR quote_hash IS DISTINCT FROM encode(verivaro_private.digest(convert_to(quote_text,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'OCR source denied' USING ERRCODE='42501';END IF;
 SELECT o.media_type INTO media FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t AND o.project_id=p AND o.evidence_id=e AND o.sha256=h AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256');
 IF NOT FOUND OR media NOT IN ('image/png','application/pdf') OR NOT verivaro_private.ocr_location_valid(loc) OR (media='image/png' AND (loc ? 'page')) OR (media='application/pdf' AND NOT (loc ? 'page')) THEN RAISE EXCEPTION 'OCR source denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_sources WHERE version_id=v;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.evidence_id<>e OR prior.source_sha256<>h OR prior.line_number<>ln OR prior.page_number IS NOT NULL OR prior.quote_sha256<>quote_hash OR prior.algorithm<>'ocr-human-source-v1' OR prior.office_location IS DISTINCT FROM loc THEN RAISE EXCEPTION 'source conflict' USING ERRCODE='23505';END IF;
 RETURN verivaro_verification.write_requirement(t,p,r,v,0,'OCR region '||ln,quote_text,app);
 END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_versions WHERE version_id=v) THEN RAISE EXCEPTION 'source conflict' USING ERRCODE='23505';END IF;
 outcome:=verivaro_verification.write_requirement(t,p,r,v,0,'OCR region '||ln,quote_text,app);
 INSERT INTO verivaro_private.requirement_sources(version_id,tenant_id,project_id,evidence_id,source_sha256,line_number,page_number,quote_sha256,algorithm,office_location)
 VALUES(v,t,p,e,h,ln,NULL,quote_hash,'ocr-human-source-v1',loc);
 RETURN outcome;
END $import$;
CREATE OR REPLACE FUNCTION verivaro_verification.review_ocr_source(t uuid,p uuid,v uuid,h text,qh text,rh text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE d text:='approved';c text[];q verivaro_private.requirement_versions%ROWTYPE;prior verivaro_private.requirement_reviews%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');q:=verivaro_private.graph_current(t,p,v);
 IF why IS NULL OR char_length(why) NOT BETWEEN 1 AND 450 OR why<>btrim(why) OR NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_sources s JOIN verivaro_private.evidence_objects o ON o.evidence_id=s.evidence_id AND o.tenant_id=s.tenant_id AND o.project_id=s.project_id WHERE s.version_id=v AND s.tenant_id=t AND s.project_id=p AND s.algorithm='ocr-human-source-v1' AND s.source_sha256=h AND s.quote_sha256=qh AND s.office_location->>'regionDigest'=rh AND o.sha256=h AND ((o.media_type='image/png' AND NOT(s.office_location ? 'page')) OR (o.media_type='application/pdf' AND s.office_location->>'page'='1' AND s.office_location->>'rasterSha256'~'^[a-f0-9]{64}$')) AND o.actor_id<>c[2]::uuid AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256') AND qh=encode(verivaro_private.digest(convert_to(q.criterion,'UTF8'),'sha256'),'hex')) THEN RAISE EXCEPTION 'OCR review denied' USING ERRCODE='42501';END IF;
 why:='OCR transcription and criterion independently confirmed: '||why;
 IF q.author_id=c[2]::uuid OR d IS NULL OR d NOT IN ('approved','rejected') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'graph review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_reviews WHERE version_id=v;
 IF FOUND THEN
 IF prior.reviewer_id<>c[2]::uuid OR prior.decision<>d OR prior.reason<>why THEN RAISE EXCEPTION 'graph conflict' USING ERRCODE='23505';END IF;
 RETURN true;END IF;
 INSERT INTO verivaro_private.requirement_reviews(version_id,reviewer_id,session_id,decision,reason) VALUES(v,c[2]::uuid,c[3]::uuid,d,why);
 RETURN true;
END $review$;
COMMIT;
