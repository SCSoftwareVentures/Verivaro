BEGIN;
ALTER TABLE verivaro_private.requirement_sources DROP CONSTRAINT requirement_sources_page_number_check;
ALTER TABLE verivaro_private.requirement_sources ADD CONSTRAINT requirement_sources_page_number_check CHECK(page_number IS NULL OR (page_number BETWEEN 1 AND 32 AND line_number BETWEEN page_number AND 40*page_number));
CREATE OR REPLACE FUNCTION verivaro_verification.import_source_line(t uuid,p uuid,r uuid,v uuid,e uuid,h text,ln integer,pg integer,quote_text text,quote_hash text,app text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $import$
DECLARE c text[];prior verivaro_private.requirement_sources%ROWTYPE;outcome jsonb;media text;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');
 IF r IS NULL OR v IS NULL OR e IS NULL OR h IS NULL OR ln IS NULL OR ln NOT BETWEEN 1 AND 262144 OR quote_text IS NULL
 OR char_length(quote_text) NOT BETWEEN 1 AND 1024 OR octet_length(quote_text)>4096 OR quote_text<>btrim(quote_text) OR quote_text~'[[:cntrl:]]'
 OR quote_hash IS DISTINCT FROM encode(verivaro_private.digest(convert_to(quote_text,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'source import denied' USING ERRCODE='42501';END IF;
 SELECT o.media_type INTO media FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t AND o.project_id=p AND o.evidence_id=e AND o.sha256=h AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256');
 IF NOT FOUND OR (media='application/pdf' AND (pg IS NULL OR pg NOT BETWEEN 1 AND 32 OR ln<pg OR ln>40*pg)) OR (media='text/plain; charset=utf-8' AND pg IS NOT NULL) OR media NOT IN ('application/pdf','text/plain; charset=utf-8') THEN RAISE EXCEPTION 'source import denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_sources WHERE version_id=v;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.evidence_id<>e OR prior.source_sha256<>h OR prior.line_number<>ln OR prior.page_number IS DISTINCT FROM pg OR prior.quote_sha256<>quote_hash OR prior.algorithm<>'modal-line-v1' THEN RAISE EXCEPTION 'source conflict' USING ERRCODE='23505';END IF;
 RETURN verivaro_verification.write_requirement(t,p,r,v,0,'Source line '||ln,quote_text,app);
 END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_versions WHERE version_id=v) THEN RAISE EXCEPTION 'source conflict' USING ERRCODE='23505';END IF;
 outcome:=verivaro_verification.write_requirement(t,p,r,v,0,'Source line '||ln,quote_text,app);
 INSERT INTO verivaro_private.requirement_sources(version_id,tenant_id,project_id,evidence_id,source_sha256,line_number,page_number,quote_sha256,algorithm)
 VALUES(v,t,p,e,h,ln,pg,quote_hash,'modal-line-v1');
 RETURN outcome;
END $import$;
CREATE OR REPLACE FUNCTION verivaro_verification.import_source_line_v2(t uuid,p uuid,r uuid,v uuid,e uuid,h text,ln integer,pg integer,quote_text text,quote_hash text,app text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $import$
DECLARE c text[];prior verivaro_private.requirement_sources%ROWTYPE;outcome jsonb;media text;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'submitter');
 IF r IS NULL OR v IS NULL OR e IS NULL OR h IS NULL OR ln IS NULL OR ln NOT BETWEEN 1 AND 262144 OR quote_text IS NULL
 OR char_length(quote_text) NOT BETWEEN 1 AND 1024 OR octet_length(quote_text)>4096 OR quote_text<>btrim(quote_text) OR quote_text~'[[:cntrl:]]'
 OR quote_hash IS DISTINCT FROM encode(verivaro_private.digest(convert_to(quote_text,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'source import denied' USING ERRCODE='42501';END IF;
 SELECT o.media_type INTO media FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t AND o.project_id=p AND o.evidence_id=e AND o.sha256=h AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256');
 IF NOT FOUND OR (media='application/pdf' AND (pg IS NULL OR pg NOT BETWEEN 1 AND 32 OR ln<pg OR ln>40*pg)) OR (media='text/plain; charset=utf-8' AND pg IS NOT NULL) OR media NOT IN ('application/pdf','text/plain; charset=utf-8') THEN RAISE EXCEPTION 'source import denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.requirement_sources WHERE version_id=v;
 IF FOUND THEN
 IF prior.tenant_id<>t OR prior.project_id<>p OR prior.evidence_id<>e OR prior.source_sha256<>h OR prior.line_number<>ln OR prior.page_number IS DISTINCT FROM pg OR prior.quote_sha256<>quote_hash OR prior.algorithm<>'obligation-line-v2' THEN RAISE EXCEPTION 'source conflict' USING ERRCODE='23505';END IF;
 RETURN verivaro_verification.write_requirement(t,p,r,v,0,'Source line '||ln,quote_text,app);
 END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.requirement_versions WHERE version_id=v) THEN RAISE EXCEPTION 'source conflict' USING ERRCODE='23505';END IF;
 outcome:=verivaro_verification.write_requirement(t,p,r,v,0,'Source line '||ln,quote_text,app);
 INSERT INTO verivaro_private.requirement_sources(version_id,tenant_id,project_id,evidence_id,source_sha256,line_number,page_number,quote_sha256,algorithm)
 VALUES(v,t,p,e,h,ln,pg,quote_hash,'obligation-line-v2');
 RETURN outcome;
END $import$;
COMMIT;
