BEGIN;
CREATE TABLE verivaro_private.financial_records(
 record_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,
 reference text NOT NULL CHECK(reference~'^[a-z0-9][a-z0-9._-]{0,63}$'),
 kind text NOT NULL CHECK(kind IN ('milestone','retention','disputed')),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),
 UNIQUE(tenant_id,project_id,kind,reference));
CREATE TABLE verivaro_private.financial_versions(
 version_id uuid PRIMARY KEY,record_id uuid NOT NULL REFERENCES verivaro_private.financial_records(record_id),
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 16),
 title text NOT NULL CHECK(char_length(title) BETWEEN 1 AND 128 AND octet_length(title)<=512),
 currency text NOT NULL CHECK(currency IN ('AUD','USD','NZD','GBP','EUR','CAD','SGD','JPY','KWD','BHD')),
 tax_basis text NOT NULL CHECK(tax_basis IN ('tax_inclusive','tax_exclusive','tax_not_applicable')),
 amount_text text,amount_minor bigint CHECK(amount_minor BETWEEN 0 AND 999999999999999),
 due_at timestamptz,
 source_evidence_id uuid NOT NULL REFERENCES verivaro_private.evidence_objects(evidence_id),
 source_sha256 text NOT NULL CHECK(source_sha256~'^[0-9a-f]{64}$'),
 condition_versions uuid[] NOT NULL CHECK(cardinality(condition_versions)<=32),
 author_id uuid NOT NULL,session_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((amount_text IS NULL)=(amount_minor IS NULL)),UNIQUE(record_id,revision));
CREATE TABLE verivaro_private.financial_reviews(
 version_id uuid PRIMARY KEY REFERENCES verivaro_private.financial_versions(version_id),
 reviewer_id uuid NOT NULL,session_id uuid NOT NULL,decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),
 reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON verivaro_private.financial_records,verivaro_private.financial_versions,verivaro_private.financial_reviews FROM PUBLIC;
CREATE TRIGGER financial_record_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.financial_records FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER financial_version_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.financial_versions FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER financial_review_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.financial_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER financial_archive_guard BEFORE INSERT ON verivaro_private.financial_records FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE FUNCTION verivaro_private.financial_minor(a text,c text) RETURNS bigint LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $minor$
DECLARE n integer;v numeric;
BEGIN
 n:=CASE WHEN c='JPY' THEN 0 WHEN c IN ('KWD','BHD') THEN 3 WHEN c IN ('AUD','USD','NZD','GBP','EUR','CAD','SGD') THEN 2 ELSE NULL END;
 IF n IS NULL THEN RAISE EXCEPTION 'invalid currency' USING ERRCODE='22023';END IF;
 IF a IS NULL THEN RETURN NULL;END IF;
 IF char_length(a)>20 OR a!~'^(0|[1-9][0-9]*)(\.[0-9]+)?$' OR (position('.' in a)>0 AND char_length(split_part(a,'.',2))>n) THEN RAISE EXCEPTION 'invalid amount' USING ERRCODE='22023';END IF;
 v:=a::numeric*power(10::numeric,n);
 IF v>999999999999999 OR v<>trunc(v) THEN RAISE EXCEPTION 'invalid amount' USING ERRCODE='22023';END IF;
 RETURN v::bigint;
END $minor$;
REVOKE ALL ON FUNCTION verivaro_private.financial_minor(text,text) FROM PUBLIC;
CREATE FUNCTION verivaro_private.financial_pins(t uuid,p uuid,pins uuid[]) RETURNS uuid[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $pins$
DECLARE v uuid;q verivaro_private.requirement_versions%ROWTYPE;ids uuid[]:=ARRAY[]::uuid[];result uuid[];
BEGIN
 IF pins IS NULL OR cardinality(pins)>32 OR array_position(pins,NULL) IS NOT NULL THEN RAISE EXCEPTION 'invalid condition pins' USING ERRCODE='22023';END IF;
 FOREACH v IN ARRAY pins LOOP
  q:=verivaro_private.graph_current(t,p,v);
  IF q.requirement_id=ANY(ids) OR q.applicability NOT IN ('required','optional') OR NOT EXISTS(SELECT 1 FROM verivaro_private.requirement_reviews r WHERE r.version_id=v AND r.decision='approved') THEN RAISE EXCEPTION 'financial condition denied' USING ERRCODE='42501';END IF;
  ids:=array_append(ids,q.requirement_id);
 END LOOP;
 SELECT COALESCE(array_agg(x ORDER BY x),ARRAY[]::uuid[]) INTO result FROM unnest(pins) x;
 RETURN result;
END $pins$;
REVOKE ALL ON FUNCTION verivaro_private.financial_pins(uuid,uuid,uuid[]) FROM PUBLIC;
CREATE FUNCTION verivaro_verification.write_financial_record(t uuid,p uuid,r uuid,v uuid,expected integer,ref text,k text,n text,currency_code text,basis text,amount text,due text,e uuid,h text,pins uuid[]) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $write$
DECLARE ctx text[];rec verivaro_private.financial_records%ROWTYPE;prior verivaro_private.financial_versions%ROWTYPE;latest integer;minor bigint;due_value timestamptz;sorted_pins uuid[];
BEGIN
 ctx:=verivaro_private.graph_actor(t,p,'owner');
 IF r IS NULL OR v IS NULL OR expected IS NULL OR expected NOT BETWEEN 0 AND 15 OR ref IS NULL OR ref!~'^[a-z0-9][a-z0-9._-]{0,63}$'
 OR k IS NULL OR k NOT IN ('milestone','retention','disputed') OR n IS NULL OR char_length(n) NOT BETWEEN 1 AND 128 OR octet_length(n)>512 OR n<>btrim(n) OR n~'[[:cntrl:]]'
 OR currency_code IS NULL OR basis IS NULL OR basis NOT IN ('tax_inclusive','tax_exclusive','tax_not_applicable') OR e IS NULL OR h IS NULL OR h!~'^[a-f0-9]{64}$'
 OR pins IS NULL OR cardinality(pins)>32 OR array_position(pins,NULL) IS NOT NULL
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects x WHERE x.tenant_id=t AND x.project_id=p AND x.evidence_id=e AND x.sha256=h AND x.cipher_digest=verivaro_private.digest(x.envelope,'sha256')) THEN RAISE EXCEPTION 'financial record denied' USING ERRCODE='42501';END IF;
 minor:=verivaro_private.financial_minor(amount,currency_code);
 IF due IS NOT NULL THEN
  IF due!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$' THEN RAISE EXCEPTION 'invalid date' USING ERRCODE='22023';END IF;
  due_value:=due::timestamptz;
  IF to_char(due_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')<>due THEN RAISE EXCEPTION 'invalid date' USING ERRCODE='22023';END IF;
 END IF;
 SELECT COALESCE(array_agg(x ORDER BY x),ARRAY[]::uuid[]) INTO sorted_pins FROM unnest(pins) x;
 SELECT * INTO rec FROM verivaro_private.financial_records x WHERE x.record_id=r;
 IF FOUND AND (rec.tenant_id<>t OR rec.project_id<>p OR rec.reference<>ref OR rec.kind<>k) THEN RAISE EXCEPTION 'financial record conflict' USING ERRCODE='23505';END IF;
 SELECT * INTO prior FROM verivaro_private.financial_versions x WHERE x.version_id=v;
 IF FOUND THEN
  IF prior.record_id<>r OR prior.author_id<>ctx[2]::uuid OR prior.revision<>expected+1 OR prior.title<>n OR prior.currency<>currency_code OR prior.tax_basis<>basis OR prior.amount_text IS DISTINCT FROM amount OR prior.due_at IS DISTINCT FROM due_value OR prior.source_evidence_id<>e OR prior.source_sha256<>h OR prior.condition_versions<>sorted_pins THEN RAISE EXCEPTION 'financial conflict' USING ERRCODE='23505';END IF;
  RETURN jsonb_build_object('recordId',r,'versionId',v,'revision',prior.revision);
 END IF;
 sorted_pins:=verivaro_private.financial_pins(t,p,pins);
 SELECT COALESCE(max(x.revision),0) INTO latest FROM verivaro_private.financial_versions x WHERE x.record_id=r;
 IF latest<>expected THEN RAISE EXCEPTION 'stale financial revision' USING ERRCODE='23505';END IF;
 PERFORM pg_advisory_xact_lock(740129816164::bigint);
 IF (SELECT count(*) FROM verivaro_private.financial_versions)>=32768 OR (SELECT count(*) FROM verivaro_private.financial_versions x JOIN verivaro_private.financial_records z USING(record_id) WHERE z.tenant_id=t AND z.project_id=p)>=512 OR (latest=0 AND (SELECT count(*) FROM verivaro_private.financial_records x WHERE x.tenant_id=t AND x.project_id=p)>=128) THEN RAISE EXCEPTION 'financial capacity' USING ERRCODE='54000';END IF;
 IF latest=0 THEN INSERT INTO verivaro_private.financial_records(record_id,tenant_id,project_id,reference,kind) VALUES(r,t,p,ref,k);END IF;
 INSERT INTO verivaro_private.financial_versions(version_id,record_id,revision,title,currency,tax_basis,amount_text,amount_minor,due_at,source_evidence_id,source_sha256,condition_versions,author_id,session_id)
 VALUES(v,r,expected+1,n,currency_code,basis,amount,minor,due_value,e,h,sorted_pins,ctx[2]::uuid,ctx[3]::uuid);
 RETURN jsonb_build_object('recordId',r,'versionId',v,'revision',expected+1);
END $write$;
CREATE FUNCTION verivaro_verification.review_financial_record(t uuid,p uuid,v uuid,d text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE ctx text[];item verivaro_private.financial_versions%ROWTYPE;prior verivaro_private.financial_reviews%ROWTYPE;
BEGIN
 ctx:=verivaro_private.graph_actor(t,p,'reviewer');
 SELECT x.* INTO item FROM verivaro_private.financial_versions x JOIN verivaro_private.financial_records z USING(record_id) WHERE z.tenant_id=t AND z.project_id=p AND x.version_id=v;
 IF NOT FOUND OR item.author_id=ctx[2]::uuid OR d IS NULL OR d NOT IN ('approved','rejected') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'financial review denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.financial_reviews x WHERE x.version_id=v;
 IF FOUND THEN
 IF prior.reviewer_id<>ctx[2]::uuid OR prior.decision<>d OR prior.reason<>why THEN RAISE EXCEPTION 'financial review conflict' USING ERRCODE='23505';END IF;
 RETURN true;END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.financial_versions x WHERE x.record_id=item.record_id AND x.revision>item.revision) THEN RAISE EXCEPTION 'stale financial revision' USING ERRCODE='23505';END IF;
 IF d='approved' THEN
  IF NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects x WHERE x.tenant_id=t AND x.project_id=p AND x.evidence_id=item.source_evidence_id AND x.sha256=item.source_sha256 AND x.actor_id<>ctx[2]::uuid AND x.cipher_digest=verivaro_private.digest(x.envelope,'sha256')) THEN RAISE EXCEPTION 'financial source review denied' USING ERRCODE='42501';END IF;
  PERFORM verivaro_private.financial_pins(t,p,item.condition_versions);
 END IF;
 INSERT INTO verivaro_private.financial_reviews(version_id,reviewer_id,session_id,decision,reason) VALUES(v,ctx[2]::uuid,ctx[3]::uuid,d,why);
 RETURN true;
END $review$;
CREATE FUNCTION verivaro_verification.financial_records(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $records$
DECLARE g jsonb;ctx text[];items jsonb;tr text;pr text;
BEGIN
 g:=verivaro_verification.assessment(t,p);ctx:=verivaro.bound_context();
 SELECT tm.role,pm.role INTO tr,pr FROM verivaro.memberships tm JOIN verivaro.project_members pm ON pm.tenant_id=tm.tenant_id AND pm.actor_id=tm.actor_id
 WHERE tm.tenant_id=t AND pm.project_id=p AND tm.actor_id=ctx[2]::uuid AND tm.revoked_at IS NULL AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp());
 IF NOT FOUND OR NOT ((tr='owner' AND pr='owner') OR (tr='reviewer' AND pr='reviewer')) THEN RAISE EXCEPTION 'financial read denied' USING ERRCODE='42501';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('tenantId',t,'projectId',p,'recordId',z.record_id,'reference',z.reference,'kind',z.kind,'versionId',x.version_id,'revision',x.revision,'title',x.title,'currency',x.currency,'taxBasis',x.tax_basis,'amountStatus',CASE WHEN x.amount_text IS NULL THEN 'unknown' ELSE 'confirmed' END,'amount',x.amount_text,'storedMinor',x.amount_minor::text,'dueStatus',CASE WHEN x.due_at IS NULL THEN 'unknown' ELSE 'confirmed' END,'dueAt',CASE WHEN x.due_at IS NULL THEN NULL ELSE to_char(x.due_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,'sourceEvidenceId',x.source_evidence_id,'sourceSha256',x.source_sha256,'sourceIntact',o.sha256=x.source_sha256 AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256'),'decision',COALESCE(rv.decision,'pending'),'reviewReason',rv.reason,'conditions',(SELECT COALESCE(jsonb_agg(jsonb_build_object('requirementId',q.requirement_id,'versionId',q.version_id) ORDER BY q.requirement_id),'[]'::jsonb) FROM verivaro_private.requirement_versions q WHERE q.version_id=ANY(x.condition_versions)),
 'history',(SELECT jsonb_agg(jsonb_build_object('versionId',h.version_id,'revision',h.revision,'title',h.title,'currency',h.currency,'taxBasis',h.tax_basis,'amount',h.amount_text,'sourceEvidenceId',h.source_evidence_id,'sourceSha256',h.source_sha256,'dueAt',CASE WHEN h.due_at IS NULL THEN NULL ELSE to_char(h.due_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,'decision',COALESCE(hr.decision,'pending'),'reviewReason',hr.reason,'recordedAt',to_char(h.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) ORDER BY h.revision) FROM verivaro_private.financial_versions h LEFT JOIN verivaro_private.financial_reviews hr ON hr.version_id=h.version_id WHERE h.record_id=z.record_id)) ORDER BY z.record_id),'[]'::jsonb)
 INTO items FROM verivaro_private.financial_records z JOIN LATERAL (SELECT * FROM verivaro_private.financial_versions f WHERE f.record_id=z.record_id ORDER BY f.revision DESC LIMIT 1) x ON true JOIN verivaro_private.evidence_objects o ON o.evidence_id=x.source_evidence_id LEFT JOIN verivaro_private.financial_reviews rv ON rv.version_id=x.version_id WHERE z.tenant_id=t AND z.project_id=p;
 RETURN jsonb_build_object('scope',jsonb_build_object('tenantId',t,'projectId',p),'asOf',to_char(statement_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'assessment',g,'records',items,'canWrite',tr='owner' AND pr='owner' AND NOT (g->>'archived')::boolean,'canReview',tr='reviewer' AND pr='reviewer' AND NOT (g->>'archived')::boolean);
END $records$;
REVOKE ALL ON FUNCTION verivaro_verification.write_financial_record(uuid,uuid,uuid,uuid,integer,text,text,text,text,text,text,text,uuid,text,uuid[]),verivaro_verification.review_financial_record(uuid,uuid,uuid,text,text),verivaro_verification.financial_records(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.write_financial_record(uuid,uuid,uuid,uuid,integer,text,text,text,text,text,text,text,uuid,text,uuid[]),verivaro_verification.review_financial_record(uuid,uuid,uuid,text,text),verivaro_verification.financial_records(uuid,uuid) TO verivaro_runtime;
COMMIT;
