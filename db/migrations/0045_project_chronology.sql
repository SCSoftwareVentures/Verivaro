BEGIN;
CREATE TABLE verivaro_private.project_chronology(
 event_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,
 submission_id uuid REFERENCES verivaro_private.submission_snapshots(submission_id),submission_sha256 text,
 event_type text NOT NULL CHECK(event_type IN ('submission_asserted','delivery_asserted','receipt_asserted','acceptance_asserted','rejection_asserted','dispute_asserted','response_asserted','correspondence','correction_asserted')),
 description text NOT NULL CHECK(char_length(description) BETWEEN 1 AND 1024 AND octet_length(description)<=4096),
 asserted_at timestamptz,source_evidence_id uuid NOT NULL REFERENCES verivaro_private.evidence_objects(evidence_id),
 source_sha256 text NOT NULL CHECK(source_sha256~'^[0-9a-f]{64}$'),
 actor_id uuid NOT NULL,session_id uuid NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((submission_id IS NULL)=(submission_sha256 IS NULL)),CHECK(submission_sha256 IS NULL OR submission_sha256~'^[0-9a-f]{64}$'),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id));
CREATE TABLE verivaro_private.project_chronology_reviews(
 event_id uuid PRIMARY KEY REFERENCES verivaro_private.project_chronology(event_id),
 reviewer_id uuid NOT NULL,session_id uuid NOT NULL,decision text NOT NULL CHECK(decision IN ('source_supports','source_does_not_support','inconclusive')),
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 512 AND octet_length(reason)<=2048),reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON verivaro_private.project_chronology,verivaro_private.project_chronology_reviews FROM PUBLIC;
CREATE TRIGGER chronology_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.project_chronology FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER chronology_review_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.project_chronology_reviews FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER chronology_archive_guard BEFORE INSERT ON verivaro_private.project_chronology FOR EACH ROW EXECUTE FUNCTION verivaro_private.guard_project_write();
CREATE INDEX chronology_scope_idx ON verivaro_private.project_chronology(tenant_id,project_id,recorded_at,event_id);
CREATE FUNCTION verivaro_verification.record_chronology(t uuid,p uuid,r uuid,s uuid,sh text,k text,n text,asserted text,e uuid,h text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $write$
DECLARE c text[];prior verivaro_private.project_chronology%ROWTYPE;a timestamptz;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'owner');
 IF r IS NULL OR k IS NULL OR k NOT IN ('submission_asserted','delivery_asserted','receipt_asserted','acceptance_asserted','rejection_asserted','dispute_asserted','response_asserted','correspondence','correction_asserted')
 OR n IS NULL OR char_length(n) NOT BETWEEN 1 AND 1024 OR octet_length(n)>4096 OR n<>btrim(n) OR n~'[[:cntrl:]]'
 OR (s IS NULL)<>(sh IS NULL) OR (k IN ('submission_asserted','delivery_asserted','receipt_asserted','acceptance_asserted','rejection_asserted') AND s IS NULL)
 OR (s IS NOT NULL AND NOT EXISTS(SELECT 1 FROM verivaro_private.submission_snapshots x WHERE x.tenant_id=t AND x.project_id=p AND x.submission_id=s AND x.sha256=sh AND encode(verivaro_private.digest(convert_to(x.manifest,'UTF8'),'sha256'),'hex')=sh))
 OR e IS NULL OR h IS NULL OR h!~'^[a-f0-9]{64}$' OR NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects x WHERE x.tenant_id=t AND x.project_id=p AND x.evidence_id=e AND x.sha256=h AND x.cipher_digest=verivaro_private.digest(x.envelope,'sha256'))
 THEN RAISE EXCEPTION 'chronology denied' USING ERRCODE='42501';END IF;
 IF asserted IS NOT NULL THEN
  IF asserted!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$' THEN RAISE EXCEPTION 'invalid event time' USING ERRCODE='22023';END IF;
  a:=asserted::timestamptz;
  IF to_char(a AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')<>asserted OR a>statement_timestamp() THEN RAISE EXCEPTION 'invalid event time' USING ERRCODE='22023';END IF;
 END IF;
 SELECT * INTO prior FROM verivaro_private.project_chronology x WHERE x.event_id=r;
 IF FOUND THEN
  IF prior.tenant_id<>t OR prior.project_id<>p OR prior.actor_id<>c[2]::uuid OR prior.submission_id IS DISTINCT FROM s OR prior.submission_sha256 IS DISTINCT FROM sh OR prior.event_type<>k OR prior.description<>n OR prior.asserted_at IS DISTINCT FROM a OR prior.source_evidence_id<>e OR prior.source_sha256<>h THEN RAISE EXCEPTION 'chronology conflict' USING ERRCODE='23505';END IF;
  RETURN r;
 END IF;
 PERFORM pg_advisory_xact_lock(740129816165::bigint);
 IF (SELECT count(*) FROM verivaro_private.project_chronology)>=32768 OR (SELECT count(*) FROM verivaro_private.project_chronology x WHERE x.tenant_id=t AND x.project_id=p)>=128 THEN RAISE EXCEPTION 'chronology capacity' USING ERRCODE='54000';END IF;
 INSERT INTO verivaro_private.project_chronology(event_id,tenant_id,project_id,submission_id,submission_sha256,event_type,description,asserted_at,source_evidence_id,source_sha256,actor_id,session_id)
 VALUES(r,t,p,s,sh,k,n,a,e,h,c[2]::uuid,c[3]::uuid);
 RETURN r;
END $write$;
CREATE FUNCTION verivaro_verification.review_chronology(t uuid,p uuid,r uuid,d text,why text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $review$
DECLARE c text[];item verivaro_private.project_chronology%ROWTYPE;prior verivaro_private.project_chronology_reviews%ROWTYPE;
BEGIN
 c:=verivaro_private.graph_actor(t,p,'reviewer');
 SELECT * INTO item FROM verivaro_private.project_chronology x WHERE x.tenant_id=t AND x.project_id=p AND x.event_id=r;
 IF NOT FOUND OR item.actor_id=c[2]::uuid OR d IS NULL OR d NOT IN ('source_supports','source_does_not_support','inconclusive') OR why IS NULL OR char_length(why) NOT BETWEEN 1 AND 512 OR octet_length(why)>2048 OR why<>btrim(why) OR why~'[[:cntrl:]]' THEN RAISE EXCEPTION 'chronology review denied' USING ERRCODE='42501';END IF;
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.evidence_objects x WHERE x.tenant_id=t AND x.project_id=p AND x.evidence_id=item.source_evidence_id AND x.sha256=item.source_sha256 AND x.actor_id<>c[2]::uuid AND x.cipher_digest=verivaro_private.digest(x.envelope,'sha256')) THEN RAISE EXCEPTION 'chronology source denied' USING ERRCODE='42501';END IF;
 SELECT * INTO prior FROM verivaro_private.project_chronology_reviews x WHERE x.event_id=r;
 IF FOUND THEN
  IF prior.reviewer_id<>c[2]::uuid OR prior.decision<>d OR prior.reason<>why THEN RAISE EXCEPTION 'chronology review conflict' USING ERRCODE='23505';END IF;
  RETURN true;
 END IF;
 INSERT INTO verivaro_private.project_chronology_reviews(event_id,reviewer_id,session_id,decision,reason) VALUES(r,c[2]::uuid,c[3]::uuid,d,why);
 RETURN true;
END $review$;
CREATE FUNCTION verivaro_verification.project_archive_records(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $records$
DECLARE f jsonb;lock_data jsonb;items jsonb;submissions jsonb;
BEGIN
 f:=verivaro_verification.financial_records(t,p);
 lock_data:=verivaro_verification.prooflock_records(t,p);
 SELECT COALESCE(jsonb_agg(jsonb_build_object('eventId',x.event_id,'submissionId',x.submission_id,'submissionSha256',x.submission_sha256,'type',x.event_type,'description',x.description,
 'assertedAt',CASE WHEN x.asserted_at IS NULL THEN NULL ELSE to_char(x.asserted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
 'recordedAt',to_char(x.recorded_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'sourceEvidenceId',x.source_evidence_id,'sourceSha256',x.source_sha256,
 'sourceIntact',o.sha256=x.source_sha256 AND o.cipher_digest=verivaro_private.digest(o.envelope,'sha256'),'decision',COALESCE(z.decision,'pending'),'reviewReason',z.reason,
 'reviewedAt',CASE WHEN z.reviewed_at IS NULL THEN NULL ELSE to_char(z.reviewed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END)
 ORDER BY COALESCE(x.asserted_at,x.recorded_at),x.recorded_at,x.event_id),'[]'::jsonb)
 INTO items FROM verivaro_private.project_chronology x JOIN verivaro_private.evidence_objects o ON o.evidence_id=x.source_evidence_id LEFT JOIN verivaro_private.project_chronology_reviews z ON z.event_id=x.event_id WHERE x.tenant_id=t AND x.project_id=p;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('submissionId',s.submission_id,'sha256',s.sha256,'preparedAt',to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
 'decision',v.decision,'reason',v.reason,'reviewedAt',CASE WHEN v.reviewed_at IS NULL THEN NULL ELSE to_char(v.reviewed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
 'authorizedAt',CASE WHEN z.authorized_at IS NULL THEN NULL ELSE to_char(z.authorized_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
 'manifestIntact',encode(verivaro_private.digest(convert_to(s.manifest,'UTF8'),'sha256'),'hex')=s.sha256) ORDER BY s.created_at,s.submission_id),'[]'::jsonb)
 INTO submissions FROM verivaro_private.submission_snapshots s LEFT JOIN verivaro_private.submission_reviews v USING(submission_id) LEFT JOIN verivaro_private.submission_authorizations z USING(submission_id) WHERE s.tenant_id=t AND s.project_id=p;
 RETURN jsonb_build_object('scope',f->'scope','asOf',f->'asOf','financial',f,'prooflock',lock_data,'events',items,'submissions',submissions);
END $records$;
REVOKE ALL ON FUNCTION verivaro_verification.record_chronology(uuid,uuid,uuid,uuid,text,text,text,text,uuid,text),verivaro_verification.review_chronology(uuid,uuid,uuid,text,text),verivaro_verification.project_archive_records(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_verification.record_chronology(uuid,uuid,uuid,uuid,text,text,text,text,uuid,text),verivaro_verification.review_chronology(uuid,uuid,uuid,text,text),verivaro_verification.project_archive_records(uuid,uuid) TO verivaro_runtime;
COMMIT;
