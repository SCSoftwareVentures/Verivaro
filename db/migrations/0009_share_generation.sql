-- G1: permanent share invalidation on identity or membership changes.
BEGIN;
ALTER TABLE verivaro.memberships ADD COLUMN share_generation uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE verivaro.project_members ADD COLUMN share_generation uuid NOT NULL DEFAULT gen_random_uuid();
CREATE FUNCTION verivaro_private.rotate_share_generation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $rotate$
BEGIN
 NEW.share_generation:=gen_random_uuid();
 RETURN NEW;
END $rotate$;
REVOKE ALL ON FUNCTION verivaro_private.rotate_share_generation() FROM PUBLIC;
CREATE TRIGGER tenant_share_generation BEFORE UPDATE ON verivaro.memberships
 FOR EACH ROW EXECUTE FUNCTION verivaro_private.rotate_share_generation();
CREATE TRIGGER project_share_generation BEFORE UPDATE ON verivaro.project_members
 FOR EACH ROW EXECUTE FUNCTION verivaro_private.rotate_share_generation();
CREATE TABLE verivaro_private.actor_share_generations(
 actor_id uuid PRIMARY KEY, generation uuid NOT NULL DEFAULT gen_random_uuid()
);
REVOKE ALL ON verivaro_private.actor_share_generations FROM PUBLIC;
INSERT INTO verivaro_private.actor_share_generations(actor_id)
 SELECT actor_id FROM verivaro_private.disabled_actors;
CREATE FUNCTION verivaro_private.rotate_disabled_actor_share_generation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,verivaro_private AS $disabled$
BEGIN
 INSERT INTO verivaro_private.actor_share_generations(actor_id) VALUES(NEW.actor_id)
 ON CONFLICT(actor_id) DO UPDATE SET generation=gen_random_uuid();
 RETURN NEW;
END $disabled$;
REVOKE ALL ON FUNCTION verivaro_private.rotate_disabled_actor_share_generation() FROM PUBLIC;
CREATE TRIGGER disable_share_generation AFTER INSERT ON verivaro_private.disabled_actors
 FOR EACH ROW EXECUTE FUNCTION verivaro_private.rotate_disabled_actor_share_generation();

-- Legacy grants are deliberately invalidated; no migration can manufacture
-- proof of their historical membership generations.
ALTER TABLE verivaro_private.share_grants ADD COLUMN owner_generation uuid[];
ALTER TABLE verivaro_private.share_grants ADD CONSTRAINT share_generation_shape CHECK
 (owner_generation IS NULL OR (cardinality(owner_generation)=3 AND array_position(owner_generation,NULL) IS NULL));
CREATE FUNCTION verivaro_private.share_owner_generation(t uuid,p uuid,a uuid) RETURNS uuid[]
LANGUAGE sql STABLE SET search_path=pg_catalog,verivaro_private AS $generation$
 SELECT ARRAY[m.share_generation,pm.share_generation,COALESCE(g.generation,'00000000-0000-0000-0000-000000000000'::uuid)]
 FROM verivaro.memberships m
 JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id
 LEFT JOIN verivaro_private.actor_share_generations g ON g.actor_id=m.actor_id
 WHERE m.tenant_id=t AND pm.project_id=p AND m.actor_id=a
 AND m.role='owner' AND pm.role='owner' AND m.revoked_at IS NULL AND pm.revoked_at IS NULL
 AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp())
 AND NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=a)
$generation$;
REVOKE ALL ON FUNCTION verivaro_private.share_owner_generation(uuid,uuid,uuid) FROM PUBLIC;
CREATE OR REPLACE FUNCTION verivaro_sharing.issue_share(e uuid,s uuid,digest bytea,expiry timestamptz) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $issue$
DECLARE ctx text[]; item verivaro_private.released_exports%ROWTYPE; n timestamptz; generation uuid[];
BEGIN
 ctx:=verivaro.bound_context();
 IF NOT verivaro.active_identity() THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO item FROM verivaro_private.released_exports WHERE export_id=e FOR SHARE;
 n:=clock_timestamp();
 generation:=verivaro_private.share_owner_generation(item.tenant_id,item.project_id,ctx[2]::uuid);
 IF NOT FOUND OR item.tenant_id::text<>ctx[1] OR item.revoked_at IS NOT NULL OR NOT item.bearer_allowed
 OR generation IS NULL
 OR s IS NULL OR digest IS NULL OR octet_length(digest)<>32 OR expiry IS NULL
 OR expiry<=n OR expiry>n+interval '24 hours'
 THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501'; END IF;
 INSERT INTO verivaro_private.share_grants(share_id,export_id,issuer_id,token_digest,created_at,expires_at,owner_generation)
 VALUES(s,e,ctx[2]::uuid,digest,n,expiry,generation);
 INSERT INTO verivaro_private.share_events(export_id,share_id,action,actor_id) VALUES(e,s,'issued',ctx[2]::uuid);
END $issue$;

CREATE OR REPLACE FUNCTION verivaro_sharing.resolve_share(digest bytea)
RETURNS TABLE(artifact_id uuid,sha256 text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $resolve$
DECLARE grant_row verivaro_private.share_grants%ROWTYPE; item verivaro_private.released_exports%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR digest IS NULL OR octet_length(digest)<>32 THEN RETURN; END IF;
 SELECT g.* INTO grant_row FROM verivaro_private.share_grants g WHERE g.token_digest=digest;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT e.* INTO item FROM verivaro_private.released_exports e WHERE e.export_id=grant_row.export_id FOR SHARE;
 IF NOT FOUND OR item.revoked_at IS NOT NULL OR NOT item.bearer_allowed THEN RETURN; END IF;
 SELECT g.* INTO grant_row FROM verivaro_private.share_grants g WHERE g.share_id=grant_row.share_id FOR SHARE;
 IF NOT FOUND OR grant_row.revoked_at IS NOT NULL OR grant_row.expires_at<=clock_timestamp()
 OR grant_row.owner_generation IS DISTINCT FROM verivaro_private.share_owner_generation(item.tenant_id,item.project_id,grant_row.issuer_id) OR grant_row.owner_generation IS NULL THEN RETURN; END IF;
 INSERT INTO verivaro_private.share_events(export_id,share_id,action) VALUES(item.export_id,grant_row.share_id,'accessed');
 RETURN QUERY SELECT item.artifact_id,item.sha256;
END $resolve$;

COMMIT;
