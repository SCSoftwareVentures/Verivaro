BEGIN;
CREATE FUNCTION verivaro_sharing.workspace_issue_recipient(t uuid,p uuid,e uuid,s uuid,d bytea,recipient uuid) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $issue$
DECLARE c text[];g verivaro_private.share_grants%ROWTYPE;expires timestamptz;
BEGIN
 c:=verivaro_private.release_actor(t,p,'owner');
 IF s IS NULL OR recipient IS NULL OR recipient=c[2]::uuid OR d IS NULL OR octet_length(d)<>32 THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501';END IF;
 PERFORM 1 FROM verivaro_private.released_exports x JOIN verivaro_private.evidence_release_receipts z ON x.export_id=z.export_id
 WHERE x.export_id=e AND x.tenant_id=t AND x.project_id=p AND x.revoked_at IS NULL AND NOT x.bearer_allowed FOR UPDATE OF x;
 IF NOT FOUND THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501';END IF;
 SELECT * INTO g FROM verivaro_private.share_grants WHERE share_id=s;
 IF FOUND THEN
 IF g.export_id<>e OR g.issuer_id<>c[2]::uuid OR g.token_digest<>d OR g.recipient_id IS DISTINCT FROM recipient OR g.revoked_at IS NOT NULL OR g.expires_at<=clock_timestamp()
 OR g.owner_generation IS DISTINCT FROM verivaro_private.share_owner_generation(t,p,c[2]::uuid)
 OR g.recipient_generation IS DISTINCT FROM verivaro_private.recipient_generation(recipient)
 THEN RAISE EXCEPTION 'share conflict' USING ERRCODE='23505';END IF;
 RETURN g.expires_at;END IF;
 IF (SELECT count(*) FROM verivaro_private.share_grants WHERE export_id=e)>=32 THEN RAISE EXCEPTION 'share capacity exhausted' USING ERRCODE='54000';END IF;
 expires:=clock_timestamp()+interval '15 minutes';
 PERFORM verivaro_sharing.issue_recipient_share(e,s,d,expires,recipient);
 RETURN expires;
END $issue$;
CREATE FUNCTION verivaro_sharing.workspace_revoke_recipient(t uuid,p uuid,s uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $revoke$
BEGIN
 PERFORM verivaro_private.release_actor(t,p,'owner');
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.share_grants g JOIN verivaro_private.released_exports x ON x.export_id=g.export_id WHERE g.share_id=s AND x.tenant_id=t AND x.project_id=p AND g.recipient_id IS NOT NULL) THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501';END IF;
 PERFORM verivaro_sharing.revoke_share(s);
 RETURN true;
END $revoke$;
CREATE FUNCTION verivaro_sharing.workspace_shares(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $list$
BEGIN
 PERFORM verivaro_private.release_actor(t,p,'owner');
 RETURN COALESCE((SELECT jsonb_agg(to_jsonb(q) ORDER BY q.id) FROM (
 SELECT g.share_id AS id,g.export_id AS "exportId",g.recipient_id AS "recipientId",g.expires_at AS "expiresAt",
 CASE WHEN g.revoked_at IS NOT NULL OR x.revoked_at IS NOT NULL THEN 'revoked' WHEN g.expires_at<=statement_timestamp() THEN 'expired'
 WHEN g.owner_generation IS DISTINCT FROM verivaro_private.share_owner_generation(t,p,g.issuer_id) OR g.recipient_generation IS DISTINCT FROM verivaro_private.recipient_generation(g.recipient_id) THEN 'invalidated' ELSE 'active' END AS state
 FROM verivaro_private.share_grants g JOIN verivaro_private.released_exports x ON x.export_id=g.export_id WHERE x.tenant_id=t AND x.project_id=p AND g.recipient_id IS NOT NULL ORDER BY g.created_at DESC,g.share_id LIMIT 200) q),'[]'::jsonb);
END $list$;
REVOKE ALL ON FUNCTION verivaro_sharing.workspace_issue_recipient(uuid,uuid,uuid,uuid,bytea,uuid),verivaro_sharing.workspace_revoke_recipient(uuid,uuid,uuid),verivaro_sharing.workspace_shares(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_sharing.workspace_issue_recipient(uuid,uuid,uuid,uuid,bytea,uuid),verivaro_sharing.workspace_revoke_recipient(uuid,uuid,uuid),verivaro_sharing.workspace_shares(uuid,uuid) TO verivaro_runtime;
REVOKE EXECUTE ON FUNCTION verivaro_sharing.issue_recipient_share(uuid,uuid,bytea,timestamptz,uuid),verivaro_sharing.issue_share(uuid,uuid,bytea,timestamptz),verivaro_sharing.revoke_share(uuid) FROM verivaro_runtime;
COMMIT;
