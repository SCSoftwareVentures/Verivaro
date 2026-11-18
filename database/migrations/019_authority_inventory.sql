BEGIN;
SET LOCAL ROLE verivaro_owner;
-- Membership management must not accidentally preserve a previously signed context after role loss and restoration.
CREATE FUNCTION vv_private.guard_membership_version() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
DECLARE changed boolean;
BEGIN
 IF TG_TABLE_NAME='project_member' THEN changed:=(NEW.active,NEW.role) IS DISTINCT FROM (OLD.active,OLD.role);
 ELSE changed:=(NEW.active,NEW.tenant_role) IS DISTINCT FROM (OLD.active,OLD.tenant_role);END IF;
 IF NEW.version<OLD.version THEN RAISE EXCEPTION 'membership version cannot decrease' USING ERRCODE='22023';END IF;
 IF changed AND NEW.version=OLD.version THEN
 IF OLD.version=2147483647 THEN RAISE EXCEPTION 'membership version exhausted' USING ERRCODE='22023';END IF;
 NEW.version:=OLD.version+1;END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER membership_version_guard BEFORE UPDATE ON vv_private.membership FOR EACH ROW EXECUTE FUNCTION vv_private.guard_membership_version();
CREATE TRIGGER project_member_version_guard BEFORE UPDATE ON vv_private.project_member FOR EACH ROW EXECUTE FUNCTION vv_private.guard_membership_version();
-- Retain immutable approvals as history. Revoke issued capabilities when their issuer loses the owner authority.
-- Member row updates serialize with grant creation via capture_actor's membership SHARE locks.
CREATE FUNCTION vv_private.revoke_lost_owner_grants() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
BEGIN
 IF TG_TABLE_NAME='project_member' THEN
 IF OLD.active AND OLD.role='owner' AND (NOT NEW.active OR NEW.role<>'owner') THEN
 UPDATE vv_private.index_grant SET revoked_at=clock_timestamp(),revoked_by=OLD.actor_id
 WHERE tenant_id=OLD.tenant_id AND project_id=OLD.project_id AND created_by=OLD.actor_id AND revoked_at IS NULL;
 END IF;
 ELSE
 IF OLD.active AND NOT NEW.active THEN
 UPDATE vv_private.index_grant SET revoked_at=clock_timestamp(),revoked_by=OLD.actor_id
 WHERE tenant_id=OLD.tenant_id AND created_by=OLD.actor_id AND revoked_at IS NULL;
 END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER membership_revoke_grants AFTER UPDATE ON vv_private.membership FOR EACH ROW EXECUTE FUNCTION vv_private.revoke_lost_owner_grants();
CREATE TRIGGER project_member_revoke_grants AFTER UPDATE ON vv_private.project_member FOR EACH ROW EXECUTE FUNCTION vv_private.revoke_lost_owner_grants();
-- Existing potentially orphaned grants cannot remain active after deployment.
UPDATE vv_private.index_grant g SET revoked_at=clock_timestamp(),revoked_by=g.created_by WHERE g.revoked_at IS NULL AND NOT EXISTS(
 SELECT 1 FROM vv_private.project_member p JOIN vv_private.membership m ON (p.tenant_id,p.actor_id)=(m.tenant_id,m.actor_id)
 WHERE (p.tenant_id,p.project_id,p.actor_id)=(g.tenant_id,g.project_id,g.created_by) AND p.active AND p.role='owner' AND m.active);
-- Every actual new inventory item invalidates prior scope confirmation and current customer grants.
-- The foreign key to project and checkpoint row serialize changes against graph_lock; do not upgrade
-- the project FK lock here. AFTER INSERT does not run for ON CONFLICT DO NOTHING exact replays.
CREATE FUNCTION vv_private.inventory_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_app,vv_private AS $$
BEGIN
 PERFORM vv_private.bump_graph(NEW.tenant_id,NEW.project_id);
 IF TG_TABLE_NAME='document' THEN
 IF (SELECT count(*) FROM vv_app.document WHERE tenant_id=NEW.tenant_id AND project_id=NEW.project_id)>500 THEN RAISE EXCEPTION 'document quota' USING ERRCODE='54000';END IF;
 ELSE
 IF (SELECT count(*) FROM vv_app.upload_intent WHERE tenant_id=NEW.tenant_id AND project_id=NEW.project_id)>2000 THEN RAISE EXCEPTION 'upload quota' USING ERRCODE='54000';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER document_inventory_changed AFTER INSERT ON vv_app.document FOR EACH ROW EXECUTE FUNCTION vv_private.inventory_changed();
CREATE TRIGGER intent_inventory_changed AFTER INSERT ON vv_app.upload_intent FOR EACH ROW EXECUTE FUNCTION vv_private.inventory_changed();
REVOKE ALL ON FUNCTION vv_private.guard_membership_version(),vv_private.revoke_lost_owner_grants(),vv_private.inventory_changed() FROM PUBLIC;
RESET ROLE;
COMMIT;
