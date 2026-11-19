-- G1: durable cross-replica admission; never reclaim on an unproven timeout.
BEGIN;
CREATE ROLE verivaro_admission_service NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE verivaro_admission_reconciler NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA verivaro_admission;
REVOKE ALL ON SCHEMA verivaro_admission FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro_admission TO verivaro_admission_service,verivaro_admission_reconciler;
CREATE TABLE verivaro_private.download_admission_config(
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 capacity_bytes bigint NOT NULL CHECK(capacity_bytes BETWEEN 1 AND 2147483648),
 max_active integer NOT NULL CHECK(max_active BETWEEN 1 AND 64),
 global_limit integer NOT NULL CHECK(global_limit BETWEEN 1 AND 10000),
 peer_limit integer NOT NULL CHECK(peer_limit BETWEEN 1 AND global_limit),
 bucket bigint NOT NULL DEFAULT -1,
 count integer NOT NULL DEFAULT 0 CHECK(count>=0)
);
INSERT INTO verivaro_private.download_admission_config(capacity_bytes,max_active,global_limit,peer_limit)
 VALUES(2147483648,16,120,20);
CREATE TABLE verivaro_private.download_peer_buckets(
 peer_digest bytea PRIMARY KEY CHECK(octet_length(peer_digest)=32),
 count integer NOT NULL CHECK(count>0)
);
CREATE TABLE verivaro_private.download_leases(
 lease_id uuid PRIMARY KEY, login_name name NOT NULL,
 reserved_bytes bigint NOT NULL CHECK(reserved_bytes BETWEEN 1 AND 2147483648),
 acquired_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE verivaro_private.download_reconciliations(
 approval_ref uuid PRIMARY KEY, lease_id uuid NOT NULL UNIQUE,
 login_name name NOT NULL, reserved_bytes bigint NOT NULL,
 reconciled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON verivaro_private.download_admission_config,verivaro_private.download_peer_buckets,
 verivaro_private.download_leases,verivaro_private.download_reconciliations FROM PUBLIC;
CREATE TRIGGER download_reconciliation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
 ON verivaro_private.download_reconciliations FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();

CREATE FUNCTION verivaro_admission.acquire(l uuid,peer bytea,bytes bigint) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $acquire$
DECLARE cfg verivaro_private.download_admission_config%ROWTYPE; b bigint; n integer; used bigint; active integer;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR l IS NULL OR peer IS NULL OR octet_length(peer)<>32
 OR bytes IS NULL OR bytes<1 OR bytes>2147483648 THEN RETURN false; END IF;
 SELECT * INTO cfg FROM verivaro_private.download_admission_config WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 b:=floor(extract(epoch FROM clock_timestamp())/60)::bigint;
 -- Clock regression never resets a rate window.
 IF b>cfg.bucket THEN
  DELETE FROM verivaro_private.download_peer_buckets;
  UPDATE verivaro_private.download_admission_config SET bucket=b,count=0 WHERE singleton;
  cfg.count:=0;
 END IF;
 IF cfg.count>=cfg.global_limit THEN RETURN false; END IF;
 UPDATE verivaro_private.download_admission_config SET count=count+1 WHERE singleton;
 SELECT count INTO n FROM verivaro_private.download_peer_buckets WHERE peer_digest=peer;
 IF COALESCE(n,0)>=cfg.peer_limit THEN RETURN false; END IF;
 INSERT INTO verivaro_private.download_peer_buckets(peer_digest,count) VALUES(peer,1)
 ON CONFLICT(peer_digest) DO UPDATE SET count=verivaro_private.download_peer_buckets.count+1;
 SELECT COALESCE(sum(reserved_bytes),0),count(*) INTO used,active FROM verivaro_private.download_leases;
 IF active>=cfg.max_active OR bytes>cfg.capacity_bytes-used
 OR EXISTS(SELECT 1 FROM verivaro_private.download_reconciliations WHERE lease_id=l)
 THEN RETURN false; END IF;
 INSERT INTO verivaro_private.download_leases(lease_id,login_name,reserved_bytes) VALUES(l,session_user,bytes);
 RETURN true;
END $acquire$;

CREATE FUNCTION verivaro_admission.release(l uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $release$
BEGIN
 -- Serialize with acquisitions, including their quota calculations.
 PERFORM 1 FROM verivaro_private.download_admission_config WHERE singleton FOR UPDATE;
 DELETE FROM verivaro_private.download_leases WHERE lease_id=l AND login_name=session_user;
 RETURN FOUND;
END $release$;

-- Only a separately credentialed incident operator may certify that the original
-- worker has stopped AND its resources are gone. Approval reference is an audit
-- correlation identifier, not proof of cleanup. No automated TTL bypass.
CREATE FUNCTION verivaro_admission.reconcile(l uuid,approval uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $reconcile$
DECLARE old verivaro_private.download_leases%ROWTYPE;
BEGIN
 IF l IS NULL OR approval IS NULL THEN RETURN false; END IF;
 PERFORM 1 FROM verivaro_private.download_admission_config WHERE singleton FOR UPDATE;
 DELETE FROM verivaro_private.download_leases WHERE lease_id=l RETURNING * INTO old;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO verivaro_private.download_reconciliations(approval_ref,lease_id,login_name,reserved_bytes)
 VALUES(approval,old.lease_id,old.login_name,old.reserved_bytes);
 RETURN true;
END $reconcile$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA verivaro_admission FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_admission.acquire(uuid,bytea,bigint),verivaro_admission.release(uuid) TO verivaro_admission_service;
GRANT EXECUTE ON FUNCTION verivaro_admission.reconcile(uuid,uuid) TO verivaro_admission_reconciler;
COMMIT;
