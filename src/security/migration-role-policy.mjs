// Fail-closed privilege inventory for production migration planning.
// SQL keyword scanning is advisory: a database reviewer must verify each DDL.
const problem=msg=>{throw Error('migration role policy rejected: '+msg);};
const allowed=/^db\/migrations\/[0-9]{4}_[a-z0-9_]+\.sql$/;
export function inventoryPrivilegedMigrations(migrations){
 if(!Array.isArray(migrations)||migrations.length===0||migrations.length>500)
  problem('missing or oversized catalogue');
 const findings=[];
 let expected=1;
 for(const m of migrations){
  if(!m||!allowed.test(m.path)||parseInt(m.path.slice(14,18),10)!==expected||
   typeof m.source!=='string'||!m.source)problem('untrusted migration input or order');
  // Drop SQL comments; this intentionally errs on the side of review-required.
  const sql=m.source.replace(/--[^\r\n]*/g,' ');
  const classes=[];
  for(const [name,re] of [
   ['ROLE_DDL',/\b(?:CREATE|ALTER|DROP)\s+ROLE\b/i],
   ['ROLE_MEMBERSHIP',/\bGRANT\s+[a-z_][a-z_0-9]*\s+TO\s+[a-z_][a-z_0-9]*/i],
   ['EXTENSION_DDL',/\b(?:CREATE|ALTER|DROP)\s+EXTENSION\b/i],
   ['SYSTEM_ADMIN',/\b(?:ALTER\s+SYSTEM|CREATE\s+DATABASE|CREATE\s+TABLESPACE)\b/i]
  ])if(re.test(sql))classes.push(name);
  if(classes.length)findings.push({version:expected,path:m.path,classes});
  expected++;
 }
 return Object.freeze({
  fileCount:migrations.length,privilegedFiles:findings,
  requiresSeparatelyApprovedBootstrap:findings.length>0,
  productionAutomaticApplyApproved:false,
  serviceRolesMayRunMigrations:false
 });
}
export const PRODUCTION_ROLES=Object.freeze({
 schemaOwner:'vv_production_schema_owner',
 executor:'vv_production_migration_executor',
 mandatoryAttributes:['NOSUPERUSER','NOCREATEDB','NOCREATEROLE','NOREPLICATION','NOBYPASSRLS','NOINHERIT'],
 runtimeMustNotBeMember:true
});
export function validateRoleSnapshot({owner,executor,application,canExecutorSetOwner}={}){
 if(!owner||!executor||!application)problem('missing role inventory');
 for(const role of [owner,executor,application]){
  if(typeof role.name!=='string'||role.superuser!==false||
   role.createRole!==false||role.createDb!==false||
   role.bypassRls!==false||role.replication!==false)
   problem('privileged production role detected');
 }
 if(owner.name!==PRODUCTION_ROLES.schemaOwner||owner.canLogin!==false||
  executor.name!==PRODUCTION_ROLES.executor||executor.inherit!==false||
  executor.canLogin!==false||canExecutorSetOwner!==true||
  application.canSetOwner!==false||application.isOwnerMember!==false)
  problem('ownership, membership or login contract not met');
 return Object.freeze({roleSeparationVerified:true,ownerLoginDisabled:true,
  executorLoginDisabledUntilProvisioned:true,productionApproval:false});
}
