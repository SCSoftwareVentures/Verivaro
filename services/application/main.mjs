import {createRequire} from 'node:module';
import {createApplicationRuntime} from '../../src/security/application-runtime.mjs';
// Reject ambient overrides that would bypass the explicit file configuration.
const blocked=['PGPASSWORD','PGOPTIONS','PGSERVICE','PGSERVICEFILE','PGSSLMODE','PGSSLROOTCERT','PGSSLCERT','PGSSLKEY','PGPASSFILE','DATABASE_URL','NODE_TLS_REJECT_UNAUTHORIZED','NODE_EXTRA_CA_CERTS','NODE_OPTIONS'];
let app;
try{
 if(process.argv.length!==3||blocked.some(k=>process.env[k]!==undefined))throw Error('explicit private configuration required');
 const {Pool}=createRequire(new URL('./driver/package.json',import.meta.url))('pg');
 const report=event=>process.stderr.write(event+'\n');
 app=await createApplicationRuntime({configPath:process.argv[2],Pool,report});
 await app.listen();process.stdout.write('application_listening\n');
 const stop=()=>{const timeout=setTimeout(()=>process.exit(1),30000);timeout.unref();app.stop().then(()=>{clearTimeout(timeout);},()=>{process.exitCode=1;});};
 process.once('SIGTERM',stop);process.once('SIGINT',stop);
 app.server.on('error',()=>{report('application_listener_failed');process.exitCode=1;stop();});
}catch{process.stderr.write('application_startup_failed\n');if(app)await app.stop();process.exitCode=1;}
