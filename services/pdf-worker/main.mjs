import {readPrivate} from '../../src/security/service-pool-config.mjs';
import {createOfflinePoppler,normalizeExternalPdf} from '../../src/security/pdf-normalization.mjs';
import {startPdfWorker} from '../../src/security/pdf-worker-socket.mjs';
import {join} from 'node:path';
// Separate service identity is mandatory: never execute Poppler in the web app.
if(process.platform!=='linux'||typeof process.getuid!=='function'||process.getuid()===0||!process.env.CREDENTIALS_DIRECTORY)throw Error('restricted PDF normalizer service account required');
const key=await readPrivate(join(process.env.CREDENTIALS_DIRECTORY,'pdf-key'),32);
const renderer=createOfflinePoppler();
let worker;
try{
 worker=await startPdfWorker({socketPath:'/run/verivaro-pdf/worker.sock',key,convert:(source,signal)=>normalizeExternalPdf(source,{renderer,signal})});
}finally{key.fill(0);}
let stopping=false;
async function stop(){if(stopping)return;stopping=true;await worker.close();}
process.once('SIGINT',stop);process.once('SIGTERM',stop);
