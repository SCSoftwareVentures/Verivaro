import {readPrivate} from '../../src/security/service-pool-config.mjs';
import {createTesseractEngine} from '../../src/security/ocr-preview.mjs';
import {startOcrWorker} from '../../src/security/ocr-socket.mjs';
import {join} from 'node:path';
if(process.platform!=='linux'||process.getuid()===0||!process.env.CREDENTIALS_DIRECTORY)throw Error('restricted OCR service account required');
const key=await readPrivate(join(process.env.CREDENTIALS_DIRECTORY,'ocr-key'),32);let worker;
try{worker=await startOcrWorker({socketPath:'/run/verivaro-ocr/worker.sock',key,recognize:createTesseractEngine()});}finally{key.fill(0);}
let stopping=false;
const stop=async()=>{if(stopping)return;stopping=true;await worker.close();};
process.once('SIGTERM',stop);process.once('SIGINT',stop);
