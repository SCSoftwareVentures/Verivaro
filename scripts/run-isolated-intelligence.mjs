// Dedicated rootless Podman host CLI; never expose the runtime socket to the API.
import {spawnSync} from 'node:child_process';
import {intelligenceContainerArgs} from '../packages/security/intelligence-container.mjs';
import {randomUUID} from 'node:crypto';
const bin='/usr/bin/podman';
try{
 const image=process.argv[2],args=intelligenceContainerArgs(image);
 if(process.argv.length!==3)throw Error('one image ID required');
 const info=spawnSync(bin,['info','--format','{{.Host.Security.Rootless}}'],{encoding:'utf8',timeout:5000,maxBuffer:8192,stdio:['ignore','pipe','ignore']});
 if(info.status!==0||info.stdout.trim()!=='true'||process.getuid?.()===0)throw Error('rootless runtime required');
 const chunks=[];let bytes=0;
 for await(const chunk of process.stdin){bytes+=chunk.length;if(bytes>262144)throw Error('input limit');chunks.push(chunk);}
 const name='vv-intelligence-'+randomUUID();
 let result;
 try{result=spawnSync(bin,[...args.slice(0,-1),'--name='+name,image],{input:Buffer.concat(chunks),timeout:12000,killSignal:'SIGKILL',maxBuffer:262144,stdio:['pipe','pipe','ignore']});}
 finally{
 // Forced cleanup after CLI timeout, in addition to in-container deadline.
 const rm=spawnSync(bin,['rm','--force','--ignore',name],{timeout:5000,stdio:'ignore'});
 if(rm.status!==0)throw Error('cleanup unverified; quarantine worker host');
 }
 if(result.error||result.status!==0||!result.stdout||result.stdout.length>262144)throw Error('isolated provider failed');
 const parsed=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(result.stdout));if(!Array.isArray(parsed))throw Error('protocol failure');
 process.stdout.write(result.stdout);
}catch{process.stderr.write('Isolated intelligence unavailable\n');process.exitCode=1;}
