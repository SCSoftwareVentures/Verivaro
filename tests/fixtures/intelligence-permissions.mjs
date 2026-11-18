// Verify the runtime permission boundary, not a hostile native-code sandbox.
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
let fsDenied=false,spawnDenied=false;
try{readFileSync('/etc/passwd');}catch(e){fsDenied=e.code==='ERR_ACCESS_DENIED';}
try{spawnSync(process.execPath,['--version']);}catch(e){spawnDenied=e.code==='ERR_ACCESS_DENIED';}
if(!fsDenied||!spawnDenied)process.exit(2);
process.stdout.write('[]');
