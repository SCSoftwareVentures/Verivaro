import test from 'node:test';
import assert from 'node:assert/strict';
import {createHttpServer} from '../../packages/api/http.mjs';
test('static app exact routes and restrictive browser policy',async t=>{const s=createHttpServer({});await new Promise(r=>s.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>s.close(r)));const base='http://127.0.0.1:'+s.address().port;const r=await fetch(base+'/app');assert.equal(r.status,200);assert.match(r.headers.get('content-security-policy'),/script-src 'self'/);assert.equal(r.headers.get('cache-control'),'no-store');assert.match(await r.text(),/id="login"/);for(const p of ['/app/app.mjs','/app/style.css'])assert.equal((await fetch(base+p)).status,200);assert.equal((await fetch(base+'/app/%2e%2e%2fpackage.json')).status,404);});
