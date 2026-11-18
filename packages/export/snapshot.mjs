import { createHash } from 'node:crypto';
import { evaluate } from '../domain/evidence.ts';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function canonical(x){if(x===null||typeof x==='boolean'||typeof x==='string')return JSON.stringify(x);if(typeof x==='number'&&Number.isFinite(x))return JSON.stringify(x);if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';if(x&&typeof x==='object'&&Object.getPrototypeOf(x)===Object.prototype)return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';throw new Error('unsupported snapshot value');}
const sorted=rows=>[...rows].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
/** Local synthetic index, not signed, authorised, or a released handover. */
export function draftSnapshot(input){const reviewed=evaluate(input);const payload={schema:'verivaro-draft-1',scope:{...input.scope},requirements:sorted(input.requirements),evidence:sorted(input.evidence),sources:sorted(input.sources).map(({text,...s})=>({...s,textSha256:sha(Buffer.from(text,'utf8'))})),readiness:reviewed,disposition:reviewed.ready?'READY_UNDER_CONFIGURED_CHECKS_DRAFT':'BLOCKED_DRAFT'};const json=canonical(payload);return Object.freeze({json,sha256:sha(json)});}
export function verifySnapshot(snapshot,expectedHash){if(typeof snapshot?.json!=='string'||typeof expectedHash!=='string'||! /^[a-f0-9]{64}$/.test(expectedHash))return false;return sha(snapshot.json)===expectedHash;}
export function isCurrentSnapshot(input,snapshot){return verifySnapshot(snapshot,snapshot.sha256)&&draftSnapshot(input).sha256===snapshot.sha256;}
