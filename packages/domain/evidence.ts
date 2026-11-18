/** Pure domain model. Scope and review claims must be authenticated by the future API. */
export type Scope = Readonly<{tenantId:string; projectId:string}>;
export type Source = Scope & Readonly<{id:string; documentId:string; revision:number; text:string; scan:'clean'|'pending'|'rejected'; reviewed:boolean; current:boolean}>;
export type Span = Readonly<{sourceId:string; start:number; end:number; quote:string}>;
export type Requirement = Scope & Readonly<{id:string; revision:number; approved:boolean; applicability:'applicable'|'not-applicable'|'unknown'; mandatory:boolean; span:Span; criterion:Readonly<{kind:string; expected:string}>}>;
export type Evidence = Scope & Readonly<{id:string; requirementId:string; requirementRevision:number; span:Span; kind:string; value:string; review:'approved'|'pending'|'rejected'}>;
export type Input = Readonly<{scope:Scope; sources:readonly Source[]; requirements:readonly Requirement[]; evidence:readonly Evidence[]}>;
export type Status = 'verified-configured-checks'|'missing'|'unknown'|'provisional'|'conflicting'|'not-applicable';
export type Finding = Readonly<{requirementId:string; revision:number; status:Status; blocker:boolean; reason:string; sourceIds:readonly string[]}>;
function text(v:unknown):v is string { return typeof v==='string'&&v.trim().length>0; }
function rev(v:unknown):v is number { return typeof v==='number'&&Number.isSafeInteger(v)&&v>0; }
export function sameScope(a:Scope,b:Scope):boolean {return text(a.tenantId)&&text(a.projectId)&&a.tenantId===b.tenantId&&a.projectId===b.projectId;}
function unique<T extends {id:string}>(items:readonly T[], name:string):Map<string,T>{const map=new Map<string,T>();for(const x of items){if(!text(x.id)||map.has(x.id))throw new Error(`invalid/duplicate ${name} ID`);map.set(x.id,x);}return map;}
function validate(input:Input){const {scope,sources,requirements,evidence}=input;if(!sameScope(scope,scope))throw new Error('invalid scope');for(const x of [...sources,...requirements,...evidence])if(!sameScope(x,scope))throw new Error('scope mismatch');
 const sm=unique(sources,'source'),rm=unique(requirements,'requirement');unique(evidence,'evidence');const active=new Set<string>(),versions=new Set<string>();
 for(const s of sources){if(!text(s.documentId)||!rev(s.revision)||typeof s.text!=='string'||!['clean','pending','rejected'].includes(s.scan)||typeof s.reviewed!=='boolean'||typeof s.current!=='boolean')throw new Error('invalid source');const k=JSON.stringify([s.documentId,s.revision]);if(versions.has(k))throw new Error('duplicate source revision');versions.add(k);if(s.current){if(active.has(s.documentId))throw new Error('multiple current source versions');active.add(s.documentId);}}
 for(const r of requirements)if(!rev(r.revision)||typeof r.approved!=='boolean'||typeof r.mandatory!=='boolean'||!['applicable','not-applicable','unknown'].includes(r.applicability)||!text(r.criterion?.kind)||!text(r.criterion?.expected)||!r.span)throw new Error('invalid requirement');
 for(const e of evidence)if(!rm.has(e.requirementId)||!rev(e.requirementRevision)||!text(e.kind)||!text(e.value)||!e.span||!['approved','pending','rejected'].includes(e.review))throw new Error('invalid evidence');
 return {sm,rm};}
/** Offsets are UTF-16 code units in the exact extracted source version. */
export function validSpan(span:Span,sources:ReadonlyMap<string,Source>):boolean{const s=sources.get(span?.sourceId);return !!s&&Number.isSafeInteger(span.start)&&Number.isSafeInteger(span.end)&&span.start>=0&&span.end>span.start&&span.end<=s.text.length&&text(span.quote)&&s.text.slice(span.start,span.end)===span.quote;}
function usable(span:Span,sources:ReadonlyMap<string,Source>):boolean{const s=sources.get(span?.sourceId);return !!s&&s.current&&s.reviewed&&s.scan==='clean'&&validSpan(span,sources);}
function compare(a:string,b:string):number{return a<b?-1:a>b?1:0;}
export function evaluate(input:Input){const {sm}=validate(input);const findings:Finding[]=[];const byReq=new Map<string,Evidence[]>();for(const e of input.evidence){const arr=byReq.get(e.requirementId)??[];arr.push(e);byReq.set(e.requirementId,arr);}
 for(const r of [...input.requirements].sort((a,b)=>compare(a.id,b.id))){const related=(byReq.get(r.id)??[]).filter(e=>e.requirementRevision===r.revision&&e.review!=='rejected');const ids=[r.span.sourceId,...related.map(e=>e.span.sourceId)].filter(id=>sm.has(id));let status:Status,reason:string;
 if(!r.approved||r.applicability==='unknown'||!usable(r.span,sm)){status='unknown';reason='Requirement approval, applicability or current source is unresolved.';}
 else if(r.applicability==='not-applicable'){status='not-applicable';reason='Approved not-applicable requirement.';}
 else if(related.length===0){status='missing';reason='No current candidate evidence.';}
 else {const relevant=related.filter(e=>e.kind===r.criterion.kind);const usableEvidence=relevant.filter(e=>usable(e.span,sm)&&e.span.quote===e.value);const values=new Set(usableEvidence.map(e=>e.value));
 if(values.size>1||(values.size===1&&!values.has(r.criterion.expected))){status='conflicting';reason='Current evidence contradicts the configured criterion.';}
 else if(relevant.some(e=>!usable(e.span,sm)||e.span.quote!==e.value)){status='unknown';reason='Evidence provenance, asserted value or revision is unresolved.';}
 else if(usableEvidence.some(e=>e.review==='approved'&&e.value===r.criterion.expected)){status='verified-configured-checks';reason='Approved current evidence matches the configured exact-text criterion.';}
 else {status='provisional';reason='No approved evidence matching the configured criterion.';}}
 findings.push(Object.freeze({requirementId:r.id,revision:r.revision,status,blocker:r.mandatory&&!['verified-configured-checks','not-applicable'].includes(status),reason,sourceIds:Object.freeze([...new Set(ids)].sort(compare))}));}
 const confirmed=input.requirements.filter(r=>r.approved&&r.applicability==='applicable'&&usable(r.span,sm)).length;const verified=findings.filter(f=>f.status==='verified-configured-checks').length;const blockers=findings.filter(f=>f.blocker).length;const unknown=findings.filter(f=>f.status==='unknown').length;
 return Object.freeze({confirmed,verified,blockers,unknown,coverage:confirmed?verified/confirmed:null,ready:confirmed>0&&blockers===0,findings:Object.freeze(findings),label:'Readiness under configured documentary checks only; not compliance, authenticity or payment entitlement.'});}
/** Conservative impact set for changes to source versions; final preflight always runs in full. */
export function impactedRequirements(input:Input, changedSourceIds:readonly string[]):readonly string[]{validate(input);const changed=new Set(changedSourceIds);const affected=new Set(input.requirements.filter(r=>changed.has(r.span.sourceId)).map(r=>r.id));for(const e of input.evidence)if(changed.has(e.span.sourceId))affected.add(e.requirementId);return Object.freeze([...affected].sort(compare));}
