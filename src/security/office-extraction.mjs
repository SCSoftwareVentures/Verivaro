import {createHash} from 'node:crypto';
import {readOfficeZip,preflightOfficePackage} from './office-zip.mjs';
import {parseOfficeXml} from './office-xml.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex'),fail=()=>{throw Error('unsupported Office document schema');};
const main='http://schemas.openxmlformats.org/',rel=main+'officeDocument/2006/relationships',pkg=main+'package/2006/relationships',types=main+'package/2006/content-types',word=main+'wordprocessingml/2006/main',sheet=main+'spreadsheetml/2006/main';
const MIME='application/vnd.openxmlformats-officedocument.';
function attrs(n,required={},optional=[]){
 if(!n||Object.keys(n.attrs).some(k=>!Object.hasOwn(required,k)&&!optional.includes(k))||Object.entries(required).some(([k,v])=>!Object.hasOwn(n.attrs,k)||v!==null&&n.attrs[k]!==v))fail();
}
function nodes(n){if(n.children.some(x=>typeof x==='string'&&x.trim()))fail();return n.children.filter(x=>typeof x!=='string');}
function shape(n,name,required={},optional=[]){if(n?.name!==name)fail();attrs(n,required,optional);return nodes(n);}
function empty(n,name,required={}){if(shape(n,name,required).length)fail();}
function text(n,name){if(n?.name!==name)fail();attrs(n,{},['xml:space']);if(n.attrs['xml:space']!==undefined&&n.attrs['xml:space']!=='preserve'||n.children.some(x=>typeof x!=='string'))fail();const s=n.children.join('');if(n.attrs['xml:space']!=='preserve'&&s!==s.trim()||/_x[0-9a-f]{4}_/i.test(s))fail();return s;}
function int(x,max){if(typeof x!=='string'||! /^[1-9][0-9]{0,5}$/.test(x)||Number(x)>max)fail();return Number(x);}
function relationships(root){
 const records=new Map();
 for(const n of shape(root,'Relationships',{xmlns:pkg})){
  empty(n,'Relationship',{Id:null,Type:null,Target:null});
  const {Id,Type,Target}=n.attrs;if(!/^rId[1-9][0-9]{0,5}$/.test(Id)||records.has(Id)||!Type.startsWith(rel+'/')||! /^[A-Za-z0-9_.\/-]+$/.test(Target)||Target.split('/').some(x=>!x||x==='.'||x==='..'))fail();
  records.set(Id,{type:Type.slice(rel.length+1),target:Target});
 }
 return records;
}
function checkTypes(root,expected){
 const seen=new Map(),defaults=new Map();
 for(const n of shape(root,'Types',{xmlns:types})){
  if(n.name==='Default'){empty(n,'Default',{Extension:null,ContentType:null});const {Extension,ContentType}=n.attrs;if(defaults.has(Extension))fail();defaults.set(Extension,ContentType);}
  else if(n.name==='Override'){empty(n,'Override',{PartName:null,ContentType:null});const {PartName,ContentType}=n.attrs;if(seen.has(PartName))fail();seen.set(PartName,ContentType);}
  else fail();
 }
 if(defaults.size!==2||defaults.get('rels')!=='application/vnd.openxmlformats-package.relationships+xml'||defaults.get('xml')!=='application/xml'||seen.size!==expected.size||[...expected].some(([k,v])=>seen.get('/'+k)!==v))fail();
}
const colNumber=s=>[...s].reduce((n,c)=>n*26+c.charCodeAt(0)-64,0);
// Returns exact decoded text, its digest and deterministic source location.
// Parsing is intentionally limited to explicitly accepted content-only Office
// schemas: no hidden content, formulas, fields, styles or external relationships.
export function extractOfficeSpans(archive,kind){
 preflightOfficePackage(archive,kind);
 const entries=readOfficeZip(archive),spans=[];let total=0;
 try{
  const get=path=>{const b=entries.get(path);if(!b)fail();return parseOfficeXml(b);};
  const expected=new Map(),used=new Set(['[Content_Types].xml','_rels/.rels']);
  const add=(part,location,quote)=>{
   const bytes=Buffer.byteLength(quote,'utf8');total+=bytes;
   if(spans.length>=8192||bytes>32768||total>524288||/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/u.test(quote))fail();
   spans.push(Object.freeze({part,...location,quote,quoteSha256:hash(quote),partSha256:partHashes.get(part)}));
  };
  const partHashes=new Map([...entries].map(([p,b])=>[p,hash(b)]));
  const rootRels=relationships(get('_rels/.rels')),mainPath=kind==='docx'?'word/document.xml':'xl/workbook.xml';
  if(rootRels.size!==1||![...rootRels.values()].every(r=>r.type==='officeDocument'&&r.target===mainPath))fail();
  used.add(mainPath);
  if(kind==='docx'){
   expected.set(mainPath,MIME+'wordprocessingml.document.main+xml');
   const body=shape(get(mainPath),'w:document',{'xmlns:w':word});if(body.length!==1)fail();
   const paragraphs=shape(body[0],'w:body');
   for(let i=0;i<paragraphs.length;i++){
    const p=paragraphs[i],runs=shape(p,'w:p');let quote='';
    for(const r of runs){const children=shape(r,'w:r');if(children.length!==1)fail();quote+=text(children[0],'w:t');}
    if(quote)add(mainPath,{paragraph:i+1},quote);
   }
  }else{
   expected.set(mainPath,MIME+'spreadsheetml.sheet.main+xml');
   const book=shape(get(mainPath),'workbook',{xmlns:sheet,'xmlns:r':rel});if(book.length!==1)fail();
   const sheets=shape(book[0],'sheets');if(sheets.length<1||sheets.length>16)fail();
   const rp='xl/_rels/workbook.xml.rels';used.add(rp);const records=relationships(get(rp));
   let shared=[],sharedCount=null,sharedUses=0;const sharedRels=[...records].filter(([,r])=>r.type==='sharedStrings');
   if(sharedRels.length>1)fail();
   if(sharedRels.length){
    const [id,r]=sharedRels[0];if(r.target!=='sharedStrings.xml')fail();records.delete(id);
    const part='xl/sharedStrings.xml';used.add(part);expected.set(part,MIME+'spreadsheetml.sharedStrings+xml');
    const ss=get(part),items=shape(ss,'sst',{xmlns:sheet},['count','uniqueCount']);
    if(items.length>8192||ss.attrs.uniqueCount!==undefined&&(!/^(?:0|[1-9][0-9]{0,5})$/.test(ss.attrs.uniqueCount)||Number(ss.attrs.uniqueCount)!==items.length)||ss.attrs.count!==undefined&&!/^(?:0|[1-9][0-9]{0,5})$/.test(ss.attrs.count))fail();
    sharedCount=ss.attrs.count===undefined?null:Number(ss.attrs.count);
    shared=items.map(si=>{const k=shape(si,'si');if(k.length!==1)fail();return text(k[0],'t');});
   }
   const ids=new Set(),names=new Set(),targets=new Set();
   for(let i=0;i<sheets.length;i++){
    const sh=sheets[i];empty(sh,'sheet',{name:null,sheetId:null,'r:id':null});
    const id=int(sh.attrs.sheetId,65535),name=sh.attrs.name,r=records.get(sh.attrs['r:id']);
    if(!name||[...name].length>31||/[\[\]:*?\/\\\x00-\x1f]/.test(name)||name!==name.trim()||ids.has(id)||names.has(name.toLowerCase())||!r||r.type!=='worksheet'||!/^worksheets\/sheet(?:[1-9]|[1-5][0-9]|6[0-4])\.xml$/.test(r.target)||targets.has(r.target))fail();
    ids.add(id);names.add(name.toLowerCase());targets.add(r.target);records.delete(sh.attrs['r:id']);
    const part='xl/'+r.target;used.add(part);expected.set(part,MIME+'spreadsheetml.worksheet+xml');
    const children=shape(get(part),'worksheet',{xmlns:sheet});
    let j=0;
    // Recognise only the inert layout generated by Verivaro's register exporter.
    if(children[j]?.name==='sheetViews'){const a=shape(children[j++],'sheetViews');if(a.length!==1)fail();const b=shape(a[0],'sheetView',{workbookViewId:'0'});if(b.length!==1)fail();empty(b[0],'pane',{ySplit:'1',topLeftCell:'A2',activePane:'bottomLeft',state:'frozen'});}
    if(children[j]?.name==='sheetFormatPr')empty(children[j++],'sheetFormatPr',{defaultRowHeight:'15'});
    if(children[j]?.name==='cols'){const a=shape(children[j++],'cols');if(a.length!==1)fail();empty(a[0],'col',{min:'1',max:'16',width:'32',customWidth:'1'});}
    const rows=shape(children[j++],'sheetData');let prevRow=0;
    for(const row of rows){
     const cells=shape(row,'row',{r:null}),rn=int(row.attrs.r,1024);if(rn<=prevRow)fail();prevRow=rn;let prevCol=0;
     for(const cell of cells){
      const ch=shape(cell,'c',{r:null},['t']),m=/^([A-Z]{1,2})([1-9][0-9]{0,3})$/.exec(cell.attrs.r);
      if(!m||Number(m[2])!==rn||colNumber(m[1])<=prevCol||colNumber(m[1])>52||ch.length!==1)fail();prevCol=colNumber(m[1]);
      let quote,reference={},kind=cell.attrs.t??'n';
      if(kind==='inlineStr'){const k=shape(ch[0],'is');if(k.length!==1)fail();quote=text(k[0],'t');}
      else if(kind==='s'){const s=text(ch[0],'v');if(!/^(?:0|[1-9][0-9]{0,4})$/.test(s)||Number(s)>=shared.length)fail();const index=Number(s);quote=shared[index];sharedUses++;reference={sharedStringIndex:index,sharedStringPart:'xl/sharedStrings.xml',sharedStringPartSha256:partHashes.get('xl/sharedStrings.xml')};}
      else if(kind==='n'){quote=text(ch[0],'v');if(!/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[Ee][+-]?\d+)?$/.test(quote)||!Number.isFinite(Number(quote)))fail();}
      else fail();
      if(quote)add(part,{sheet:name,sheetId:id,cell:cell.attrs.r,valueKind:kind,...reference},quote);
     }
    }
    if(children[j]?.name==='autoFilter'){const filter=children[j++];empty(filter,'autoFilter',{ref:null});if(!/^A1:[A-Z]{1,2}[1-9][0-9]{0,3}$/.test(filter.attrs.ref))fail();}
    if(j!==children.length)fail();
   }
   if(records.size||sharedCount!==null&&sharedCount!==sharedUses)fail();
  }
  if(used.size!==entries.size||[...entries.keys()].some(p=>!used.has(p)))fail();
  checkTypes(get('[Content_Types].xml'),expected);
  return Object.freeze({kind,algorithm:'office-spans-v1',sha256:hash(archive),spans:Object.freeze(spans),warning:'Decoded source text only; no formula evaluation, visual layout, legal interpretation or independent verification.'});
 }finally{for(const b of entries.values())b.fill(0);}
}
