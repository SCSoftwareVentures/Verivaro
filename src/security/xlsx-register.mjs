import {zip} from './verification-report-export.mjs';
const ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main',rel='http://schemas.openxmlformats.org/officeDocument/2006/relationships',pkg='http://schemas.openxmlformats.org/package/2006/relationships',decl='<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
const xml=s=>String(s??'').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]/gu,'\ufffd').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'","&apos;");
// All values are inline strings: no formula, hyperlink, macro or external relationship.
function sheet(rows){
 if(!Array.isArray(rows)||rows.length<1||rows.length>129||rows.some(r=>!Array.isArray(r)||r.length<1||r.length>16))throw Error('invalid workbook rows');
 let s=decl+'<worksheet xmlns="'+ns+'"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="15"/><cols><col min="1" max="16" width="32" customWidth="1"/></cols><sheetData>';
 for(const [i,r] of rows.entries()){s+='<row r="'+(i+1)+'">';for(const [j,val] of r.entries()){
  const t=String(val??'');if(t.length>8192)throw Error('workbook cell limit');
  s+='<c r="'+String.fromCharCode(65+j)+(i+1)+'" t="inlineStr"><is><t xml:space="preserve">'+xml(t)+'</t></is></c>';
 }s+='</row>';}
 return s+'</sheetData><autoFilter ref="A1:'+String.fromCharCode(64+rows[0].length)+rows.length+'"/></worksheet>';
}
export function createRegisterXlsx(requirements,evidence){
 const content=decl+'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>';
 const parts=[['[Content_Types].xml',content],['_rels/.rels',decl+'<Relationships xmlns="'+pkg+'"><Relationship Id="rId1" Type="'+rel+'/officeDocument" Target="xl/workbook.xml"/></Relationships>'],['xl/workbook.xml',decl+'<workbook xmlns="'+ns+'" xmlns:r="'+rel+'"><sheets><sheet name="Requirements" sheetId="1" r:id="rId1"/><sheet name="Evidence" sheetId="2" r:id="rId2"/></sheets></workbook>'],['xl/_rels/workbook.xml.rels',decl+'<Relationships xmlns="'+pkg+'"><Relationship Id="rId1" Type="'+rel+'/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="'+rel+'/worksheet" Target="worksheets/sheet2.xml"/></Relationships>'],['xl/worksheets/sheet1.xml',sheet(requirements)],['xl/worksheets/sheet2.xml',sheet(evidence)]];
 const out=zip(parts.map(([name,s])=>[name,Buffer.from(s,'utf8')]));if(out.length>1048576)throw Error('workbook capacity');return out;
}
