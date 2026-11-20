import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {zip} from '../../src/security/verification-report-export.mjs';
import {createRegisterXlsx} from '../../src/security/xlsx-register.mjs';
import {parseOfficeXml} from '../../src/security/office-xml.mjs';
import {extractOfficeSpans} from '../../src/security/office-extraction.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex'),base='http://schemas.openxmlformats.org/',r=base+'officeDocument/2006/relationships',p=base+'package/2006/',m='application/vnd.openxmlformats-officedocument.';
const archive=parts=>zip(parts.map(([n,s])=>[n,Buffer.from(s)]));
const types=parts=>'<Types xmlns="'+p+'content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'+parts.map(([n,t])=>'<Override PartName="/'+n+'" ContentType="'+m+t+'"/>').join('')+'</Types>';
const rels=rows=>'<Relationships xmlns="'+p+'relationships">'+rows.map(([id,type,target])=>'<Relationship Id="'+id+'" Type="'+r+'/'+type+'" Target="'+target+'"/>').join('')+'</Relationships>';
function doc(body,extra=[]){return archive([['[Content_Types].xml',types([['word/document.xml','wordprocessingml.document.main+xml']])],['_rels/.rels',rels([['rId1','officeDocument','word/document.xml']])],['word/document.xml','<w:document xmlns:w="'+base+'wordprocessingml/2006/main"><w:body>'+body+'</w:body></w:document>'],...extra]);}
test('strict XML subset rejects malformed markup, entities, duplicate attributes, depth and processing instructions',()=>{
 const parse=s=>parseOfficeXml(Buffer.from(s));
 assert.equal(parse('<a x="&amp;">A&#x20AC;&lt;</a>').children[0],'A€<');
 for(const s of ['<a><b></a>','<a/>x','<a/><b/>','<a x="1" x="2"/>','<a x="&bogus;"/>','<a>&#0;</a>','<a>&#x202e;</a>','<!DOCTYPE a><a/>','<a><!--x--></a>','<a><?x?></a>','<a>]]></a>','<a>'.repeat(25)+'</a>'.repeat(25),'<a/> <'])assert.throws(()=>parse(s));
});
test('DOCX exact paragraph locations and run text joins, with original and part digests',()=>{
 const b=doc('<w:p><w:r><w:t xml:space="preserve">Equipment must </w:t></w:r><w:r><w:t>carry &amp; retain ID.</w:t></w:r></w:p><w:p/><w:p><w:r><w:t>Inspection is mandatory.</w:t></w:r></w:p>');
 const x=extractOfficeSpans(b,'docx');assert.equal(x.sha256,hash(b));assert.deepEqual(x.spans.map(s=>[s.paragraph,s.quote,s.quoteSha256]),[[1,'Equipment must carry & retain ID.',hash('Equipment must carry & retain ID.')],[3,'Inspection is mandatory.',hash('Inspection is mandatory.')]]);
 assert.ok(x.spans.every(s=>s.part==='word/document.xml'&&s.partSha256===x.spans[0].partSha256));
 for(const body of ['<w:p><w:r><w:instrText>bad</w:instrText></w:r></w:p>','<w:p><w:r><w:t> x </w:t></w:r></w:p>','<w:p><w:r><w:t>_x0041_</w:t></w:r></w:p>','<w:p><w:r><w:rPr/><w:t>hide</w:t></w:r></w:p>','<w:tbl/>'])assert.throws(()=>extractOfficeSpans(doc(body),'docx'));
 assert.throws(()=>extractOfficeSpans(doc('<w:p/>',[['word/styles.xml','<x/>']]),'docx'));
});
test('XLSX register spans retain workbook order, sheet labels and exact cell coordinates',()=>{
 const b=createRegisterXlsx([['Requirement','Status'],['Equipment must carry ID.','Pending']],[['Evidence'],['Proof & record']]);
 const x=extractOfficeSpans(b,'xlsx');assert.equal(x.sha256,hash(b));assert.deepEqual(x.spans.map(s=>[s.sheet,s.cell,s.quote]),[['Requirements','A1','Requirement'],['Requirements','B1','Status'],['Requirements','A2','Equipment must carry ID.'],['Requirements','B2','Pending'],['Evidence','A1','Evidence'],['Evidence','A2','Proof & record']]);
});
function book(content,{sheetAttrs='',extra='',shared=false}={}){
 const part='xl/worksheets/sheet1.xml',list=[['xl/workbook.xml','spreadsheetml.sheet.main+xml'],[part,'spreadsheetml.worksheet+xml']],relationships=[['rId1','worksheet','worksheets/sheet1.xml']];
 if(shared){list.push(['xl/sharedStrings.xml','spreadsheetml.sharedStrings+xml']);relationships.push(['rId2','sharedStrings','sharedStrings.xml']);}
 const ns=base+'spreadsheetml/2006/main';
 return archive([['[Content_Types].xml',types(list)],['_rels/.rels',rels([['rId1','officeDocument','xl/workbook.xml']])],['xl/workbook.xml','<workbook xmlns="'+ns+'" xmlns:r="'+r+'"><sheets><sheet name="Tasks" sheetId="1" r:id="rId1"'+sheetAttrs+'/></sheets></workbook>'],['xl/_rels/workbook.xml.rels',rels(relationships)], [part,'<worksheet xmlns="'+ns+'"><sheetData>'+content+'</sheetData>'+extra+'</worksheet>'],...(shared?[['xl/sharedStrings.xml','<sst xmlns="'+ns+'" count="1" uniqueCount="1"><si><t>Provide proof.</t></si></sst>']]:[])]);
}
test('XLSX shared strings and literal numeric values; formulas, hidden sheets and ambiguous coordinates refused',()=>{
 const valid=book('<row r="2"><c r="B2" t="s"><v>0</v></c><c r="C2"><v>3.75</v></c></row>',{shared:true});
 assert.deepEqual(extractOfficeSpans(valid,'xlsx').spans.map(s=>[s.cell,s.valueKind,s.quote]),[['B2','s','Provide proof.'],['C2','n','3.75']]);
 for(const b of [book('<row r="1"><c r="A1"><f>1+1</f><v>2</v></c></row>'),book('<row r="1"><c r="A2"><v>2</v></c></row>'),book('<row r="1"><c r="A1"><v>2</v></c><c r="A1"><v>3</v></c></row>'),book('<row r="1"><c r="A1" t="s"><v>1</v></c></row>',{shared:true}),book('',{sheetAttrs:' state="hidden"'}),book('',{extra:'<drawing r:id="rId1"/>'})])assert.throws(()=>extractOfficeSpans(b,'xlsx'));
});
