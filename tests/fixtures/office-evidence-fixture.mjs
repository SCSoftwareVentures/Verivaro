import {zip} from '../../src/security/verification-report-export.mjs';
import {createRegisterXlsx} from '../../src/security/xlsx-register.mjs';
export const DOCX='application/vnd.openxmlformats-officedocument.wordprocessingml.document',XLSX='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
export function officeFixtures(){
 const base='http://schemas.openxmlformats.org/',r=base+'officeDocument/2006/relationships',p=base+'package/2006/';
 const doc=zip([
 ['[Content_Types].xml',Buffer.from('<Types xmlns="'+p+'content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="'+DOCX+'.main+xml"/></Types>')],
 ['_rels/.rels',Buffer.from('<Relationships xmlns="'+p+'relationships"><Relationship Id="rId1" Type="'+r+'/officeDocument" Target="word/document.xml"/></Relationships>')],
 ['word/document.xml',Buffer.from('<w:document xmlns:w="'+base+'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Equipment must carry ID.</w:t></w:r></w:p></w:body></w:document>')]
 ]);
 return [[DOCX,doc],[XLSX,createRegisterXlsx([['Requirement'],['Work must comply.']],[['Evidence']])]];
}
