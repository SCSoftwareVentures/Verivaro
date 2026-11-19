// ZeroSwitch bounded preview only. No external fetch, file paths, formula
// evaluation, implicit field mapping, or direct database writes.
const invalid=()=>{throw Error('invalid CSV preview input');};
export function previewRequirementCsv(bytes,mapping){
 if(!(bytes instanceof Uint8Array)||bytes.byteLength<1||bytes.byteLength>262144||!mapping||Object.keys(mapping).sort().join(',')!=='applicability,criterion,title'||!Object.values(mapping).every(x=>typeof x==='string'&&x.length>0&&x.length<=128)||new Set(Object.values(mapping)).size!==3)invalid();
 let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{invalid();}
 if(text.includes('\0'))invalid();
 const rows=[];let row=[],cell='',quoted=false,closed=false;
 const finishCell=()=>{if(cell.length>4096||row.length>=32)invalid();row.push(cell);cell='';closed=false;};
 const finishRow=()=>{finishCell();if(rows.length>=129)invalid();rows.push(row);row=[];};
 for(let i=0;i<text.length;i++){const c=text[i];if(quoted){if(c==='"'){if(text[i+1]==='"'){cell+='"';i++;}else{quoted=false;closed=true;}}else cell+=c;}else if(c===',')finishCell();else if(c==='\n'||c==='\r'){if(c==='\r'){if(text[i+1]!=='\n')invalid();i++;}finishRow();}else if(c==='"'&&!closed&&!cell)quoted=true;else{if(closed||c==='"')invalid();cell+=c;}if(cell.length>4096)invalid();}
 if(quoted)invalid();if(row.length||cell||closed)finishRow();
 if(!rows.length)invalid();
 const headers=rows.shift();if(headers.length<3||headers.some(x=>!x||x.length>128)||new Set(headers).size!==headers.length||Object.values(mapping).some(x=>!headers.includes(x)))invalid();
 const accepted=[],errors=[],seen=new Set();
 for(const [i,r] of rows.entries()){
  const rowNumber=i+2,errorsHere=[];
  if(r.length!==headers.length){errors.push({row:rowNumber,errors:['column_count']});continue;}
  const title=r[headers.indexOf(mapping.title)].trim(),criterion=r[headers.indexOf(mapping.criterion)].trim(),applicability=r[headers.indexOf(mapping.applicability)].trim();
  for(const [v,key,max] of [[title,'title',128],[criterion,'criterion',1024]])if(!v||[...v].length>max||/[\x00-\x1f\x7f-\x9f]/u.test(v))errorsHere.push('invalid_'+key);
  if(!['unknown','required','optional','not_applicable'].includes(applicability))errorsHere.push('invalid_applicability');
  const key=JSON.stringify([title,criterion,applicability]);if(seen.has(key))errorsHere.push('duplicate_row');
  if(errorsHere.length)errors.push({row:rowNumber,errors:errorsHere});else{seen.add(key);accepted.push({row:rowNumber,title,criterion,applicability,reviewRequired:true});}
 }
 return {version:1,headers,rows:rows.length,accepted,errors,writes:0};
}
