// Bounded XML subset for offline Office extraction. No DTD, namespaces
// resolved by caller's exact schemas, no external fetch, PI or execution.
const fail=()=>{throw Error('unsupported Office XML');};
const nameRe=/(?:[A-Za-z_][A-Za-z0-9_.-]*:)?[A-Za-z_][A-Za-z0-9_.-]*/y;
const validChar=n=>n===9||n===10||n===13||n>=32&&n<=0xd7ff||n>=0xe000&&n<=0xfffd||n>=0x10000&&n<=0x10ffff;
function decode(s){
 if(s.includes(']]>')||/[\u202a-\u202e\u2066-\u2069]/u.test(s)||[...s].some(ch=>!validChar(ch.codePointAt(0))))fail();
 const values={amp:'&',lt:'<',gt:'>',apos:"'",quot:'"'};
 return s.replace(/&(?:[^&;]{0,24};)?/g,m=>{
  const key=m.slice(1,-1);
  if(m.endsWith(';')&&Object.hasOwn(values,key))return values[key];
  if(!/^&#(?:[0-9]{1,7}|x[0-9a-fA-F]{1,6});$/.test(m))fail();
  const n=key[1]==='x'?parseInt(key.slice(2),16):Number(key.slice(1));
  if(!validChar(n)||n>=0x202a&&n<=0x202e||n>=0x2066&&n<=0x2069)fail();
  return String.fromCodePoint(n);
 });
}
export function parseOfficeXml(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>262144)fail();
 let s=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes).replace(/\r\n?/g,'\n'),p=0,count=0,root;
 if(s.charCodeAt(0)===0xfeff)p++;
 if(s.startsWith('<?xml',p)){
  const d=/^<\?xml version=(?:"1\.0"|'1\.0')(?: encoding=(?:"UTF-8"|'UTF-8'))?(?: standalone=(?:"(?:yes|no)"|'(?:yes|no)'))?\?>/.exec(s.slice(p));
  if(!d)fail();p+=d[0].length;
 }
 const stack=[];
 function ws(){const before=p;while(p<s.length&&/[ \t\n]/.test(s[p]))p++;return p>before;}
 function name(){nameRe.lastIndex=p;const m=nameRe.exec(s);if(!m||m[0].length>128)fail();p=nameRe.lastIndex;return m[0];}
 while(p<s.length){
  if(s[p]!=='<'){
   const end=s.indexOf('<',p),q=end<0?s.length:end,raw=s.slice(p,q),value=decode(raw);p=q;
   if(!stack.length){if(value.trim()||raw.includes('&'))fail();}
   else if(value)stack.at(-1).children.push(value);
   continue;
  }
  if(s.startsWith('</',p)){p+=2;const n=name();ws();if(s[p++]!=='>'||!stack.length||stack.pop().name!==n)fail();continue;}
  p++;if(++count>12000||stack.length>=24)fail();
  const n=name(),attrs=Object.create(null),node={name:n,attrs,children:[]};
  let closed=false;
  while(p<s.length){
   const separated=ws();
   if(s.startsWith('/>',p)){p+=2;closed=true;break;}
   if(s[p]==='>'){p++;break;}
   if(!separated||Object.keys(attrs).length>=24)fail();
   const a=name();if(Object.hasOwn(attrs,a))fail();ws();if(s[p++]!=='=')fail();ws();
   const quote=s[p++];if(quote!=='"'&&quote!=="'")fail();
   const end=s.indexOf(quote,p);if(end<0||end-p>2048)fail();
   const raw=s.slice(p,end);if(/[<\t\n]/.test(raw))fail();attrs[a]=decode(raw);p=end+1;
  }
  if(stack.length)stack.at(-1).children.push(node);else{if(root)fail();root=node;}
  if(!closed)stack.push(node);
 }
 if(!root||stack.length)fail();return root;
}
