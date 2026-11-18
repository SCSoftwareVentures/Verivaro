import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
const hash=s=>createHash('sha256').update(s,'utf8').digest('hex');
const message=(kid,json)=>Buffer.from('verivaro-release-v1\0'+kid+'\0'+json,'utf8');
export function createReleaseSigner({keyId,privateKey}){
 if(typeof keyId!=='string'||! /^[A-Za-z0-9_-]{1,80}$/.test(keyId))throw Error('invalid signing key identifier');
 const key=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey);
 if(key.asymmetricKeyType!=='ed25519')throw Error('Ed25519 required');
 return Object.freeze({sign(row){
 if(typeof row?.json!=='string'||hash(row.json)!==row.sha256)throw Error('release integrity failure');
 return {...row,signature:{algorithm:'Ed25519',keyId,value:sign(null,message(keyId,row.json),key).toString('base64url')}};
 }});
}
export function verifyRelease(row,{keyId,publicKey}){
 try{
 if(row?.signature?.algorithm!=='Ed25519'||row.signature.keyId!==keyId||typeof row.json!=='string'||hash(row.json)!==row.sha256||!/^[A-Za-z0-9_-]{86}$/.test(row.signature.value))return false;
 const key=publicKey?.type==='public'?publicKey:createPublicKey(publicKey);
 return key.asymmetricKeyType==='ed25519'&&verify(null,message(keyId,row.json),key,Buffer.from(row.signature.value,'base64url'));
 }catch{return false;}
}
