const ID=/^[a-z][a-z0-9_-]{0,31}$/;
export const validBackupKeyId=x=>typeof x==='string'&&ID.test(x);
const validKey=x=>Buffer.isBuffer(x)&&x.length===32;
export function createBackupKeyring({activeId,keys,legacyKey}){
 if(!validBackupKeyId(activeId)||!Array.isArray(keys)||keys.length<1||keys.length>16||(legacyKey!==undefined&&!validKey(legacyKey)))throw Error('invalid backup keyring');
 const store=new Map();
 for(const item of keys){
  if(!item||!validBackupKeyId(item.id)||!validKey(item.key)||store.has(item.id))throw Error('invalid backup key entry');
  store.set(item.id,Buffer.from(item.key));
 }
 if(!store.has(activeId))throw Error('active backup key unavailable');
 const legacy=legacyKey===undefined?null:Buffer.from(legacyKey);
 let closed=false;
 return Object.freeze({
  activeId,
  writeKey(){if(closed)throw Error('keyring closed');return {id:activeId,key:Buffer.from(store.get(activeId))};},
  readKey(id){if(closed)throw Error('keyring closed');const k=id===null?legacy:store.get(id);if(!k)throw Error('backup key unavailable');return Buffer.from(k);},
  close(){if(closed)return;closed=true;for(const k of store.values())k.fill(0);legacy?.fill(0);store.clear();}
 });
}
export function backupKeyConfigValid(key,keyring){return keyring===undefined?validKey(key):key===undefined&&typeof keyring?.writeKey==='function'&&typeof keyring?.readKey==='function';}
