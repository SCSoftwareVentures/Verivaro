// Optional witness-backed G1 trust boundary. Production must supply an
// independently governed, durable monotonic compare-and-swap authority.
// A local/in-memory witness is ONLY a synthetic CI fixture.
import {createRotatingProviderVerifier} from './provider-key-rotation.mjs';

const valid=c=>c&&Number.isSafeInteger(c.sequence)&&c.sequence>=1&&
 typeof c.digest==='string'&&/^[a-f0-9]{64}$/.test(c.digest);
const equal=(a,b)=>valid(a)&&valid(b)&&a.sequence===b.sequence&&a.digest===b.digest;

// Single active verifier per disk lease, with independent witness comparison
// at startup and witness-before-local ordering for each keyset replacement.
// The witness must be an independent fault/security domain: NOT another file
// on the same volume or an unprotected in-memory process variable.
export async function openWitnessBoundProviderVerifier({store,witness,issuer,audience,...config}){
 if(!store||typeof store.read!=='function'||typeof store.bindVerifier!=='function'||
   typeof store.isOpen!=='function'||!store.isOpen()||
   !witness||typeof witness.read!=='function'||typeof witness.compareAndSwap!=='function')
  throw Error('independent provider checkpoint witness required');
 const scope=Object.freeze({issuer,audience});
 const local=await store.read();
 const witnessState=await witness.read(scope);
 if(!equal(local,witnessState))throw Error('provider checkpoint witness disagreement');
 // Every token check must observe a fresh consistent witness/local pair.
 // A detected mismatch or witness I/O error latches denial until a supervised
 // restart, even if the witness subsequently becomes available again.
 let commitLocal,expected=Object.freeze({...local}),failed=false,rotating=false,epoch=0,persistStarted=false;
 const inner=createRotatingProviderVerifier({...config,issuer,audience,checkpoint:local,
  persistCheckpoint:async(previous,next)=>{
   if(typeof commitLocal!=='function')throw Error('provider verifier not bound');
   // Once trusted persistence was attempted, any subsequent exception leaves
   // the in-memory verifier unavailable until a supervised restart.
   persistStarted=true;
   // Detect an independent checkpoint advance before trying to rotate. On any
   // failure the inner verifier enters FAULTED and stops authorising tokens.
   const before=await witness.read(scope);
   if(!equal(before,previous))throw Error('provider witness rollback or conflict');
   // Witness advances BEFORE local disk. If this process crashes between the
   // commits, the next startup rejects the mismatched pair instead of
   // accepting a rolled-back/retired local keyset.
   const confirmed=await witness.compareAndSwap({...scope,previous,next});
   if(!equal(confirmed,next))throw Error('independent checkpoint commit unconfirmed');
   const saved=await commitLocal(previous,next);
   if(!equal(saved,next))throw Error('local checkpoint commit unconfirmed');
   expected=Object.freeze({...next});
   return saved;
  }});
 commitLocal=store.bindVerifier();
 // Recheck after acquiring the one-verifier lease to reject any write that
 // raced with the initial startup reads. On failure the store stays bound:
 // operator must close it and reconcile the two checkpoints before retrying.
 const [localFinal,witnessFinal]=await Promise.all([store.read(),witness.read(scope)]);
 if(!equal(localFinal,local)||!equal(witnessFinal,local))
  throw Error('provider checkpoint changed during verifier binding');
 return Object.freeze({
  issuer:inner.issuer,audience:inner.audience,
  async verify(token,now){
   if(failed||rotating||!store.isOpen())throw Error('provider checkpoint witness unavailable');
   const observedEpoch=epoch;
   let localNow,witnessNow;
   try{
    // Require strongly consistent, current witness reads: cached or
    // eventually consistent responses are not production-safe.
    [localNow,witnessNow]=await Promise.all([store.read(),witness.read(scope)]);
   }catch{
    failed=true;
    throw Error('provider checkpoint witness unavailable');
   }
   // A rotation may start or finish while the remote read is pending.
   // Reject that attempt without falsely latching a rollback fault.
   if(rotating||observedEpoch!==epoch)throw Error('provider checkpoint changed during verification');
   if(!equal(localNow,expected)||!equal(witnessNow,expected)){
    failed=true;
    throw Error('provider checkpoint witness disagreement');
   }
   if(failed||!store.isOpen())throw Error('provider checkpoint witness unavailable');
   return inner.verify(token,now);
  },
  async rotate(bytes,signature,anchor){
   if(failed||rotating||!store.isOpen())throw Error('provider checkpoint witness unavailable');
   rotating=true;persistStarted=false;epoch++;
   try{return await inner.rotate(bytes,signature,anchor);}
   catch(e){
    if(persistStarted)failed=true;
    throw e;
   }finally{rotating=false;epoch++;}
  }
 });
}
