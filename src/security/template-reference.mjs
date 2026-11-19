const id=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export function normalizeTemplateReference(v){
 if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).sort().join(',')!=='reference,revision,templateId,versionId'||typeof v.templateId!=='string'||!id.test(v.templateId)||typeof v.versionId!=='string'||!id.test(v.versionId)||!Number.isInteger(v.revision)||v.revision<1||v.revision>16||typeof v.reference!=='string'||!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(v.reference))throw Error('invalid template reference');
 return {templateId:v.templateId,versionId:v.versionId,revision:v.revision,reference:v.reference};
}
