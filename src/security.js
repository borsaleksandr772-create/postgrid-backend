const enc = new TextEncoder();
export const b64 = bytes => { let s=''; for (let i=0;i<bytes.length;i+=8192) s+=String.fromCharCode(...bytes.subarray(i,i+8192)); return btoa(s); };
export const unb64 = s => Uint8Array.from(atob(s), c=>c.charCodeAt(0));
export const random = () => b64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
export const hash = async s => b64(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(s)))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
async function key(env){ const raw=unb64(env.TOKEN_ENCRYPTION_KEY||''); if(raw.length!==32)throw new Error('encryption_config'); return crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']); }
export async function seal(env, value, context){ const iv=crypto.getRandomValues(new Uint8Array(12)); const data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(context)},await key(env),enc.encode(JSON.stringify(value))); return 'v1.'+b64(iv)+'.'+b64(new Uint8Array(data)); }
export async function unseal(env,value,context){ const [v,iv,data]=value.split('.'); if(v!=='v1')throw new Error('cipher_version'); return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(iv),additionalData:enc.encode(context)},await key(env),unb64(data)))); }
export class Problem extends Error { constructor(code,status=400){super(code);this.status=status;} }
export function requireValue(condition,code,status=400){if(!condition)throw new Problem(code,status);}
export function uuid(s){return typeof s==='string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);}
export function validateTargets(targets,now=Date.now()){
  requireValue(Array.isArray(targets)&&targets.length>0&&targets.length<=4,'select_platforms');
  requireValue(new Set(targets.map(t=>t.platform)).size===targets.length,'duplicate_platform');
  for(const t of targets){
    requireValue(['instagram','tiktok','youtube','x'].includes(t.platform),'platform');
    const time=Date.parse(t.scheduled_at);
    requireValue(Number.isFinite(time)&&time>now&&time<now+90*86400000,'schedule_next_90_days');
    requireValue(typeof t.description==='string'&&t.description.length<=({instagram:2200,tiktok:2200,youtube:5000,x:280})[t.platform],'description_length');
    if(t.platform==='youtube'){
      requireValue(typeof t.title==='string'&&t.title.trim().length>0&&t.title.length<=100&&!/[<>]/.test(t.title),'youtube_title');
      requireValue(['private','unlisted','public'].includes(t.options?.privacy),'youtube_privacy');
      requireValue(typeof t.options?.madeForKids==='boolean','youtube_audience');
    }
    if(t.platform==='tiktok'){
      requireValue(t.options?.consent===true,'tiktok_consent_privacy');
    }
  }
  return targets;
}
