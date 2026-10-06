import { Problem } from './security.js';
export function database(env){
  const headers={apikey:env.SUPABASE_SERVICE_ROLE_KEY,Authorization:'Bearer '+env.SUPABASE_SERVICE_ROLE_KEY,'Content-Type':'application/json'};
  async function request(path,method='GET',body,extra={}){
    const r=await fetch(env.SUPABASE_URL+path,{method,headers:{...headers,...extra},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(20000)});
    if(!r.ok)throw new Problem('database_request_failed',503);
    return r.status===204?null:r.json();
  }
  return {
    rows:(table,q='')=>request('/rest/v1/'+table+'?'+q),
    insert:(table,body)=>request('/rest/v1/'+table,'POST',body,{Prefer:'return=representation'}),
    patch:(table,q,body)=>request('/rest/v1/'+table+'?'+q,'PATCH',body,{Prefer:'return=representation'}),
    remove:(table,q)=>request('/rest/v1/'+table+'?'+q,'DELETE',undefined,{Prefer:'return=representation'}),
    rpc:(fn,body)=>request('/rest/v1/rpc/'+fn,'POST',body),
    storage:(path,body)=>request('/storage/v1/'+path,'POST',body),
    async user(token){
      const r=await fetch(env.SUPABASE_URL+'/auth/v1/user',{headers:{apikey:env.SUPABASE_SERVICE_ROLE_KEY,Authorization:'Bearer '+token},signal:AbortSignal.timeout(15000)});
      if(!r.ok)throw new Problem('login_required',401); const u=await r.json(); if(!u.id)throw new Problem('login_required',401); return u;
    },
    async video(path,range){
      const r=await fetch(env.SUPABASE_URL+'/storage/v1/object/authenticated/videos/'+path,{headers:{...headers,...(range?{Range:range}:{})},signal:AbortSignal.timeout(25000)});
      if(!r.ok)throw new Problem('video_unavailable',502);return r;
    }
  };
}
