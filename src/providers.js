import { b64, seal, unseal, Problem, requireValue } from './security.js';
export const platforms=['instagram','tiktok','youtube','x'];
export function provider(env,p){
 const definitions={
  instagram:{prefix:'INSTAGRAM',authorize:'https://www.instagram.com/oauth/authorize',token:'https://api.instagram.com/oauth/access_token',scope:'instagram_business_basic,instagram_business_content_publish'},
  tiktok:{prefix:'TIKTOK',authorize:'https://www.tiktok.com/v2/auth/authorize/',token:'https://open.tiktokapis.com/v2/oauth/token/',scope:'user.info.basic,video.publish'},
  youtube:{prefix:'GOOGLE',authorize:'https://accounts.google.com/o/oauth2/v2/auth',token:'https://oauth2.googleapis.com/token',scope:'https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.readonly'},
  x:{prefix:'X',authorize:'https://x.com/i/oauth2/authorize',token:'https://api.x.com/2/oauth2/token',scope:'tweet.read tweet.write users.read media.write offline.access'}
 };
 requireValue(platforms.includes(p),'platform');const d=definitions[p];
 return {...d,id:env[d.prefix+'_CLIENT_ID'],secret:env[d.prefix+'_CLIENT_SECRET'],redirect:env.PUBLIC_BACKEND_URL+'/api/oauth/'+p+'/callback'};
}
export function authorizeURL(env,p,state,challenge){
 const c=provider(env,p);requireValue(c.id&&c.secret,'provider_not_configured',503);
 const u=new URL(c.authorize);const q={response_type:'code',redirect_uri:c.redirect,scope:c.scope,state,[p==='tiktok'?'client_key':'client_id']:c.id};
 if(p==='x'||p==='youtube')Object.assign(q,{code_challenge:challenge,code_challenge_method:'S256'});
 if(p==='youtube')Object.assign(q,{access_type:'offline',prompt:'consent',include_granted_scopes:'true'});
 if(p==='instagram')Object.assign(q,{enable_fb_login:'0',force_authentication:'1'});
 u.search=new URLSearchParams(q);return u.toString();
}
// Do not pass provider response bodies into logs, errors or frontend JSON: they can contain credentials.
export async function remote(url,options={}){
 let r;try{r=await fetch(url,{...options,signal:AbortSignal.timeout(25000)});}catch{throw new Problem('provider_network_ambiguous',502);}
 let j={};const text=await r.text();try{j=text?JSON.parse(text):{};}catch{throw new Problem('provider_response_invalid',502);}
 if(!r.ok||j.error&&(typeof j.error!=='object'||j.error.code&&j.error.code!=='ok')||j.errors?.length)throw new Problem('provider_http_'+r.status,502);
 return j;
}
export const bearer=t=>({Authorization:'Bearer '+t});
export const jsonPost=(token,body)=>({method:'POST',headers:{...bearer(token),'Content-Type':'application/json'},body:JSON.stringify(body)});
export const formPost=body=>({method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(body)});
async function tokenRequest(env,p,body){
 const c=provider(env,p);const fields={...body};
 if(p==='tiktok')Object.assign(fields,{client_key:c.id,client_secret:c.secret});
 else if(p!=='x')Object.assign(fields,{client_id:c.id,client_secret:c.secret});
 const opts=formPost(fields);
 if(p==='x')opts.headers.Authorization='Basic '+b64(new TextEncoder().encode(encodeURIComponent(c.id)+':'+encodeURIComponent(c.secret)));
 return remote(c.token,opts);
}
export const igBase=env=>'https://graph.instagram.com/'+(env.INSTAGRAM_API_VERSION||'v25.0');
export async function exchange(env,p,code,verifier){
 let t=await tokenRequest(env,p,{grant_type:'authorization_code',code,redirect_uri:provider(env,p).redirect,...(['x','youtube'].includes(p)?{code_verifier:verifier}:{})});
 if(p==='instagram'){
   // Instagram may wrap the short-lived token in data[].
   t=t.data?.[0]||t;
   const q=new URLSearchParams({grant_type:'ig_exchange_token',client_secret:provider(env,p).secret,access_token:t.access_token});
   t={...t,...await remote('https://graph.instagram.com/access_token?'+q)};
 }
 requireValue(t.access_token,'token_missing',502);
 if(t.scope){const wanted=provider(env,p).scope.split(/[ ,]+/),got=t.scope.split(/[ ,]+/);requireValue(wanted.every(s=>got.includes(s)),'required_scope_denied');}
 let id,name;
 if(p==='instagram'){const j=await remote(igBase(env)+'/me?fields=user_id,username',{headers:bearer(t.access_token)});id=j.user_id||j.id;name=j.username;}
 if(p==='tiktok'){const j=await remote('https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name',{headers:bearer(t.access_token)});id=j.data?.user?.open_id;name=j.data?.user?.display_name;}
 if(p==='youtube'){const j=await remote('https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true',{headers:bearer(t.access_token)});id=j.items?.[0]?.id;name=j.items?.[0]?.snippet?.title;}
 if(p==='x'){const j=await remote('https://api.x.com/2/users/me',{headers:bearer(t.access_token)});id=j.data?.id;name=j.data?.username;}
 requireValue(id&&name,'provider_account_missing',422);
 t.expires_at=new Date(Date.now()+Number(t.expires_in||3600)*1000).toISOString();
 return {tokens:t,remote_id:String(id),display_name:String(name)};
}
export async function accessToken(env,db,a){
 requireValue(a?.connected,'account_disconnected',409);
 let t=await unseal(env,a.tokens,a.user_id+':'+a.platform);
 const margin=a.platform==='instagram'?7*86400000:120000;
 if(Date.parse(a.expires_at)>Date.now()+margin)return t.access_token;
 const now=new Date().toISOString();
 const locked=await db.patch('accounts',`id=eq.${a.id}&connected=eq.true&token_lock_until=lt.${now}`,{token_lock_until:new Date(Date.now()+60000).toISOString()});
 requireValue(locked.length,'token_refresh_busy',409);
 try{
   a=locked[0];t=await unseal(env,a.tokens,a.user_id+':'+a.platform);
   if(Date.parse(a.expires_at)>Date.now()+margin)return t.access_token;
   let next;
   if(a.platform==='instagram')next=await remote('https://graph.instagram.com/refresh_access_token?'+new URLSearchParams({grant_type:'ig_refresh_token',access_token:t.access_token}));
   else {requireValue(t.refresh_token,'reconnect_required',409);next=await tokenRequest(env,a.platform,{grant_type:'refresh_token',refresh_token:t.refresh_token});}
   requireValue(next.access_token,'reconnect_required',409);
   t={...t,...next,expires_at:new Date(Date.now()+Number(next.expires_in||3600)*1000).toISOString()};
   await db.patch('accounts',`id=eq.${a.id}&connected=eq.true`,{tokens:await seal(env,t,a.user_id+':'+a.platform),expires_at:t.expires_at});
   return t.access_token;
 }finally{await db.patch('accounts',`id=eq.${a.id}`,{token_lock_until:'1970-01-01T00:00:00Z'});}
}
export async function revoke(env,p,t,remoteId){
 if(p==='youtube')return remote('https://oauth2.googleapis.com/revoke',formPost({token:t.refresh_token||t.access_token}));
 if(p==='tiktok'){const c=provider(env,p);return remote('https://open.tiktokapis.com/v2/oauth/revoke/',formPost({client_key:c.id,client_secret:c.secret,token:t.access_token}));}
 if(p==='x'){const c=provider(env,p),o=formPost({token:t.refresh_token||t.access_token,token_type_hint:t.refresh_token?'refresh_token':'access_token'});o.headers.Authorization='Basic '+b64(new TextEncoder().encode(encodeURIComponent(c.id)+':'+encodeURIComponent(c.secret)));return remote('https://api.x.com/2/oauth2/revoke',o);}
 return remote(igBase(env)+'/'+encodeURIComponent(remoteId)+'/permissions',{method:'DELETE',headers:bearer(t.access_token)});
}
export async function creatorInfo(token){return (await remote('https://open.tiktokapis.com/v2/post/publish/creator_info/query/',jsonPost(token,{}))).data;}
export function validateTikTok(t,info,duration){
 requireValue(info?.privacy_level_options?.includes(t.options.privacy),'tiktok_privacy_changed');
 requireValue(duration<=info.max_video_post_duration_sec,'tiktok_video_too_long');
 for(const name of ['comment','duet','stitch'])requireValue(!(info[name+'_disabled']&&t.options[name]),'tiktok_interaction_disabled');
}
