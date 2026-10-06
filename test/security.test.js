import test from 'node:test';
import assert from 'node:assert/strict';
import {random,hash,seal,unseal,validateTargets} from '../src/security.js';
import {authorizeURL,exchange,accessToken,validateTikTok,remote} from '../src/providers.js';
import {route,handle} from '../src/app.js';
import {publishStep,runQueue} from '../src/publish.js';
const uid='00000000-0000-4000-8000-000000000001';
const env={TOKEN_ENCRYPTION_KEY:Buffer.alloc(32,7).toString('base64'),PUBLIC_BACKEND_URL:'https://api.example.com',FRONTEND_URL:'https://u.github.io/postgrid/',CRON_SECRET:'test-only',INSTAGRAM_CLIENT_ID:'ig',INSTAGRAM_CLIENT_SECRET:'ig-secret',TIKTOK_CLIENT_ID:'tt',TIKTOK_CLIENT_SECRET:'tt-secret',GOOGLE_CLIENT_ID:'g',GOOGLE_CLIENT_SECRET:'g-secret',X_CLIENT_ID:'x',X_CLIENT_SECRET:'x-secret'};
const req=(path,method='GET',data,auth=true)=>new Request('https://api.example.com'+path,{method,headers:{...(auth?{Authorization:'Bearer user-token'}:{}),'Content-Type':'application/json'},body:data?JSON.stringify(data):undefined});
const json=v=>new Response(JSON.stringify(v),{headers:{'Content-Type':'application/json'}});
test('AES-GCM hides tokens; tampering, wrong key and cross-user substitution fail',async()=>{
 const c=await seal(env,{access_token:'secret'},uid+':x');assert(!c.includes('secret'));assert.deepEqual(await unseal(env,c,uid+':x'),{access_token:'secret'});
 await assert.rejects(unseal(env,c,'other-user:x'));
 await assert.rejects(unseal({...env,TOKEN_ENCRYPTION_KEY:Buffer.alloc(32,9).toString('base64')},c,uid+':x'));
 await assert.rejects(unseal(env,c.slice(0,-5)+'AAAAA',uid+':x'));
});
test('OAuth URLs contain correct backend callbacks, scopes, PKCE and no secrets',async()=>{
 for(const p of ['instagram','tiktok','youtube','x']){const u=new URL(authorizeURL(env,p,random(),await hash('proof')));assert.equal(u.searchParams.get('redirect_uri'),env.PUBLIC_BACKEND_URL+'/api/oauth/'+p+'/callback');assert(!u.toString().includes('secret'));if(['x','youtube'].includes(p))assert.equal(u.searchParams.get('code_challenge_method'),'S256');if(p==='tiktok')assert.equal(u.searchParams.get('client_key'),'tt');}
});
test('backend denies missing login, cross-origin requests and missing cron secret',async()=>{
 const r=await handle(new Request('https://api.example.com/api/accounts'),env);assert.equal(r.status,401);
 const evil=await handle(new Request('https://api.example.com/api/health',{headers:{Origin:'https://evil.example'}}),env);assert.equal(evil.status,403);assert.equal(evil.headers.get('access-control-allow-origin'),null);
 const cors=await handle(new Request('https://api.example.com/api/accounts',{method:'OPTIONS',headers:{Origin:'https://u.github.io'}}),env);assert.equal(cors.status,204);assert.equal(cors.headers.get('access-control-allow-origin'),'https://u.github.io');
 await assert.rejects(route(req('/api/cron'),env,{}),/unauthorized/);
});
test('state replay or wrong provider fails before token exchange',async()=>{
 let calls=0;const db={patch:async()=>{calls++;return [];}};
 await assert.rejects(route(req('/api/oauth/x/callback?state='+random()+'&code=bad'),env,db),/oauth_state_expired_or_used/);assert.equal(calls,1);
});
test('OAuth completion passes authenticated owner and hashed browser proof',async()=>{
 const state=random(),proof=random();const db={user:async()=>({id:uid}),rpc:async(fn,b)=>{assert.equal(fn,'complete_oauth');assert.equal(b.p_user,uid);assert.equal(b.p_state,await hash(state));assert.equal(b.p_proof,await hash(proof));return false;}};
 await assert.rejects(route(req('/api/oauth/complete','POST',{state,proof}),env,db),/oauth_expired/);
});
test('account response excludes tokens and queries authenticated owner',async()=>{
 const db={user:async()=>({id:uid}),rows:async(t,q)=>{assert.equal(t,'accounts');assert(q.includes('user_id=eq.'+uid));assert(!q.includes('tokens'));return [];}};
 const r=await route(req('/api/accounts'),env,db);const j=await r.json();assert.equal(j.accounts.length,4);assert(!JSON.stringify(j).includes('secret'));
});
test('schedule rejects past dates, duplicate targets, invalid title and missing TikTok consent',()=>{
 const t={platform:'x',description:'hello',scheduled_at:new Date(Date.now()+60000).toISOString()};assert.equal(validateTargets([t]).length,1);
 assert.throws(()=>validateTargets([{...t,scheduled_at:'2020-01-01'}]),/schedule/);
 assert.throws(()=>validateTargets([t,t]),/duplicate/);
 assert.throws(()=>validateTargets([{...t,platform:'youtube',title:''}]),/youtube_title/);
 assert.throws(()=>validateTargets([{...t,platform:'tiktok',options:{}}]),/tiktok_consent/);
});
test('TikTok enforces current creator privacy, duration and interaction settings',()=>{
 const info={privacy_level_options:['SELF_ONLY'],max_video_post_duration_sec:30,comment_disabled:true};
 assert.throws(()=>validateTikTok({options:{privacy:'PUBLIC_TO_EVERYONE'}},info,10),/privacy/);
 assert.throws(()=>validateTikTok({options:{privacy:'SELF_ONLY'}},info,31),/too_long/);
 assert.throws(()=>validateTikTok({options:{privacy:'SELF_ONLY',comment:true}},info,10),/interaction/);
});
test('provider failure bodies do not leak tokens to errors',async(t)=>{
 t.mock.method(globalThis,'fetch',async()=>new Response(JSON.stringify({error:'secret-access-token'}),{status:400}));await assert.rejects(remote('https://provider.test'),e=>e.message==='provider_http_400');
});
test('all four code exchanges resolve account identity; token never sent to frontend',async(t)=>{
 for(const p of ['instagram','tiktok','youtube','x']){
  t.mock.method(globalThis,'fetch',async(url,opts)=>{
   const u=String(url);
   if(u.includes('/oauth/access_token')||u.endsWith('/oauth/token/')||u.endsWith('/oauth2/token')||u==='https://oauth2.googleapis.com/token'){assert.equal(opts.method,'POST');return json({access_token:'short',refresh_token:'refresh',expires_in:3600});}
   if(u.startsWith('https://graph.instagram.com/access_token?'))return json({access_token:'long',expires_in:5000000});
   if(u.includes('/me?fields='))return json({user_id:'123',username:'tester'});
   if(u.includes('/user/info/'))return json({data:{user:{open_id:'123',display_name:'tester'}},error:{code:'ok'}});
   if(u.includes('/channels?'))return json({items:[{id:'123',snippet:{title:'tester'}}]});
   if(u.endsWith('/users/me'))return json({data:{id:'123',username:'tester'}});
   throw Error('unexpected endpoint '+u);
  });
  const result=await exchange(env,p,'code','verifier');assert.equal(result.remote_id,'123');assert.equal(result.display_name,'tester');assert(result.tokens.access_token);t.mock.restoreAll();
 }
});
test('refresh rotation is encrypted and persists replacement refresh token',async(t)=>{
 const a={id:uid,user_id:uid,platform:'x',connected:true,expires_at:new Date(0).toISOString(),tokens:await seal(env,{access_token:'old',refresh_token:'r1'},uid+':x')};let saved;
 const db={patch:async(table,q,b)=>{if(b.tokens)saved=b.tokens;return [a];}};
 t.mock.method(globalThis,'fetch',async()=>json({access_token:'new',refresh_token:'r2',expires_in:7200}));
 assert.equal(await accessToken(env,db,a),'new');assert.equal((await unseal(env,saved,uid+':x')).refresh_token,'r2');
});
test('Instagram only becomes published after media_publish, not container init',async(t)=>{
 const j={id:uid,platform:'instagram',description:'test',step:{}},a={remote_id:'123'},u={path:uid+'/'+uid+'.mp4'};
 t.mock.method(globalThis,'fetch',async()=>json({id:'container'}));const first=await publishStep(env,{},j,a,u,'token');assert.equal(first.status,'processing');assert.equal(first.step.container,'container');
 t.mock.restoreAll();t.mock.method(globalThis,'fetch',async()=>json({id:'real-post'}));const final=await publishStep(env,{}, {...j,step:{container:'container',ready:true}},a,u,'token');assert.equal(final.status,'published');assert.equal(final.external_id,'real-post');
});
test('TikTok init is processing; final status is polled',async(t)=>{
 t.mock.method(globalThis,'fetch',async()=>json({data:{status:'PROCESSING_UPLOAD'},error:{code:'ok'}}));const j={platform:'tiktok',step:{publish_id:'123'}};assert.equal((await publishStep(env,{},j,{}, {},'token')).status,'processing');
 t.mock.restoreAll();t.mock.method(globalThis,'fetch',async()=>json({data:{status:'PUBLISH_COMPLETE',publicaly_available_post_id:['post-id']},error:{code:'ok'}}));assert.equal((await publishStep(env,{},j,{}, {},'token')).external_id,'post-id');
});
test('YouTube validates resumable session destination',async(t)=>{
 t.mock.method(globalThis,'fetch',async()=>new Response('',{headers:{location:'https://evil.example/upload'}}));
 await assert.rejects(publishStep(env,{}, {id:uid,platform:'youtube',step:{},options:{privacy:'private',madeForKids:false}}, {},{size:10},'token'),/session_host/);
});
test('X publication uses media ID only after processing',async(t)=>{
 t.mock.method(globalThis,'fetch',async(url,o)=>{assert.equal(url,'https://api.x.com/2/tweets');assert.deepEqual(JSON.parse(o.body).media.media_ids,['123']);return json({data:{id:'456'}});});
 const j={platform:'x',description:'hello',step:{media_id:'123',offset:100,finalized:true,ready:true}};assert.equal((await publishStep(env,{},j,{}, {size:100},'token')).external_id,'456');
});
test('worker refuses account replacement and uses lease guard for result',async()=>{
 let saved;const job={id:uid,lease_id:uid,account_id:uid,remote_id:'original',scheduled_at:new Date().toISOString()};
 const db={rpc:async()=>[job],rows:async()=>[{remote_id:'replacement',connected:true}],patch:async(table,q,b)=>{assert(q.includes('lease_id=eq.'+uid));saved=b;}};
 await runQueue({...env,PUBLISH_ENABLED:'true'},db);assert.equal(saved.status,'needs_attention');assert.equal(saved.error,'account_changed_recreate_post');
});
test('publishing switch stops worker before claiming jobs',async()=>{const r=await runQueue({...env,PUBLISH_ENABLED:'false'},{rpc:()=>{throw Error('must not claim');}});assert.equal(r.processed,0);});
test('cancel is owner-scoped and cannot cancel a running job',async()=>{
 const db={user:async()=>({id:uid}),patch:async(t,q)=>{assert(q.includes('user_id=eq.'+uid));assert(q.includes('status=in.(scheduled,processing)'));return [];}};
 await assert.rejects(route(req('/api/jobs/'+uid+'/cancel','POST',{}),env,db),/cannot_cancel/);
});
test('media capability rejects expiry and wrong context before storage access',async()=>{
 const expired=await seal(env,{path:uid+'/'+uid+'.mp4',exp:Date.now()-1000},'media');
 await assert.rejects(route(req('/api/media?ticket='+encodeURIComponent(expired),'GET',undefined,false),env,{}),/media_expired/);
 const wrong=await seal(env,{path:uid+'/'+uid+'.mp4',exp:Date.now()+60000},'other');
 await assert.rejects(route(req('/api/media?ticket='+encodeURIComponent(wrong),'GET',undefined,false),env,{}),/media_expired/);
});
test('upload size limit and caller-supplied paths cannot grant another user a video',async()=>{
 const db={user:async()=>({id:uid}),rows:async()=>[],insert:async(t,b)=>{assert.equal(b.user_id,uid);assert(b.path.startsWith(uid+'/'));},storage:async(p)=>{assert(p.startsWith('object/upload/sign/videos/'+uid+'/'));return {url:'/object/upload/sign/videos/file?token=test'};}};
 await assert.rejects(route(req('/api/uploads','POST',{name:'v.mp4',size:52428801,type:'video/mp4',duration:10}),env,db),/mp4_max_50mb/);
 const result=await route(req('/api/uploads','POST',{name:'v.mp4',size:100,type:'video/mp4',duration:10,path:'victim/video.mp4'}),{...env,SUPABASE_URL:'https://storage.test'},db);assert.equal(result.status,200);
});
test('enqueue refuses another users upload even with a valid UUID',async()=>{
 const db={user:async()=>({id:uid}),rows:async(t,q)=>{assert(q.includes('user_id=eq.'+uid));return [];}};
 await assert.rejects(route(req('/api/posts','POST',{id:uid,upload_id:uid,name:'Video',targets:[{platform:'x',description:'',scheduled_at:new Date(Date.now()+60000).toISOString()}]}),env,db),/upload_not_found/);
});
test('ambiguous provider timeout is quarantined, never marked published or automatically retried',async(t)=>{
 const a={id:uid,user_id:uid,platform:'x',remote_id:'1',connected:true,expires_at:new Date(Date.now()+3600000).toISOString(),tokens:await seal(env,{access_token:'token'},uid+':x')};
 const j={id:uid,lease_id:uid,account_id:uid,post_id:uid,platform:'x',remote_id:'1',scheduled_at:new Date().toISOString(),step:{media_id:'123',offset:100,finalized:true,ready:true},description:'hello'};
 let saved;const db={rpc:async()=>[j],rows:async(t)=>t==='accounts'?[a]:t==='posts'?[{upload_id:uid}]:[{size:100}],patch:async(t,q,b)=>{saved=b;}};
 t.mock.method(globalThis,'fetch',async()=>{throw Error('network lost after POST');});
 await runQueue({...env,PUBLISH_ENABLED:'true'},db);assert.equal(saved.status,'needs_attention');assert.equal(saved.error,'provider_network_ambiguous');
});
test('YouTube upload checkpoint advances by actual acknowledged range',async(t)=>{
 const session=await seal(env,'https://www.googleapis.com/upload/session','youtube:'+uid);
 const j={id:uid,platform:'youtube',step:{session,offset:0}},db={video:async()=>new Response(new Uint8Array(4194304),{status:206})};
 t.mock.method(globalThis,'fetch',async(url,o)=>{assert.equal(o.headers['Content-Range'],'bytes 0-4194303/5000000');return new Response(null,{status:308,headers:{Range:'bytes=0-4194303'}});});
 const result=await publishStep(env,db,j,{}, {path:'path',size:5000000},'token');assert.equal(result.status,'processing');assert.equal(result.step.offset,4194304);
});
