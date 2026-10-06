import {database} from './db.js';
import {random,hash,seal,unseal,Problem,requireValue,uuid,validateTargets} from './security.js';
import {platforms,provider,authorizeURL,exchange,revoke,accessToken,creatorInfo,validateTikTok} from './providers.js';
import {runQueue} from './publish.js';
const response=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json; charset=utf-8'}});
async function body(req){requireValue((req.headers.get('content-type')||'').startsWith('application/json'),'json_required',415);const s=await req.text();requireValue(s.length<=65536,'body_too_large',413);try{return JSON.parse(s);}catch{throw new Problem('invalid_json');}}
const redirect=url=>new Response(null,{status:303,headers:{Location:url}});

export async function route(req,env,db=database(env)){
 const url=new URL(req.url),path=url.pathname,method=req.method;
 if(path==='/api/health'&&method==='GET')return response({service:'PostGrid',version:2,publishing:env.PUBLISH_ENABLED==='true'});
 if(path==='/api/cron'&&['GET','POST'].includes(method)){
   requireValue(env.CRON_SECRET&&req.headers.get('authorization')==='Bearer '+env.CRON_SECRET,'unauthorized',401);
   return response(await runQueue(env,db));
 }
 if(path==='/api/media'&&['GET','HEAD'].includes(method)){
   let ticket;try{ticket=await unseal(env,url.searchParams.get('ticket')||'','media');}catch{throw new Problem('media_expired',403);}
   requireValue(ticket.exp>Date.now()&&/^[0-9a-f-]+\/[0-9a-f-]+\.mp4$/.test(ticket.path),'media_expired',403);
   const range=req.headers.get('range');requireValue(!range||/^bytes=\d+-\d*$/.test(range),'invalid_range',416);
   const r=await db.video(ticket.path,range),headers=new Headers({'Content-Type':'video/mp4','Cache-Control':'private, no-store'});
   for(const h of ['content-length','content-range','accept-ranges'])if(r.headers.get(h))headers.set(h,r.headers.get(h));
   if(method==='HEAD')await r.body?.cancel();
   return new Response(method==='HEAD'?null:r.body,{status:r.status,headers});
 }
 const callback=/^\/api\/oauth\/(instagram|tiktok|youtube|x)\/callback$/.exec(path);
 if(callback&&method==='GET'){
   const p=callback[1],state=url.searchParams.get('state')||'';
   requireValue(/^[\w-]{43}$/.test(state),'oauth_state_invalid');
   const stateHash=await hash(state);
   const flows=await db.patch('oauth_flows',`state_hash=eq.${stateHash}&platform=eq.${p}&status=eq.pending&expires_at=gt.${new Date().toISOString()}`,{status:'exchanging'});
   requireValue(flows.length===1,'oauth_state_expired_or_used');
   const flow=flows[0];
   if(url.searchParams.has('error')){await db.remove('oauth_flows','state_hash=eq.'+stateHash);return redirect(env.FRONTEND_URL+'#oauth_error=access_denied');}
   try{
     const code=url.searchParams.get('code');requireValue(code&&code.length<=4096,'oauth_code_missing');
     const verifier=await unseal(env,flow.verifier,'flow:'+stateHash);
     const result=await exchange(env,p,code,verifier);
     await db.patch('oauth_flows','state_hash=eq.'+stateHash,{status:'ready',result:await seal(env,result.tokens,flow.user_id+':'+p),remote_id:result.remote_id,display_name:result.display_name,token_expiry:result.tokens.expires_at,verifier:''});
     return redirect(env.FRONTEND_URL+'#oauth='+encodeURIComponent(state));
   }catch{await db.remove('oauth_flows','state_hash=eq.'+stateHash);return redirect(env.FRONTEND_URL+'#oauth_error=exchange_failed');}
 }
 const token=req.headers.get('authorization')?.replace(/^Bearer /,'');requireValue(token,'login_required',401);
 const user=await db.user(token);requireValue(uuid(user.id),'invalid_user',401);
 if(path==='/api/accounts'&&method==='GET'){
   const rows=await db.rows('accounts',`user_id=eq.${user.id}&select=id,platform,remote_id,display_name,expires_at,connected`);
   return response({accounts:platforms.map(p=>({...rows.find(a=>a.platform===p),platform:p,configured:!!(provider(env,p).id&&provider(env,p).secret)})),publishing:env.PUBLISH_ENABLED==='true'});
 }
 const start=/^\/api\/oauth\/(instagram|tiktok|youtube|x)\/start$/.exec(path);
 if(start&&method==='POST'){
   const b=await body(req);requireValue(/^[\w-]{43}$/.test(b.proof_hash),'proof_required');
   const state=random(),stateHash=await hash(state),verifier=random();
   const target=authorizeURL(env,start[1],state,await hash(verifier));
   // Bound storage growth for a signed-in user.
   const old=await db.rows('oauth_flows',`user_id=eq.${user.id}&expires_at=gt.${new Date().toISOString()}&select=state_hash`);requireValue(old.length<8,'too_many_oauth_attempts',429);
   await db.insert('oauth_flows',{state_hash:stateHash,user_id:user.id,platform:start[1],proof_hash:b.proof_hash,verifier:await seal(env,verifier,'flow:'+stateHash)});
   return response({url:target,state});
 }
 if(path==='/api/oauth/complete'&&method==='POST'){
   const b=await body(req);requireValue(/^[\w-]{43}$/.test(b.state)&&/^[\w-]{43}$/.test(b.proof),'proof_required');
   const ok=await db.rpc('complete_oauth',{p_state:await hash(b.state),p_proof:await hash(b.proof),p_user:user.id});
   requireValue(ok,'oauth_expired_wrong_browser_or_account_busy',409);return response({connected:true});
 }
 const disconnect=/^\/api\/accounts\/(instagram|tiktok|youtube|x)$/.exec(path);
 if(disconnect&&method==='DELETE'){
   const [a]=await db.rows('accounts',`user_id=eq.${user.id}&platform=eq.${disconnect[1]}`);
   if(!a?.connected)return response({disconnected:true});
   const tokens=await unseal(env,a.tokens,a.user_id+':'+a.platform);
   const ok=await db.rpc('disconnect_account',{p_user:user.id,p_platform:a.platform});requireValue(ok,'publication_in_progress_try_later',409);
   let revoked=true;try{await revoke(env,a.platform,tokens,a.remote_id);}catch{revoked=false;}finally{await db.patch('accounts','id=eq.'+a.id,{token_lock_until:'1970-01-01T00:00:00Z'});}
   return response({disconnected:true,revoked});
 }
 if(path==='/api/tiktok/creator'&&method==='GET'){
   const [a]=await db.rows('accounts',`user_id=eq.${user.id}&platform=eq.tiktok`);return response(await creatorInfo(await accessToken(env,db,a)));
 }
 if(path==='/api/uploads'&&method==='POST'){
   const b=await body(req);requireValue(b.type==='video/mp4'&&Number.isInteger(b.size)&&b.size>0&&b.size<=52428800,'mp4_max_50mb');
   requireValue(typeof b.name==='string'&&b.name.length<=200&&Number.isFinite(b.duration)&&b.duration>0,'video_metadata');
   const recent=await db.rows('uploads',`user_id=eq.${user.id}&created_at=gt.${new Date(Date.now()-86400000).toISOString()}&select=id`);requireValue(recent.length<30,'daily_upload_limit',429);
   const id=crypto.randomUUID(),path=user.id+'/'+id+'.mp4';
   await db.insert('uploads',{id,user_id:user.id,path,name:b.name,size:b.size,duration:b.duration});
   const signed=await db.storage('object/upload/sign/videos/'+path,{});
   requireValue(signed.url,'upload_url_missing',502);
   return response({id,url:env.SUPABASE_URL+'/storage/v1'+signed.url});
 }
 if(path==='/api/posts'&&method==='POST'){
   const b=await body(req);requireValue(uuid(b.id)&&uuid(b.upload_id),'invalid_id');
   requireValue(typeof b.name==='string'&&b.name.length>0&&b.name.length<=200,'post_name');
   const existing=await db.rows('posts',`id=eq.${b.id}&user_id=eq.${user.id}&select=id`);if(existing.length)return response({id:b.id});
   validateTargets(b.targets);
   const [u]=await db.rows('uploads',`id=eq.${b.upload_id}&user_id=eq.${user.id}`);requireValue(u,'upload_not_found',404);
   // Check bytes exist and match declared size; do not accept arbitrary external video URLs.
   const video=await db.video(u.path,'bytes=0-31');
   const total=Number(video.headers.get('content-range')?.split('/')[1]||video.headers.get('content-length'));
   const head=new Uint8Array(await video.arrayBuffer());
   requireValue(total===u.size&&new TextDecoder().decode(head.slice(4,8))==='ftyp','invalid_mp4_or_upload_incomplete');
   for(const t of b.targets)if(t.platform==='tiktok'){
     const [a]=await db.rows('accounts',`user_id=eq.${user.id}&platform=eq.tiktok`);validateTikTok(t,await creatorInfo(await accessToken(env,db,a)),u.duration);
   }
   const id=await db.rpc('enqueue_post',{p_id:b.id,p_user:user.id,p_upload:b.upload_id,p_name:b.name,p_targets:b.targets});
   return response({id},201);
 }
 if(path==='/api/jobs'&&method==='GET')return response({jobs:await db.rows('jobs',`user_id=eq.${user.id}&select=id,post_id,platform,scheduled_at,description,title,options,status,external_id,error,posts(name)&order=scheduled_at.asc&limit=500`)});
 const jobAction=/^\/api\/jobs\/([\w-]+)\/(edit|preview)$/.exec(path);
 if(jobAction&&method==='POST'){
   const id=jobAction[1];requireValue(uuid(id),'invalid_id');
   const [job]=await db.rows('jobs',`id=eq.${id}&user_id=eq.${user.id}`);requireValue(job,'job_not_found',404);
   const [post]=await db.rows('posts',`id=eq.${job.post_id}&user_id=eq.${user.id}`);requireValue(post,'post_not_found',404);
   const [upload]=await db.rows('uploads',`id=eq.${post.upload_id}&user_id=eq.${user.id}`);requireValue(upload,'upload_not_found',404);
   if(jobAction[2]==='preview'){
     const signed=await db.storage('object/sign/videos/'+upload.path,{expiresIn:900});
     requireValue(typeof signed.signedURL==='string'&&signed.signedURL.startsWith('/object/sign/'),'preview_unavailable',502);
     return response({url:env.SUPABASE_URL+'/storage/v1'+signed.signedURL,expires_at:Date.now()+900000});
   }
   requireValue(job.status==='scheduled','job_already_started',409);
   const b=await body(req),target={platform:job.platform,scheduled_at:b.scheduled_at,description:b.description,title:b.title??job.title,options:job.options};
   if(job.platform==='youtube')target.options={...job.options,privacy:b.privacy??job.options.privacy};
   validateTargets([target]);
   if(job.platform==='tiktok'){
     requireValue(b.consent===true,'tiktok_consent_privacy');
     const [a]=await db.rows('accounts',`id=eq.${job.account_id}&user_id=eq.${user.id}`);
     validateTikTok(target,await creatorInfo(await accessToken(env,db,a)),upload.duration);
   }
   // The status condition is checked atomically by PostgreSQL, including after a worker row lock.
   const saved=await db.patch('jobs',`id=eq.${id}&user_id=eq.${user.id}&status=eq.scheduled`,{scheduled_at:target.scheduled_at,next_run:target.scheduled_at,description:target.description,title:target.title,options:target.options});
   requireValue(saved.length===1,'job_already_started',409);return response({saved:true});
 }
 const cancel=/^\/api\/jobs\/([\w-]+)\/cancel$/.exec(path);
 if(cancel&&method==='POST'){
   requireValue(uuid(cancel[1]),'invalid_id');const rows=await db.patch('jobs',`id=eq.${cancel[1]}&user_id=eq.${user.id}&status=in.(scheduled,processing)`,{status:'cancelled'});
   requireValue(rows.length,'cannot_cancel_running_or_finished',409);return response({cancelled:true});
 }
 throw new Problem('not_found',404);
}
export async function handle(req,env){
 let r;const origin=req.headers.get('origin'),allowed=new URL(env.FRONTEND_URL).origin;
 try{
   requireValue(!origin||origin===allowed,'origin_denied',403);
   if(req.method==='OPTIONS')r=new Response(null,{status:204});else r=await route(req,env);
 }catch(e){r=response({error:e instanceof Problem?e.message:'internal_error'},e instanceof Problem?e.status:500);}
 const headers=new Headers(r.headers);
 headers.set('Cache-Control','no-store');headers.set('X-Content-Type-Options','nosniff');headers.set('Referrer-Policy','no-referrer');
 if(origin===allowed){headers.set('Access-Control-Allow-Origin',allowed);headers.set('Vary','Origin');headers.set('Access-Control-Allow-Headers','Authorization, Content-Type');headers.set('Access-Control-Allow-Methods','GET, POST, DELETE, OPTIONS');}
 return new Response(r.body,{status:r.status,headers});
}
