import { bearer, jsonPost, remote, igBase, canUploadTikTok, accessToken } from './providers.js';
import { seal, unseal, requireValue, Problem } from './security.js';

async function mediaURL(env,upload){
 const ticket=await seal(env,{path:upload.path,exp:Date.now()+24*3600000},'media');
 return env.PUBLIC_BACKEND_URL+'/api/media?ticket='+encodeURIComponent(ticket);
}
const progress=(step,delay=15)=>({status:'processing',step,next_run:new Date(Date.now()+delay*1000).toISOString()});
const done=id=>{requireValue(id,'publication_id_missing',502);return {status:'published',external_id:String(id)};};

// Each invocation does at most one remote mutation. SQL leases prevent simultaneous execution.
export async function publishStep(env,db,j,a,u,token){
 const s=j.step||{},p=j.platform, id=encodeURIComponent(a.remote_id);
 if(p==='instagram'){
   if(!s.container){const v=await remote(igBase(env)+'/'+id+'/media',jsonPost(token,{media_type:'REELS',video_url:await mediaURL(env,u),caption:j.description,share_to_feed:true}));requireValue(v.id,'container_missing',502);return progress({container:v.id});}
   if(!s.ready){const v=await remote(igBase(env)+'/'+encodeURIComponent(s.container)+'?fields=status_code',{headers:bearer(token)});if(['ERROR','EXPIRED'].includes(v.status_code))throw new Problem('instagram_processing_failed');return progress({...s,ready:v.status_code==='FINISHED'},30);}
   const v=await remote(igBase(env)+'/'+id+'/media_publish',jsonPost(token,{creation_id:s.container}));return done(v.id);
 }
 if(p==='tiktok'){
   if(!s.publish_id){
     requireValue(await canUploadTikTok(env,a),'tiktok_reconnect_upload',409);
     const v=await remote('https://open.tiktokapis.com/v2/post/publish/inbox/video/init/',jsonPost(token,{source_info:{source:'PULL_FROM_URL',video_url:await mediaURL(env,u)}}));
     requireValue(v.data?.publish_id,'publish_id_missing',502);return progress({publish_id:v.data.publish_id,delivery:'inbox'},30);
   }
   const v=await remote('https://open.tiktokapis.com/v2/post/publish/status/fetch/',jsonPost(token,{publish_id:s.publish_id}));
   if(v.data?.status==='SEND_TO_USER_INBOX')return {status:'needs_attention',step:s,error:'tiktok_inbox_ready',external_id:s.publish_id};
   if(v.data?.status==='PUBLISH_COMPLETE')return done(v.data.publicaly_available_post_id?.[0]||s.publish_id);
   if(v.data?.status==='FAILED')throw new Problem('tiktok_processing_failed');
   return progress(s,30);
 }
 if(p==='youtube'){
   if(!s.session){
     const r=await fetch('https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status',{
       ...jsonPost(token,{snippet:{title:j.title,description:j.description},status:{privacyStatus:j.options.privacy,selfDeclaredMadeForKids:j.options.madeForKids}}),
       headers:{...bearer(token),'Content-Type':'application/json','X-Upload-Content-Type':'video/mp4','X-Upload-Content-Length':String(u.size)},signal:AbortSignal.timeout(25000)
     });
     const url=r.headers.get('location');requireValue(r.ok&&url,'youtube_session_failed',502);
     requireValue(new URL(url).protocol==='https:'&&new URL(url).hostname==='www.googleapis.com','youtube_session_host',502);
     return progress({session:await seal(env,url,'youtube:'+j.id),offset:0});
   }
   if(!s.video_id){
     const start=s.offset||0,end=Math.min(start+4*1024*1024,u.size)-1;
     const video=await db.video(u.path,`bytes=${start}-${end}`);
     requireValue(video.status===206||start===0&&end===u.size-1,'storage_range_unsupported',502);
     const body=await video.arrayBuffer();requireValue(body.byteLength===end-start+1,'video_size_changed',502);
     const url=await unseal(env,s.session,'youtube:'+j.id);
     const r=await fetch(url,{method:'PUT',headers:{...bearer(token),'Content-Type':'video/mp4','Content-Length':String(body.byteLength),'Content-Range':`bytes ${start}-${end}/${u.size}`},body,signal:AbortSignal.timeout(25000)});
     if(r.status===308){const range=r.headers.get('range');const received=range&&/^bytes=0-(\d+)$/.exec(range);requireValue(received&&Number(received[1])===end,'youtube_upload_range',502);return progress({...s,offset:end+1},1);}
     requireValue(r.ok,'youtube_upload_failed',502);const v=await r.json();requireValue(v.id,'youtube_video_id',502);return progress({...s,video_id:v.id},30);
   }
   const v=await remote('https://www.googleapis.com/youtube/v3/videos?part=status,processingDetails&id='+encodeURIComponent(s.video_id),{headers:bearer(token)});
   const item=v.items?.[0];requireValue(item,'youtube_video_missing',502);
   if(['failed','rejected','deleted'].includes(item.status?.uploadStatus)||['failed','terminated'].includes(item.processingDetails?.processingStatus))throw new Problem('youtube_processing_failed');
   if(item.status?.uploadStatus==='processed'||item.processingDetails?.processingStatus==='succeeded')return done(s.video_id);
   return progress(s,30);
 }
 if(p==='x'){
   if(!s.media_id){const v=await remote('https://api.x.com/2/media/upload/initialize',jsonPost(token,{media_type:'video/mp4',media_category:'tweet_video',total_bytes:u.size}));requireValue(v.data?.id,'x_media_id',502);return progress({media_id:v.data.id,offset:0,segment:0});}
   if(s.offset<u.size){
     const end=Math.min(s.offset+4*1024*1024,u.size)-1,video=await db.video(u.path,`bytes=${s.offset}-${end}`);
     requireValue(video.status===206||s.offset===0&&end===u.size-1,'storage_range_unsupported',502);
     const bytes=await video.arrayBuffer();requireValue(bytes.byteLength===end-s.offset+1,'video_size_changed',502);
     const body=new FormData();body.set('segment_index',String(s.segment));body.set('media',new Blob([bytes],{type:'application/octet-stream'}),'chunk');
     await remote('https://api.x.com/2/media/upload/'+encodeURIComponent(s.media_id)+'/append',{method:'POST',headers:bearer(token),body});
     return progress({...s,offset:end+1,segment:s.segment+1},1);
   }
   if(!s.finalized){await remote('https://api.x.com/2/media/upload/'+encodeURIComponent(s.media_id)+'/finalize',jsonPost(token,{}));return progress({...s,finalized:true});}
   if(!s.ready){const v=await remote('https://api.x.com/2/media/upload?'+new URLSearchParams({media_id:s.media_id,command:'STATUS'}),{headers:bearer(token)});const info=v.data?.processing_info;if(info?.state==='failed')throw new Problem('x_processing_failed');return progress({...s,ready:!info||info.state==='succeeded'},Math.max(5,info?.check_after_secs||15));}
   return done((await remote('https://api.x.com/2/tweets',jsonPost(token,{text:j.description,media:{media_ids:[s.media_id]}}))).data?.id);
 }
 throw new Problem('unsupported_platform');
}
export async function runQueue(env,db){
 if(env.PUBLISH_ENABLED!=='true')return {enabled:false,processed:0};
 const [j]=await db.rpc('claim_job',{});if(!j)return {enabled:true,processed:0};
 let result;
 try{
   const [a]=await db.rows('accounts','id=eq.'+j.account_id);
   requireValue(a?.connected&&a.remote_id===j.remote_id,'account_changed_recreate_post',409);
   const [post]=await db.rows('posts','id=eq.'+j.post_id);const [u]=await db.rows('uploads','id=eq.'+post.upload_id);
   requireValue(Date.now()-Date.parse(j.scheduled_at)<24*3600000,'job_overdue_review',409);
   const token=await accessToken(env,db,a);
   result=await publishStep(env,db,j,a,u,token);
 }catch(e){
   // A timeout/5xx could mean the upstream accepted a write. Do not automatically retry it.
   const code=e instanceof Problem?e.message:'provider_network_ambiguous';
   result={status:code.endsWith('_processing_failed')?'failed':'needs_attention',error:code};
 }
 await db.patch('jobs',`id=eq.${j.id}&lease_id=eq.${j.lease_id}&status=eq.running`,{...result,lease_until:null,error:result.error||null});
 return {enabled:true,processed:1};
}
