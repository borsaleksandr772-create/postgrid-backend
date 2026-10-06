import {handle} from '../src/app.js';
import {Readable} from 'node:stream';
export default async function handler(req,res){
 const body=['GET','HEAD'].includes(req.method)?undefined:(typeof req.body==='string'?req.body:JSON.stringify(req.body));
 const r=await handle(new Request(process.env.PUBLIC_BACKEND_URL+req.url,{method:req.method,headers:req.headers,body}),process.env);
 res.statusCode=r.status;r.headers.forEach((v,k)=>res.setHeader(k,v));
 if(r.body)Readable.fromWeb(r.body).pipe(res);else res.end();
}
