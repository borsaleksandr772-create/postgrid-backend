import {createServer} from 'node:http';
import {Readable} from 'node:stream';
import {handle} from './app.js';
createServer(async(req,res)=>{
 try{
  const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>65536){res.writeHead(413).end();return;}chunks.push(chunk);}
  const body=['GET','HEAD'].includes(req.method)?undefined:Buffer.concat(chunks);
  const r=await handle(new Request('http://localhost:8787'+req.url,{method:req.method,headers:req.headers,body}),process.env);
  res.writeHead(r.status,Object.fromEntries(r.headers));if(r.body)Readable.fromWeb(r.body).pipe(res);else res.end();
 }catch{res.writeHead(500).end('Internal error');}
}).listen(8787,'127.0.0.1',()=>console.log('PostGrid API http://localhost:8787'));
