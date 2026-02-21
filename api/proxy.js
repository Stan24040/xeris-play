'use strict';
// XERIS.PLAY Proxy — Vercel serverless function
// Forwards HTTPS frontend → HTTP Xeris node (avoids mixed-content)
const NODE_IP='138.197.116.81',RPC_PORT=50008,NET_PORT=56001;
const BASE={rpc:'http://'+NODE_IP+':'+RPC_PORT+'/rpc',api:'http://'+NODE_IP+':'+RPC_PORT,net:'http://'+NODE_IP+':'+NET_PORT};
const SAFE=/^[/a-zA-Z0-9\-_.~%:@!$&'()*+,;=?#[\]]*$/;
function safePath(raw){if(!raw)return '';const d=decodeURIComponent(raw);if(d.includes('..')||d.includes('//'))return null;if(!SAFE.test(d))return null;return d;}
module.exports=async function(req,res){
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  res.setHeader('X-Content-Type-Options','nosniff');
  if(req.method==='OPTIONS')return res.status(204).end();
  if(!['GET','POST'].includes(req.method))return res.status(405).json({error:'Method not allowed'});
  const target=((req.query.target)||'rpc').toLowerCase();
  const base=BASE[target];
  if(!base)return res.status(400).json({error:'Unknown target'});
  let url=base;
  if(target!=='rpc'&&req.query.path){const p=safePath(req.query.path);if(p===null)return res.status(400).json({error:'Invalid path'});url=base+p;}
  let body;
  if(req.method==='POST'){
    body=await new Promise((res,rej)=>{const c=[];req.on('data',d=>c.push(Buffer.isBuffer(d)?d:Buffer.from(d)));req.on('end',()=>res(Buffer.concat(c).toString('utf8')));req.on('error',rej);});
    if(Buffer.byteLength(body,'utf8')>524288)return res.status(413).json({error:'Body too large'});
  }
  const ctl=new AbortController();const t=setTimeout(()=>ctl.abort(),12000);
  try{
    const up=await fetch(url,{method:req.method,headers:{'Content-Type':'application/json'},body:body??undefined,signal:ctl.signal});
    const ct=up.headers.get('content-type')||'application/json';
    const txt=await up.text();
    res.setHeader('Content-Type',ct);res.setHeader('Cache-Control','no-store');
    return res.status(up.status).send(txt);
  }catch(e){
    return res.status(502).json({error:e.name==='AbortError'?'Node timed out':'Proxy: '+e.message});
  }finally{clearTimeout(t);}
};
