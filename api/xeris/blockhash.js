const http=require('http');
const NODE_IP=process.env.XERIS_NODE_IP||'138.197.116.81';
module.exports=async function(req,res){
  const body=JSON.stringify({jsonrpc:'2.0',id:1,method:'getRecentBlockhash',params:[]});
  const opts={hostname:NODE_IP,port:50008,path:'/',method:'POST',
    headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}};
  http.request(opts,r=>{let d='';r.on('data',x=>d+=x);r.on('end',()=>{
    try{const j=JSON.parse(d);const bh=j?.result?.value?.blockhash;
    if(bh) return res.end(JSON.stringify({blockhash:bh,format:'hex'}));
    }catch(e){}
    res.statusCode=500;res.end(JSON.stringify({error:'blockhash failed'}));
  })}).on('error',e=>{res.statusCode=502;res.end(JSON.stringify({error:e.message}))})
  .end(body);
};