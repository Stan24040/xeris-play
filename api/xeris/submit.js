const http=require('http');
const NODE_IP=process.env.XERIS_NODE_IP||'138.197.116.81';
module.exports=function(req,res){
  let b='';req.on('data',d=>b+=d);req.on('end',()=>{
    let p;try{p=JSON.parse(b)}catch(e){res.statusCode=400;return res.end(JSON.stringify({error:'Bad JSON'}));}
    const {tx_base64}=p;
    if(!tx_base64){res.statusCode=400;return res.end(JSON.stringify({error:'Missing tx_base64'}));}
    const body=JSON.stringify({tx_base64});
    const opts={hostname:NODE_IP,port:56001,path:'/submit',method:'POST',
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}};
    const nr=http.request(opts,nr2=>{let d='';nr2.on('data',x=>d+=x);nr2.on('end',()=>{
      let j;try{j=JSON.parse(d)}catch(e){res.statusCode=502;return res.end(JSON.stringify({error:'Bad node response'}));}
      if(j.error){res.statusCode=400;return res.end(JSON.stringify({error:j.error}));}
      res.end(JSON.stringify(j));
    })});
    nr.on('error',e=>{res.statusCode=502;res.end(JSON.stringify({error:e.message}))});
    nr.setTimeout(15000,()=>{nr.destroy();res.statusCode=504;res.end(JSON.stringify({error:'timeout'}))});
    nr.write(body);nr.end();
  });
};