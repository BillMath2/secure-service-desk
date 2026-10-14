import {readFileSync} from 'node:fs';
import {createHash,randomUUID} from 'node:crypto';
import {join} from 'node:path';
const cfg=JSON.parse(readFileSync(join(process.env.APPDATA,'obs-studio/plugin_config/obs-websocket/config.json'),'utf8').replace(/^\uFEFF/,''));
const hash=s=>createHash('sha256').update(s).digest('base64');
const ws=new WebSocket(`ws://127.0.0.1:${cfg.server_port}`);
const request=process.argv[2] || 'GetVersion';
const arg=process.argv[3] || '{}'; const data=JSON.parse(arg.startsWith('@')?readFileSync(arg.slice(1),'utf8'):arg);
const timer=setTimeout(()=>{console.error('OBS request timeout');ws.close();process.exitCode=1},15000);
ws.onmessage=e=>{
 const m=JSON.parse(e.data);
 if(m.op===0){let d={rpcVersion:1,eventSubscriptions:0};if(m.d.authentication)d.authentication=hash(hash(cfg.server_password+m.d.authentication.salt)+m.d.authentication.challenge);ws.send(JSON.stringify({op:1,d}));}
 if(m.op===2)ws.send(JSON.stringify({op:6,d:{requestType:request,requestId:randomUUID(),requestData:data}}));
 if(m.op===7){clearTimeout(timer);console.log(JSON.stringify(m.d));if(!m.d.requestStatus.result)process.exitCode=1;ws.close();}
};
ws.onerror=()=>{clearTimeout(timer);console.error('OBS connection failed');process.exitCode=1;};
