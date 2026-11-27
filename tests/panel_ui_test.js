// Execute the actual panel script with a small DOM fixture. No external modules.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const ids = ['login','workspace','logout','protocol','auth','auth-field','action',
  'account-help','name-field','name','days-field','days','password-field','password',
  'run','download','copy','clear','output','message','admin','secret','accounts','status',
  'server','target-name','refresh-servers','revoke-server','pairing','pair-server','server-name','otp','otp-field','central-controls','scope-label','page-title','page-description'];
const nodes = Object.fromEntries(ids.map(id=>[id,{value:'',hidden:false,disabled:false,textContent:''}]));
nodes.protocol.value='ssh'; nodes.auth.value='ssh'; nodes.action.value='list'; nodes.days.value='30';
nodes.server.value='local';nodes.server.options=[{value:'local',textContent:'This VPS'}];
nodes.server.replaceChildren=(...options)=>{nodes.server.options=options;};
nodes.action.options=['list','create','renew','delete','export','share'].map(value=>({value}));
const calls=[]; let clipboard='';
const context=vm.createContext({document:{getElementById:id=>nodes[id]}, confirm:()=>true,
  fetch:async(url, options)=>{if(options && options.body)calls.push({url,data:JSON.parse(options.body)});return {ok:true,status:200,json:async()=>({csrf:'token',output:'test output'})};},
  URL,Blob,setTimeout,console,Option:class{constructor(text,value){this.textContent=text;this.value=value;}},navigator:{clipboard:{writeText:async text=>{clipboard=text;}}}});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../panel.js'),'utf8'),context);
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function main(){
  await tick();
  assert.equal(nodes['auth-field'].hidden,false);
  assert.equal(nodes['password-field'].hidden,true);
  assert.equal(nodes.action.options.find(x=>x.value==='share').disabled,true);
  nodes.action.value='create';nodes.action.onchange();
  assert.equal(nodes.password.required,true);
  nodes.name.value='alice';nodes.password.value='password123';
  nodes.accounts.onsubmit({preventDefault(){}});await tick();
  assert.equal(calls.at(-1).data.protocol,'ssh');
  assert.equal(calls.at(-1).data.password,'password123');
  assert.equal(nodes.copy.disabled,false);
  await nodes.copy.onclick();
  assert.equal(clipboard,'test output');
  nodes.clear.onclick();
  assert.equal(nodes.output.textContent,'');
  assert.equal(nodes.copy.disabled,true);
  assert.equal(nodes.download.disabled,true);
  nodes.password.value='do-not-reuse';nodes.auth.value='certificate';nodes.auth.onchange();
  assert.equal(nodes.password.value,'');
  assert.equal(nodes.password.disabled,true);
  assert.equal(nodes.output.textContent,'');
  assert.equal(nodes.action.options.find(x=>x.value==='share').disabled,false);
  nodes.accounts.onsubmit({preventDefault(){}});await tick();
  assert.equal(calls.at(-1).data.protocol,'certificate');
  assert.equal(calls.at(-1).data.password,'');
  nodes.action.value='export';nodes.action.onchange();
  nodes.accounts.onsubmit({preventDefault(){}});await tick();
  assert.equal(calls.at(-1).data.protocol,'certificate');
  assert.equal(calls.at(-1).data.action,'export');
  nodes.auth.value='ssh';nodes.auth.onchange();
  assert.equal(nodes.action.value,'list');
  assert.equal(nodes.name.required,false);
  nodes.protocol.value='openvpn';nodes.protocol.onchange();
  assert.equal(nodes['auth-field'].hidden,true);
  nodes.action.value='create';nodes.action.onchange();nodes.password.value='openvpnpass';
  nodes.accounts.onsubmit({preventDefault(){}});await tick();
  assert.equal(calls.at(-1).data.protocol,'openvpn');
  assert.equal(calls.at(-1).data.password,'openvpnpass');
  const remote='b'.repeat(32);let registered=true;
  vm.runInContext("centralMode=true;centralUrl='https://panel.example:8445'",context);
  context.fetch=async(url,options)=>{
    if(options && options.body)calls.push({url,data:JSON.parse(options.body)});
    if(url==='/api/revoke-server')registered=false;
    const result=url==='/api/servers'?{servers:[{id:'local',label:'France',local:true,ready:true},...(registered?[{id:remote,label:'USA',ready:true}]:[])]}:
      url==='/api/pairing-code'?{label:'Germany',code:'one-use-code'}:{ok:true,output:'REMOTE RESULT'};
    return {ok:true,status:200,json:async()=>result};
  };
  await context.refreshServers();
  nodes.server.value=remote;nodes.server.onchange();
  assert.match(nodes['target-name'].textContent,/USA/);
  nodes.password.value='remote-password';
  nodes.accounts.onsubmit({preventDefault(){}});await tick();
  assert.equal(calls.at(-1).data.server,remote);
  assert.equal(calls.at(-1).data.protocol,'openvpn');
  nodes['server-name'].value='Germany';
  await nodes.pairing.onsubmit({preventDefault(){}});
  assert.equal(calls.at(-1).url,'/api/pairing-code');
  assert.match(nodes.output.textContent,/one-use-code/);
  await nodes['revoke-server'].onclick();
  assert.equal(calls.at(-1).url,'/api/revoke-server');
  assert.equal(calls.at(-1).data.server,remote);
  assert.equal(nodes.server.value,'');
  const before=calls.length;
  await context.operate({action:'status'});
  assert.equal(calls.length,before); // Removed selection must never fall back to A.
  nodes.server.value='local';nodes.server.onchange();
  let finishRequest;
  context.fetch=async(url)=>{
    if(url==='/api/action')return new Promise(resolve=>{finishRequest=()=>resolve({ok:true,status:200,json:async()=>({output:'private result'})});});
    return {ok:true,status:200,json:async()=>({})};
  };
  const pending=context.operate({action:'status'});
  await tick();
  assert.equal(nodes.protocol.disabled,true);
  await nodes.logout.onclick();
  finishRequest(); await pending;
  assert.equal(nodes.output.textContent,'');
  assert.equal(nodes.copy.disabled,true);
  assert.equal(nodes.workspace.hidden,true);
  console.log('Panel UI routing and field checks passed.');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
