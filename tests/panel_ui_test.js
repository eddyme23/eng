// Execute the actual panel script with a small DOM fixture. No external modules.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const ids = ['login','workspace','logout','protocol','auth','auth-field','action',
  'account-help','name-field','name','days-field','days','password-field','password',
  'run','download','output','message','admin','secret','accounts','status'];
const nodes = Object.fromEntries(ids.map(id=>[id,{value:'',hidden:false,disabled:false,textContent:''}]));
nodes.protocol.value='ssh'; nodes.auth.value='ssh'; nodes.action.value='list'; nodes.days.value='30';
nodes.action.options=['list','create','renew','delete','export','share'].map(value=>({value}));
const calls=[];
const context=vm.createContext({document:{getElementById:id=>nodes[id]}, confirm:()=>true,
  fetch:async(url, options)=>{if(options)calls.push({url,data:JSON.parse(options.body)});return {ok:true,status:200,json:async()=>({csrf:'token',output:'test output'})};},
  URL,Blob,setTimeout,console});
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
  console.log('Panel UI routing and field checks passed.');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
