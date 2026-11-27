'use strict';
const byId = id => document.getElementById(id);
let csrf = '', lastOutput = '', busy = false;
function signedIn(value) { byId('login').hidden = value; byId('workspace').hidden = !value; byId('logout').hidden = !value; }
async function request(path, data) {
  const options = data === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(data)};
  const response = await fetch(path, options);
  const result = await response.json();
  if (response.status === 401 && path !== '/api/login') { signedIn(false); csrf=''; }
  if (!response.ok) throw new Error(result.error || result.output || 'Operation failed');
  return result;
}
byId('login').onsubmit = async event => {
  event.preventDefault();
  try { const result = await request('/api/login',{username:byId('admin').value,password:byId('secret').value}); csrf=result.csrf; signedIn(true); byId('message').textContent='Signed in. Sessions expire after 30 minutes.'; }
  catch (error) { byId('message').textContent=error.message; }
  finally { byId('secret').value=''; }
};
async function operate(data) {
  if (busy) return;
  busy=true; byId('run').disabled=true; byId('message').textContent='Working…';
  lastOutput=''; byId('output').textContent=''; byId('download').disabled=true;
  try { const result=await request('/api/action',data); lastOutput=result.output; byId('output').textContent=lastOutput; byId('download').disabled=false; byId('message').textContent='Completed.'; }
  catch (error) { byId('message').textContent=error.message; }
  finally { busy=false; byId('run').disabled=false; byId('password').value=''; }
}
byId('accounts').onsubmit = event => {
  event.preventDefault();
  const data={protocol:byId('protocol').value,action:byId('action').value,name:byId('name').value,days:Number(byId('days').value),password:byId('password').value};
  if (data.action !== 'list' && !data.name) { byId('message').textContent='Enter an account name.'; return; }
  if (data.action==='delete' && !confirm('Delete '+data.name+' from '+data.protocol+' on this VPS? Certificate deletion removes all its local identities.')) return;
  if (data.action==='export' && !confirm('Display private account credentials on this screen?')) return;
  operate(data);
};
byId('status').onclick=()=>operate({action:'status'});
byId('logout').onclick=async()=>{ try{await request('/api/logout',{});}finally{csrf='';lastOutput='';byId('output').textContent='';byId('download').disabled=true;signedIn(false);} };
byId('download').onclick=()=>{const url=URL.createObjectURL(new Blob([lastOutput],{type:'text/plain'}));const a=document.createElement('a');a.href=url;a.download='eng-account-export.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
request('/api/session').then(result=>{csrf=result.csrf;signedIn(true);}).catch(()=>signedIn(false));
