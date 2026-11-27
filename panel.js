'use strict';
const byId = id => document.getElementById(id);
let csrf = '', lastOutput = '', busy = false, viewEpoch = 0;
let centralMode = false, centralUrl = '';
function selectedServer() { return byId('server').value; }
function targetName() {
  const option = [...byId('server').options].find(item => item.value === selectedServer());
  return option ? option.textContent : 'Choose a server';
}
function updateTarget() {
  byId('target-name').textContent = targetName();
  byId('revoke-server').disabled = !centralMode || !selectedServer() || selectedServer() === 'local';
}
async function refreshServers() {
  if (!centralMode) return;
  const result = await request('/api/servers');
  const previous = selectedServer();
  byId('server').replaceChildren(...result.servers.map(server =>
    new Option(server.label + (server.local ? ' · this VPS' : server.ready ? ' · ready' : server.online ? ' · busy / reconnecting' : ' · offline'), server.id)));
  byId('server').value = result.servers.some(server => server.id === previous) ? previous : '';
  updateTarget();
}
byId('server').onchange = () => { changeAccountSystem(); updateTarget(); };
byId('refresh-servers').onclick = () => refreshServers().catch(error => {byId('message').textContent=error.message;});
byId('pairing').onsubmit = async event => {
  event.preventDefault();
  if (busy) return;
  const epoch=viewEpoch;
  byId('pair-server').disabled = true;
  try {
    const result = await request('/api/pairing-code', {label:byId('server-name').value.trim()});
    if (epoch !== viewEpoch) return;
    clearOutput();
    lastOutput = 'Server: '+result.label+'\nCentral URL: '+centralUrl+'\nSingle-use pairing code: '+result.code+
      '\nExpires in 15 minutes. Keep this code private.\n\nOn the target ENG VPS run:\nbash ./panel-agent-install.sh --central '+centralUrl+'\nThen enter this pairing code when prompted.';
    byId('output').textContent=lastOutput;
    for(const id of ['download','copy','clear'])byId(id).disabled=false;
    byId('message').textContent='Pairing code created. Refresh servers after the VPS has joined.';
  } catch(error) {if(epoch===viewEpoch)byId('message').textContent=error.message;}
  finally {byId('pair-server').disabled=false;}
};
byId('revoke-server').onclick = async () => {
  if(busy || selectedServer()==='local' || !selectedServer())return;
  if(!confirm('Remove central management access for '+targetName()+'? Its VPN accounts will remain running. Already delivered operations cannot be cancelled.'))return;
  try {
    const result=await request('/api/revoke-server',{server:selectedServer()});
    changeAccountSystem(); await refreshServers(); byId('message').textContent=result.output;
  } catch(error) {byId('message').textContent=error.message;}
};
function clearOutput() {
  lastOutput = ''; byId('output').textContent = '';
  for (const id of ['download','copy','clear']) byId(id).disabled = true;
}
function selectedProtocol() {
  return byId('protocol').value === 'ssh' ? byId('auth').value : byId('protocol').value;
}
function updateFields() {
  const group = byId('protocol').value === 'ssh', protocol = selectedProtocol();
  byId('auth-field').hidden = !group;
  for (const option of byId('action').options) {
    option.hidden = option.disabled = (option.value === 'share' && protocol !== 'certificate') ||
      (option.value === 'export' && protocol === 'ssh');
  }
  if ([...byId('action').options].some(option => option.value === byId('action').value && option.disabled)) byId('action').value = 'list';
  const action = byId('action').value, validity = action === 'create' || action === 'renew';
  const needsPassword = action === 'create' && (protocol === 'ssh' || protocol === 'openvpn');
  byId('name-field').hidden = action === 'list'; byId('name').required = action !== 'list';
  byId('days-field').hidden = !validity; byId('days').disabled = !validity;
  byId('password-field').hidden = !needsPassword; byId('password').disabled = !needsPassword;
  byId('password').required = needsPassword;
  if (!needsPassword) byId('password').value = '';
  byId('account-help').textContent = group ? (protocol === 'certificate'
    ? 'App certificates authenticate SSH, WebSocket, SSL/TLS, BHTTP, HCR and SlowDNS/DNSTT through OpenSSH. Export the private bundle for Gen. SocksIP and UDP Custom use password authentication; the bundle may include separate UDP Custom credentials.'
    : 'One password account serves SSH, WebSocket, SSL/TLS, BHTTP, HCR, SlowDNS/DNSTT, SocksIP and UDP Custom. Certificate accounts are managed separately using the authentication selector.')
    : 'This section uses its existing ENG account manager.';
}
function changeAccountSystem() {
  byId('password').value = ''; viewEpoch++; clearOutput();
  updateFields();
}
byId('protocol').onchange = changeAccountSystem;
byId('auth').onchange = changeAccountSystem;
byId('action').onchange = updateFields;
function signedIn(value) {
  byId('login').hidden = value; byId('workspace').hidden = !value; byId('logout').hidden = !value;
  if (!value) { viewEpoch++; clearOutput(); }
  else if (byId('message').textContent === 'Sign in to begin.') byId('message').textContent = 'Ready. Choose an account operation or check service status.';
}
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
  try { const result = await request('/api/login',{username:byId('admin').value,password:byId('secret').value,otp:byId('otp').value}); csrf=result.csrf; signedIn(true); await refreshServers(); byId('message').textContent='Signed in. Sessions expire after 30 minutes.'; }
  catch (error) { byId('message').textContent=error.message; }
  finally { byId('secret').value=''; byId('otp').value=''; }
};
async function operate(data) {
  if (busy) return;
  if (!selectedServer()) {byId('message').textContent='Choose the target VPS first.';return;}
  busy=true; const epoch=viewEpoch;
  const target=selectedServer(), label=targetName();
  for (const id of ['run','protocol','auth','action','status','server','refresh-servers','pair-server','revoke-server']) byId(id).disabled=true;
  byId('message').textContent='Working on '+label+'…'; clearOutput();
  try {
    const result=await request('/api/action',{...data,server:target});
    if (epoch !== viewEpoch) return;
    lastOutput=result.output; byId('output').textContent=lastOutput;
    for (const id of ['download','copy','clear']) byId(id).disabled=!lastOutput;
    byId('message').textContent='Completed on '+label+'.';
  }
  catch (error) { if (epoch === viewEpoch) byId('message').textContent=error.message; }
  finally {
    busy=false;
    for (const id of ['run','protocol','auth','action','status','server','refresh-servers','pair-server']) byId(id).disabled=false;
    updateTarget();
    byId('password').value='';
  }
}
byId('accounts').onsubmit = event => {
  event.preventDefault();
  const data={protocol:selectedProtocol(),action:byId('action').value,name:byId('name').value,days:Number(byId('days').value),password:byId('password').disabled ? '' : byId('password').value};
  if (data.action !== 'list' && !data.name) { byId('message').textContent='Enter an account name.'; return; }
  if (data.action==='delete' && !confirm('Delete '+data.name+' from '+data.protocol+' on '+targetName()+'? Certificate deletion removes all its identities on that VPS.')) return;
  if (data.action==='export' && !confirm('Display private account credentials from '+targetName()+' on this screen?')) return;
  operate(data);
};
byId('status').onclick=()=>operate({action:'status'});
byId('logout').onclick=async()=>{ try{await request('/api/logout',{});}finally{csrf='';signedIn(false);byId('message').textContent='Signed out.';} };
byId('copy').onclick=async()=>{
  if (!lastOutput) return;
  try { await navigator.clipboard.writeText(lastOutput); byId('message').textContent='Copied to clipboard.'; }
  catch { byId('message').textContent='Clipboard access unavailable. Select the result to copy it manually.'; }
};
byId('clear').onclick=()=>{clearOutput();byId('message').textContent='Result cleared.';};
byId('download').onclick=()=>{const url=URL.createObjectURL(new Blob([lastOutput],{type:'text/plain'}));const a=document.createElement('a');a.href=url;a.download='eng-account-export.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
updateFields();
updateTarget();
request('/api/info').then(info=>{
  centralMode=Boolean(info.central);centralUrl=info.origin || '';
  if(centralMode){byId('scope-label').textContent='YOUR SERVER WORKSPACE';byId('page-title').textContent='Your servers, organized.';byId('page-description').textContent='Manage accounts across your connected VPS servers.';}
  byId('central-controls').hidden=!centralMode;
  byId('otp-field').hidden=!info.otpRequired;
  byId('otp').disabled=!info.otpRequired;byId('otp').required=Boolean(info.otpRequired);
  return request('/api/session');
}).then(async result=>{csrf=result.csrf;signedIn(true);await refreshServers();}).catch(()=>signedIn(false));
