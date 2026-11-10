"""Minimal first-party standalone customer portal shell."""
CUSTOMER_PORTAL_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JAS-SI Customer Portal</title>
<style>
:root{font-family:system-ui,sans-serif;color:#172033;background:#f5f7fb}
body{margin:0;padding:24px}.wrap{max-width:760px;margin:5vh auto;background:white;border:1px solid #e2e7f0;border-radius:18px;padding:28px;box-shadow:0 12px 40px #17203310}
h1{margin-top:0}.muted{color:#596579}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px}
section{border:1px solid #e2e7f0;border-radius:12px;padding:18px}label{display:block;margin:12px 0 5px}input{box-sizing:border-box;width:100%;padding:11px;border:1px solid #cbd3e1;border-radius:8px}
button{margin-top:14px;padding:11px 16px;border:0;border-radius:8px;background:#182b4a;color:white;font-weight:600;cursor:pointer}
button.secondary{background:#e8edf5;color:#182b4a}#notice{padding:12px;border-radius:8px;background:#eef3fa;min-height:22px}
[hidden]{display:none!important}
</style>
</head>
<body><main class="wrap">
<h1>JAS-SI Customer Portal</h1>
<p class="muted">Create your account or sign in using a secure, one-time email link.</p>
<p id="notice" role="status" aria-live="polite">Checking your account session…</p>
<div class="grid" id="auth">
<section><h2>Create account</h2>
<form id="register">
<label for="reg-email">Work email</label><input id="reg-email" type="email" maxlength="254" autocomplete="email" required>
<label for="reg-org">Organization</label><input id="reg-org" maxlength="160" autocomplete="organization" required>
<button type="submit">Send verification link</button>
</form></section>
<section><h2>Sign in</h2>
<form id="login"><label for="login-email">Email</label><input id="login-email" type="email" maxlength="254" autocomplete="email" required>
<button type="submit">Email me a sign-in link</button></form></section>
</div>
<section id="account" hidden><h2>Account</h2><p><strong id="account-email"></strong></p><p id="account-org" class="muted"></p>
<p>Account session is active. Create and manage your tenant-scoped API keys below.</p>
<button id="logout" class="secondary">Sign out</button>
<hr><h3>Plans</h3>
<div id="plan-list"></div>
<p id="plan-note" class="muted">Paid plans and manual checkout are not enabled yet. No payment number or price is displayed until verified and approved.</p>
<hr><h3>Usage</h3>
<p id="usage-summary" class="muted">Loading technical usage…</p>
<ul id="usage-operations"></ul>
<hr><h3>API keys</h3>
<form id="create-key">
<label for="key-name">Key name</label><input id="key-name" maxlength="120" required>
<label for="key-scope">Permission</label>
<select id="key-scope"><option value="authorization:check">Authorization check</option><option value="outcomes:submit">Submit outcomes</option><option value="github:evidence:verify">Verify GitHub evidence</option><option value="usage:read">Read usage</option></select>
<label for="key-expiry">Expires in days</label><input id="key-expiry" type="number" min="1" max="365" value="90" required>
<button type="submit">Create API key</button>
</form>
<p id="new-key" role="status" aria-live="polite"></p>
<ul id="key-list"></ul>
</section>
</main>
<script>
const notice=document.getElementById('notice');
const auth=document.getElementById('auth');
const account=document.getElementById('account');
async function request(path,body){
 const headers={'Content-Type':'application/json'};
 if(path.endsWith('/logout')||path.includes('/customer/api-keys')){
  const csrf=document.cookie.split('; ').find(item=>item.startsWith('jassi_customer_csrf='));
  if(csrf)headers['X-JAS-SI-CSRF']=decodeURIComponent(csrf.split('=').slice(1).join('='));
 }
 const response=await fetch(path,{method:'POST',headers,body:JSON.stringify(body),credentials:'same-origin'});
 let data={};try{data=await response.json()}catch(_){}
 if(!response.ok)throw new Error(data.detail||'Request could not be completed');
 return data;
}
function showAccount(data){
 document.getElementById('account-email').textContent=data.email;
 document.getElementById('account-org').textContent=data.organization_name;
 auth.hidden=true;account.hidden=false;
 notice.textContent='You are signed in to JAS-SI.';
 loadApiKeys();
 loadUsage();
 loadPlans();
}
async function loadPlans(){
 const list=document.getElementById('plan-list');list.replaceChildren();
 try{
  const response=await fetch('/plans',{credentials:'same-origin'});
  if(!response.ok)throw new Error('Plan catalogue is not available.');
  const data=await response.json();
  for(const plan of data.plans){
   const card=document.createElement('section');
   const title=document.createElement('h4');title.textContent=plan.name;card.appendChild(title);
   const price=document.createElement('p');
   price.textContent=plan.price_minor===0?'Free':(plan.price_minor===null?'Price not published':'Price: '+(plan.price_minor/100).toFixed(2)+' '+plan.currency);
   card.appendChild(price);
   const quota=document.createElement('p');quota.textContent=plan.monthly_units===null?'Usage allowance to be announced':plan.monthly_units+' technical units / UTC month';card.appendChild(quota);
   const features=document.createElement('ul');
   for(const feature of plan.features){const item=document.createElement('li');item.textContent=feature;features.appendChild(item)}
   card.appendChild(features);
   const status=document.createElement('p');status.textContent=plan.purchasable?'Available':'Preview only — checkout disabled';card.appendChild(status);
   list.appendChild(card);
  }
  document.getElementById('plan-note').textContent=data.disclaimer+' Manual TrxID checkout is not active.';
 }catch(error){document.getElementById('plan-note').textContent=error.message}
}
async function loadUsage(){
 const summary=document.getElementById('usage-summary');
 const operations=document.getElementById('usage-operations');operations.replaceChildren();
 try{
  const response=await fetch('/v1/customer/usage',{credentials:'same-origin'});
  if(!response.ok)throw new Error('Usage reporting is not available yet.');
  const data=await response.json();const q=data.quota;
  summary.textContent='Last 30 days: '+data.units+' units across '+data.events+' events. Current UTC month: '+q.used_units+' / '+q.monthly_limit+' units; '+q.remaining_units+' remaining. Resets '+q.resets_at+'. Billing is not connected; these are technical usage units, not money.';
  for(const op of data.by_operation){
   const item=document.createElement('li');
   item.textContent=op.operation+': '+op.units+' units ('+op.events+' events)';
   operations.appendChild(item);
  }
 }catch(error){summary.textContent=error.message}
}
async function loadApiKeys(){
 const list=document.getElementById('key-list');list.replaceChildren();
 try{
  const response=await fetch('/v1/customer/api-keys',{credentials:'same-origin'});
  if(!response.ok)throw new Error('API key management is not enabled for this account yet.');
  const data=await response.json();
  for(const key of data.items){
   const item=document.createElement('li');
   const label=document.createElement('span');
   label.textContent=key.key_name+' · '+key.key_prefix+' · '+key.status;
   item.appendChild(label);
   if(key.status==='active'){
    const button=document.createElement('button');button.type='button';button.className='secondary';button.textContent='Revoke';
    button.addEventListener('click',async()=>{
     try{await request('/v1/customer/api-keys/'+encodeURIComponent(key.key_id)+'/revoke',{});await loadApiKeys()}
     catch(error){notice.textContent=error.message}
    });
    item.appendChild(button);
   }
   list.appendChild(item);
  }
 }catch(error){notice.textContent=error.message}
}
async function loadAccount(){
 const response=await fetch('/v1/customer/me',{credentials:'same-origin'});
 if(response.ok){showAccount(await response.json());return}
 auth.hidden=false;account.hidden=true;notice.textContent='Sign in or create your JAS-SI account.';
}
document.getElementById('register').addEventListener('submit',async event=>{
 event.preventDefault();notice.textContent='Submitting…';
 try{await request('/v1/customer/register',{email:document.getElementById('reg-email').value,organization_name:document.getElementById('reg-org').value});notice.textContent='If eligible, a verification link has been sent. Check your inbox and spam folder.'}
 catch(error){notice.textContent=error.message}
});
document.getElementById('login').addEventListener('submit',async event=>{
 event.preventDefault();notice.textContent='Submitting…';
 try{await request('/v1/customer/login',{email:document.getElementById('login-email').value});notice.textContent='If an active account exists, a sign-in link has been sent.'}
 catch(error){notice.textContent=error.message}
});
document.getElementById('create-key').addEventListener('submit',async event=>{
 event.preventDefault();notice.textContent='Creating API key…';
 try{
  const data=await request('/v1/customer/api-keys',{
   key_name:document.getElementById('key-name').value,
   scopes:[document.getElementById('key-scope').value],
   expires_in_days:Number(document.getElementById('key-expiry').value)
  });
  const output=document.getElementById('new-key');
  output.textContent='Copy this key now. It will not be shown again: '+data.token;
  document.getElementById('key-name').value='';
  await loadApiKeys();notice.textContent='API key created. Store it securely.';
 }catch(error){notice.textContent=error.message}
});
document.getElementById('logout').addEventListener('click',async()=>{
 try{await request('/v1/customer/logout',{});await loadAccount()}
 catch(error){notice.textContent=error.message}
});
(async()=>{
 const fragment=location.hash.slice(1);history.replaceState(null,'',location.pathname);
 const params=new URLSearchParams(fragment);
 const verification=params.get('verify-email'),login=params.get('login');
 try{
  if(verification){await request('/v1/customer/verify-email',{token:verification});notice.textContent='Email verified. You can now sign in.';auth.hidden=false;account.hidden=true;return}
  if(login){await request('/v1/customer/session',{token:login});await loadAccount();return}
 }catch(error){notice.textContent='This one-time link is invalid or expired. Request a new link.';auth.hidden=false;account.hidden=true;return}
 await loadAccount();
})();
</script></body></html>"""
