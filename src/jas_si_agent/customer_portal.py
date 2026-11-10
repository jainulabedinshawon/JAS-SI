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
<p>Account session is active. API key management and detailed usage controls will appear here when enabled.</p>
<button id="logout" class="secondary">Sign out</button></section>
</main>
<script>
const notice=document.getElementById('notice');
const auth=document.getElementById('auth');
const account=document.getElementById('account');
async function request(path,body){
 const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'});
 let data={};try{data=await response.json()}catch(_){}
 if(!response.ok)throw new Error(data.detail||'Request could not be completed');
 return data;
}
function showAccount(data){
 document.getElementById('account-email').textContent=data.email;
 document.getElementById('account-org').textContent=data.organization_name;
 auth.hidden=true;account.hidden=false;
 notice.textContent='You are signed in to JAS-SI.';
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
