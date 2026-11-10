"""Static developer console landing page for JAS-SI.

The page intentionally exposes documentation and honest service metadata only.
Credential issuance and usage billing are not exposed as mock controls.
"""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#090b10">
<meta name="description" content="JAS-SI developer console — authorization-gated actions and evidence-based outcome verification.">
<title>JAS-SI — Developer Console</title>
<style>
:root{color-scheme:dark;--bg:#090b10;--panel:#10141d;--panel2:#0c1017;--line:#252d3a;--muted:#929bad;--text:#f3f6fb;--accent:#b7f36b;--blue:#8bb8ff;--danger:#ffb4a9}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(ellipse at 75% -15%,#1a2634 0,transparent 38%),var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
a{color:inherit;text-decoration:none}button{font:inherit}.shell{max-width:1180px;margin:auto;padding:0 28px}
.topbar{height:68px;border-bottom:1px solid var(--line);display:flex;align-items:center;position:sticky;top:0;background:#090b10eF;backdrop-filter:blur(14px);z-index:5}.nav{display:flex;align-items:center;justify-content:space-between;width:100%;gap:18px}.brand{display:flex;align-items:center;gap:11px;font-weight:750;letter-spacing:.02em}.mark{width:30px;height:30px;border:1px solid #50643a;border-radius:9px;display:grid;place-items:center;color:var(--accent);font-size:17px}.navlinks{display:flex;gap:24px;color:var(--muted);font-size:13px}.navlinks a:hover,.textlink:hover{color:var(--text)}.navright{display:flex;align-items:center;gap:12px}.status{display:inline-flex;align-items:center;gap:8px;border:1px solid #30432b;background:#111b10;color:#c8f59d;border-radius:99px;padding:6px 10px;font-size:12px}.dot{width:7px;height:7px;background:var(--accent);border-radius:50%;box-shadow:0 0 12px #b7f36b88}.button{border:1px solid var(--line);background:#151b25;color:var(--text);padding:9px 13px;border-radius:8px;font-size:12px;font-weight:650;cursor:pointer}.button.primary{background:var(--accent);color:#11170b;border-color:var(--accent)}.button:hover{filter:brightness(1.12)}
main{padding:62px 0 80px}.eyebrow{color:var(--accent);font-size:11px;letter-spacing:.16em;text-transform:uppercase;font-weight:750}.hero{max-width:820px}.hero h1{font-size:clamp(34px,5vw,56px);line-height:1.06;letter-spacing:-.045em;margin:15px 0 18px}.hero p{max-width:720px;color:#aab3c2;font-size:16px;line-height:1.75;margin:0}.heroactions{display:flex;gap:10px;flex-wrap:wrap;margin-top:25px}.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:14px;margin-top:42px}.card{background:linear-gradient(145deg,#121823,#0e121a);border:1px solid var(--line);border-radius:13px;padding:20px;min-width:0}.span4{grid-column:span 4}.span5{grid-column:span 5}.span7{grid-column:span 7}.span12{grid-column:span 12}.cardhead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:15px}.card h2{font-size:14px;margin:0;font-weight:700}.muted{color:var(--muted)}.metric{font-size:25px;font-weight:720;letter-spacing:-.03em}.sub{font-size:12px;color:var(--muted);margin-top:4px}.tag{font-size:10px;color:#b8c3d3;border:1px solid #344052;padding:3px 7px;border-radius:99px}.smalllinks{display:flex;flex-wrap:wrap;gap:9px;margin-top:14px}.textlink{font-size:12px;color:var(--blue)}.keybox{background:var(--panel2);border:1px solid #293242;border-radius:9px;padding:13px}.keyrow{display:flex;justify-content:space-between;gap:12px;align-items:center}.keyrow strong{font-size:12px}.keyrow span{font-size:11px;color:var(--muted)}.keybox p{font-size:12px;color:var(--muted);margin:10px 0 0}.notice{border-left:2px solid #d7b36b;padding:8px 0 8px 11px;color:#c9c1ad;font-size:12px;margin-top:13px}
.tabs{display:flex;gap:5px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:10px}.tab{border:1px solid transparent;background:transparent;color:var(--muted);padding:6px 11px;border-radius:7px;cursor:pointer;font-size:12px}.tab[aria-selected=true]{background:#202938;border-color:#354154;color:var(--text)}.codehead{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:13px 0 8px}.codehead span{font-size:11px;color:var(--muted)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080b10;border:1px solid #252d3a;border-radius:9px;padding:17px;margin:0;color:#d6e2f4;font:12px/1.75 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;min-height:220px}.copy{background:#1a2330;border:1px solid #354154;color:#e7edf6;padding:6px 10px;border-radius:7px;font-size:11px;cursor:pointer}.endpoint{display:flex;justify-content:space-between;gap:12px;padding:11px 0;border-bottom:1px solid #222b37;align-items:center}.endpoint:last-child{border:0}.method{font:10px ui-monospace,monospace;color:var(--accent);background:#19251a;padding:4px 7px;border-radius:5px;margin-right:8px}.endpoint code{font:12px ui-monospace,monospace}.footer{border-top:1px solid var(--line);padding:22px 0 34px;color:var(--muted);font-size:11px;display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap}
@media(max-width:800px){.span4,.span5,.span7{grid-column:span 12}.navlinks{display:none}.shell{padding:0 17px}main{padding-top:42px}.hero p{font-size:14px}.grid{margin-top:30px}.topbar{height:60px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
</style>
</head>
<body>
<header class="topbar"><div class="shell nav">
<a class="brand" href="/"><span class="mark">J</span><span>JAS-SI <span class="muted">/ Console</span></span></a>
<nav class="navlinks" aria-label="Main navigation"><a href="#overview">Overview</a><a href="#quickstart">Quickstart</a><a href="/demo">Synthetic Demo</a><a href="/live-demo">Live GitHub Check</a><a href="/docs">API Reference</a></nav>
<div class="navright"><span class="status" id="system-status"><i class="dot"></i><span>Checking status…</span></span></div>
</div></header>
<main class="shell">
<section class="hero">
<div class="eyebrow">Developer platform · API v1</div>
<h1>JAS-SI Reality-Based<br>Intelligence Architecture</h1>
<p>Build systems that distinguish reported outcomes from evidence-supported reality. JAS-SI evaluates authorization and verifies outcomes; it does not execute actions on your behalf.</p>
<div class="heroactions"><a class="button primary" href="/live-demo">Run live GitHub check ↗</a><a class="button" href="/demo">Synthetic demo ↗</a><a class="button" href="#quickstart">Start building ↗</a><a class="button" href="/docs">Explore API docs ↗</a><a class="button" href="https://github.com/jainulabedinshawon/JAS-SI">GitHub ↗</a></div>
</section>
<section id="overview" class="grid">
<article class="card span4"><div class="cardhead"><h2>Service status</h2><span class="tag">LIVE CHECK</span></div><div class="metric" id="health-value">Checking</div><div class="sub" id="health-detail">Reading the public health endpoint</div><div class="smalllinks"><a class="textlink" href="/health">Health JSON ↗</a><a class="textlink" href="/openapi.json">OpenAPI schema ↗</a></div></article>
<article class="card span4"><div class="cardhead"><h2>API credentials</h2><span class="tag">CONTROLLED</span></div><div class="metric">Tenant-scoped</div><div class="sub">Scoped keys · expiry · revocation · audit trail</div><div class="notice">Self-service key creation is not exposed in this public console. Use the approved secure provisioning process; never paste a secret into support chats.</div></article>
<article class="card span4"><div class="cardhead"><h2>Usage & quota</h2><span class="tag">NOT CONNECTED</span></div><div class="metric">—</div><div class="sub">No billing or metering data is currently presented here.</div><div class="smalllinks"><a class="textlink" href="/openapi.json">Inspect API contract ↗</a></div></article>
<article class="card span7" id="quickstart"><div class="cardhead"><h2>Quickstart</h2><span class="tag">COPY-READY</span></div><div class="muted" style="font-size:12px;margin-bottom:13px">Set JAS_SI_BASE_URL to this Preview deployment and JAS_SI_API_KEY in your local environment; never hard-code either value.</div>
<div class="tabs" role="tablist" aria-label="Quickstart language">
<button class="tab" role="tab" aria-selected="true" data-lang="curl">cURL</button><button class="tab" role="tab" aria-selected="false" data-lang="python">Python</button><button class="tab" role="tab" aria-selected="false" data-lang="php">PHP</button><button class="tab" role="tab" aria-selected="false" data-lang="node">Node.js</button>
</div>
<div class="codehead"><span id="snippet-label">POST /v1/authorize · authorization:check</span><button class="copy" id="copy-snippet" type="button">Copy code</button></div>
<pre><code id="snippet-code">curl "$JAS_SI_BASE_URL/v1/authorize" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $JAS_SI_API_KEY" \
  -d '{"action_id":"demo-001","action":"read","resource":"jas-si://demo"}'</code></pre>
<div class="sub" style="margin-top:10px">Expected response includes <code>allowed</code> and <code>executed: false</code>. Authorization evaluation is not action execution.</div>
</article>
<article class="card span5"><div class="cardhead"><h2>API reference</h2><span class="tag">OPENAPI</span></div>
<div class="endpoint"><div><span class="method">GET</span><code>/health</code></div><a class="textlink" href="/health">Open ↗</a></div>
<div class="endpoint"><div><span class="method">GET</span><code>/docs</code></div><a class="textlink" href="/docs">Swagger ↗</a></div>
<div class="endpoint"><div><span class="method">GET</span><code>/openapi.json</code></div><a class="textlink" href="/openapi.json">Schema ↗</a></div>
<div class="endpoint"><div><span class="method">POST</span><code>/v1/authorize</code></div><span class="muted" style="font-size:11px">Authorization check</span></div>
<div class="endpoint"><div><span class="method">POST</span><code>/v1/verify</code></div><span class="muted" style="font-size:11px">Outcome verification</span></div>
<div class="endpoint"><div><span class="method">POST</span><code>/v1/github/evidence</code></div><span class="muted" style="font-size:11px">GitHub evidence</span></div>
</article>
<article class="card span12"><div class="cardhead"><h2>Operating principle</h2><span class="tag">JAS-SI CORE</span></div><div style="font-size:17px;font-weight:650;letter-spacing:-.02em">Capability → Authorization → Action → Verification → Accountability</div><div class="sub" style="margin-top:8px">A reported result is not automatically a verified result. Evidence must support the state being claimed.</div></article>
</section>
</main>
<footer class="shell footer"><span>© JAS-SI · Reality-Based Intelligence Architecture</span><span><a class="textlink" href="https://github.com/jainulabedinshawon/JAS-SI">Source</a> · <a class="textlink" href="/docs">API docs</a></span></footer>
<script>
const snippets = {
curl: {label:"POST /v1/authorize · authorization:check",code:`curl "$JAS_SI_BASE_URL/v1/authorize" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: $JAS_SI_API_KEY" \\
  -d '{"action_id":"demo-001","action":"read","resource":"jas-si://demo"}'`},
python: {label:"POST /v1/authorize · Python standard library",code:`import json
import os
import urllib.request

url = os.environ["JAS_SI_BASE_URL"].rstrip("/") + "/v1/authorize"
payload = {
    "action_id": "demo-001",
    "action": "read",
    "resource": "jas-si://demo",
}
request = urllib.request.Request(
    url,
    data=json.dumps(payload).encode(),
    headers={
        "Content-Type": "application/json",
        "X-API-Key": os.environ["JAS_SI_API_KEY"],
    },
    method="POST",
)
with urllib.request.urlopen(request, timeout=20) as response:
    print(response.status, response.read().decode())`},
php: {label:"POST /v1/authorize · PHP cURL",code:`<?php
$payload = [
    "action_id" => "demo-001",
    "action" => "read",
    "resource" => "jas-si://demo",
];
$ch = curl_init(rtrim(getenv("JAS_SI_BASE_URL"), "/") . "/v1/authorize");
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => [
        "Content-Type: application/json",
        "X-API-Key: " . getenv("JAS_SI_API_KEY"),
    ],
    CURLOPT_POSTFIELDS => json_encode($payload),
]);
$result = curl_exec($ch);
if ($result === false) { throw new RuntimeException(curl_error($ch)); }
echo $result;
curl_close($ch);`},
node: {label:"POST /v1/authorize · Node.js fetch",code:`const response = await fetch(
  `${process.env.JAS_SI_BASE_URL}/v1/authorize`,
  {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": process.env.JAS_SI_API_KEY,
    },
    body: JSON.stringify({
      action_id: "demo-001",
      action: "read",
      resource: "jas-si://demo",
    }),
  }
);
console.log(response.status, await response.json());`}
};
const code = document.getElementById("snippet-code");
const label = document.getElementById("snippet-label");
document.querySelectorAll("[data-lang]").forEach(tab => tab.addEventListener("click", () => {
  document.querySelectorAll("[data-lang]").forEach(item => item.setAttribute("aria-selected", String(item === tab)));
  const selected = snippets[tab.dataset.lang];
  code.textContent = selected.code;
  label.textContent = selected.label;
}));
document.getElementById("copy-snippet").addEventListener("click", async () => {
  const button = document.getElementById("copy-snippet");
  try {
    await navigator.clipboard.writeText(code.textContent);
    button.textContent = "Copied";
    setTimeout(() => button.textContent = "Copy code", 1600);
  } catch (_) {
    button.textContent = "Select code to copy";
  }
});
fetch("/health", {headers: {"Accept":"application/json"}}).then(response => {
  if (!response.ok) throw new Error("HTTP " + response.status);
  return response.json();
}).then(data => {
  const online = data.status === "ok";
  document.getElementById("health-value").textContent = online ? "Operational" : "Degraded";
  document.getElementById("health-detail").textContent = "API enabled: " + (data.api_enabled ? "yes" : "no");
  document.getElementById("system-status").innerHTML = '<i class="dot"></i><span>' + (online ? "System Operational" : "Service degraded") + '</span>';
}).catch(() => {
  document.getElementById("health-value").textContent = "Unavailable";
  document.getElementById("health-detail").textContent = "Health endpoint could not be reached.";
  document.getElementById("system-status").textContent = "Status unavailable";
});
</script>
</body>
</html>"""
