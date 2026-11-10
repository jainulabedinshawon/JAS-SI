"""A live, read-only browser console for the existing GitHub evidence API."""

LIVE_GITHUB_DEMO_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#090b10">
<meta name="description" content="Run a live, read-only JAS-SI GitHub commit and file-integrity check.">
<title>JAS-SI — Live GitHub Evidence Check</title>
<style>
:root{color-scheme:dark;--bg:#090b10;--panel:#121823;--line:#293242;--text:#f3f6fb;--muted:#aab3c2;--accent:#b7f36b;--blue:#8bb8ff;--bad:#ff9c91;--warn:#f0c674}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 75% -15%,#1a2634 0,transparent 38%),var(--bg);color:var(--text);font:14px/1.65 system-ui,-apple-system,"Segoe UI",sans-serif}
.shell{max-width:900px;margin:auto;padding:24px 18px 60px}a{color:var(--blue);text-decoration:none}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:16px}.brand{font-weight:750}
h1{font-size:clamp(30px,5vw,46px);line-height:1.08;letter-spacing:-.04em;margin:38px 0 12px}.intro{max-width:720px;color:var(--muted)}
.panel{margin-top:22px;background:linear-gradient(145deg,#121823,#0e121a);border:1px solid var(--line);border-radius:14px;padding:22px}
.notice{border-left:3px solid var(--warn);background:#211b10;padding:12px 14px;color:#f1dba9;border-radius:5px;margin:18px 0}
label{display:block;font-weight:650;margin:15px 0 6px}input{width:100%;background:#080b10;color:var(--text);border:1px solid #354154;border-radius:8px;padding:12px;font:inherit}input:focus{outline:2px solid var(--blue);outline-offset:2px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.hint{color:var(--muted);font-size:12px;margin-top:5px}
button{font:inherit;cursor:pointer;border:1px solid var(--accent);background:var(--accent);color:#11170b;font-weight:750;padding:11px 16px;border-radius:8px;margin-top:18px}button:disabled{opacity:.6;cursor:wait}
#result{margin-top:18px;white-space:pre-wrap;overflow-wrap:anywhere;background:#080b10;border:1px solid #354154;border-radius:10px;padding:16px;min-height:80px;color:#dce5f1;font:12px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace}
.small{font-size:12px;color:var(--muted)}.success{color:var(--accent)}.error{color:var(--bad)}
@media(max-width:650px){.grid{grid-template-columns:1fr}.shell{padding:18px 14px 42px}.panel{padding:16px}}
</style>
</head>
<body><main class="shell">
<header class="top"><a class="brand" href="/">JAS-SI / Developer Console</a><a href="/docs">API reference ↗</a></header>
<h1>Live GitHub evidence check</h1>
<p class="intro">Run the deployed JAS-SI API against a real public GitHub repository, immutable commit SHA, and file path. This is a read-only Git blob integrity check—not an AI agent execution or a semantic review.</p>
<div class="notice"><strong>Credential safety:</strong> Use only an API key already issued to you by an authorized JAS-SI operator. The key is sent directly from this page to this same JAS-SI origin in the X-API-Key header. It is not saved to browser storage or sent to GitHub. The field is cleared after each request. Do not use a production key on a shared device.</div>
<section class="panel" aria-labelledby="form-title">
<h2 id="form-title">Verify a committed file</h2>
<form id="verify-form">
<label for="api-key">JAS-SI API key</label>
<input id="api-key" type="password" autocomplete="off" spellcheck="false" required>
<div class="grid">
<div><label for="repository">Public GitHub repository</label><input id="repository" value="jainulabedinshawon/JAS-SI" pattern="[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+" required><div class="hint">owner/repository</div></div>
<div><label for="commit">Full commit SHA</label><input id="commit" minlength="40" maxlength="40" pattern="[0-9a-f]{40}" placeholder="40 lowercase hexadecimal characters" required><div class="hint">Use an immutable 40-character commit SHA</div></div>
</div>
<label for="path">File path at that commit</label>
<input id="path" value="README.md" maxlength="500" required>
<div class="hint">One file per request. The API enforces its own path and size limits.</div>
<button id="submit" type="submit">Run live integrity check</button>
</form>
<div id="result" role="status" aria-live="polite">Ready. No request has been sent.</div>
</section>
<section class="panel">
<h2>What a successful result proves</h2>
<ul>
<li>JAS-SI fetched the requested file at the exact commit SHA from GitHub.</li>
<li>The returned file bytes reproduce the Git blob SHA reported by GitHub.</li>
<li>The response includes a SHA-256 digest and file size for the bytes checked.</li>
</ul>
<p class="small"><strong>What it does not prove:</strong> that code is safe, that a task was executed, that a workflow passed, that a deployment is healthy, or that repository content is semantically true. The endpoint is read-only and explicitly returns <code>semantic_truth_verified: false</code>.</p>
</section>
</main>
<script>
const form = document.getElementById("verify-form");
const keyField = document.getElementById("api-key");
const submit = document.getElementById("submit");
const result = document.getElementById("result");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const apiKey = keyField.value;
  const payload = {
    repository: document.getElementById("repository").value.trim(),
    commit_sha: document.getElementById("commit").value.trim(),
    paths: [document.getElementById("path").value.trim()]
  };
  if (!apiKey) return;
  submit.disabled = true;
  result.className = "";
  result.textContent = "Contacting JAS-SI and GitHub…";
  try {
    const response = await fetch("/v1/github/evidence", {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-API-Key": apiKey},
      body: JSON.stringify(payload),
      cache: "no-store",
      credentials: "same-origin"
    });
    const body = await response.json().catch(() => ({detail: "Non-JSON API response"}));
    result.className = response.ok ? "success" : "error";
    result.textContent = JSON.stringify({http_status: response.status, ...body}, null, 2);
  } catch (error) {
    result.className = "error";
    result.textContent = "Request failed: " + String(error);
  } finally {
    keyField.value = "";
    submit.disabled = false;
  }
});
</script>
</body>
</html>"""
