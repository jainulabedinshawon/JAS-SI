"""Interactive, explicitly synthetic JAS-SI verification walkthrough."""

DEMO_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#090b10">
<meta name="description" content="Explore illustrative JAS-SI outcome-verification scenarios.">
<title>JAS-SI — Interactive Demo</title>
<style>
:root{color-scheme:dark;--bg:#090b10;--panel:#121823;--line:#293242;--text:#f3f6fb;--muted:#aab3c2;--accent:#b7f36b;--warn:#f0c674;--bad:#ff9c91;--blue:#8bb8ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 75% -15%,#1a2634 0,transparent 38%),var(--bg);color:var(--text);font:15px/1.65 system-ui,-apple-system,"Segoe UI",sans-serif}
.shell{max-width:920px;margin:auto;padding:28px 20px 60px}a{color:var(--blue);text-decoration:none}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:18px}.brand{font-weight:750;letter-spacing:.03em}.eyebrow{color:var(--accent);font-size:11px;letter-spacing:.16em;text-transform:uppercase;font-weight:750;margin-top:42px}
h1{font-size:clamp(32px,6vw,52px);line-height:1.08;letter-spacing:-.04em;margin:12px 0}.intro{max-width:720px;color:var(--muted)}
.warning{margin:24px 0;padding:15px 17px;border:1px solid #6a5530;background:#211b10;border-radius:10px;color:#f4dba6}.warning strong{display:block;margin-bottom:4px}
.panel{margin-top:20px;background:linear-gradient(145deg,#121823,#0e121a);border:1px solid var(--line);border-radius:14px;padding:22px}
.choices{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:16px 0}
button{font:inherit;cursor:pointer}.choice{background:#171f2b;color:var(--text);border:1px solid #354154;border-radius:9px;padding:12px;text-align:left;min-height:76px}.choice[aria-pressed=true]{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}.choice small{display:block;color:var(--muted);margin-top:4px}
.result{background:#080b10;border:1px solid #354154;border-radius:10px;padding:18px;min-height:190px}.result h2{font-size:21px;margin:0 0 8px}.result p{color:var(--muted);margin:8px 0}.tag{display:inline-block;font-size:11px;letter-spacing:.08em;text-transform:uppercase;border:1px solid #596779;border-radius:99px;padding:4px 9px;color:#dce5f1}.facts{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px}.fact{background:#141b25;border-radius:8px;padding:12px}.fact b{display:block;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.fact span{display:block;margin-top:5px}
.footnote{font-size:12px;color:var(--muted);margin-top:18px}.actions{display:flex;gap:16px;flex-wrap:wrap;margin-top:20px}
@media(max-width:650px){.choices{grid-template-columns:1fr}.choice{min-height:auto}.facts{grid-template-columns:1fr}.shell{padding:18px 15px 42px}}
</style>
</head>
<body><main class="shell">
<header class="top"><a class="brand" href="/">JAS-SI / Developer Console</a><a href="/docs">API reference ↗</a></header>
<div class="eyebrow">Interactive walkthrough · v0.1</div>
<h1>Reported success is not verified success.</h1>
<p class="intro">Explore how JAS-SI compares an action report with evidence. Select a scenario to see how the illustrative verdict changes.</p>
<div class="warning" role="note"><strong>SIMULATED EXAMPLES — NOT LIVE VERIFICATION</strong>Every scenario below uses invented fixture data in your browser. No GitHub repository, external evidence source, customer account, or live action is accessed. These examples do not prove that an action occurred.</div>
<section class="panel" aria-labelledby="scenario-title">
<h2 id="scenario-title">Choose a scenario</h2>
<div class="choices" role="group" aria-label="Verification scenarios">
<button class="choice" type="button" data-case="false" aria-pressed="true">False success<small>Report says success; fixture says failure</small></button>
<button class="choice" type="button" data-case="match" aria-pressed="false">Matching evidence<small>Report and fixture both say success</small></button>
<button class="choice" type="button" data-case="missing" aria-pressed="false">Missing evidence<small>Report exists; no evidence supplied</small></button>
</div>
<div class="result" id="result" aria-live="polite">
<span class="tag">Synthetic fixture verdict</span>
<h2>FALSE_SUCCESS</h2>
<p>The report claims success, but the illustrative evidence fixture records failure. A success claim must not override contradictory evidence.</p>
<div class="facts"><div class="fact"><b>Reported state</b><span>Success</span></div><div class="fact"><b>Fixture observation</b><span>Failure</span></div><div class="fact"><b>Evidence origin</b><span>Browser fixture (synthetic)</span></div><div class="fact"><b>Real-world verification</b><span>Not performed</span></div></div>
</div>
<p class="footnote">The result names mirror JAS-SI's verification vocabulary for learning purposes. This page does not call <code>/v1/verify</code> and does not submit audit events.</p>
</section>
<section class="panel"><h2>What this demo proves — and what it does not</h2>
<p><strong>It demonstrates:</strong> why a reported outcome and an evidence-supported outcome must be evaluated separately.</p>
<p><strong>It does not demonstrate:</strong> independent evidence collection, GitHub state verification, action execution, production tenant isolation, or live API performance.</p>
<div class="actions"><a href="/">← Back to console</a><a href="/docs">Read API documentation ↗</a></div>
</section>
</main>
<script>
const scenarios = {
  false: {
    title: "FALSE_SUCCESS",
    description: "The report claims success, but the illustrative evidence fixture records failure. A success claim must not override contradictory evidence.",
    reported: "Success",
    observed: "Failure"
  },
  match: {
    title: "VERIFIED_SUCCESS (ILLUSTRATIVE)",
    description: "The report and the synthetic fixture agree on success. In a real deployment, this label would require a trusted, independently obtained evidence source; this browser fixture does not provide one.",
    reported: "Success",
    observed: "Success (synthetic)"
  },
  missing: {
    title: "INCONCLUSIVE",
    description: "A report without supporting evidence cannot establish what happened. The responsible result is inconclusive, not assumed success or failure.",
    reported: "Success",
    observed: "No evidence supplied"
  }
};
const result = document.getElementById("result");
document.querySelectorAll("[data-case]").forEach(button => {
  button.addEventListener("click", () => {
    document.querySelectorAll("[data-case]").forEach(item =>
      item.setAttribute("aria-pressed", String(item === button))
    );
    const item = scenarios[button.dataset.case];
    result.innerHTML = "";
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = "Synthetic fixture verdict";
    const heading = document.createElement("h2");
    heading.textContent = item.title;
    const description = document.createElement("p");
    description.textContent = item.description;
    const facts = document.createElement("div");
    facts.className = "facts";
    const entries = [
      ["Reported state", item.reported],
      ["Fixture observation", item.observed],
      ["Evidence origin", "Browser fixture (synthetic)"],
      ["Real-world verification", "Not performed"]
    ];
    entries.forEach(([label, value]) => {
      const fact = document.createElement("div");
      fact.className = "fact";
      const key = document.createElement("b");
      key.textContent = label;
      const text = document.createElement("span");
      text.textContent = value;
      fact.append(key, text);
      facts.append(fact);
    });
    result.append(tag, heading, description, facts);
  });
});
</script></body></html>"""
