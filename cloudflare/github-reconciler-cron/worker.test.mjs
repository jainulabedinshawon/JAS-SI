import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import worker from "./worker.mjs";

const originalFetch = globalThis.fetch;
const originalLog = console.log;
const originalError = console.error;
const endpoint = "https://jas-si-git-staging-example.vercel.app/internal/github/reconcile";
const secret = "S".repeat(40);

afterEach(() => {
  globalThis.fetch = originalFetch;
  console.log = originalLog;
  console.error = originalError;
});

test("scheduled trigger sends authenticated POST only to configured JAS-SI Preview", async () => {
  let captured;
  globalThis.fetch = async (url, options) => {
    captured = { url, options };
    return new Response(JSON.stringify({
      webhook: { claimed: 1, processed: 1, retry: 0, lease_lost: 0 },
      pending_claims: { claimed: 1, reconciled: 1, retry: 0 },
    }), { status: 200, headers: { "content-type": "application/json" } });
  };
  console.log = () => {};
  await worker.scheduled(
    { scheduledTime: 123456 },
    {
      JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: secret,
      JAS_SI_RECONCILER_ENDPOINT: endpoint,
    },
  );
  assert.equal(captured.url, endpoint);
  assert.equal(captured.options.method, "POST");
  assert.equal(captured.options.headers.Authorization, "Bearer " + secret);
  assert.equal(captured.options.headers.Accept, "application/json");
});

test("missing or short scheduler secret fails closed before network access", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("{}"); };
  await assert.rejects(worker.scheduled({}, {}), /scheduler secret is not configured/);
  await assert.rejects(
    worker.scheduled({}, { JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: "short" }),
    /scheduler secret is not configured/,
  );
  assert.equal(called, false);
});

test("missing endpoint fails closed before network access", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("{}"); };
  await assert.rejects(
    worker.scheduled({}, { JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: secret }),
    /endpoint is not configured/,
  );
  assert.equal(called, false);
});

test("production and non-JAS-SI hosts are rejected before sending the secret", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("{}"); };
  for (const rejected of [
    "https://jas-si.vercel.app/internal/github/reconcile",
    "https://attacker.vercel.app/internal/github/reconcile",
    "http://jas-si-git-staging-example.vercel.app/internal/github/reconcile",
    "https://jas-si-git-staging-example.vercel.app/other",
    "https://jas-si-git-staging-example.vercel.app/internal/github/reconcile?x=1",
  ]) {
    await assert.rejects(worker.scheduled({}, {
      JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: secret,
      JAS_SI_RECONCILER_ENDPOINT: rejected,
    }));
  }
  assert.equal(called, false);
});

test("non-success API response fails without logging response body", async () => {
  let logged = "";
  globalThis.fetch = async () => new Response("private server diagnostics", { status: 503 });
  console.error = (...args) => { logged += args.join(" "); };
  await assert.rejects(worker.scheduled({}, {
    JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: secret,
    JAS_SI_RECONCILER_ENDPOINT: endpoint,
  }), /reconciliation request failed/);
  assert.match(logged, /503/);
  assert.doesNotMatch(logged, /private server diagnostics/);
});

test("invalid JSON response is rejected", async () => {
  globalThis.fetch = async () => new Response("not-json", { status: 200 });
  await assert.rejects(worker.scheduled({}, {
    JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: secret,
    JAS_SI_RECONCILER_ENDPOINT: endpoint,
  }), /invalid JSON/);
});
