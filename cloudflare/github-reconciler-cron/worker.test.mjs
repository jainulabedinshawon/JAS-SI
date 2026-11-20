import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import worker from "./worker.mjs";

const originalFetch = globalThis.fetch;
const originalLog = console.log;
const originalError = console.error;
const endpoint = "https://jas-si-git-staging-example.vercel.app/internal/github/reconcile";
const allowedHost = "jas-si-git-staging-example.vercel.app";
const secret = "S".repeat(40);
const env = (extra = {}) => ({
  JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: secret,
  JAS_SI_RECONCILER_ENDPOINT: endpoint,
  JAS_SI_RECONCILER_ALLOWED_HOST: allowedHost,
  ...extra,
});

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
  await worker.scheduled({ scheduledTime: 123456 }, env());
  assert.equal(captured.url, endpoint);
  assert.equal(captured.options.method, "POST");
  assert.equal(captured.options.redirect, "error");
  assert.equal(captured.options.headers.Authorization, "Bearer " + secret);
  assert.equal(captured.options.headers.Accept, "application/json");
});

test("missing or short scheduler secret fails closed before network access", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("{}"); };
  await assert.rejects(worker.scheduled({}, {}), /scheduler secret is not configured/);
  await assert.rejects(
    worker.scheduled({}, env({ JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: "short" })),
    /scheduler secret is not configured/,
  );
  assert.equal(called, false);
});

test("missing endpoint or exact allowed host fails closed before network access", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("{}"); };
  await assert.rejects(
    worker.scheduled({}, {
      JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: secret,
      JAS_SI_RECONCILER_ALLOWED_HOST: allowedHost,
    }),
    /endpoint is not configured/,
  );
  await assert.rejects(
    worker.scheduled({}, {
      JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: secret,
      JAS_SI_RECONCILER_ENDPOINT: endpoint,
    }),
    /Exact JAS-SI Staging endpoint host is not configured/,
  );
  assert.equal(called, false);
});

test("endpoint host must exactly match the configured staging host", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("{}"); };
  await assert.rejects(
    worker.scheduled({}, env({
      JAS_SI_RECONCILER_ALLOWED_HOST: "jas-si-git-another-preview.vercel.app",
    })),
    /Only an HTTPS JAS-SI Vercel Preview endpoint is allowed/,
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
    await assert.rejects(worker.scheduled({}, env({ JAS_SI_RECONCILER_ENDPOINT: rejected })));
  }
  assert.equal(called, false);
});

test("Vercel Production branch alias is rejected even when explicitly allowlisted", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("{}"); };
  const productionAlias = "jas-si-git-main-jainulabedinshawon.vercel.app";
  await assert.rejects(
    worker.scheduled({}, env({
      JAS_SI_RECONCILER_ENDPOINT: `https://${productionAlias}/internal/github/reconcile`,
      JAS_SI_RECONCILER_ALLOWED_HOST: productionAlias,
    })),
    /Exact JAS-SI Vercel Preview hostname is invalid/,
  );
  assert.equal(called, false);
});

test("non-success API response fails without logging response body", async () => {
  let logged = "";
  globalThis.fetch = async () => new Response("private server diagnostics", { status: 503 });
  console.error = (...args) => { logged += args.join(" "); };
  await assert.rejects(worker.scheduled({}, env()), /reconciliation request failed/);
  assert.match(logged, /503/);
  assert.doesNotMatch(logged, /private server diagnostics/);
});

test("invalid JSON response is rejected", async () => {
  globalThis.fetch = async () => new Response("not-json", { status: 200 });
  await assert.rejects(worker.scheduled({}, env()), /invalid JSON/);
});
