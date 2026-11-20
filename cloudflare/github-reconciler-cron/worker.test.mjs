import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import worker from "./worker.mjs";

const originalFetch = globalThis.fetch;
const originalLog = console.log;
const originalError = console.error;

afterEach(() => {
  globalThis.fetch = originalFetch;
  console.log = originalLog;
  console.error = originalError;
});

test("scheduled trigger sends authenticated POST to the fixed JAS-SI endpoint", async () => {
  let captured;
  globalThis.fetch = async (url, options) => {
    captured = { url, options };
    return new Response(JSON.stringify({
      webhook: { claimed: 2, processed: 1, retry: 1, lease_lost: 0 },
      pending_claims: { claimed: 1, reconciled: 1, retry: 0 },
    }), { status: 200, headers: { "content-type": "application/json" } });
  };
  console.log = () => {};

  await worker.scheduled(
    { scheduledTime: 123456 },
    { JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: "S".repeat(40) },
  );

  assert.equal(captured.url, "https://jas-si.vercel.app/internal/github/reconcile");
  assert.equal(captured.options.method, "POST");
  assert.equal(captured.options.headers.Authorization, "Bearer " + "S".repeat(40));
  assert.equal(captured.options.headers.Accept, "application/json");
});

test("missing or short scheduler secret fails closed before network access", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("{}"); };
  await assert.rejects(
    worker.scheduled({}, {}),
    /scheduler secret is not configured/,
  );
  await assert.rejects(
    worker.scheduled({}, { JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: "short" }),
    /scheduler secret is not configured/,
  );
  assert.equal(called, false);
});

test("non-success API response fails without logging response body", async () => {
  let logged = "";
  globalThis.fetch = async () => new Response("private server diagnostics", { status: 503 });
  console.error = (...args) => { logged += args.join(" "); };
  await assert.rejects(
    worker.scheduled({}, { JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: "S".repeat(40) }),
    /reconciliation request failed/,
  );
  assert.match(logged, /503/);
  assert.doesNotMatch(logged, /private server diagnostics/);
});

test("invalid JSON response is rejected", async () => {
  globalThis.fetch = async () => new Response("not-json", { status: 200 });
  await assert.rejects(
    worker.scheduled({}, { JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET: "S".repeat(40) }),
    /invalid JSON/,
  );
});
