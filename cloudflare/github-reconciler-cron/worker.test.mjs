import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import worker from "./worker.mjs";

const originalFetch = globalThis.fetch;
const originalLog = console.log;
const originalError = console.error;
const webhookEndpoint = "https://jas-si-git-staging-example.vercel.app/webhooks/github";
const allowedHost = "jas-si-git-staging-example.vercel.app";
const secret = "S".repeat(40);
const protectionSecret = "P".repeat(48);
const env = (extra = {}) => ({
  JAS_SI_VERCEL_PROTECTION_BYPASS_SECRET: protectionSecret,
  JAS_SI_GITHUB_WEBHOOK_SECRET: secret,
  JAS_SI_GITHUB_WEBHOOK_FORWARD_ENDPOINT: webhookEndpoint,
  JAS_SI_GITHUB_WEBHOOK_ALLOWED_HOST: allowedHost,
  ...extra,
});

async function signBody(body, key = secret) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, body));
  return "sha256=" + Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

test("worker has no scheduler handler; reconciliation belongs to the isolated Render worker", () => {
  assert.equal(worker.scheduled, undefined);
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  console.log = originalLog;
  console.error = originalError;
});

test("webhook proxy validates raw-body HMAC then forwards original delivery headers and protection header", async () => {
  const raw = new TextEncoder().encode(JSON.stringify({ action: "created", installation: { id: 123 } }));
  const signature = await signBody(raw);
  let captured;
  globalThis.fetch = async (url, options) => {
    captured = { url, options };
    return new Response("{}", { status: 202 });
  };
  const response = await worker.fetch(new Request("https://worker.example/github/webhook", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-github-delivery": "delivery-123",
      "x-github-event": "installation",
      "x-hub-signature-256": signature,
    },
    body: raw,
  }), env());
  assert.equal(response.status, 202);
  assert.equal(captured.url, webhookEndpoint);
  assert.equal(captured.options.method, "POST");
  assert.deepEqual(new Uint8Array(captured.options.body), raw);
  assert.equal(captured.options.headers.get("x-github-delivery"), "delivery-123");
  assert.equal(captured.options.headers.get("x-github-event"), "installation");
  assert.equal(captured.options.headers.get("x-hub-signature-256"), signature);
  assert.equal(captured.options.headers.get("x-vercel-protection-bypass"), protectionSecret);
});

test("invalid webhook signature is rejected without forwarding", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("{}", { status: 202 }); };
  const response = await worker.fetch(new Request("https://worker.example/github/webhook", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-github-delivery": "delivery-123",
      "x-github-event": "installation",
      "x-hub-signature-256": "sha256=" + "0".repeat(64),
    },
    body: "{}",
  }), env());
  assert.equal(response.status, 401);
  assert.equal(called, false);
});

test("webhook proxy fails closed on missing bypass config, bad headers, and oversized body", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response("{}", { status: 202 }); };
  const raw = new TextEncoder().encode("{}");
  const signature = await signBody(raw);
  const base = {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-github-delivery": "delivery-123",
      "x-github-event": "installation",
      "x-hub-signature-256": signature,
    },
    body: raw,
  };
  const missingBypass = await worker.fetch(new Request("https://worker.example/github/webhook", base), env({
    JAS_SI_VERCEL_PROTECTION_BYPASS_SECRET: undefined,
  }));
  assert.equal(missingBypass.status, 503);
  const invalidDelivery = await worker.fetch(new Request("https://worker.example/github/webhook", {
    ...base,
    headers: { ...base.headers, "x-github-delivery": "bad delivery id" },
  }), env());
  assert.equal(invalidDelivery.status, 400);
  const oversized = await worker.fetch(new Request("https://worker.example/github/webhook", {
    method: "POST",
    headers: { ...base.headers, "content-length": "2000001" },
    body: raw,
  }), env());
  assert.equal(oversized.status, 413);
  assert.equal(called, false);
});

test("webhook proxy rejects unexpected routes and methods", async () => {
  const notFound = await worker.fetch(new Request("https://worker.example/not-webhook", { method: "POST" }), env());
  assert.equal(notFound.status, 404);
  const method = await worker.fetch(new Request("https://worker.example/github/webhook", { method: "GET" }), env());
  assert.equal(method.status, 405);
});

