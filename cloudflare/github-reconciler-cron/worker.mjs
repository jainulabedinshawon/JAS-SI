const MIN_SECRET_LENGTH = 32;
const MAX_WEBHOOK_BODY_BYTES = 2_000_000;
const WEBHOOK_PATH = "/webhooks/github";

function isPreviewBranchHostname(hostname) {
  // Vercel's production branch alias is jas-si-git-main-<team>.vercel.app.
  // Never accept it, even if an operator accidentally configures it as the
  // exact allowed host. Unique production deployment URLs do not match either.
  return /^jas-si-git-(?!main(?:-|\.))[a-z0-9-]+\.vercel\.app$/i.test(hostname);
}

function resolvePreviewEndpoint(raw, allowedHostRaw, expectedPath) {
  if (typeof raw !== "string" || raw.length > 512) {
    throw new Error("JAS-SI Staging endpoint is not configured");
  }
  if (typeof allowedHostRaw !== "string" || allowedHostRaw.length > 253) {
    throw new Error("Exact JAS-SI Staging endpoint host is not configured");
  }
  const allowedHost = allowedHostRaw.toLowerCase();
  if (!isPreviewBranchHostname(allowedHost)) {
    throw new Error("Exact JAS-SI Vercel Preview hostname is invalid");
  }
  let endpoint;
  try {
    endpoint = new URL(raw);
  } catch {
    throw new Error("JAS-SI Staging endpoint is invalid");
  }
  if (
    endpoint.protocol !== "https:"
    || !isPreviewBranchHostname(endpoint.hostname)
    || endpoint.hostname.toLowerCase() !== allowedHost
    || endpoint.pathname !== expectedPath
    || endpoint.search
    || endpoint.hash
    || endpoint.username
    || endpoint.password
    || endpoint.port
  ) {
    throw new Error("Only the exact HTTPS JAS-SI Vercel Preview endpoint is allowed");
  }
  return endpoint.toString();
}

function hasStrongSecret(value) {
  return typeof value === "string" && new TextEncoder().encode(value).length >= MIN_SECRET_LENGTH;
}

function constantTimeEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function decodeHex(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) return null;
  const output = new Uint8Array(32);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

async function verifyWebhookSignature(secret, rawBody, signatureHeader) {
  if (!hasStrongSecret(secret)) return false;
  if (typeof signatureHeader !== "string" || !signatureHeader.startsWith("sha256=")) {
    return false;
  }
  const supplied = decodeHex(signatureHeader.slice(7));
  if (!supplied) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, rawBody));
  return constantTimeEqual(expected, supplied);
}

async function readBoundedBody(request) {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength)) return { error: 400 };
    if (Number(declaredLength) > MAX_WEBHOOK_BODY_BYTES) return { error: 413 };
  }
  if (!request.body) return { body: new Uint8Array() };
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_WEBHOOK_BODY_BYTES) {
        await reader.cancel();
        return { error: 413 };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { body };
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

async function forwardGitHubWebhook(request, env) {
  const webhookSecret = env?.JAS_SI_GITHUB_WEBHOOK_SECRET;
  const protectionSecret = env?.JAS_SI_VERCEL_PROTECTION_BYPASS_SECRET;
  if (!hasStrongSecret(webhookSecret)) {
    return jsonResponse(503, { error: "Webhook verification is not configured" });
  }
  if (!hasStrongSecret(protectionSecret)) {
    return jsonResponse(503, { error: "Preview access is not configured" });
  }

  let endpoint;
  try {
    endpoint = resolvePreviewEndpoint(
      env?.JAS_SI_GITHUB_WEBHOOK_FORWARD_ENDPOINT,
      env?.JAS_SI_RECONCILER_ALLOWED_HOST,
      WEBHOOK_PATH,
    );
  } catch {
    return jsonResponse(503, { error: "Staging webhook destination is not configured" });
  }

  const parsedBody = await readBoundedBody(request);
  if (parsedBody.error) {
    return jsonResponse(parsedBody.error, { error: parsedBody.error === 413 ? "Payload too large" : "Invalid content length" });
  }

  const signature = request.headers.get("x-hub-signature-256") || "";
  let validSignature = false;
  try {
    validSignature = await verifyWebhookSignature(webhookSecret, parsedBody.body, signature);
  } catch {
    return jsonResponse(503, { error: "Webhook signature verification is unavailable" });
  }
  if (!validSignature) {
    return jsonResponse(401, { error: "Webhook signature is invalid" });
  }

  const delivery = request.headers.get("x-github-delivery") || "";
  const event = request.headers.get("x-github-event") || "";
  if (!/^[A-Za-z0-9-]{1,128}$/.test(delivery) || !/^[A-Za-z0-9_-]{1,64}$/.test(event)) {
    return jsonResponse(400, { error: "GitHub delivery headers are invalid" });
  }

  const headers = new Headers({
    "accept": "application/json",
    "content-type": request.headers.get("content-type") || "application/json",
    "x-github-delivery": delivery,
    "x-github-event": event,
    "x-hub-signature-256": signature,
    "x-vercel-protection-bypass": protectionSecret,
  });

  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: parsedBody.body,
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    return jsonResponse(502, { error: "Staging webhook endpoint could not be reached" });
  }
  if (!response.ok) {
    console.error("JAS-SI webhook endpoint returned HTTP", response.status);
    return jsonResponse(502, { error: "Staging webhook endpoint rejected the delivery" });
  }
  return jsonResponse(202, { accepted: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/github/webhook" || url.search || url.hash) {
      return jsonResponse(404, { error: "Not found" });
    }
    if (request.method !== "POST") {
      return new Response("Method not allowed", {
        status: 405,
        headers: { allow: "POST", "cache-control": "no-store" },
      });
    }
    return forwardGitHubWebhook(request, env);
  },

};
