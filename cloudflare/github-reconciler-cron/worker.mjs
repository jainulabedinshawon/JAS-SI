const MIN_SECRET_LENGTH = 32;
const EXPECTED_PATH = "/internal/github/reconcile";

function isPreviewBranchHostname(hostname) {
  // Vercel's production branch alias is jas-si-git-main-<team>.vercel.app.
  // Never accept it, even if an operator accidentally configures it as the
  // exact allowed host. Unique production deployment URLs do not match either.
  return /^jas-si-git-(?!main(?:-|\\.))[a-z0-9-]+\\.vercel\\.app$/i.test(hostname);
}

function resolveStagingEndpoint(raw, allowedHostRaw) {
  if (typeof raw !== "string" || raw.length > 512) {
    throw new Error("JAS-SI Staging reconciliation endpoint is not configured");
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
    throw new Error("JAS-SI Staging reconciliation endpoint is invalid");
  }
  if (
    endpoint.protocol !== "https:"
    || !isPreviewBranchHostname(endpoint.hostname)
    || endpoint.hostname.toLowerCase() !== allowedHost
    || endpoint.pathname !== EXPECTED_PATH
    || endpoint.search
    || endpoint.hash
    || endpoint.username
    || endpoint.password
    || endpoint.port
  ) {
    throw new Error("Only an HTTPS JAS-SI Vercel Preview endpoint is allowed");
  }
  return endpoint.toString();
}

export default {
  async scheduled(controller, env) {
    const secret = env?.JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET;
    if (typeof secret !== "string" || secret.length < MIN_SECRET_LENGTH) {
      throw new Error("GitHub reconciliation scheduler secret is not configured");
    }
    const endpoint = resolveStagingEndpoint(
      env?.JAS_SI_RECONCILER_ENDPOINT,
      env?.JAS_SI_RECONCILER_ALLOWED_HOST,
    );

    let response;
    try {
      response = await fetch(endpoint, {
        method: "POST",
        redirect: "error",
        headers: {
          Authorization: `Bearer ${secret}`,
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(20_000),
      });
    } catch {
      throw new Error("JAS-SI reconciliation endpoint could not be reached");
    }

    if (!response.ok) {
      // Never log response bodies: server errors may contain operational detail.
      console.error("JAS-SI reconciliation endpoint returned HTTP", response.status);
      throw new Error("JAS-SI reconciliation request failed");
    }

    let result;
    try {
      result = await response.json();
    } catch {
      throw new Error("JAS-SI reconciliation endpoint returned invalid JSON");
    }

    const webhook = result?.webhook ?? {};
    const pending = result?.pending_claims ?? {};
    console.log(JSON.stringify({
      event: "jas_si_github_reconciliation_completed",
      scheduled_time: controller?.scheduledTime ?? null,
      webhook_claimed: Number(webhook.claimed) || 0,
      webhook_processed: Number(webhook.processed) || 0,
      webhook_retry: Number(webhook.retry) || 0,
      webhook_lease_lost: Number(webhook.lease_lost) || 0,
      pending_claimed: Number(pending.claimed) || 0,
      pending_reconciled: Number(pending.reconciled) || 0,
      pending_retry: Number(pending.retry) || 0,
    }));
  },
};
