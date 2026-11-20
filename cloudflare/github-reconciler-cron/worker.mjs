const RECONCILE_ENDPOINT = "https://jas-si.vercel.app/internal/github/reconcile";
const MIN_SECRET_LENGTH = 32;

export default {
  async scheduled(controller, env) {
    const secret = env?.JAS_SI_GITHUB_RECONCILER_TRIGGER_SECRET;
    if (typeof secret !== "string" || secret.length < MIN_SECRET_LENGTH) {
      throw new Error("GitHub reconciliation scheduler secret is not configured");
    }

    let response;
    try {
      response = await fetch(RECONCILE_ENDPOINT, {
        method: "POST",
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
