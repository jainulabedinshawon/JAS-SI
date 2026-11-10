"""Standalone JAS-SI plan catalogue and quota policy primitives.

This module intentionally does not process payments or maintain balances.
The free allowance is configurable; paid prices remain unpublished until
infrastructure cost and payment-provider readiness have been verified.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Plan:
    plan_id: str
    name: str
    monthly_units: int | None
    price_minor: int | None
    currency: str | None
    purchasable: bool
    features: tuple[str, ...]


def _free_monthly_units() -> int:
    raw = os.getenv("JAS_SI_FREE_MONTHLY_UNITS", "100")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise RuntimeError("JAS_SI_FREE_MONTHLY_UNITS must be a positive integer") from None
    if value < 1 or value > 1_000_000:
        raise RuntimeError("JAS_SI_FREE_MONTHLY_UNITS must be between 1 and 1000000")
    return value


def get_plan_catalog() -> dict:
    """Return public plan metadata without inventing prices or payment status."""
    free_units = _free_monthly_units()
    plans = (
        Plan(
            plan_id="free",
            name="Free",
            monthly_units=free_units,
            price_minor=0,
            currency=None,
            purchasable=True,
            features=(
                "Developer portal and API documentation",
                "Synthetic demo",
                "Basic authorization and verification API",
                "Tenant-scoped usage reporting",
            ),
        ),
        Plan(
            plan_id="starter",
            name="Starter",
            monthly_units=None,
            price_minor=None,
            currency=None,
            purchasable=False,
            features=("Higher usage allowance", "API key management", "Usage history"),
        ),
        Plan(
            plan_id="pro",
            name="Pro",
            monthly_units=None,
            price_minor=None,
            currency=None,
            purchasable=False,
            features=("Higher rate limits", "Advanced verification capacity", "Priority support"),
        ),
        Plan(
            plan_id="enterprise",
            name="Enterprise",
            monthly_units=None,
            price_minor=None,
            currency=None,
            purchasable=False,
            features=("Custom usage", "Security and audit options", "Integration support"),
        ),
    )
    return {
        "catalog_version": "1.0",
        "billing_mode": "standalone_limited",
        "payment_status": "not_connected",
        "currency_policy": "Prices are unpublished until cost and provider validation.",
        "plans": [asdict(plan) for plan in plans],
        "disclaimer": (
            "The Free allowance is a configurable product limit, not a monetary credit. "
            "Paid plans are preview-only and cannot be purchased or grant entitlements."
        ),
    }


def evaluate_monthly_quota(*, monthly_limit: int, used_units: int, requested_units: int = 1) -> dict:
    """Pure quota decision primitive; callers must supply durable tenant usage."""
    if monthly_limit < 1 or used_units < 0 or requested_units < 1:
        raise ValueError("Quota values must be positive and usage cannot be negative")
    remaining = max(0, monthly_limit - used_units)
    allowed = requested_units <= remaining
    return {
        "allowed": allowed,
        "monthly_limit": monthly_limit,
        "used_units": used_units,
        "requested_units": requested_units,
        "remaining_units": remaining if allowed else 0,
        "reason": "within_quota" if allowed else "monthly_quota_exceeded",
    }
