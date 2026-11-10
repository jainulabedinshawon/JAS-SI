"""Tests for the standalone plan catalogue and quota policy."""
import os
from unittest import TestCase
from unittest.mock import patch

from jas_si_agent.billing_catalog import evaluate_monthly_quota, get_plan_catalog


class TestBillingCatalog(TestCase):
    def test_catalog_exposes_free_and_limited_paid_tiers(self):
        with patch.dict(os.environ, {"JAS_SI_FREE_MONTHLY_UNITS": "125"}):
            catalog = get_plan_catalog()
        self.assertEqual(catalog["payment_status"], "not_connected")
        plans = {plan["plan_id"]: plan for plan in catalog["plans"]}
        self.assertEqual(plans["free"]["monthly_units"], 125)
        self.assertEqual(plans["free"]["price_minor"], 0)
        self.assertTrue(plans["free"]["purchasable"])
        for plan_id in ("starter", "pro", "enterprise"):
            self.assertFalse(plans[plan_id]["purchasable"])
            self.assertIsNone(plans[plan_id]["price_minor"])
            self.assertIsNone(plans[plan_id]["monthly_units"])

    def test_invalid_free_allowance_fails_closed(self):
        with patch.dict(os.environ, {"JAS_SI_FREE_MONTHLY_UNITS": "0"}):
            with self.assertRaises(RuntimeError):
                get_plan_catalog()

    def test_quota_allows_request_within_limit(self):
        result = evaluate_monthly_quota(
            monthly_limit=100, used_units=98, requested_units=2
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["remaining_units"], 2)

    def test_quota_denies_request_over_limit(self):
        result = evaluate_monthly_quota(
            monthly_limit=100, used_units=100, requested_units=1
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "monthly_quota_exceeded")
        self.assertEqual(result["remaining_units"], 0)

    def test_invalid_quota_values_are_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_monthly_quota(monthly_limit=0, used_units=0)
        with self.assertRaises(ValueError):
            evaluate_monthly_quota(monthly_limit=100, used_units=-1)
