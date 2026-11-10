"""Tests for standalone plan catalogue and public plan endpoint."""
import os
from unittest import TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient
from jas_si_agent import api
from jas_si_agent.billing_catalog import get_free_monthly_units, get_plan_catalog


class TestBillingCatalog(TestCase):
    def test_catalog_exposes_free_and_preview_paid_tiers(self):
        with patch.dict(os.environ, {"JAS_SI_FREE_MONTHLY_UNITS": "125"}):
            catalog = get_plan_catalog()
        plans = {plan["plan_id"]: plan for plan in catalog["plans"]}
        self.assertEqual(plans["free"]["monthly_units"], 125)
        self.assertEqual(plans["free"]["price_minor"], 0)
        for plan_id in ("starter", "pro", "enterprise"):
            self.assertFalse(plans[plan_id]["purchasable"])
            self.assertIsNone(plans[plan_id]["price_minor"])
            self.assertIsNone(plans[plan_id]["monthly_units"])

    def test_invalid_allowance_fails_closed(self):
        with patch.dict(os.environ, {"JAS_SI_FREE_MONTHLY_UNITS": "0"}):
            with self.assertRaises(RuntimeError):
                get_free_monthly_units()

    def test_public_plans_endpoint(self):
        response = TestClient(api.app).get("/plans")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["payment_status"], "not_connected")
