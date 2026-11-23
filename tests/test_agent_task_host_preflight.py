from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import MagicMock, patch

from jas_si_agent.agent_task_host_preflight import (
    AgentHostPreflightError,
    verify_agent_host_database_access,
)


WORKER_FUNCTIONS = (
    "public.jas_si_agent_task_claim(uuid,integer)",
    "public.jas_si_agent_task_renew(uuid,uuid,bigint,integer)",
    "public.jas_si_agent_task_ack_cancel(uuid,uuid,bigint)",
    "public.jas_si_agent_task_report(uuid,uuid,bigint,jsonb)",
    "public.jas_si_agent_task_fail(uuid,uuid,bigint,text,integer)",
)
VERIFIER_FUNCTIONS = (
    "public.jas_si_agent_task_verification_claim(integer,integer)",
    "public.jas_si_agent_task_verification_release(uuid,uuid,uuid)",
    "public.jas_si_agent_task_finalize_success(uuid,uuid,uuid,uuid,text,bytea,jsonb,timestamptz)",
)


class AgentTaskHostPreflightTests(unittest.TestCase):
    def setUp(self):
        self.cursor = MagicMock()
        self.connection = MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.cursor.return_value.__enter__.return_value = self.cursor
        self.psycopg = types.SimpleNamespace(connect=MagicMock(return_value=self.connection))
        self.patch = patch.dict(sys.modules, {"psycopg": self.psycopg})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    @staticmethod
    def valid_row(login, role, routine_count):
        return (
            login, role, True, True, False, False,
            *([True] * routine_count),
            *([False] * 22),
        )

    def test_worker_preflight_checks_role_and_all_worker_routines(self):
        self.cursor.fetchone.return_value = self.valid_row(
            "jas_si_agent_worker_login", "jas_si_agent_worker", 5
        )
        verify_agent_host_database_access(
            "postgresql://not-logged",
            capability_role="jas_si_agent_worker",
            expected_login="jas_si_agent_worker_login",
            required_functions=WORKER_FUNCTIONS,
        )
        self.psycopg.connect.assert_called_once_with(
            "postgresql://not-logged", connect_timeout=5
        )
        query, params = self.cursor.execute.call_args.args
        self.assertIn("session_user", query)
        self.assertIn("current_user", query)
        self.assertEqual(params, ("jas_si_agent_verifier", *WORKER_FUNCTIONS))
        self.assertEqual(
            self.cursor.execute.call_args_list[0].args[0],
            "SET ROLE jas_si_agent_worker",
        )

    def test_verifier_preflight_checks_separate_role_and_routines(self):
        self.cursor.fetchone.return_value = self.valid_row(
            "jas_si_agent_verifier_login", "jas_si_agent_verifier", 3
        )
        verify_agent_host_database_access(
            "postgresql://not-logged",
            capability_role="jas_si_agent_verifier",
            expected_login="jas_si_agent_verifier_login",
            required_functions=VERIFIER_FUNCTIONS,
        )
        self.assertEqual(
            self.cursor.execute.call_args.args[1],
            ("jas_si_agent_worker", *VERIFIER_FUNCTIONS),
        )

    def test_rejects_membership_in_opposite_capability_role(self):
        row = list(self.valid_row(
            "jas_si_agent_worker_login", "jas_si_agent_worker", 5
        ))
        row[4] = True
        self.cursor.fetchone.return_value = tuple(row)
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_agent_worker",
                expected_login="jas_si_agent_worker_login",
                required_functions=WORKER_FUNCTIONS,
            )

    def test_rejects_unsafe_database_login_attributes(self):
        row = list(self.valid_row("jas_si_agent_worker_login", "jas_si_agent_worker", 5))
        row[2] = False
        self.cursor.fetchone.return_value = tuple(row)
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access("postgresql://not-logged", capability_role="jas_si_agent_worker", expected_login="jas_si_agent_worker_login", required_functions=WORKER_FUNCTIONS)

    def test_rejects_unsafe_capability_role_attributes(self):
        row = list(self.valid_row("jas_si_agent_worker_login", "jas_si_agent_worker", 5))
        row[3] = False
        self.cursor.fetchone.return_value = tuple(row)
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access("postgresql://not-logged", capability_role="jas_si_agent_worker", expected_login="jas_si_agent_worker_login", required_functions=WORKER_FUNCTIONS)

    def test_rejects_unapproved_role_membership(self):
        row = list(self.valid_row("jas_si_agent_worker_login", "jas_si_agent_worker", 5))
        row[5] = True
        self.cursor.fetchone.return_value = tuple(row)
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access("postgresql://not-logged", capability_role="jas_si_agent_worker", expected_login="jas_si_agent_worker_login", required_functions=WORKER_FUNCTIONS)

    def test_rejects_verifier_direct_task_insert_privilege(self):
        row = list(self.valid_row(
            "jas_si_agent_verifier_login", "jas_si_agent_verifier", 3
        ))
        row[6 + 3 + 1] = True  # task-table INSERT
        self.cursor.fetchone.return_value = tuple(row)
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_agent_verifier",
                expected_login="jas_si_agent_verifier_login",
                required_functions=VERIFIER_FUNCTIONS,
            )

    def test_rejects_verifier_evidence_column_update(self):
        row = list(self.valid_row(
            "jas_si_agent_verifier_login", "jas_si_agent_verifier", 3
        ))
        row[6 + 3 + 11 + 9] = True
        self.cursor.fetchone.return_value = tuple(row)
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_agent_verifier",
                expected_login="jas_si_agent_verifier_login",
                required_functions=VERIFIER_FUNCTIONS,
            )

    def test_rejects_missing_role_membership(self):
        self.cursor.execute.side_effect = RuntimeError(
            "permission denied: cannot SET ROLE"
        )
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_agent_worker",
                expected_login="jas_si_agent_worker_login",
                required_functions=WORKER_FUNCTIONS,
            )

    def test_rejects_missing_function_privilege(self):
        row = list(self.valid_row(
            "jas_si_agent_worker_login", "jas_si_agent_worker", 5
        ))
        row[6] = False
        self.cursor.fetchone.return_value = tuple(row)
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_agent_worker",
                expected_login="jas_si_agent_worker_login",
                required_functions=WORKER_FUNCTIONS,
            )

    def test_rejects_direct_worker_table_insert(self):
        row = list(self.valid_row(
            "jas_si_agent_worker_login", "jas_si_agent_worker", 5
        ))
        row[6 + 5 + 1] = True
        self.cursor.fetchone.return_value = tuple(row)
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_agent_worker",
                expected_login="jas_si_agent_worker_login",
                required_functions=WORKER_FUNCTIONS,
            )

    def test_rejects_worker_truncate_privilege(self):
        row = list(self.valid_row(
            "jas_si_agent_worker_login", "jas_si_agent_worker", 5
        ))
        row[6 + 5 + 4] = True
        self.cursor.fetchone.return_value = tuple(row)
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_agent_worker",
                expected_login="jas_si_agent_worker_login",
                required_functions=WORKER_FUNCTIONS,
            )

    def test_rejects_worker_column_level_select(self):
        row = list(self.valid_row(
            "jas_si_agent_worker_login", "jas_si_agent_worker", 5
        ))
        row[6 + 5 + 7] = True
        self.cursor.fetchone.return_value = tuple(row)
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_agent_worker",
                expected_login="jas_si_agent_worker_login",
                required_functions=WORKER_FUNCTIONS,
            )

    def test_redacts_database_driver_errors(self):
        self.psycopg.connect.side_effect = RuntimeError(
            "password=do-not-leak"
        )
        with self.assertRaisesRegex(
            AgentHostPreflightError, "preflight failed"
        ) as caught:
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_agent_worker",
                expected_login="jas_si_agent_worker_login",
                required_functions=WORKER_FUNCTIONS,
            )
        self.assertNotIn("do-not-leak", str(caught.exception))

    def test_rejects_unknown_role_and_untrusted_routine_signature(self):
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_admin",
                expected_login="jas_si_admin_login",
                required_functions=WORKER_FUNCTIONS,
            )
        with self.assertRaises(AgentHostPreflightError):
            verify_agent_host_database_access(
                "postgresql://not-logged",
                capability_role="jas_si_agent_worker",
                expected_login="jas_si_agent_worker_login",
                required_functions=("public.anything(); DROP TABLE x; --",),
            )


if __name__ == "__main__":
    unittest.main()
