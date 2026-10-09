from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

import requests

from event_horizon.adapters import TransactionState
from event_horizon.adapters.http import HTTPAdapter, HTTPConfig


class HTTPAdapterBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.session_patch = patch("event_horizon.adapters.http.requests.Session")
        self.session_factory = self.session_patch.start()
        self.addCleanup(self.session_patch.stop)
        self.session = self.session_factory.return_value
        self.session.request.return_value = Mock(
            status_code=200, text="ok", headers={"X-Request-ID": "synthetic-123"}
        )
        self.adapter = HTTPAdapter(HTTPConfig(base_url="https://example.invalid/api"))
        self.addCleanup(self.adapter.close)

    def test_requests_adapter_is_mounted_without_name_collision(self):
        self.assertEqual(self.session.mount.call_count, 2)
        mounted = self.session.mount.call_args_list[0].args[1]
        self.assertNotIn("POST", mounted.max_retries.allowed_methods)
        self.assertNotIn("DELETE", mounted.max_retries.allowed_methods)

    def test_prepare_does_not_write_and_abort_never_sends_delete(self):
        result = self.adapter.prepare("txn-1", {"endpoint": "object", "type": "POST", "data": {"value": 1}})
        self.assertTrue(result.success, result.error)
        self.assertEqual(self.session.request.call_args.kwargs["method"], "HEAD")
        self.assertFalse(self.session.request.call_args.kwargs["allow_redirects"])
        self.assertEqual(self.adapter.get_status("txn-1"), TransactionState.PREPARED)
        result = self.adapter.abort("txn-1", {})
        self.assertTrue(result.success)
        self.assertEqual(self.adapter.get_status("txn-1"), TransactionState.ABORTED)
        self.assertEqual(self.session.request.call_count, 1)
        self.session.delete.assert_not_called()

    def test_commit_dispatches_write_once_and_marks_complete(self):
        op = {"endpoint": "object", "type": "POST", "data": {"value": 1}}
        self.assertTrue(self.adapter.prepare("txn-1", op).success)
        result = self.adapter.commit("txn-1", {})
        self.assertTrue(result.success, result.error)
        self.assertEqual(self.adapter.get_status("txn-1"), TransactionState.COMMITTED)
        self.assertEqual(self.session.request.call_count, 2)
        self.assertEqual(self.session.request.call_args.kwargs["method"], "POST")
        self.assertFalse(self.session.request.call_args.kwargs["allow_redirects"])
        self.assertFalse(self.adapter.commit("txn-1", {}).success)
        self.assertEqual(self.session.request.call_count, 2)

    def test_lost_response_is_indeterminate_and_never_retried(self):
        self.session.request.side_effect = [
            Mock(status_code=200, text="ok", headers={}),
            requests.Timeout("lost response after dispatch"),
        ]
        self.assertTrue(self.adapter.prepare("txn-1", {"endpoint": "item", "type": "POST"}).success)
        result = self.adapter.commit("txn-1", {})
        self.assertFalse(result.success)
        self.assertEqual(self.adapter.get_status("txn-1"), TransactionState.INDETERMINATE)
        self.assertFalse(self.adapter.abort("txn-1", {}).success)
        self.assertFalse(self.adapter.commit("txn-1", {}).success)
        self.assertEqual(self.session.request.call_count, 2)

    def test_redirects_and_unsafe_methods_fail_preflight(self):
        self.assertFalse(self.adapter.prepare("del", {"endpoint": "item", "type": "DELETE"}).success)
        self.assertFalse(self.adapter.prepare("bad", {"endpoint": "../private", "type": "POST"}).success)
        self.assertEqual(self.session.request.call_count, 0)
        self.session.request.return_value = Mock(status_code=302, text="redirect", headers={})
        self.assertFalse(self.adapter.prepare("redir", {"endpoint": "item", "type": "POST"}).success)


if __name__ == "__main__":
    unittest.main()
