"""Issue #30: refused peers are not proof that a signer is healthy."""
import unittest
from event_horizon.isolated_authority_lab import wrong_uid_probe, confirm_wrong_uid_rejection


class WrongUidRejectionTests(unittest.TestCase):
    def test_only_known_early_closures_and_explicit_denial(self):
        for exc in (BrokenPipeError(), ConnectionResetError()):
            def failed():
                raise exc
            result = wrong_uid_probe(failed)
            self.assertTrue(confirm_wrong_uid_rejection(
                result, alive=True, authorized_succeeded=True))
        self.assertEqual(wrong_uid_probe(lambda: {
            "ok": False, "result": {"error": "denied"}}), "structured-denial")

    def test_crash_or_failed_authorized_control_is_not_denial(self):
        for alive, ok in ((False, True), (True, False), (False, False)):
            with self.assertRaises(RuntimeError):
                confirm_wrong_uid_rejection("early-peer-disconnect",
                                            alive=alive, authorized_succeeded=ok)

    def test_other_transport_failures_propagate(self):
        for exc in (TimeoutError(), EOFError(), OSError("unexpected")):
            def failed():
                raise exc
            with self.assertRaises(type(exc)):
                wrong_uid_probe(failed)

    def test_admitted_peer_is_failure(self):
        with self.assertRaises(RuntimeError):
            wrong_uid_probe(lambda: {"ok": True, "result": {}})
