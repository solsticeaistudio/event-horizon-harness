from __future__ import annotations

import unittest

from scripts.verify_canonicalization_vectors import DEFAULT_VECTORS, evaluate_vectors


class SharedCanonicalizationVectorTests(unittest.TestCase):
    def test_python_consumes_all_shared_adversarial_vectors(self) -> None:
        results = evaluate_vectors(DEFAULT_VECTORS)
        self.assertEqual(len(results), 26)
        self.assertTrue(results["string-exact-byte-limit"]["accepted"])
        self.assertFalse(results["reject-negative-zero"]["accepted"])
        self.assertFalse(results["reject-nfd-string"]["accepted"])


if __name__ == "__main__":
    unittest.main()
