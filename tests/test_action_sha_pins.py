"""Reject floating refs in every workflow, not just the primary CI file."""
from pathlib import Path
import tempfile
import unittest

from scripts.check_action_sha_pins import check_workflows


class ActionPinPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.file = self.directory / "one.yml"

    def test_immutable_shas_and_local_actions_allowed(self):
        self.file.write_text(
            "steps:\n"
            "  - uses: actions/checkout@" + "a" * 40 + " # v4\n"
            "  - uses: ./local/action\n"
            "  - uses: docker://alpine@sha256:" + "b" * 64 + "\n"
        )
        self.assertEqual(check_workflows(self.directory), [])

    def test_floating_action_tag_rejected(self):
        self.file.write_text("steps:\n  - uses: actions/checkout@v4\n")
        self.assertTrue(check_workflows(self.directory))

    def test_dynamic_and_unpinned_docker_rejected(self):
        self.file.write_text("steps:\n  - uses: " + "$" + "{{ inputs.action }}\n"
                             "  - uses: docker://alpine:latest\n")
        self.assertEqual(len(check_workflows(self.directory)), 2)

    def test_reusable_workflow_tag_rejected(self):
        self.file.write_text("jobs:\n  call:\n    uses: org/repo/.github/workflows/ci.yml@main\n")
        self.assertTrue(check_workflows(self.directory))

    def test_no_workflow_is_error(self):
        self.assertTrue(check_workflows(self.directory))


if __name__ == "__main__":
    unittest.main()
