"""Self-test for scripts/xcheck-compare-reports.py (stdlib unittest).

Run from the repo root:  python3 -m unittest discover -s scripts/tests
"""

import importlib.util
import os
import unittest

_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "xcheck-compare-reports.py")
_spec = importlib.util.spec_from_file_location("xcheck_compare_reports", _PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def report(gate=True, **outcomes):
    return {
        "gates": [{"name": "AITP v0.3", "passed": gate}],
        "results": [{"id": k.replace("_", "-"), "outcome": v} for k, v in outcomes.items()],
    }


class Compare(unittest.TestCase):
    def test_identical_outcomes_pass(self):
        rs = report(env_001="pass", a2a_001="skip")
        self.assertEqual(mod.compare(rs, report(env_001="pass", a2a_001="skip"), set()), [])

    def test_a_differing_outcome_fails(self):
        problems = mod.compare(report(tct_013="pass"), report(tct_013="fail"), set())
        self.assertEqual(len(problems), 1)
        self.assertIn("tct-013", problems[0])

    def test_a_failed_verifier_gate_fails_even_when_outcomes_match(self):
        problems = mod.compare(report(env_001="pass"), report(gate=False, env_001="pass"), set())
        self.assertEqual(len(problems), 1)
        self.assertIn("AITP v0.3", problems[0])

    def test_a_known_divergence_is_tolerated(self):
        rs, py = report(del_004="pass"), report(del_004="fail")
        self.assertEqual(mod.compare(rs, py, {"del-004"}), [])

    def test_a_known_divergence_that_agrees_again_fails(self):
        problems = mod.compare(report(del_004="pass"), report(del_004="pass"), {"del-004"})
        self.assertEqual(len(problems), 1)
        self.assertIn("remove it", problems[0])

    def test_a_fixture_missing_from_one_report_fails(self):
        problems = mod.compare(report(env_001="pass", env_002="pass"), report(env_001="pass"), set())
        self.assertEqual(problems, ["env-002: aitp-rs pass, aitp-verifier-py absent"])

    def test_messages_name_the_verifier(self):
        problems = mod.compare(report(env_001="pass"), report(gate=False, env_001="fail"), set(),
                               "aitp-verifier-ts")
        self.assertTrue(problems[0].startswith("aitp-verifier-ts: "))
        self.assertEqual(problems[1], "env-001: aitp-rs pass, aitp-verifier-ts fail")


if __name__ == "__main__":
    unittest.main()
