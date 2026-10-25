"""Self-test for scripts/check-breaking-entry.sh (stdlib unittest).

Run from the repo root:  python3 -m unittest discover -s scripts/tests
"""

import os
import subprocess
import tempfile
import textwrap
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "check-breaking-entry.sh")


def run(changelog):
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(textwrap.dedent(changelog))
    try:
        return subprocess.run(["bash", SCRIPT, f.name], capture_output=True, text=True)
    finally:
        os.unlink(f.name)


class CheckBreakingEntry(unittest.TestCase):
    def test_passes_with_a_breaking_entry_under_unreleased(self):
        r = run("""\
            # Changelog

            ## [Unreleased]

            ### Added

            - a thing

            ### BREAKING

            - `aitp`: removed `Foo`.

            ## [0.1.0]
            """)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_fails_without_a_breaking_heading(self):
        r = run("""\
            ## [Unreleased]

            ### Added

            - a thing
            """)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BREAKING", r.stderr)

    def test_fails_on_an_empty_breaking_heading(self):
        r = run("""\
            ## [Unreleased]

            ### BREAKING

            ### Fixed

            - a fix
            """)
        self.assertNotEqual(r.returncode, 0)

    def test_a_released_breaking_entry_does_not_count(self):
        r = run("""\
            ## [Unreleased]

            ### Fixed

            - a fix

            ## [0.2.0]

            ### BREAKING

            - an old break
            """)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
