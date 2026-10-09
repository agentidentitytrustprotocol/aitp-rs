"""Self-test for scripts/check-docs.py (stdlib unittest, no pytest).

Run from the repo root:  python3 -m unittest discover -s scripts/tests

Each case builds a throwaway repository in a temp dir (plus a fake spec git
repo for the § check), seeds one defect, and asserts the checker fails on
exactly that defect -- and that the unseeded tree passes, so a checker that
fails on everything cannot pass this suite either.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

CHECKER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "check-docs.py")

PROTECTED_STUBS = {
    "docs/sdk-python.md": """\
        # Python SDK
        ## Build
        ## Mutual handshake (RFC-AITP-0004)
        <a id="tct-verification-rfc-aitp-0005-9"></a>
        ## TCT verification (RFC-AITP-0005 §7.2)
        ## Delegation (RFC-AITP-0006)
        ## Additional capabilities (on by default)
        ## OIDC identity (RFC-AITP-0002)
        ## SPKI cert pinning (HPKP-style, feature `spki-pinning`)
        """,
    "docs/conformance.md": "# Conformance\n## v0.2 conformance matrix\n",
    "docs/key-management.md": "# Keys\n## Rotation\n",
    "docs/architecture.md": "# Arch\n## The two signing profiles\n## Debugging a TCT\n",
    **{f"docs/{name}.md": f"# {name}\n" for name in (
        "sdk-node", "handshake-transcripts", "jcs", "deployment",
        "transport-hardening", "tct-renewal", "multihop-delegation",
        "session-bundle", "README")},
}

FAKE_RFC = """\
# RFC-AITP-0005: TCT

## 7. Verification

### 7.2 Verifier algorithm

```
## 99. Not a heading (inside a fence)
```
"""


def git(cwd, *args):
    subprocess.run(["git", "-C", cwd, *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class CheckDocsTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="check-docs-test-")
        cls.spec = os.path.join(cls.tmp, "spec")
        os.makedirs(os.path.join(cls.spec, "rfcs"))
        with open(os.path.join(cls.spec, "rfcs", "RFC-AITP-0005-tct.md"), "w") as fh:
            fh.write(FAKE_RFC)
        git(cls.spec, "init", "-q")
        git(cls.spec, "add", ".")
        git(cls.spec, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
            "commit", "-q", "-m", "fake spec")
        cls.pin = subprocess.run(["git", "-C", cls.spec, "rev-parse", "HEAD"],
                                 check=True, stdout=subprocess.PIPE).stdout.decode().strip()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def make_repo(self, extra=None):
        root = tempfile.mkdtemp(dir=self.tmp)
        files = {
            "tests/schemas/SPEC_VERSION": self.pin + "\n",
            "README.md": """\
                # Repo
                See [arch](docs/architecture.md#debugging-a-tct) and
                [build](docs/sdk-python.md#build), per RFC-AITP-0005 §7.2.
                Old anchor: [tct](docs/sdk-python.md#tct-verification-rfc-aitp-0005-9).
                ## Same
                ## Same
                [dup](#same-1) [self](#repo)
                ```
                [ignored](missing.md) RFC-AITP-0005 §42
                ```
                Inline `[ignored](missing.md)` is not a link.
                """,
            **PROTECTED_STUBS,
        }
        files.update(extra or {})
        for rel, body in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(textwrap.dedent(body))
        return root

    def run_checker(self, root, spec=None):
        r = subprocess.run([sys.executable, CHECKER, "--root", root,
                            "--spec", spec or self.spec],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return r.returncode, r.stdout.decode()

    def test_clean_tree_passes(self):
        code, out = self.run_checker(self.make_repo())
        self.assertEqual(code, 0, out)
        self.assertIn("0 error(s)", out)
        self.assertIn("2 § citation(s)", out)

    def test_broken_anchor_fails(self):
        root = self.make_repo({"docs/README.md": "[x](architecture.md#no-such-heading)\n"})
        code, out = self.run_checker(root)
        self.assertEqual(code, 1, out)
        self.assertIn("docs/README.md:1:", out)
        self.assertIn("no anchor #no-such-heading", out)

    def test_missing_file_fails(self):
        root = self.make_repo({"examples/README.md": "[x](../docs/gone.md)\n"})
        code, out = self.run_checker(root)
        self.assertEqual(code, 1, out)
        self.assertIn("examples/README.md:1:", out)

    def test_bad_section_citation_fails(self):
        root = self.make_repo({"docs/README.md": "Per RFC-AITP-0005 §9.9, verify.\n"})
        code, out = self.run_checker(root)
        self.assertEqual(code, 1, out)
        self.assertIn("RFC-AITP-0005 §9.9", out)
        self.assertIn("docs/README.md:1:", out)

    def test_fenced_heading_in_spec_does_not_count(self):
        root = self.make_repo({"docs/README.md": "RFC-AITP-0005 §99\n"})
        code, out = self.run_checker(root)
        self.assertEqual(code, 1, out)

    def test_missing_spec_skips_citation_check(self):
        root = self.make_repo({"docs/README.md": "RFC-AITP-0005 §9.9\n"})
        code, out = self.run_checker(root, spec=os.path.join(self.tmp, "absent"))
        self.assertEqual(code, 0, out)
        self.assertIn("SKIPPED", out)

    def test_banned_string_fails(self):
        root = self.make_repo({"docs/README.md": "```js\nconst k = generateP256();\n```\n"})
        code, out = self.run_checker(root)
        self.assertEqual(code, 1, out)
        self.assertIn("banned string `generateP256`", out)

    def test_protected_anchor_removed_fails(self):
        root = self.make_repo({"docs/key-management.md": "# Keys\n## Key rotation\n"})
        code, out = self.run_checker(root)
        self.assertEqual(code, 1, out)
        self.assertIn("protected anchor #rotation", out)

    def test_html_comment_is_mdx_error(self):
        root = self.make_repo({"docs/README.md": "text <!-- hidden -->\n"})
        code, out = self.run_checker(root)
        self.assertEqual(code, 1, out)
        self.assertIn("MDX", out)

    def test_placeholder_is_warning_only(self):
        root = self.make_repo({"docs/README.md": "Use <token> here; `<ok>` in code.\n"})
        code, out = self.run_checker(root)
        self.assertEqual(code, 0, out)
        self.assertIn("warning: docs/README.md:1:", out)
        self.assertNotIn("<ok>", out)


if __name__ == "__main__":
    unittest.main()
