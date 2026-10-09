#!/usr/bin/env python3
"""Drift guard for the aitp-rs documentation (`make docs-check`).

Python 3 standard library only. Checks, in order:

  1. links      Every relative Markdown link resolves to a file or directory
                in this repository (exact case, so a link that only works on a
                case-insensitive filesystem still fails), and every `#anchor`
                -- same-file or cross-file -- resolves against GitHub's heading
                slug rules or an explicit `<a id="...">` anchor.
  2. citations  Every `RFC-AITP-NNNN §x.y` (and `RFC-NNNN §x.y`, when NNNN is
                an AITP RFC number) names a numbered heading that exists in
                that RFC *at the spec commit pinned by tests/schemas/
                SPEC_VERSION* -- not the spec's current main. Needs a spec
                checkout ($AITP_SPEC, else ../agentidentitytrustprotocol);
                when that is absent or lacks the pinned commit the check
                prints a notice and is skipped, not failed.
  3. protected  Anchors other repositories link to (the spec repo and
                aitp-playground) must keep existing. Renaming one of these
                headings breaks a link this repository cannot see.
  4. banned     Stale strings from earlier releases that must not reappear in
                the docs (CHANGELOG.md and plans/ are history and not scanned).
  5. mdx        README.md and docs/**/*.md are synced into the website as MDX.
                Constructs that the website's escape-mdx.py cannot neutralise
                (HTML comments, unclosed HTML tags with attributes) are
                errors; raw `<placeholder>` tokens and bare `{`/`}` in prose
                are warnings (escape-mdx handles them for the site, but GitHub
                silently drops an unknown `<placeholder>` tag from the
                rendered page, so they are still worth wrapping in backticks).

Fenced code blocks and inline code spans are ignored when collecting links,
headings and MDX hazards. Banned strings are searched everywhere, code
included, because stale API names mostly live in code samples.

Exit status: 0 when no check reports an error, 1 otherwise. Every error is
printed as `path:line: message`.

Usage:
  python3 scripts/check-docs.py [--root DIR] [--spec DIR]

Modelled on the spec repo's scripts/check-doc-coherence.sh (slug rules,
§-citation resolution) and aitp-website's scripts/check-links.py.
"""

import argparse
import os
import re
import subprocess
import sys
from urllib.parse import unquote

# ── Configuration ────────────────────────────────────────────────────────────

# Directory names never descended into, wherever they appear.
SKIP_DIR_NAMES = {
    ".git", "target", "node_modules", ".venv", "venv", "__pycache__",
    ".pytest_cache", ".mypy_cache", "dist", "build", "corpus", "artifacts",
}
# Repo-relative directory prefixes never descended into.
SKIP_DIR_PATHS = {
    "plans",
    # Mirrored verbatim from the spec repo by scripts/sync-schemas.sh; its
    # links are spec-relative and are checked by the spec repo, not here.
    "tests/schemas",
}

# Anchors other repositories link into (plan ground rule 3). Renaming the
# heading is fine only if an explicit `<a id="...">` keeps the old anchor.
PROTECTED_ANCHORS = {
    "docs/sdk-python.md": [
        "build",
        "mutual-handshake-rfc-aitp-0004",
        "tct-verification-rfc-aitp-0005-9",
        "delegation-rfc-aitp-0006",
        "additional-capabilities-on-by-default",
        "oidc-identity-rfc-aitp-0002",
        "spki-cert-pinning-hpkp-style-feature-spki-pinning",
    ],
    "docs/conformance.md": ["v02-conformance-matrix"],
    "docs/key-management.md": ["rotation"],
    "docs/architecture.md": ["the-two-signing-profiles", "debugging-a-tct"],
}

# Whole pages other repositories link to (the spec repo's docs/ecosystem.md and
# friends): renaming or deleting one breaks those links.
PROTECTED_FILES = [
    "docs/sdk-python.md", "docs/sdk-node.md", "docs/handshake-transcripts.md",
    "docs/jcs.md", "docs/conformance.md", "docs/deployment.md",
    "docs/transport-hardening.md", "docs/key-management.md",
    "docs/tct-renewal.md", "docs/multihop-delegation.md",
    "docs/session-bundle.md", "docs/README.md",
]

# (regex, why) -- stale strings that must not reappear in the docs.
BANNED = [
    (re.compile(r"v0\.2 Draft"),
     "status wording is `Community Standards Track (Draft)`, never 'v0.2 Draft'"),
    (re.compile(r"generateP256"),
     "removed Node API name; see docs/sdk-node.md for the current key API"),
    (re.compile(r"""from ['"]aitp['"]"""),
     "the Node package is `@agentidentitytrustprotocol/aitp`"),
    (re.compile(r"held\.tct\.token"),
     "stale Python attribute path"),
    (re.compile(r"timestamp_be_8"),
     "removed transcript field; the docs must not describe it"),
    (re.compile(r"(?<![\d.])0\.4\.x"),
     "stale version line; say 'see Cargo.toml / release notes'"),
]

LINK_RE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)")
REFDEF_RE = re.compile(r"^ {0,3}\[[^\]]+\]:\s*(<[^>]*>|\S+)")
HEADING_RE = re.compile(r"^ {0,3}(#{1,6})(?:\s+(.*?))?(?:\s+#+)?\s*$")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
HTML_ID_RE = re.compile(r"""<[A-Za-z][A-Za-z0-9]*\b[^>]*?\b(?:id|name)\s*=\s*["']([^"']+)["']""")
SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")

SEC = r"§\s?(\d+(?:\.\d+)*)"
# `RFC-\s*AITP-` tolerates a hard wrap mid-hyphen once newlines are flattened.
CITE_RE = re.compile(
    r"RFC-\s*(?:AITP-\s*)?(\d{4})\s+" + SEC + r"(?:\s*(?:[/,]|and)\s*" + SEC + r")*"
)
SPEC_HEADING_RE = re.compile(r"^(#{2,6})\s+(\d+(?:\.\d+)*)(?:[.\s]|$)")

PLACEHOLDER_RE = re.compile(r"<([A-Za-z][A-Za-z0-9_./:-]*)>")
TAG_WITH_ATTRS_RE = re.compile(r"<([A-Za-z][A-Za-z0-9]*)\s+[^<>]*?(/?)>")
HTML_COMMENT_RE = re.compile(r"<!--")
# Tags GitHub and MDX both render; a bare `<br>` etc. is markup, not a placeholder.
KNOWN_HTML = {
    "a", "b", "i", "em", "strong", "code", "pre", "br", "hr", "p", "div",
    "span", "img", "sub", "sup", "details", "summary", "kbd", "table", "tr",
    "td", "th", "thead", "tbody", "ul", "ol", "li", "picture", "source",
}


# ── Markdown helpers ─────────────────────────────────────────────────────────

def mask_code(lines):
    """Return `lines` with fenced blocks blanked and inline code spans replaced
    by spaces (same length, so columns and line numbers are preserved)."""
    out, fence = [], None
    for line in lines:
        m = FENCE_RE.match(line)
        if fence is None and m:
            fence = m.group(1)
            out.append("")
            continue
        if fence is not None:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) \
                    and not line.strip()[len(m.group(1)):].strip():
                fence = None
            out.append("")
            continue
        out.append(mask_inline_code(line))
    return out


def mask_inline_code(line):
    res, i, n = [], 0, len(line)
    while i < n:
        if line[i] == "`":
            j = i
            while j < n and line[j] == "`":
                j += 1
            ticks = line[i:j]
            close = line.find(ticks, j)
            if close == -1:
                res.append(line[i:])
                break
            res.append(" " * (close + len(ticks) - i))
            i = close + len(ticks)
        else:
            res.append(line[i])
            i += 1
    return "".join(res)


def slugify(text):
    """GitHub (github-slugger) heading anchor for the heading's source text."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)   # links -> text
    text = re.sub(r"<[^>]+>", "", text)                       # inline HTML
    text = text.replace("`", "").replace("*", "")
    text = text.strip().lower()
    return "".join(ch for ch in text if ch.isalnum() or ch in " -_").replace(" ", "-")


def anchors_of(lines):
    """Every anchor a page exposes: heading slugs (with GitHub's -1, -2 ...
    suffixes for repeats) plus explicit <a id> / <a name> anchors."""
    anchors, seen, fence = set(), set(), None
    for line in lines:
        m = FENCE_RE.match(line)
        if fence is None and m:
            fence = m.group(1)
            continue
        if fence is not None:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) \
                    and not line.strip()[len(m.group(1)):].strip():
                fence = None
            continue
        for idm in HTML_ID_RE.finditer(mask_inline_code(line)):
            anchors.add(idm.group(1))
        h = HEADING_RE.match(line)
        if not h:
            continue
        base = slugify(h.group(2) or "")
        slug, k = base, 0
        while slug in seen:
            k += 1
            slug = f"{base}-{k}"
        seen.add(slug)
        anchors.add(slug)
    return anchors


# ── File discovery ───────────────────────────────────────────────────────────

def scan_set(root):
    """README.md, docs/**/*.md, every README.md at any depth, CONTRIBUTING.md
    and SECURITY.md -- repo-relative, sorted."""
    found = set()
    for top in ("README.md", "CONTRIBUTING.md", "SECURITY.md"):
        if os.path.isfile(os.path.join(root, top)):
            found.add(top)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIR_NAMES
            and (f"{rel_dir}/{d}" if rel_dir else d) not in SKIP_DIR_PATHS
        )
        for f in filenames:
            rel = f"{rel_dir}/{f}" if rel_dir else f
            if f == "README.md" or (rel.startswith("docs/") and f.endswith(".md")):
                found.add(rel)
    return sorted(found)


def exists_exact(root, rel):
    """True when `rel` exists under root with exactly this letter case."""
    cur = root
    for part in [p for p in rel.split("/") if p not in ("", ".")]:
        if part == "..":
            cur = os.path.dirname(cur)
            continue
        try:
            if part not in os.listdir(cur):
                return False
        except OSError:
            return False
        cur = os.path.join(cur, part)
    return os.path.exists(cur)


# ── Checks ───────────────────────────────────────────────────────────────────

class Report:
    def __init__(self):
        self.errors, self.warnings, self.notices = [], [], []

    def error(self, where, msg):
        self.errors.append(f"{where}: {msg}")

    def warn(self, where, msg):
        self.warnings.append(f"{where}: {msg}")


def read_lines(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read().split("\n")


def check_links(root, files, rep):
    cache = {}

    def anchors_for(rel):
        if rel not in cache:
            cache[rel] = anchors_of(read_lines(os.path.join(root, rel)))
        return cache[rel]

    count = 0
    root_real = os.path.realpath(root)
    for rel in files:
        masked = mask_code(read_lines(os.path.join(root, rel)))
        for n, line in enumerate(masked, 1):
            targets = [m.group(1) for m in LINK_RE.finditer(line)]
            rd = REFDEF_RE.match(line)
            if rd:
                targets.append(rd.group(1))
            for raw in targets:
                t = raw[1:-1] if raw.startswith("<") and raw.endswith(">") else raw
                if SCHEME_RE.match(t) or t.startswith("//"):
                    continue
                count += 1
                where = f"{rel}:{n}"
                path, _, anchor = t.partition("#")
                path = unquote(path.split("?", 1)[0])
                anchor = unquote(anchor)
                if path:
                    target = os.path.normpath(
                        os.path.join(os.path.dirname(rel), path)).replace(os.sep, "/")
                    full = os.path.realpath(os.path.join(root, target))
                    if target.startswith("..") or not (
                            full == root_real or full.startswith(root_real + os.sep)):
                        rep.error(where, f"link `{t}` escapes the repository "
                                         "(GitHub cannot resolve it; use a full URL)")
                        continue
                    if not exists_exact(root, target):
                        rep.error(where, f"link `{t}`: {target} does not exist")
                        continue
                else:
                    target = rel
                if not anchor or not target.endswith(".md") \
                        or os.path.isdir(os.path.join(root, target)):
                    continue
                if anchor.lower() not in {a.lower() for a in anchors_for(target)}:
                    rep.error(where, f"link `{t}`: no anchor #{anchor} in {target}")
    return count


def check_protected(root, rep):
    n = 0
    for rel in PROTECTED_FILES:
        if not os.path.isfile(os.path.join(root, rel)):
            rep.error(rel, "protected file is missing (other repositories link to it)")
    for rel, anchors in PROTECTED_ANCHORS.items():
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            rep.error(rel, "protected file is missing (other repositories link to it)")
            continue
        have = anchors_of(read_lines(path))
        for a in anchors:
            n += 1
            if a not in have:
                rep.error(rel, f"protected anchor #{a} is gone -- other repositories "
                               f"link to it; keep it with `<a id=\"{a}\"></a>` above "
                               "the renamed heading")
    return n


def check_banned(root, files, rep):
    for rel in files:
        for n, line in enumerate(read_lines(os.path.join(root, rel)), 1):
            for rx, why in BANNED:
                m = rx.search(line)
                if m:
                    rep.error(f"{rel}:{n}", f"banned string `{m.group(0)}` ({why})")


def check_mdx(root, files, rep):
    targets = [r for r in files if r == "README.md" or
               (r.startswith("docs/") and r.endswith(".md"))]
    for rel in targets:
        for n, line in enumerate(mask_code(read_lines(os.path.join(root, rel))), 1):
            where = f"{rel}:{n}"
            if HTML_COMMENT_RE.search(line):
                rep.error(where, "HTML comment `<!--` breaks the website's MDX build")
            for m in TAG_WITH_ATTRS_RE.finditer(line):
                tag, selfclose = m.group(1).lower(), m.group(2)
                if selfclose or re.search(rf"</{tag}\s*>", line[m.end():], re.I):
                    continue
                if tag in ("details", "summary", "table", "div", "picture"):
                    continue  # block elements closed on a later line
                rep.error(where, f"unclosed `<{m.group(1)} ...>` with attributes: MDX "
                                 "rejects it; close it on the same line or use `/>`")
            for m in PLACEHOLDER_RE.finditer(line):
                inner = m.group(1)
                if inner.startswith(("http://", "https://", "mailto:")) \
                        or inner.lower() in KNOWN_HTML:
                    continue
                rep.warn(where, f"raw `<{inner}>` outside code: GitHub drops it from "
                                "the rendered page; wrap it in backticks")
            if "{" in line or "}" in line:
                rep.warn(where, "bare `{`/`}` outside code (escape-mdx rewrites it for "
                                "the website); prefer inline code")


def spec_headings(spec, pin, rep):
    """{ 'NNNN': set(section numbers) } at the pinned commit, or None (skip)."""
    def git(*args):
        return subprocess.run(["git", "-C", spec, *args], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL)

    if not spec or not os.path.isdir(spec):
        rep.notices.append(f"citations: spec checkout not found at {spec!r} "
                           "(set AITP_SPEC); § citation check SKIPPED")
        return None
    if git("cat-file", "-e", f"{pin}^{{commit}}").returncode != 0:
        rep.notices.append(f"citations: pinned spec commit {pin} not present in "
                           f"{spec} (git fetch there); § citation check SKIPPED")
        return None
    ls = git("ls-tree", "--name-only", pin, "rfcs/").stdout.decode().split()
    out = {}
    for path in ls:
        m = re.match(r"rfcs/RFC-AITP-(\d{4})-.*\.md$", path)
        if not m:
            continue
        body = git("show", f"{pin}:{path}").stdout.decode("utf-8", "replace")
        nums, fence = set(), False
        for line in body.split("\n"):
            if FENCE_RE.match(line):
                fence = not fence
                continue
            if not fence:
                h = SPEC_HEADING_RE.match(line)
                if h:
                    nums.add(h.group(2))
        out[m.group(1)] = (path, nums)
    if not out:
        rep.notices.append(f"citations: no rfcs/RFC-AITP-*.md at {pin}; check SKIPPED")
        return None
    return out


def check_citations(root, files, spec, rep):
    pin_file = os.path.join(root, "tests", "schemas", "SPEC_VERSION")
    if not os.path.isfile(pin_file):
        rep.notices.append("citations: tests/schemas/SPEC_VERSION missing; check SKIPPED")
        return None
    pin = open(pin_file, encoding="utf-8").read().strip()
    heads = spec_headings(spec, pin, rep)
    if heads is None:
        return None
    count = 0
    for rel in files:
        # Fences blanked (Rust/Python samples are not prose citations); inline
        # code kept -- a cited section in backticks is still a claim.
        lines, fence = [], None
        for line in read_lines(os.path.join(root, rel)):
            m = FENCE_RE.match(line)
            if fence is None and m:
                fence = m.group(1)
                lines.append("")
            elif fence is not None:
                if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) \
                        and not line.strip()[len(m.group(1)):].strip():
                    fence = None
                lines.append("")
            else:
                lines.append(line)
        text = "\n".join(lines)
        flat = text.replace("\n", " ")
        for m in CITE_RE.finditer(flat):
            num = m.group(1)
            explicit = re.match(r"RFC-\s*AITP-", m.group(0)) is not None
            if num not in heads:
                if explicit:
                    rep.error(f"{rel}:{text.count(chr(10), 0, m.start()) + 1}",
                              f"RFC-AITP-{num} is not an RFC at the pinned spec commit")
                continue  # `RFC-NNNN` that is not an AITP RFC: not ours to check
            path, nums = heads[num]
            for sm in re.finditer(SEC, m.group(0)):
                count += 1
                sec = sm.group(1)
                if sec not in nums:
                    line_no = text.count("\n", 0, m.start() + sm.start()) + 1
                    rep.error(f"{rel}:{line_no}",
                              f"RFC-AITP-{num} §{sec}: no heading {sec} in {path} "
                              f"at pinned spec {pin[:12]}")
    return count


# ── Main ─────────────────────────────────────────────────────────────────────

def main(argv=None):
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=here, help="repository root (default: this repo)")
    ap.add_argument("--spec", default=None,
                    help="spec checkout (default: $AITP_SPEC, else ../agentidentitytrustprotocol)")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    spec = args.spec or os.environ.get("AITP_SPEC") or \
        os.path.join(os.path.dirname(root), "agentidentitytrustprotocol")

    rep = Report()
    files = scan_set(root)
    n_links = check_links(root, files, rep)
    n_prot = check_protected(root, rep)
    n_cites = check_citations(root, files, spec, rep)
    check_banned(root, files, rep)
    check_mdx(root, files, rep)

    for w in rep.warnings:
        print(f"warning: {w}")
    for e in rep.errors:
        print(f"error: {e}")
    for msg in rep.notices:
        print(f"notice: {msg}")
    cites = "skipped" if n_cites is None else f"{n_cites} § citation(s)"
    print(f"docs-check: {len(files)} file(s), {n_links} relative link(s), "
          f"{n_prot} protected anchor(s), {cites}; "
          f"{len(rep.errors)} error(s), {len(rep.warnings)} warning(s)")
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
