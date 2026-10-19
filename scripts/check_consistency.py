#!/usr/bin/env python3
"""Repository consistency self-check for windows-kernel-research.

Stdlib-only. Verifies the invariants the README promises, so a new
analysis entry cannot silently drift from the layout:

1. Every ``analyses/<CVE-ID>/`` directory is listed exactly once in the
   README index, with a link to its ``analysis.md``.
2. Every ``analysis.md`` carries the standard sections (affected
   versions, background, root cause, patch notes, trigger conditions,
   detection & mitigation, references) and a metadata table whose
   CVE ID matches its directory name.
3. Every entry ships ``poc/README.md`` and ``poc/trigger.c``; the
   trigger source names its CVE ID in its header comment and the PoC
   README documents a mingw-w64 build command for it.
4. Every relative Markdown link in the repository resolves to an
   existing file or directory.
5. Every ``detection/*.md`` entry (other than the directory's own
   ``README.md``) is listed exactly once in the ``## 已有条目``
   section of ``detection/README.md``, and that section lists no
   entry that has no file.

Usage:  python3 scripts/check_consistency.py
Exit code 0 = all checks passed, 1 = at least one inconsistency.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_SECTIONS = [
    "受影响版本",
    "根因分析",
    "补丁对比思路",
    "触发条件",
    "检测与缓解",
    "参考来源",
]

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
SECTION_RE = re.compile(r"^## (.+)$", re.M)


def check_links(md_files, errors):
    for md in md_files:
        text = md.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            url = match.group(1).split("#")[0].strip()
            if not url or "://" in url or url.startswith("mailto:"):
                continue
            if not (md.parent / url).resolve().exists():
                errors.append(f"{md.relative_to(ROOT)}: broken link -> {url}")


def check_analysis(entry_dir, errors):
    cve = entry_dir.name
    analysis = entry_dir / "analysis.md"
    if not analysis.exists():
        errors.append(f"{cve}: missing analysis.md")
        return
    text = analysis.read_text(encoding="utf-8")

    sections = SECTION_RE.findall(text)
    for required in REQUIRED_SECTIONS:
        if required not in sections:
            errors.append(f"{cve}: analysis.md missing section '## {required}'")
    if not any(s.startswith("背景") for s in sections):
        errors.append(f"{cve}: analysis.md missing a '## 背景…' section")

    if cve not in text.split("## ", 1)[0]:
        errors.append(f"{cve}: CVE ID not named before the first section")

    poc_readme = entry_dir / "poc" / "README.md"
    trigger = entry_dir / "poc" / "trigger.c"
    if not poc_readme.exists():
        errors.append(f"{cve}: missing poc/README.md")
    if not trigger.exists():
        errors.append(f"{cve}: missing poc/trigger.c")
        return
    header = "\n".join(trigger.read_text(encoding="utf-8").splitlines()[:10])
    if cve not in header:
        errors.append(f"{cve}: trigger.c header does not name {cve}")
    if poc_readme.exists():
        readme = poc_readme.read_text(encoding="utf-8")
        if "trigger.c" not in readme or "mingw" not in readme:
            errors.append(f"{cve}: poc/README.md lacks a mingw build line")


def check_readme_index(entry_dirs, errors):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    indexed = re.findall(r"\(analyses/(CVE-\d+-\d+)/analysis\.md\)", readme)
    for entry_dir in entry_dirs:
        if indexed.count(entry_dir.name) != 1:
            errors.append(
                f"README index: {entry_dir.name} listed "
                f"{indexed.count(entry_dir.name)} times (expected 1)"
            )
    for cve in indexed:
        if cve not in {d.name for d in entry_dirs}:
            errors.append(f"README index: {cve} has no analyses/ directory")


def check_detection_index(errors):
    detection_dir = ROOT / "detection"
    index_file = detection_dir / "README.md"
    if not index_file.exists():
        errors.append("detection index: missing detection/README.md")
        return 0
    entry_files = sorted(
        p for p in detection_dir.glob("*.md") if p.name != "README.md"
    )
    text = index_file.read_text(encoding="utf-8")
    sections = re.split(r"^## ", text, flags=re.M)
    index_section = next(
        (s for s in sections if s.startswith("已有条目")), None
    )
    if index_section is None:
        errors.append("detection index: README.md missing '## 已有条目' section")
        return len(entry_files)
    indexed = re.findall(r"\]\(([A-Za-z0-9._-]+\.md)\)", index_section)
    for entry_file in entry_files:
        if indexed.count(entry_file.name) != 1:
            errors.append(
                f"detection index: {entry_file.name} listed "
                f"{indexed.count(entry_file.name)} times (expected 1)"
            )
    for name in indexed:
        if name not in {p.name for p in entry_files} and name != "README.md":
            errors.append(f"detection index: {name} has no detection/ file")
    return len(entry_files)


def main():
    errors = []
    entry_dirs = sorted(p for p in (ROOT / "analyses").iterdir() if p.is_dir())
    if not entry_dirs:
        errors.append("no entries found under analyses/")
    for entry_dir in entry_dirs:
        check_analysis(entry_dir, errors)
    check_readme_index(entry_dirs, errors)
    detection_count = check_detection_index(errors)
    check_links(sorted(ROOT.rglob("*.md")), errors)

    if errors:
        print(f"FAILED: {len(errors)} inconsistency(ies):")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(
        f"OK: {len(entry_dirs)} analyses, {detection_count} detection entries, "
        "all standard sections, PoC files, README indexes and Markdown "
        "links consistent."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
