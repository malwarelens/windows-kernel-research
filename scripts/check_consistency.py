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
   trigger source names its CVE ID in its header comment, the PoC
   README documents a mingw-w64 build command line that actually
   compiles ``trigger.c`` (a mere prose mention of mingw is not
   enough), and the PoC README carries the standard sections (what
   it does / does not do, expected behaviour, build, run, risk
   notice).
4. Every relative Markdown link in the repository resolves to an
   existing file or directory.
5. Every ``detection/*.md`` entry (other than the directory's own
   ``README.md``) is listed exactly once in the ``## 已有条目``
   section of ``detection/README.md``, and that section lists no
   entry that has no file.
6. Every ``kernel-notes/*.md`` entry is listed exactly once in the
   "Supporting notes" list of the README ``## Index`` section, and
   that list names no entry that has no file.
7. Every ``analysis.md`` cites at least one external (http/https)
   link in its ``## 参考来源`` (references) section, backing the
   repository's stance that all material is based on already-public
   information.
8. Every ``analysis.md`` metadata table carries the standard rows
   shared by all entries (vendor title, affected component, bug
   class, severity, finder/reporter, in-the-wild status, fix date
   and exploitation prerequisite), each with a non-empty value, so
   a new entry cannot silently drop a field readers rely on. The
   trailing relation row (e.g. "前篇" / "与前篇的关系") is
   entry-specific and is deliberately not standardised here.

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

# Standard metadata rows, in addition to the "漏洞编号" row checked
# separately against the directory name below. Every published entry
# carries all of these; only the trailing relation row varies.
REQUIRED_METADATA_ROWS = [
    "厂商标题",
    "受影响组件",
    "漏洞类型",
    "严重程度",
    "发现与报告",
    "在野利用",
    "修复时间",
    "利用前提",
]

POC_REQUIRED_SECTIONS = [
    "它做什么、不做什么",
    "预期现象（仅限测试虚拟机）",
    "编译",
    "运行",
    "风险提示",
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

    table_match = re.search(r"\|\s*漏洞编号\s*\|\s*(CVE-\d+-\d+)\s*\|", text)
    if table_match is None:
        errors.append(f"{cve}: metadata table lacks a '漏洞编号' row")
    elif table_match.group(1) != cve:
        errors.append(
            f"{cve}: metadata table names {table_match.group(1)} "
            f"(expected {cve})"
        )

    preamble = text.split("## ", 1)[0]
    for row in REQUIRED_METADATA_ROWS:
        row_match = re.search(
            r"\|\s*" + re.escape(row) + r"\s*\|\s*([^|]+?)\s*\|", preamble
        )
        if row_match is None:
            errors.append(f"{cve}: metadata table lacks a '{row}' row")
        elif not row_match.group(1).strip():
            errors.append(f"{cve}: metadata table has an empty '{row}' row")

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
        has_build_command = any(
            "mingw32-gcc" in line and "trigger.c" in line
            for line in readme.splitlines()
        )
        if not has_build_command:
            errors.append(
                f"{cve}: poc/README.md lacks a mingw build command "
                "for trigger.c"
            )
        poc_sections = SECTION_RE.findall(readme)
        for required in POC_REQUIRED_SECTIONS:
            if required not in poc_sections:
                errors.append(
                    f"{cve}: poc/README.md missing section '## {required}'"
                )


EXTERNAL_LINK_RE = re.compile(r"https?://", re.I)


def check_reference_links(entry_dir, errors):
    analysis = entry_dir / "analysis.md"
    if not analysis.exists():
        return
    sections = re.split(
        r"^## ", analysis.read_text(encoding="utf-8"), flags=re.M
    )
    ref_section = next(
        (s for s in sections if s.startswith("参考来源")), None
    )
    if ref_section is None or not EXTERNAL_LINK_RE.search(ref_section):
        errors.append(
            f"{entry_dir.name}: analysis.md cites no external link in "
            "'## 参考来源' (all material must be based on public information)"
        )


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


def check_kernel_notes_index(errors):
    notes_dir = ROOT / "kernel-notes"
    if not notes_dir.is_dir():
        errors.append("kernel-notes index: missing kernel-notes/ directory")
        return 0
    entry_files = sorted(notes_dir.glob("*.md"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    sections = re.split(r"^## ", readme, flags=re.M)
    index_section = next((s for s in sections if s.startswith("Index")), None)
    if index_section is None:
        errors.append("kernel-notes index: README.md missing '## Index' section")
        return len(entry_files)
    notes_parts = index_section.split("Supporting notes:", 1)
    if len(notes_parts) != 2:
        errors.append(
            "kernel-notes index: README.md '## Index' section has no "
            "'Supporting notes:' list"
        )
        return len(entry_files)
    indexed = re.findall(
        r"\(kernel-notes/([A-Za-z0-9._-]+\.md)\)", notes_parts[1]
    )
    for entry_file in entry_files:
        if indexed.count(entry_file.name) != 1:
            errors.append(
                f"kernel-notes index: {entry_file.name} listed "
                f"{indexed.count(entry_file.name)} times (expected 1)"
            )
    for name in indexed:
        if name not in {p.name for p in entry_files}:
            errors.append(f"kernel-notes index: {name} has no kernel-notes/ file")
    return len(entry_files)


def main():
    errors = []
    entry_dirs = sorted(p for p in (ROOT / "analyses").iterdir() if p.is_dir())
    if not entry_dirs:
        errors.append("no entries found under analyses/")
    for entry_dir in entry_dirs:
        check_analysis(entry_dir, errors)
        check_reference_links(entry_dir, errors)
    check_readme_index(entry_dirs, errors)
    detection_count = check_detection_index(errors)
    notes_count = check_kernel_notes_index(errors)
    check_links(sorted(ROOT.rglob("*.md")), errors)

    if errors:
        print(f"FAILED: {len(errors)} inconsistency(ies):")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(
        f"OK: {len(entry_dirs)} analyses, {detection_count} detection entries, "
        f"{notes_count} kernel notes, all standard sections, standard "
        "metadata rows, PoC files and build commands, reference links, "
        "README indexes and Markdown links consistent."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
