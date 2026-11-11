#!/usr/bin/env python3
r"""Repository consistency self-check for windows-kernel-research.

Stdlib-only. Verifies the invariants the README promises, so a new
analysis entry cannot silently drift from the layout:

1. Every ``analyses/<CVE-ID>/`` directory is listed exactly once in the
   README index, with a link to its ``analysis.md``, and the table
   row carrying that link names the same CVE ID in its first cell:
   a row labelled with one CVE but linking to another entry's
   analysis would otherwise pass the exactly-once count check.
2. Every ``analysis.md`` carries the standard sections (affected
   versions, background, root cause, patch notes, trigger conditions,
   detection & mitigation, references), each with non-empty content,
   and a metadata table whose CVE ID matches its directory name.
3. Every entry ships ``poc/README.md`` and ``poc/trigger.c``; the
   trigger source names its CVE ID in its header comment, the PoC
   README documents a mingw-w64 build command line that actually
   compiles ``trigger.c`` (a mere prose mention of mingw is not
   enough), and the PoC README carries the standard sections (what
   it does / does not do, expected behaviour, build, run, risk
   notice), each with non-empty content.
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
9. Every standard section in ``analysis.md`` and ``poc/README.md``
   (including the background section, whose title varies) carries
   non-empty content, so a header-only entry cannot pass the
   section-presence checks above.
10. No Markdown file repeats a top-level (``## ``) heading: the
    section-body map used by the checks above is keyed by heading,
    so a duplicated heading would silently discard the first
    section's body and let a broken document pass.
11. When the mingw-w64 compiler named by a PoC README's build command
    is available, that command is actually run against the entry's
    ``trigger.c`` in a temporary directory: a command line that merely
    names ``trigger.c`` would otherwise pass check 3 while a wrong
    library flag or a broken source file silently broke the build.
    When the compiler is not available (the Visual Studio build is
    the documented alternative), the compile step is skipped rather
    than failing the whole check.
12. The metadata table's severity row names a CVSS score and its fix
    date row names a concrete calendar date (``YYYY 年 M 月 D 日``):
    check 8 only requires those rows to be non-empty, so a severity
    written as prose ("high") or a fix date written as a vague
    month would otherwise pass while readers lose the two fields
    they most often compare across entries.
13. The CWE class(es) named in a README index row match the CWE(s)
    in that entry's metadata "漏洞类型" row: the index is the
    first thing a reader scans, so a row claiming CWE-416 while the
    analysis says CWE-787 (or a dual-portrait entry dropping one
    side) would mislead before the reader ever opens the analysis.
    Both sides must name at least one CWE and the two sets must be
    equal.
14. The CVSS score named by the metadata severity row is a real
    score in the 0.0-10.0 range, and the fix date is a real calendar
    date: check 12's patterns would otherwise accept a severity
    that only repeats the "CVSS 3.1" version token (the version
    number itself matches ``\d+\.\d+``) or a date such as
    2023 年 2 月 30 日.
15. The driver filename (``*.sys``) named by a README index row's
    Component cell appears in that entry's metadata "受影响组件"
    row: the index is the first thing a reader scans, so a row
    claiming clfs.sys while the analysis says win32kfull.sys would
    mislead before the reader ever opens the analysis. Both sides
    name the driver in free prose, so only the ``.sys`` filename(s)
    are compared, case-insensitively, and every driver the index
    claims must be asserted by the analysis.
16. The ``## 参考来源`` (references) section of every analysis
    anchors to both the vendor advisory (a microsoft.com link)
    and the NVD entry (an nvd.nist.gov link): check 7 only
    requires one external link anywhere in the section, so an
    entry could otherwise pass while citing neither of the two
    sources every patched-CVE write-up in this repo is built on.

Usage:  python3 scripts/check_consistency.py
Exit code 0 = all checks passed, 1 = at least one inconsistency.
"""

import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import date
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


def section_bodies(text):
    """Map each ``## `` heading to its stripped body text.

    The body runs until the next ``## `` heading (or end of file);
    a heading with nothing but whitespace after it maps to ``""``,
    which is exactly the header-only case check 9 must catch.
    """
    bodies = {}
    for part in re.split(r"^## ", text, flags=re.M)[1:]:
        if "\n" in part:
            title, body = part.split("\n", 1)
        else:
            title, body = part, ""
        bodies[title.strip()] = body.strip()
    return bodies


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
    bodies = section_bodies(text)
    for required in REQUIRED_SECTIONS:
        if required not in sections:
            errors.append(f"{cve}: analysis.md missing section '## {required}'")
        elif not bodies[required]:
            errors.append(f"{cve}: analysis.md has an empty section '## {required}'")
    background = [s for s in sections if s.startswith("背景")]
    if not background:
        errors.append(f"{cve}: analysis.md missing a '## 背景…' section")
    elif not bodies[background[0]]:
        errors.append(
            f"{cve}: analysis.md has an empty section '## {background[0]}'"
        )

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

    def metadata_value(row):
        match = re.search(
            r"\|\s*" + re.escape(row) + r"\s*\|\s*([^|]+?)\s*\|", preamble
        )
        return match.group(1).strip() if match else None

    severity = metadata_value("严重程度")
    if severity is not None:
        # Check 14: the "CVSS 3.1" version token itself matches
        # ``\d+\.\d+``, so it must not count as the score. Strip
        # every version token first, then require a decimal score
        # in the 0.0-10.0 range.
        without_versions = re.sub(
            r"CVSS:?\s*v?\d+\.\d+", "", severity
        )
        scores = [
            float(s)
            for s in re.findall(r"\d+\.\d+", without_versions)
        ]
        if not any(0.0 <= score <= 10.0 for score in scores):
            errors.append(
                f"{cve}: metadata table '严重程度' row names no CVSS "
                "score in 0.0-10.0 after the CVSS version "
                f"(got: {severity[:60]})"
            )
    fix_date = metadata_value("修复时间")
    if fix_date is not None:
        date_match = re.search(
            r"(\d{4}) 年 (\d{1,2}) 月 (\d{1,2}) 日", fix_date
        )
        if date_match is None:
            errors.append(
                f"{cve}: metadata table '修复时间' row names no concrete "
                f"date (got: {fix_date[:60]})"
            )
        else:
            # Check 14: the pattern above also matches impossible
            # dates such as 2023 年 2 月 30 日; the date must exist.
            year, month, day = (
                int(group) for group in date_match.groups()
            )
            try:
                date(year, month, day)
            except ValueError:
                errors.append(
                    f"{cve}: metadata table '修复时间' row names an "
                    "impossible calendar date "
                    f"(got: {fix_date[:60]})"
                )

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
        poc_bodies = section_bodies(readme)
        for required in POC_REQUIRED_SECTIONS:
            if required not in poc_sections:
                errors.append(
                    f"{cve}: poc/README.md missing section '## {required}'"
                )
            elif not poc_bodies[required]:
                errors.append(
                    f"{cve}: poc/README.md has an empty section "
                    f"'## {required}'"
                )


def check_poc_compiles(entry_dir, errors):
    """Run the PoC README's documented mingw build command, if possible.

    Returns True only when a build was actually run and succeeded.
    Missing PoC files or a missing build command are already reported
    by ``check_analysis``; a missing compiler is a skip, not an error,
    because the Visual Studio build is the documented alternative.
    """
    cve = entry_dir.name
    poc_readme = entry_dir / "poc" / "README.md"
    trigger = entry_dir / "poc" / "trigger.c"
    if not poc_readme.exists() or not trigger.exists():
        return False
    build_lines = [
        line.strip()
        for line in poc_readme.read_text(encoding="utf-8").splitlines()
        if "mingw32-gcc" in line and "trigger.c" in line
    ]
    if not build_lines:
        return False
    try:
        args = shlex.split(build_lines[0])
    except ValueError as exc:
        errors.append(f"{cve}: mingw build command does not parse: {exc}")
        return False
    if not args or shutil.which(args[0]) is None:
        return False
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            shutil.copy(trigger, Path(tmpdir) / "trigger.c")
            result = subprocess.run(
                args,
                cwd=tmpdir,
                capture_output=True,
                text=True,
                timeout=120,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"{cve}: mingw build failed to run: {exc}")
        return False
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        detail = "; ".join(detail.splitlines()[-3:])
        errors.append(
            f"{cve}: documented mingw build command failed "
            f"(exit {result.returncode}): {detail}"
        )
        return False
    return True


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


def check_reference_anchors(entry_dir, errors):
    """References must anchor to the vendor advisory and the NVD entry.

    Check 7 only requires one external link anywhere in the
    references section, so an entry could pass while citing neither
    the vendor's own advisory nor the NVD record — the two sources
    every patched-CVE write-up in this repo is built on. Both must
    appear in ``## 参考来源``. A missing references section is
    already reported by ``check_reference_links`` and is not
    double-reported here.
    """
    analysis = entry_dir / "analysis.md"
    if not analysis.exists():
        return
    sections = re.split(
        r"^## ", analysis.read_text(encoding="utf-8"), flags=re.M
    )
    ref_section = next(
        (s for s in sections if s.startswith("参考来源")), None
    )
    if ref_section is None:
        return
    hosts = {
        host.lower()
        for host in re.findall(r"https?://([^/\s)]+)", ref_section, flags=re.I)
    }

    def has_domain(hosts, domain):
        return any(
            host == domain or host.endswith("." + domain) for host in hosts
        )

    if not has_domain(hosts, "microsoft.com"):
        errors.append(
            f"{entry_dir.name}: analysis.md cites no vendor advisory "
            "(microsoft.com) in '## 参考来源' (every entry must anchor "
            "to the vendor's own advisory)"
        )
    if not has_domain(hosts, "nvd.nist.gov"):
        errors.append(
            f"{entry_dir.name}: analysis.md cites no NVD entry "
            "(nvd.nist.gov) in '## 参考来源' (every entry must anchor "
            "to the NVD record)"
        )


def check_readme_index(entry_dirs, errors):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    indexed = re.findall(r"\(analyses/(CVE-\d+-\d+)/analysis\.md\)", readme)
    for row_cve, link_cve in re.findall(
        r"^\|\s*(CVE-\d+-\d+)\s*\|.*\(analyses/(CVE-\d+-\d+)/analysis\.md\)",
        readme,
        flags=re.M,
    ):
        if row_cve != link_cve:
            errors.append(
                f"README index: table row names {row_cve} but links to "
                f"{link_cve} analysis (row and link CVE must match)"
            )
    for entry_dir in entry_dirs:
        if indexed.count(entry_dir.name) != 1:
            errors.append(
                f"README index: {entry_dir.name} listed "
                f"{indexed.count(entry_dir.name)} times (expected 1)"
            )
    for cve in indexed:
        if cve not in {d.name for d in entry_dirs}:
            errors.append(f"README index: {cve} has no analyses/ directory")


CWE_RE = re.compile(r"CWE-(\d+)")


def check_readme_cwe_matches_metadata(entry_dirs, errors):
    """README index CWE class(es) must match the metadata 漏洞类型 row.

    The index row is what a reader scans first; the metadata row is
    what the analysis itself asserts. Both must name at least one CWE
    and the two sets must be equal, so a dual-portrait entry
    (e.g. CWE-122 / CWE-787) cannot silently drop one side in
    either place.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index_cwes = {}
    for row_cve, row_text in re.findall(
        r"^\|\s*(CVE-\d+-\d+)\s*\|(.*)$", readme, flags=re.M
    ):
        if "analyses/" in row_text:
            index_cwes[row_cve] = set(CWE_RE.findall(row_text))
    for entry_dir in entry_dirs:
        cve = entry_dir.name
        analysis = entry_dir / "analysis.md"
        if not analysis.exists():
            continue
        preamble = analysis.read_text(encoding="utf-8").split("## ", 1)[0]
        row_match = re.search(
            r"\|\s*漏洞类型\s*\|\s*([^|]+?)\s*\|", preamble
        )
        if row_match is None:
            errors.append(f"{cve}: metadata table lacks a '漏洞类型' row")
            continue
        metadata_cwes = set(CWE_RE.findall(row_match.group(1)))
        index_set = index_cwes.get(cve)
        if index_set is None:
            errors.append(f"{cve}: README index has no row naming {cve}")
            continue
        if not index_set:
            errors.append(
                f"{cve}: README index row names no CWE class "
                "(index must carry the entry's CWE class)"
            )
        elif not metadata_cwes:
            errors.append(
                f"{cve}: metadata '漏洞类型' row names no CWE class "
                "(analysis must state its CWE class)"
            )
        elif index_set != metadata_cwes:
            errors.append(
                f"{cve}: README index CWE class(es) "
                f"{sorted(index_set)} do not match metadata "
                f"'漏洞类型' CWE class(es) {sorted(metadata_cwes)}"
            )


SYS_RE = re.compile(r"[A-Za-z0-9_.-]+\.sys", re.I)


def check_readme_component_matches_metadata(entry_dirs, errors):
    """README index Component cell must name the entry's driver.

    The index Component column is what a reader scans first; the
    metadata "受影响组件" row is what the analysis itself asserts.
    Both sides name the driver in free prose, so only the ``.sys``
    filename(s) are compared, case-insensitively: every driver the
    index claims must be asserted by the analysis, so a row
    claiming clfs.sys while the analysis says win32kfull.sys
    cannot slip in.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index_drivers = {}
    for row_cve, row_text in re.findall(
        r"^\|\s*(CVE-\d+-\d+)\s*\|(.*)$", readme, flags=re.M
    ):
        if "analyses/" in row_text:
            cells = row_text.split("|")
            if cells:
                index_drivers[row_cve] = set(
                    token.lower() for token in SYS_RE.findall(cells[0])
                )
    for entry_dir in entry_dirs:
        cve = entry_dir.name
        index_set = index_drivers.get(cve)
        if index_set is None:
            # Missing index row is already reported by check 13.
            continue
        analysis = entry_dir / "analysis.md"
        if not analysis.exists():
            continue
        preamble = analysis.read_text(encoding="utf-8").split("## ", 1)[0]
        row_match = re.search(
            r"\|\s*受影响组件\s*\|\s*([^|]+?)\s*\|", preamble
        )
        if row_match is None:
            # Missing metadata row is already reported by check 8.
            continue
        metadata_drivers = set(
            token.lower()
            for token in SYS_RE.findall(row_match.group(1))
        )
        if not index_set:
            errors.append(
                f"{cve}: README index Component cell names no driver "
                "file (.sys) (index must carry the entry's driver)"
            )
        elif not metadata_drivers:
            errors.append(
                f"{cve}: metadata '受影响组件' row names no driver "
                "file (.sys) (analysis must state its driver)"
            )
        elif not index_set <= metadata_drivers:
            errors.append(
                f"{cve}: README index driver file(s) "
                f"{sorted(index_set - metadata_drivers)} do not appear "
                "in metadata '受影响组件' row "
                f"(metadata names {sorted(metadata_drivers)})"
            )


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


def check_duplicate_sections(md_files, errors):
    for md in md_files:
        sections = SECTION_RE.findall(md.read_text(encoding="utf-8"))
        for title in sorted(set(sections)):
            if sections.count(title) > 1:
                errors.append(
                    f"{md.relative_to(ROOT)}: duplicated top-level "
                    f"section '## {title}' ({sections.count(title)} times)"
                )


def main():
    errors = []
    entry_dirs = sorted(p for p in (ROOT / "analyses").iterdir() if p.is_dir())
    if not entry_dirs:
        errors.append("no entries found under analyses/")
    compiled = 0
    for entry_dir in entry_dirs:
        check_analysis(entry_dir, errors)
        check_reference_links(entry_dir, errors)
        check_reference_anchors(entry_dir, errors)
        if check_poc_compiles(entry_dir, errors):
            compiled += 1
    check_readme_index(entry_dirs, errors)
    check_readme_cwe_matches_metadata(entry_dirs, errors)
    check_readme_component_matches_metadata(entry_dirs, errors)
    detection_count = check_detection_index(errors)
    notes_count = check_kernel_notes_index(errors)
    check_links(sorted(ROOT.rglob("*.md")), errors)
    check_duplicate_sections(sorted(ROOT.rglob("*.md")), errors)

    if errors:
        print(f"FAILED: {len(errors)} inconsistency(ies):")
        for error in errors:
            print(f"  - {error}")
        return 1
    if compiled == len(entry_dirs):
        poc_build_note = f"{compiled} PoC build(s) compiled"
    else:
        poc_build_note = (
            f"{compiled}/{len(entry_dirs)} PoC build(s) compiled "
            "(mingw compiler not found for the rest, skipped)"
        )
    print(
        f"OK: {len(entry_dirs)} analyses, {detection_count} detection entries, "
        f"{notes_count} kernel notes, all standard sections (each with "
        "content), standard metadata rows, PoC files and build commands, "
        f"{poc_build_note}, "
        "reference links anchored to the vendor advisory and the NVD "
        "entry, README indexes (including CWE classes) and "
        "Markdown links consistent, "
        "no duplicated top-level headings."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
