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
17. The vendor-advisory and NVD links that anchor an entry's
    references actually name that entry's own CVE ID (case-
    insensitive): check 16 only verifies the domains, so a link
    to the vendor or NVD homepage — or to another CVE's record —
    would otherwise pass while the entry cites no advisory or
    record for the vulnerability it describes.
18. The PoC README names its own CVE ID: check 3 verifies the
    trigger source header and the build command, so a PoC README
    copied from another entry would otherwise pass every section
    check while describing the wrong vulnerability. (A PoC README
    may legitimately also name a predecessor CVE — CVE-2022-21882
    cites CVE-2021-1732 as the bug it bypasses — so only the own
    ID is required, not the absence of others.)
19. Every ``detection/*.md`` entry (other than the directory's own
    ``README.md``) links to at least one published analysis: the
    detection directory's README describes its entries as
    detection notes accompanying this repository's vulnerability
    analyses, so an entry naming no analysis would be generic
    advice disconnected from the repo. Only links to existing
    entries count; a link to an analysis that does not exist is
    already caught by check 4.
20. Every ``analysis.md`` names at least one defender telemetry
    source (Sysmon, ETW or EDR) in its ``## 检测与缓解``
    (detection & mitigation) section: the README positions every
    detection section as telling a defender what can be observed
    (behavioral traits, Sysmon/ETW/EDR telemetry), so a section
    that names no telemetry source at all would leave a reader
    with prose and no place to look. Check 9 only requires the
    section to be non-empty.
21. Every ``detection/*.md`` entry (other than the directory's own
    ``README.md``) names at least one defender telemetry source
    (Sysmon, ETW or EDR): the detection directory's README
    describes its entries as detection notes with "Sysmon / ETW /
    EDR 可观测点", so an entry naming no telemetry source at all
    would be generic advice with no place for a defender to look.
    Check 19 only requires the entry to link to an analysis.
22. Every ``analysis.md`` names at least one affected Windows
    version in its ``## 受影响版本`` (affected versions) section:
    the section exists to list the affected versions (per the NVD
    CPE list the entries cite), so a section that names no Windows
    version at all would leave a reader with prose and no way to
    tell whether their build is affected. Check 9 only requires
    the section to be non-empty.
23. Every NVD vulnerability-detail link (``nvd.nist.gov/vuln/detail/``)
    in an entry's ``## 参考来源`` (references) section names that
    entry's own CVE ID: check 17 only requires at least one NVD link
    to name the entry's CVE, so a second NVD link pasted from another
    entry — the classic copy-paste slip when a new analysis is drafted
    from an old one — would otherwise pass while sending a reader to
    the wrong record. NVD detail URLs are per-CVE by construction, so
    a detail link naming any other CVE is always wrong here; other
    NVD URLs (e.g. a search page) are not record links and are left
    alone.
24. Every MSRC advisory link (``msrc.microsoft.com/update-guide/
    vulnerability/`` or ``portal.msrc.microsoft.com/.../security-
    guidance/advisory/``) in an entry's ``## 参考来源`` (references)
    section names that entry's own CVE ID: check 17 only requires
    at least one microsoft.com link to name the entry's CVE, so a
    second advisory link pasted from another entry — the same
    copy-paste slip check 23 closed for NVD record links — would
    otherwise pass while sending a reader to the wrong advisory.
    MSRC advisory URLs are per-CVE by construction, so an advisory
    link naming any other CVE is always wrong here; other
    microsoft.com URLs (e.g. a learn.microsoft.com driver doc) are
    not advisory links and are left alone.
25. Every ``kernel-notes/*.md`` entry links to at least one
    published analysis: the note describes itself as background for
    this repository's vulnerability analyses, so a note naming no
    analysis would be background disconnected from the repo — the
    same rationale as check 19 for detection entries, applied to
    the other supporting-notes directory. Only links to existing
    entries count; a link to an analysis that does not exist is
    already caught by check 4.

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
        # Check 18: the PoC README must name its own CVE ID, so a
        # README copied from another entry cannot pass while
        # describing the wrong vulnerability.
        if cve not in readme:
            errors.append(
                f"{cve}: poc/README.md does not name {cve} "
                "(PoC README must describe its own entry)"
            )
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


def check_reference_anchors_name_cve(entry_dir, errors):
    """Vendor and NVD anchors must name the entry's own CVE ID.

    Check 16 only verifies the domains, so a link to the vendor
    or NVD homepage — or to another CVE's advisory or record —
    would pass while the entry cites no source for the
    vulnerability it describes. At least one microsoft.com link
    and at least one nvd.nist.gov link in ``## 参考来源`` must
    carry the entry's own CVE ID (case-insensitive: MSRC and NVD
    URLs spell the ID in either case). A domain that is absent
    altogether is already reported by check 16 and is not
    double-reported here.
    """
    cve = entry_dir.name
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
    urls = re.findall(
        r"https?://([^/\s)]+)([^)\s]*)", ref_section, flags=re.I
    )
    cve_lower = cve.lower()
    for domain, label in (
        ("microsoft.com", "vendor advisory"),
        ("nvd.nist.gov", "NVD entry"),
    ):
        domain_urls = [
            host + path
            for host, path in urls
            if host.lower() == domain
            or host.lower().endswith("." + domain)
        ]
        if not domain_urls:
            continue
        if not any(cve_lower in url.lower() for url in domain_urls):
            errors.append(
                f"{cve}: analysis.md cites no {label} for {cve} in "
                "'## 参考来源' (its "
                f"{domain} link(s) name no CVE ID of this entry: "
                f"{domain_urls[0][:60]})"
            )


def check_reference_nvd_links_name_cve(entry_dir, errors):
    """Every NVD record link must name the entry's own CVE ID.

    Check 17 only requires at least one nvd.nist.gov link to name
    the entry's own CVE, so a second NVD link pasted from another
    entry — the classic copy-paste slip when a new analysis is
    drafted from an old one — would pass while sending a reader to
    the wrong record. NVD vulnerability-detail URLs are per-CVE by
    construction (``/vuln/detail/CVE-YYYY-NNNNN``), so every such
    link in ``## 参考来源`` must carry this entry's own CVE ID
    (case-insensitive). Other NVD URLs (e.g. a search page) are not
    record links and are left alone. A missing references section
    or no NVD link at all is already reported by checks 7 and 16
    and is not double-reported here.
    """
    cve = entry_dir.name
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
    urls = re.findall(
        r"https?://([^/\s)]+)([^)\s]*)", ref_section, flags=re.I
    )
    cve_lower = cve.lower()
    for host, path in urls:
        if not (host.lower() == "nvd.nist.gov"
                or host.lower().endswith(".nvd.nist.gov")):
            continue
        if not path.lower().startswith("/vuln/detail/"):
            continue
        if cve_lower not in (host + path).lower():
            errors.append(
                f"{cve}: analysis.md cites an NVD record for another "
                f"CVE in '## 参考来源' "
                f"({(host + path)[:60]}) — every NVD record link must "
                f"name {cve}"
            )


MSRC_ADVISORY_RE = re.compile(
    r"/(?:update-guide/vulnerability|security-guidance/advisory)/"
    r"(CVE-\d+-\d+)",
    re.I,
)


def check_reference_msrc_links_name_cve(entry_dir, errors):
    """Every MSRC advisory link must name the entry's own CVE ID.

    Check 17 only requires at least one microsoft.com link to name
    the entry's own CVE, so a second advisory link pasted from
    another entry — the same copy-paste slip check 23 closed for
    NVD record links — would pass while sending a reader to the
    wrong advisory. MSRC advisory URLs are per-CVE by construction
    (``/update-guide/vulnerability/CVE-YYYY-NNNNN`` and
    ``/security-guidance/advisory/CVE-YYYY-NNNNN``), so every such
    link in ``## 参考来源`` must carry this entry's own CVE ID
    (case-insensitive). Other microsoft.com URLs (e.g. a
    learn.microsoft.com driver doc) are not advisory links and are
    left alone. A missing references section or no microsoft.com
    link at all is already reported by checks 7 and 16 and is not
    double-reported here.
    """
    cve = entry_dir.name
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
    urls = re.findall(
        r"https?://([^/\s)]+)([^)\s]*)", ref_section, flags=re.I
    )
    cve_lower = cve.lower()
    for host, path in urls:
        if not (host.lower() == "microsoft.com"
                or host.lower().endswith(".microsoft.com")):
            continue
        advisory = MSRC_ADVISORY_RE.search(path)
        if advisory is None:
            continue
        if advisory.group(1).lower() != cve_lower:
            errors.append(
                f"{cve}: analysis.md cites an MSRC advisory for "
                f"another CVE in '## 参考来源' "
                f"({(host + path)[:60]}) — every MSRC advisory link "
                f"must name {cve}"
            )


def check_detection_section_names_telemetry(entry_dir, errors):
    """Detection & mitigation must name a defender telemetry source.

    The README positions every detection section as telling a
    defender what can be observed (behavioral traits, Sysmon/ETW/
    EDR telemetry), so a section naming no telemetry source would
    leave a reader with prose and no place to look. Check 9 only
    requires the section to be non-empty. At least one of Sysmon,
    ETW or EDR (case-insensitive) must appear in ``## 检测与缓解``.
    A missing section is already reported by ``check_analysis``
    and is not double-reported here.
    """
    analysis = entry_dir / "analysis.md"
    if not analysis.exists():
        return
    bodies = section_bodies(analysis.read_text(encoding="utf-8"))
    detection = bodies.get("检测与缓解")
    if detection is None:
        return
    if not re.search(r"sysmon|\betw\b|\bedr\b", detection, flags=re.I):
        errors.append(
            f"{entry_dir.name}: analysis.md names no defender "
            "telemetry source (Sysmon / ETW / EDR) in "
            "'## 检测与缓解' (the section must tell a defender "
            "where to look)"
        )


def check_affected_versions_name_windows(entry_dir, errors):
    """Affected-versions section must name an affected Windows version.

    The section exists to list the affected versions (per the NVD
    CPE list the entries cite), so a section naming no Windows
    version at all would leave a reader with prose and no way to
    tell whether their build is affected. Check 9 only requires
    the section to be non-empty. At least one "Windows 10",
    "Windows 11" or "Windows Server" mention — or a concrete
    build number such as 10.0.19044 — must appear in
    ``## 受影响版本``. A missing section is already reported by
    ``check_analysis`` and is not double-reported here.
    """
    analysis = entry_dir / "analysis.md"
    if not analysis.exists():
        return
    bodies = section_bodies(analysis.read_text(encoding="utf-8"))
    affected = bodies.get("受影响版本")
    if affected is None:
        return
    if not re.search(
        r"Windows\s+(10|11|Server)|10\.0\.\d+", affected, flags=re.I
    ):
        errors.append(
            f"{entry_dir.name}: analysis.md names no affected "
            "Windows version in '## 受影响版本' (the section must "
            "list the affected Windows versions / builds)"
        )


def check_detection_entries_name_telemetry(errors):
    """Detection entries must name a defender telemetry source.

    The detection directory's README describes its entries as
    detection notes with "Sysmon / ETW / EDR 可观测点", so an
    entry naming no telemetry source at all would be generic
    advice with no place for a defender to look. Check 19 only
    requires the entry to link to a published analysis. The
    directory's own README.md is the index, not an entry, and is
    excluded — same as check 19.
    """
    detection_dir = ROOT / "detection"
    if not detection_dir.is_dir():
        return
    for entry_file in sorted(
        p for p in detection_dir.glob("*.md") if p.name != "README.md"
    ):
        text = entry_file.read_text(encoding="utf-8")
        if not re.search(r"sysmon|\betw\b|\bedr\b", text, flags=re.I):
            errors.append(
                f"detection/{entry_file.name}: names no defender "
                "telemetry source (Sysmon / ETW / EDR) "
                "(detection entries must tell a defender where to look)"
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


def check_detection_entries_anchor_to_analysis(entry_dirs, errors):
    """Detection entries must anchor to at least one published analysis.

    The detection directory's README describes its entries as
    detection notes accompanying this repository's vulnerability
    analyses, so an entry that links to no analysis at all would be
    generic advice disconnected from the repo. Only links to
    existing ``analyses/<CVE-ID>/analysis.md`` entries count; a
    link to a missing analysis is already reported by check 4.
    """
    detection_dir = ROOT / "detection"
    if not detection_dir.is_dir():
        return
    published = {d.name for d in entry_dirs}
    for entry_file in sorted(
        p for p in detection_dir.glob("*.md") if p.name != "README.md"
    ):
        text = entry_file.read_text(encoding="utf-8")
        linked = set(
            re.findall(r"analyses/(CVE-\d+-\d+)/analysis\.md", text)
        )
        if not (linked & published):
            errors.append(
                f"detection/{entry_file.name}: links to no published "
                "analysis (detection entries must anchor to at least "
                "one analyses/<CVE-ID>/analysis.md)"
            )


def check_kernel_notes_anchor_to_analysis(entry_dirs, errors):
    """Kernel notes must anchor to at least one published analysis.

    The note describes itself as background for this repository's
    vulnerability analyses, so a note linking to no analysis at
    all would be background disconnected from the repo. Only links
    to existing ``analyses/<CVE-ID>/analysis.md`` entries count; a
    link to a missing analysis is already reported by check 4.
    """
    notes_dir = ROOT / "kernel-notes"
    if not notes_dir.is_dir():
        return
    published = {d.name for d in entry_dirs}
    for note_file in sorted(notes_dir.glob("*.md")):
        text = note_file.read_text(encoding="utf-8")
        linked = set(
            re.findall(r"analyses/(CVE-\d+-\d+)/analysis\.md", text)
        )
        if not (linked & published):
            errors.append(
                f"kernel-notes/{note_file.name}: links to no published "
                "analysis (kernel notes must anchor to at least "
                "one analyses/<CVE-ID>/analysis.md)"
            )


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
        check_reference_anchors_name_cve(entry_dir, errors)
        check_reference_nvd_links_name_cve(entry_dir, errors)
        check_reference_msrc_links_name_cve(entry_dir, errors)
        check_detection_section_names_telemetry(entry_dir, errors)
        check_affected_versions_name_windows(entry_dir, errors)
        if check_poc_compiles(entry_dir, errors):
            compiled += 1
    check_readme_index(entry_dirs, errors)
    check_readme_cwe_matches_metadata(entry_dirs, errors)
    check_readme_component_matches_metadata(entry_dirs, errors)
    detection_count = check_detection_index(errors)
    check_detection_entries_anchor_to_analysis(entry_dirs, errors)
    check_detection_entries_name_telemetry(errors)
    notes_count = check_kernel_notes_index(errors)
    check_kernel_notes_anchor_to_analysis(entry_dirs, errors)
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
        "entry for the entry's own CVE, every NVD record link naming "
        "the entry's own CVE, every MSRC advisory link naming the "
        "entry's own CVE, detection sections naming a "
        "defender telemetry source, affected-versions sections naming "
        "an affected Windows version, detection entries anchored "
        "to a published analysis and naming a defender telemetry "
        "source, kernel notes anchored to a published analysis, "
        "README indexes (including CWE classes) and "
        "Markdown links consistent, "
        "no duplicated top-level headings."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
