# Windows Kernel Research

Root-cause analyses and detection notes for **publicly disclosed, already-patched**
Windows kernel vulnerabilities, with verification-only proof-of-concept triggers.

## Positioning

This repository is a **defensive research** project:

- **Root-cause analysis first.** Each entry explains *why* the bug happens, what
  state the kernel got wrong, and how the vendor patch changes that logic.
- **Detection-oriented.** Every analysis ships with a detection & mitigation
  section: what a defender can observe (behavioral traits, Sysmon/ETW/EDR
  telemetry) and what actually stops the bug class.
- **Verification PoCs only.** PoC code in this repo exists solely to prove, on
  your own test VM, that the vulnerable code path is reachable (expected
  outcome: a bugcheck or an API anomaly on an unpatched build, nothing on a
  patched build).

## Scope and hard rules

- **Patched CVEs only.** No 0-days, no embargoed issues, nothing without a
  vendor fix available.
- **No weaponization.** No privilege-escalation payloads, no token stealing,
  no mitigation bypasses (no KASLR/HVCI/CFG bypass helpers), no exploit
  reliability work, no delivery mechanisms. If a write-up needs to mention an
  exploitation primitive, it is described at the concept level only — the same
  level already published by vendor and research-team analyses.
- **Test VMs only.** Trigger code is written to be run in a disposable,
  snapshotted virtual machine that you own. It may crash the machine by
  design; that is the signal it is meant to produce.

## Layout

| Path | Contents |
|---|---|
| `analyses/<CVE-ID>/analysis.md` | Root-cause analysis, patch notes, trigger conditions, detection & mitigation |
| `analyses/<CVE-ID>/poc/` | Verification-only trigger code + build/run notes |
| `kernel-notes/` | Background notes on kernel subsystems (win32k, callbacks, desktop heap, …) |
| `detection/` | Standalone detection ideas and telemetry notes (growing collection) |

## Index

| CVE | Component | Class | Entry |
|---|---|---|---|
| CVE-2021-1732 | win32kfull.sys (`xxxCreateWindowEx`) | Window-type / field-semantics confusion across a user-mode callback → OOB write in the kernel desktop heap (CWE-787) | [analysis](analyses/CVE-2021-1732/analysis.md) |
| CVE-2022-21882 | win32kfull.sys (kernel window procedures invoking `xxxClientAllocWindowClassExtraBytes`) | Same confusion reached via non-creation (message) paths — patch bypass of CVE-2021-1732 (CWE-787) | [analysis](analyses/CVE-2022-21882/analysis.md) |
| CVE-2023-29336 | win32kfull.sys (menu item handling paths) | Use-after-free (CWE-416): the window object is locked but the nested menu object is not, so the menu can be freed mid-operation | [analysis](analyses/CVE-2023-29336/analysis.md) |

Supporting notes:

- [win32k user-mode callbacks](kernel-notes/win32k-user-callbacks.md) — why the
  callback mechanism is a recurring source of kernel bugs.

## Disclaimer

All material is provided for security research and defensive purposes only,
based exclusively on information that is already public (vendor advisories and
published research). Running any code from this repository against systems you
do not own or do not have explicit authorization to test may be illegal. The
authors assume no liability for misuse or for damage caused by trigger code —
use a snapshotted VM.
