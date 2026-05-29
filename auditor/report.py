"""
Report formatter for aws-policy-auditor.

Formats Finding lists into:
  - Color terminal output (with ANSI codes, graceful fallback)
  - Structured JSON for machine consumption

Severity ordering: CRITICAL > HIGH > MEDIUM > LOW > INFO
"""
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import TextIO

from .iam import Finding
from .rules import Severity


_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH:     "\033[0;31m",
    Severity.MEDIUM:   "\033[0;33m",
    Severity.LOW:      "\033[0;36m",
    Severity.INFO:     "\033[0;37m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
    Severity.LOW, Severity.INFO,
]


def _color(severity: Severity, text: str, stream: TextIO = sys.stdout) -> str:
    if not stream.isatty():
        return text
    return f"{_COLORS.get(severity, '')}{text}{_RESET}"


def _bold(text: str, stream: TextIO = sys.stdout) -> str:
    if not stream.isatty():
        return text
    return f"{_BOLD}{text}{_RESET}"


def _dim(text: str, stream: TextIO = sys.stdout) -> str:
    if not stream.isatty():
        return text
    return f"{_DIM}{text}{_RESET}"


def print_terminal_report(
    findings: list[Finding],
    scan_type: str = "scan",
    profile: str | None = None,
    stream: TextIO = sys.stdout,
) -> None:
    """
    Print a formatted terminal report for a list of findings.

    Args:
        findings: List of Finding objects to report.
        scan_type: Label for the scan type ('IAM', 'S3', etc.).
        profile: AWS profile name used for the scan.
        stream: Output stream (defaults to stdout, injectable for testing).
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    profile_label = profile or "default"

    stream.write("\n")
    stream.write(_bold(f"-- aws-policy-auditor -- {scan_type} scan\n", stream))
    stream.write(_dim(f"   profile: {profile_label}  |  {now}\n", stream))
    stream.write(_dim("-" * 52 + "\n", stream))
    stream.write("\n")

    if not findings:
        stream.write("  OK  No findings. All checks passed.\n\n")
        return

    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.index(f.rule.severity),
    )

    for f in sorted_findings:
        sev = f.rule.severity
        icon = {"CRITICAL": "X", "HIGH": "X", "MEDIUM": "!", "LOW": "-", "INFO": "i"}[sev.value]
        sev_str = _color(sev, f"{icon} {sev.value:<8}", stream)
        stream.write(f"  {sev_str}  {_bold(f.rule.title, stream)}\n")
        stream.write(f"           {_dim('resource:', stream)} {f.resource}\n")
        stream.write(f"           {_dim('detail:  ', stream)} {f.detail}\n")
        if f.rule.cis_reference:
            stream.write(f"           {_dim('cis ref: ', stream)} {f.rule.cis_reference}\n")
        stream.write(f"           {_dim('fix:     ', stream)} {f.rule.remediation}\n")
        stream.write("\n")

    counts = Counter(f.rule.severity for f in findings)
    stream.write(_dim("-" * 52 + "\n", stream))
    stream.write(_bold("  Summary\n", stream))
    for sev in _SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count:
            bar = "#" * min(count, 20)
            stream.write(f"  {_color(sev, f'{sev.value:<8}', stream)}  {bar} {count}\n")
    stream.write(f"\n  {_bold('Total:', stream)} {len(findings)} finding(s)\n\n")


def to_json_report(
    findings: list[Finding],
    scan_type: str = "scan",
    profile: str | None = None,
) -> dict:
    """
    Serialize findings to a structured JSON-serializable dict.

    Args:
        findings: List of Finding objects.
        scan_type: Label for the scan type.
        profile: AWS profile name.

    Returns:
        Dict ready for json.dumps().
    """
    counts = Counter(f.rule.severity.value for f in findings)
    return {
        "scan_type": scan_type,
        "profile": profile or "default",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "total_findings": len(findings),
        "severity_counts": {k: counts.get(k, 0) for k in
                            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "findings": [
            {
                "rule_id": f.rule.rule_id,
                "title": f.rule.title,
                "severity": f.rule.severity.value,
                "resource": f.resource,
                "detail": f.detail,
                "cis_reference": f.rule.cis_reference,
                "remediation": f.rule.remediation,
            }
            for f in sorted(findings, key=lambda x: _SEVERITY_ORDER.index(x.rule.severity))
        ],
    }


def save_json_report(report: dict, path: str) -> None:
    """Write a JSON report dict to a file."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
