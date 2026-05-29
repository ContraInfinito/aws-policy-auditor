"""
aws-policy-auditor CLI entrypoint.

Usage examples:
  auditor scan iam --profile default
  auditor scan s3 --profile default --output report.json
  auditor scan all --output report.json
  auditor analyze-policy iam --file policy.json
  auditor analyze-policy s3 --file bucket-policy.json
"""
import sys

import click

from .iam import analyze_iam, analyze_policy_document
from .report import print_terminal_report, save_json_report, to_json_report
from .s3 import analyze_s3, analyze_bucket_policy


@click.group()
def cli() -> None:
    """aws-policy-auditor -- CIS benchmark checks for IAM and S3."""


@cli.group()
def scan() -> None:
    """Scan a live AWS account (requires credentials)."""


@scan.command("iam")
@click.option("--profile", default=None, help="AWS credential profile name.")
@click.option("--output", default=None, type=click.Path(), help="Save JSON report to this path.")
def scan_iam(profile: str | None, output: str | None) -> None:
    """Run all IAM security checks against a live AWS account."""
    try:
        click.echo("Scanning IAM policies...", err=True)
        findings = analyze_iam(profile=profile)
    except RuntimeError as e:
        click.echo(f"\n[error] {e}", err=True)
        sys.exit(1)

    print_terminal_report(findings, scan_type="IAM", profile=profile)

    if output:
        report = to_json_report(findings, scan_type="IAM", profile=profile)
        save_json_report(report, output)
        click.echo(f"JSON report saved to {output}", err=True)


@scan.command("s3")
@click.option("--profile", default=None, help="AWS credential profile name.")
@click.option("--output", default=None, type=click.Path(), help="Save JSON report to this path.")
def scan_s3(profile: str | None, output: str | None) -> None:
    """Run all S3 security checks across all accessible buckets."""
    try:
        click.echo("Scanning S3 buckets...", err=True)
        findings = analyze_s3(profile=profile)
    except RuntimeError as e:
        click.echo(f"\n[error] {e}", err=True)
        sys.exit(1)

    print_terminal_report(findings, scan_type="S3", profile=profile)

    if output:
        report = to_json_report(findings, scan_type="S3", profile=profile)
        save_json_report(report, output)
        click.echo(f"JSON report saved to {output}", err=True)


@scan.command("all")
@click.option("--profile", default=None, help="AWS credential profile name.")
@click.option("--output", default=None, type=click.Path(), help="Save combined JSON report.")
def scan_all(profile: str | None, output: str | None) -> None:
    """Run all IAM + S3 checks and produce a combined report."""
    all_findings = []

    try:
        click.echo("Scanning IAM...", err=True)
        iam_findings = analyze_iam(profile=profile)
        all_findings.extend(iam_findings)
        print_terminal_report(iam_findings, scan_type="IAM", profile=profile)
    except RuntimeError as e:
        click.echo(f"\n[error] IAM scan failed: {e}", err=True)

    try:
        click.echo("Scanning S3...", err=True)
        s3_findings = analyze_s3(profile=profile)
        all_findings.extend(s3_findings)
        print_terminal_report(s3_findings, scan_type="S3", profile=profile)
    except RuntimeError as e:
        click.echo(f"\n[error] S3 scan failed: {e}", err=True)

    if output:
        report = to_json_report(all_findings, scan_type="ALL", profile=profile)
        save_json_report(report, output)
        click.echo(f"\nCombined JSON report saved to {output}", err=True)


@cli.group("analyze-policy")
def analyze_policy() -> None:
    """Statically analyze a policy JSON file without AWS credentials."""


@analyze_policy.command("iam")
@click.option("--file", "policy_file", required=True, type=click.Path(exists=True),
              help="Path to IAM policy JSON file.")
def analyze_iam_policy(policy_file: str) -> None:
    """Analyze an IAM policy document file for security issues."""
    with open(policy_file, encoding="utf-8") as fh:
        raw = fh.read()
    try:
        findings = analyze_policy_document(raw)
    except ValueError as e:
        click.echo(f"[error] {e}", err=True)
        sys.exit(1)
    print_terminal_report(findings, scan_type="IAM (static analysis)")


@analyze_policy.command("s3")
@click.option("--file", "policy_file", required=True, type=click.Path(exists=True),
              help="Path to S3 bucket policy JSON file.")
@click.option("--bucket", default="input_policy", help="Bucket name label for the report.")
def analyze_s3_policy(policy_file: str, bucket: str) -> None:
    """Analyze an S3 bucket policy document file for security issues."""
    with open(policy_file, encoding="utf-8") as fh:
        raw = fh.read()
    try:
        findings = analyze_bucket_policy(raw, bucket_name=bucket)
    except ValueError as e:
        click.echo(f"[error] {e}", err=True)
        sys.exit(1)
    print_terminal_report(findings, scan_type="S3 (static analysis)")


if __name__ == "__main__":
    cli()
