"""
IAM policy analysis module.

Connects to AWS via boto3 to evaluate IAM policies, password policy,
and root account MFA status against CIS benchmark rules.

In DEMO_MODE (env DEMO_MODE=true), returns mock findings without
requiring real AWS credentials -- used by the FastAPI demo endpoint.
"""
import json
import os
from dataclasses import dataclass
from typing import Any

from .rules import IAM_RULES, Rule

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"


@dataclass
class Finding:
    rule: Rule
    resource: str
    detail: str
    raw: dict[str, Any] | None = None


def analyze_iam(profile: str | None = None) -> list[Finding]:
    """
    Run all IAM checks and return a list of Findings.

    Args:
        profile: AWS credential profile name. None uses the default chain.

    Returns:
        List of Finding objects for all triggered rules.
    """
    if DEMO_MODE:
        return _demo_findings()

    if not BOTO3_AVAILABLE:
        raise RuntimeError(
            "boto3 is not installed. Run: pip install boto3"
        )

    session = boto3.Session(profile_name=profile)
    iam = session.client("iam")
    findings: list[Finding] = []

    try:
        findings.extend(_check_root_mfa(iam))
        findings.extend(_check_password_policy(iam))
        findings.extend(_check_all_policies(iam))
    except NoCredentialsError:
        raise RuntimeError(
            "No AWS credentials found. Configure via:\n"
            "  * aws configure\n"
            "  * AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars\n"
            "  * IAM instance role (on EC2)\n"
            "Or run with DEMO_MODE=true to see sample output."
        )
    except ClientError as e:
        raise RuntimeError(f"AWS API error: {e.response['Error']['Message']}")

    return findings


def analyze_policy_document(policy_doc: dict | str) -> list[Finding]:
    """
    Analyze a raw IAM policy document (dict or JSON string) without AWS credentials.

    Useful for CI/CD policy pre-checks before deployment.

    Args:
        policy_doc: IAM policy as dict or JSON string.

    Returns:
        List of Findings from static analysis of the policy document.
    """
    if isinstance(policy_doc, str):
        try:
            policy_doc = json.loads(policy_doc)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON policy document: {e}")

    findings: list[Finding] = []
    statements = policy_doc.get("Statement", [])

    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        findings.extend(_check_statement(stmt, resource="policy_document"))

    return findings


# -- Private helpers ----------------------------------------------------------

def _check_root_mfa(iam_client: Any) -> list[Finding]:
    findings = []
    summary = iam_client.get_account_summary()["SummaryMap"]
    if not summary.get("AccountMFAEnabled", 0):
        findings.append(Finding(
            rule=IAM_RULES["IAM-001"],
            resource="root",
            detail="Root account MFA is not enabled.",
            raw={"AccountMFAEnabled": 0},
        ))
    return findings


def _check_password_policy(iam_client: Any) -> list[Finding]:
    findings = []
    try:
        policy = iam_client.get_account_password_policy()["PasswordPolicy"]
    except iam_client.exceptions.NoSuchEntityException:
        for rule_id in ["IAM-005", "IAM-006", "IAM-007", "IAM-008"]:
            findings.append(Finding(
                rule=IAM_RULES[rule_id],
                resource="account_password_policy",
                detail="No IAM password policy configured.",
            ))
        return findings

    if policy.get("MinimumPasswordLength", 0) < 14:
        findings.append(Finding(
            rule=IAM_RULES["IAM-005"],
            resource="account_password_policy",
            detail=f"Minimum length is {policy.get('MinimumPasswordLength', 'not set')} (required: 14+).",
            raw=policy,
        ))
    if not policy.get("RequireUppercaseCharacters", False):
        findings.append(Finding(
            rule=IAM_RULES["IAM-006"],
            resource="account_password_policy",
            detail="Uppercase characters not required.",
            raw=policy,
        ))
    if not policy.get("RequireSymbols", False):
        findings.append(Finding(
            rule=IAM_RULES["IAM-007"],
            resource="account_password_policy",
            detail="Symbols not required.",
            raw=policy,
        ))
    if policy.get("PasswordReusePrevention", 0) < 24:
        findings.append(Finding(
            rule=IAM_RULES["IAM-008"],
            resource="account_password_policy",
            detail=f"Reuse prevention is {policy.get('PasswordReusePrevention', 0)} (required: 24).",
            raw=policy,
        ))
    return findings


def _check_all_policies(iam_client: Any) -> list[Finding]:
    """Paginate through all customer-managed policies and check each document."""
    findings = []
    paginator = iam_client.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy_meta in page["Policies"]:
            arn = policy_meta["Arn"]
            version_id = policy_meta["DefaultVersionId"]
            try:
                doc = iam_client.get_policy_version(
                    PolicyArn=arn, VersionId=version_id
                )["PolicyVersion"]["Document"]
                findings.extend(_check_statement_list(doc, resource=arn))
            except ClientError:
                continue
    return findings


def _check_statement_list(doc: dict, resource: str) -> list[Finding]:
    findings = []
    statements = doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    for stmt in statements:
        findings.extend(_check_statement(stmt, resource=resource))
    return findings


def _check_statement(stmt: dict, resource: str) -> list[Finding]:
    findings = []
    effect = stmt.get("Effect", "Allow")
    if effect != "Allow":
        return findings

    action = stmt.get("Action", [])
    if isinstance(action, str):
        action = [action]

    res = stmt.get("Resource", [])
    if isinstance(res, str):
        res = [res]

    if "*" in action or "sts:*" in action:
        findings.append(Finding(
            rule=IAM_RULES["IAM-002"],
            resource=resource,
            detail=f"Statement allows Action: {action}",
            raw=stmt,
        ))

    if "*" in res:
        findings.append(Finding(
            rule=IAM_RULES["IAM-003"],
            resource=resource,
            detail="Statement applies to Resource: *",
            raw=stmt,
        ))

    if "NotAction" in stmt:
        findings.append(Finding(
            rule=IAM_RULES["IAM-009"],
            resource=resource,
            detail=f"Statement uses NotAction: {stmt['NotAction']}",
            raw=stmt,
        ))
    if "NotResource" in stmt:
        findings.append(Finding(
            rule=IAM_RULES["IAM-009"],
            resource=resource,
            detail=f"Statement uses NotResource: {stmt['NotResource']}",
            raw=stmt,
        ))

    assume_actions = {"sts:AssumeRole", "sts:*", "*"}
    if any(a in assume_actions for a in action) and not stmt.get("Condition"):
        findings.append(Finding(
            rule=IAM_RULES["IAM-010"],
            resource=resource,
            detail="sts:AssumeRole allowed without a Condition block.",
            raw=stmt,
        ))

    return findings


def _demo_findings() -> list[Finding]:
    """Hardcoded findings for DEMO_MODE -- no AWS credentials required."""
    return [
        Finding(
            rule=IAM_RULES["IAM-001"],
            resource="root",
            detail="Root account MFA is not enabled. (demo)",
        ),
        Finding(
            rule=IAM_RULES["IAM-002"],
            resource="arn:aws:iam::123456789012:policy/DevAccess",
            detail='Statement allows Action: ["*"]. (demo)',
        ),
        Finding(
            rule=IAM_RULES["IAM-003"],
            resource="arn:aws:iam::123456789012:policy/DevAccess",
            detail="Statement applies to Resource: *. (demo)",
        ),
        Finding(
            rule=IAM_RULES["IAM-005"],
            resource="account_password_policy",
            detail="Minimum length is 8 (required: 14+). (demo)",
        ),
        Finding(
            rule=IAM_RULES["IAM-008"],
            resource="account_password_policy",
            detail="Password reuse prevention is 0 (required: 24). (demo)",
        ),
    ]
