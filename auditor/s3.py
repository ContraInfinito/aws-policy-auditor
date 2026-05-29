"""
S3 bucket security analysis module.

Checks each accessible S3 bucket against CIS benchmark rules:
public access blocks, bucket policies, encryption, versioning, logging, ACLs.

In DEMO_MODE (env DEMO_MODE=true), returns mock findings without AWS credentials.
"""
import json
import os
from typing import Any

from .iam import Finding
from .rules import S3_RULES

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"


def analyze_s3(profile: str | None = None) -> list[Finding]:
    """
    Run all S3 security checks across all accessible buckets.

    Args:
        profile: AWS credential profile name. None uses the default chain.

    Returns:
        List of Finding objects for all triggered rules.
    """
    if DEMO_MODE:
        return _demo_findings()

    if not BOTO3_AVAILABLE:
        raise RuntimeError("boto3 is not installed. Run: pip install boto3")

    session = boto3.Session(profile_name=profile)
    s3 = session.client("s3")
    findings: list[Finding] = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except NoCredentialsError:
        raise RuntimeError(
            "No AWS credentials found. Configure via aws configure or env vars.\n"
            "Or run with DEMO_MODE=true to see sample output."
        )

    for bucket in buckets:
        name = bucket["Name"]
        findings.extend(_check_public_access_block(s3, name))
        findings.extend(_check_bucket_policy(s3, name))
        findings.extend(_check_versioning(s3, name))
        findings.extend(_check_encryption(s3, name))
        findings.extend(_check_acl(s3, name))
        findings.extend(_check_logging(s3, name))

    return findings


def analyze_bucket_policy(policy_json: dict | str, bucket_name: str = "input_policy") -> list[Finding]:
    """
    Analyze a raw S3 bucket policy document without AWS credentials.

    Args:
        policy_json: Bucket policy as dict or JSON string.
        bucket_name: Name to use in findings for identification.

    Returns:
        List of Findings from static analysis.
    """
    if isinstance(policy_json, str):
        try:
            policy_json = json.loads(policy_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON policy document: {e}")

    findings: list[Finding] = []
    statements = policy_json.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        findings.extend(_check_policy_statement(stmt, bucket_name))

    return findings


# -- Private helpers ----------------------------------------------------------

def _check_public_access_block(s3: Any, bucket: str) -> list[Finding]:
    findings = []
    try:
        config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        required = [
            "BlockPublicAcls", "IgnorePublicAcls",
            "BlockPublicPolicy", "RestrictPublicBuckets",
        ]
        disabled = [k for k in required if not config.get(k, False)]
        if disabled:
            findings.append(Finding(
                rule=S3_RULES["S3-001"],
                resource=f"s3://{bucket}",
                detail=f"Block Public Access disabled for: {', '.join(disabled)}",
                raw=config,
            ))
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            findings.append(Finding(
                rule=S3_RULES["S3-001"],
                resource=f"s3://{bucket}",
                detail="No Block Public Access configuration found -- all access blocks are disabled.",
            ))
        elif code not in ("AccessDenied", "403"):
            raise
    return findings


def _check_bucket_policy(s3: Any, bucket: str) -> list[Finding]:
    findings = []
    try:
        raw = s3.get_bucket_policy(Bucket=bucket)["Policy"]
        policy = json.loads(raw)
        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        for stmt in statements:
            findings.extend(_check_policy_statement(stmt, bucket))
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NoSuchBucketPolicy", "AccessDenied", "403"):
            raise
    return findings


def _check_policy_statement(stmt: dict, bucket: str) -> list[Finding]:
    findings = []
    effect = stmt.get("Effect", "Allow")
    principal = stmt.get("Principal", "")
    action = stmt.get("Action", [])
    if isinstance(action, str):
        action = [action]
    condition = stmt.get("Condition", {})

    is_public_principal = principal == "*" or (
        isinstance(principal, dict) and principal.get("AWS") == "*"
    )
    read_actions = {"s3:GetObject", "s3:ListBucket", "s3:*", "*"}
    if (effect == "Allow" and is_public_principal
            and any(a in read_actions for a in action)
            and not condition):
        findings.append(Finding(
            rule=S3_RULES["S3-002"],
            resource=f"s3://{bucket}",
            detail=f"Policy allows public read via Principal: * with Action: {action}",
            raw=stmt,
        ))

    return findings


def _check_versioning(s3: Any, bucket: str) -> list[Finding]:
    findings = []
    try:
        status = s3.get_bucket_versioning(Bucket=bucket).get("Status", "")
        if status != "Enabled":
            findings.append(Finding(
                rule=S3_RULES["S3-003"],
                resource=f"s3://{bucket}",
                detail=f"Versioning status: '{status or 'not set'}'",
            ))
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("AccessDenied", "403"):
            raise
    return findings


def _check_encryption(s3: Any, bucket: str) -> list[Finding]:
    findings = []
    try:
        s3.get_bucket_encryption(Bucket=bucket)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append(Finding(
                rule=S3_RULES["S3-004"],
                resource=f"s3://{bucket}",
                detail="No default encryption configuration found.",
            ))
        elif code not in ("AccessDenied", "403"):
            raise
    return findings


def _check_acl(s3: Any, bucket: str) -> list[Finding]:
    findings = []
    public_acl_grants = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if uri in public_acl_grants:
                findings.append(Finding(
                    rule=S3_RULES["S3-006"],
                    resource=f"s3://{bucket}",
                    detail=f"ACL grants access to public group: {uri}",
                    raw=grant,
                ))
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("AccessDenied", "403"):
            raise
    return findings


def _check_logging(s3: Any, bucket: str) -> list[Finding]:
    findings = []
    try:
        logging_cfg = s3.get_bucket_logging(Bucket=bucket).get("LoggingEnabled")
        if not logging_cfg:
            findings.append(Finding(
                rule=S3_RULES["S3-007"],
                resource=f"s3://{bucket}",
                detail="Server access logging is not enabled.",
            ))
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("AccessDenied", "403"):
            raise
    return findings


def _demo_findings() -> list[Finding]:
    """Hardcoded findings for DEMO_MODE -- no AWS credentials required."""
    return [
        Finding(
            rule=S3_RULES["S3-001"],
            resource="s3://my-app-logs-backup",
            detail="Block Public Access disabled for: BlockPublicAcls, RestrictPublicBuckets. (demo)",
        ),
        Finding(
            rule=S3_RULES["S3-002"],
            resource="s3://my-app-assets",
            detail='Policy allows public read via Principal: * with Action: ["s3:GetObject"]. (demo)',
        ),
        Finding(
            rule=S3_RULES["S3-004"],
            resource="s3://my-app-logs-backup",
            detail="No default encryption configuration found. (demo)",
        ),
        Finding(
            rule=S3_RULES["S3-003"],
            resource="s3://my-app-assets",
            detail="Versioning status: 'not set'. (demo)",
        ),
        Finding(
            rule=S3_RULES["S3-007"],
            resource="s3://my-app-assets",
            detail="Server access logging is not enabled. (demo)",
        ),
    ]
