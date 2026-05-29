"""
CIS AWS Foundations Benchmark rule definitions.

Each rule is a dataclass carrying its ID, title, description, severity,
and the remediation guidance. Rules are referenced by the IAM and S3 checkers.
"""
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    remediation: str
    cis_reference: str = ""


# ── IAM Rules ────────────────────────────────────────────────────────────────

IAM_RULES: dict[str, Rule] = {
    "IAM-001": Rule(
        rule_id="IAM-001",
        title="Root account MFA not enabled",
        description="The root AWS account does not have multi-factor authentication enabled.",
        severity=Severity.CRITICAL,
        remediation="Enable MFA on the root account via IAM > Security credentials > MFA.",
        cis_reference="CIS 1.5",
    ),
    "IAM-002": Rule(
        rule_id="IAM-002",
        title="Policy allows wildcard Action ('Action: *')",
        description="A policy grants all actions (*) on resources, violating least-privilege.",
        severity=Severity.HIGH,
        remediation="Replace Action: * with specific actions required for the use case.",
        cis_reference="CIS 1.16",
    ),
    "IAM-003": Rule(
        rule_id="IAM-003",
        title="Policy allows wildcard Resource ('Resource: *')",
        description="A policy applies to all resources (*). Scope it to specific ARNs.",
        severity=Severity.HIGH,
        remediation="Replace Resource: * with specific resource ARNs.",
        cis_reference="CIS 1.16",
    ),
    "IAM-004": Rule(
        rule_id="IAM-004",
        title="Inline policy detected",
        description="Inline policies are attached directly to a user/role and harder to audit.",
        severity=Severity.MEDIUM,
        remediation="Convert inline policies to managed policies for better governance.",
        cis_reference="CIS 1.16",
    ),
    "IAM-005": Rule(
        rule_id="IAM-005",
        title="Weak password policy — minimum length below 14",
        description="IAM password policy enforces a minimum length below 14 characters.",
        severity=Severity.MEDIUM,
        remediation="Set minimum password length to 14+ characters in IAM password policy.",
        cis_reference="CIS 1.8",
    ),
    "IAM-006": Rule(
        rule_id="IAM-006",
        title="Password policy does not require uppercase",
        description="IAM password policy does not require uppercase letters.",
        severity=Severity.LOW,
        remediation="Enable 'require uppercase letters' in IAM password policy.",
        cis_reference="CIS 1.9",
    ),
    "IAM-007": Rule(
        rule_id="IAM-007",
        title="Password policy does not require symbols",
        description="IAM password policy does not require symbols.",
        severity=Severity.LOW,
        remediation="Enable 'require symbols' in IAM password policy.",
        cis_reference="CIS 1.10",
    ),
    "IAM-008": Rule(
        rule_id="IAM-008",
        title="Password reuse prevention not set",
        description="Password history is not configured, allowing password reuse.",
        severity=Severity.LOW,
        remediation="Set password reuse prevention to 24 in IAM password policy.",
        cis_reference="CIS 1.11",
    ),
    "IAM-009": Rule(
        rule_id="IAM-009",
        title="NotAction or NotResource used in policy",
        description="NotAction/NotResource create implicit allow-all patterns that are hard to reason about.",
        severity=Severity.MEDIUM,
        remediation="Replace NotAction/NotResource with explicit Action/Resource lists.",
        cis_reference="CIS 1.16",
    ),
    "IAM-010": Rule(
        rule_id="IAM-010",
        title="Policy allows AssumeRole without condition",
        description="sts:AssumeRole is allowed without MFA or external ID conditions.",
        severity=Severity.MEDIUM,
        remediation="Add Condition requiring MFA or ExternalId for AssumeRole actions.",
        cis_reference="CIS 1.20",
    ),
}

# ── S3 Rules ─────────────────────────────────────────────────────────────────

S3_RULES: dict[str, Rule] = {
    "S3-001": Rule(
        rule_id="S3-001",
        title="S3 bucket allows public access (Block Public Access disabled)",
        description="One or more Block Public Access settings are disabled on this bucket.",
        severity=Severity.CRITICAL,
        remediation="Enable all four Block Public Access settings on the bucket.",
        cis_reference="CIS 2.1.2",
    ),
    "S3-002": Rule(
        rule_id="S3-002",
        title="S3 bucket policy allows public read",
        description="Bucket policy has a Principal: * statement that allows read access.",
        severity=Severity.CRITICAL,
        remediation="Remove or restrict Principal: * from the bucket policy.",
        cis_reference="CIS 2.1.1",
    ),
    "S3-003": Rule(
        rule_id="S3-003",
        title="S3 bucket versioning not enabled",
        description="Versioning is disabled, preventing recovery from accidental deletion.",
        severity=Severity.LOW,
        remediation="Enable versioning on the bucket.",
        cis_reference="CIS 2.1.3",
    ),
    "S3-004": Rule(
        rule_id="S3-004",
        title="S3 bucket server-side encryption not configured",
        description="Bucket does not have a default encryption configuration.",
        severity=Severity.HIGH,
        remediation="Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
        cis_reference="CIS 2.1.1",
    ),
    "S3-005": Rule(
        rule_id="S3-005",
        title="S3 bucket does not enforce HTTPS (no SSL policy)",
        description="Bucket policy does not deny HTTP requests (aws:SecureTransport not enforced).",
        severity=Severity.MEDIUM,
        remediation="Add a Deny policy statement requiring aws:SecureTransport: true.",
        cis_reference="CIS 2.1.2",
    ),
    "S3-006": Rule(
        rule_id="S3-006",
        title="S3 bucket ACL is public-read or public-read-write",
        description="Bucket ACL grants public read or write access.",
        severity=Severity.CRITICAL,
        remediation="Set bucket ACL to private and use bucket policies for access control.",
        cis_reference="CIS 2.1.1",
    ),
    "S3-007": Rule(
        rule_id="S3-007",
        title="S3 bucket logging not enabled",
        description="Server access logging is not enabled. Audit trail is incomplete.",
        severity=Severity.INFO,
        remediation="Enable server access logging and direct logs to a dedicated bucket.",
        cis_reference="CIS 2.1.4",
    ),
}
