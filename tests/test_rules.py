"""
Unit tests for the rule engine.

These tests validate the static analysis logic with no AWS credentials
or boto3 calls needed -- safe to run in any CI environment.

Run with: pytest tests/ -v
"""
import pytest

from auditor.iam import analyze_policy_document, Finding
from auditor.rules import Severity
from auditor.s3 import analyze_bucket_policy


# -- Helpers ------------------------------------------------------------------

def _rule_ids(findings: list[Finding]) -> set[str]:
    return {f.rule.rule_id for f in findings}


def _severity(findings: list[Finding], rule_id: str) -> Severity:
    for f in findings:
        if f.rule.rule_id == rule_id:
            return f.rule.severity
    raise AssertionError(f"Rule {rule_id} not found in findings")


# -- IAM static analysis tests ------------------------------------------------

class TestIAMWildcardAction:
    def test_detects_wildcard_action(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }
        findings = analyze_policy_document(policy)
        assert "IAM-002" in _rule_ids(findings)

    def test_detects_wildcard_action_as_list(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:*", "*"], "Resource": "*"}],
        }
        findings = analyze_policy_document(policy)
        assert "IAM-002" in _rule_ids(findings)

    def test_allows_specific_action(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}
            ],
        }
        findings = analyze_policy_document(policy)
        assert "IAM-002" not in _rule_ids(findings)

    def test_deny_statements_are_ignored(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        findings = analyze_policy_document(policy)
        assert "IAM-002" not in _rule_ids(findings)


class TestIAMWildcardResource:
    def test_detects_wildcard_resource(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        findings = analyze_policy_document(policy)
        assert "IAM-003" in _rule_ids(findings)

    def test_specific_resource_passes(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}
            ],
        }
        findings = analyze_policy_document(policy)
        assert "IAM-003" not in _rule_ids(findings)


class TestIAMNotAction:
    def test_detects_not_action(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": ["s3:DeleteObject"],
                    "Resource": "*",
                }
            ],
        }
        findings = analyze_policy_document(policy)
        assert "IAM-009" in _rule_ids(findings)

    def test_detects_not_resource(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "NotResource": ["arn:aws:s3:::restricted-bucket/*"],
                }
            ],
        }
        findings = analyze_policy_document(policy)
        assert "IAM-009" in _rule_ids(findings)


class TestIAMAssumeRole:
    def test_detects_assume_role_without_condition(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}
            ],
        }
        findings = analyze_policy_document(policy)
        assert "IAM-010" in _rule_ids(findings)

    def test_assume_role_with_condition_passes(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::123456789012:role/MyRole",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                }
            ],
        }
        findings = analyze_policy_document(policy)
        assert "IAM-010" not in _rule_ids(findings)


class TestIAMJSONString:
    def test_accepts_json_string_input(self):
        import json
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        })
        findings = analyze_policy_document(policy)
        assert "IAM-002" in _rule_ids(findings)

    def test_rejects_invalid_json(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            analyze_policy_document("not json {{{")


class TestIAMMultipleStatements:
    def test_finds_issues_across_multiple_statements(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::safe/*"},
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        }
        findings = analyze_policy_document(policy)
        ids = _rule_ids(findings)
        assert "IAM-002" in ids
        assert "IAM-003" in ids


# -- S3 static analysis tests -------------------------------------------------

class TestS3PublicRead:
    def test_detects_public_read_policy(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }
        findings = analyze_bucket_policy(policy, bucket_name="my-bucket")
        assert "S3-002" in _rule_ids(findings)

    def test_detects_public_read_with_aws_principal(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": "*",
                }
            ],
        }
        findings = analyze_bucket_policy(policy, bucket_name="my-bucket")
        assert "S3-002" in _rule_ids(findings)

    def test_specific_principal_passes(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }
        findings = analyze_bucket_policy(policy, bucket_name="my-bucket")
        assert "S3-002" not in _rule_ids(findings)

    def test_deny_effect_does_not_trigger(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ],
        }
        findings = analyze_bucket_policy(policy, bucket_name="my-bucket")
        assert "S3-002" not in _rule_ids(findings)

    def test_public_with_condition_passes(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                }
            ],
        }
        findings = analyze_bucket_policy(policy, bucket_name="my-bucket")
        assert "S3-002" not in _rule_ids(findings)


class TestS3InvalidJSON:
    def test_rejects_invalid_json_string(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            analyze_bucket_policy("not {{ valid json", bucket_name="test")


# -- Severity ordering tests ---------------------------------------------------

class TestSeverityValues:
    def test_wildcard_action_is_high(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket"}],
        }
        findings = analyze_policy_document(policy)
        sev = _severity(findings, "IAM-002")
        assert sev == Severity.HIGH

    def test_public_s3_read_is_critical(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}
            ],
        }
        findings = analyze_bucket_policy(policy)
        sev = _severity(findings, "S3-002")
        assert sev == Severity.CRITICAL
