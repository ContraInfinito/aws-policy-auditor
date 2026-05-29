"""
Pydantic models for the FastAPI audit endpoints.

Separating schemas from the API module keeps the API thin
and makes schemas reusable across different transport layers.
"""
from typing import Any

from pydantic import BaseModel, Field


# -- Request models -----------------------------------------------------------

class PolicyAnalysisRequest(BaseModel):
    """Request body for static policy analysis (no AWS credentials needed)."""

    policy: dict[str, Any] = Field(
        ...,
        description="IAM or S3 bucket policy document as a JSON object.",
        examples=[
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
        ],
    )
    bucket_name: str | None = Field(
        default=None,
        description="(S3 only) Bucket name label for the report.",
    )


# -- Response models ----------------------------------------------------------

class FindingSchema(BaseModel):
    """A single security finding."""

    rule_id: str
    title: str
    severity: str
    resource: str
    detail: str
    cis_reference: str
    remediation: str


class SeverityCountsSchema(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFO: int = 0


class AuditReportResponse(BaseModel):
    """Full audit report returned by all scan/analyze endpoints."""

    scan_type: str
    profile: str
    timestamp: str
    total_findings: int
    severity_counts: SeverityCountsSchema
    findings: list[FindingSchema]
    demo_mode: bool = Field(
        default=False,
        description="True when results are simulated (no real AWS calls).",
    )
