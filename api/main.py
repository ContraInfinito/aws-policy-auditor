"""
FastAPI wrapper around aws-policy-auditor.

Endpoints:
  GET  /               -- health check
  POST /analyze/iam    -- static IAM policy analysis (no credentials needed)
  POST /analyze/s3     -- static S3 bucket policy analysis (no credentials needed)
  GET  /scan/iam       -- live IAM scan (requires DEMO_MODE=true or real credentials)
  GET  /scan/s3        -- live S3 scan (requires DEMO_MODE=true or real credentials)

Run locally:
  uvicorn api.main:app --reload --port 8000

Deploy on Render (free tier):
  Set DEMO_MODE=true for public demo access without credentials.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from auditor.iam import analyze_iam, analyze_policy_document
from auditor.report import to_json_report
from auditor.s3 import analyze_s3, analyze_bucket_policy
from api.schemas import AuditReportResponse, PolicyAnalysisRequest

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"

app = FastAPI(
    title="aws-policy-auditor",
    description=(
        "CIS benchmark security checks for AWS IAM and S3 policies. "
        "Static analysis endpoints require no AWS credentials. "
        "Built by Mathew Josue Carballo Lopez -- github.com/ContraInfinito/aws-policy-auditor"
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["health"])
def health() -> dict:
    """Health check and version info."""
    return {
        "status": "ok",
        "service": "aws-policy-auditor",
        "version": "0.1.0",
        "demo_mode": DEMO_MODE,
    }


@app.post("/analyze/iam", response_model=AuditReportResponse, tags=["static-analysis"])
def analyze_iam_policy(body: PolicyAnalysisRequest) -> AuditReportResponse:
    """Statically analyze an IAM policy document without AWS credentials."""
    try:
        findings = analyze_policy_document(body.policy)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    report = to_json_report(findings, scan_type="IAM (static)")
    return AuditReportResponse(
        **report,
        demo_mode=False,
        severity_counts=report["severity_counts"],
    )


@app.post("/analyze/s3", response_model=AuditReportResponse, tags=["static-analysis"])
def analyze_s3_policy(body: PolicyAnalysisRequest) -> AuditReportResponse:
    """Statically analyze an S3 bucket policy document without AWS credentials."""
    bucket = body.bucket_name or "input_policy"
    try:
        findings = analyze_bucket_policy(body.policy, bucket_name=bucket)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    report = to_json_report(findings, scan_type="S3 (static)")
    return AuditReportResponse(
        **report,
        demo_mode=False,
        severity_counts=report["severity_counts"],
    )


@app.get("/scan/iam", response_model=AuditReportResponse, tags=["live-scan"])
def scan_iam_live(profile: str | None = None) -> AuditReportResponse:
    """Live IAM scan -- requires AWS credentials or DEMO_MODE=true."""
    try:
        findings = analyze_iam(profile=profile)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    report = to_json_report(findings, scan_type="IAM", profile=profile)
    return AuditReportResponse(
        **report,
        demo_mode=DEMO_MODE,
        severity_counts=report["severity_counts"],
    )


@app.get("/scan/s3", response_model=AuditReportResponse, tags=["live-scan"])
def scan_s3_live(profile: str | None = None) -> AuditReportResponse:
    """Live S3 scan across all accessible buckets -- requires AWS credentials or DEMO_MODE=true."""
    try:
        findings = analyze_s3(profile=profile)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    report = to_json_report(findings, scan_type="S3", profile=profile)
    return AuditReportResponse(
        **report,
        demo_mode=DEMO_MODE,
        severity_counts=report["severity_counts"],
    )
