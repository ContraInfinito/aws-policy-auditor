# aws-policy-auditor

CIS AWS Foundations Benchmark security checks for IAM and S3, delivered as a Python CLI and FastAPI service.

[![CI](https://github.com/ContraInfinito/aws-policy-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/ContraInfinito/aws-policy-auditor/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://aws-policy-auditor.onrender.com/docs)

**Live API:** https://aws-policy-auditor.onrender.com/docs

---

## What it does

- **IAM checks** — root MFA, wildcard actions/resources, NotAction/NotResource patterns, password policy strength, AssumeRole without conditions, inline policies
- **S3 checks** — Block Public Access settings, public bucket policies, missing encryption, versioning, ACL exposure, access logging
- **Two modes** — static analysis (no credentials) for policy files, live scan (boto3) for real accounts
- **Output** — color terminal report + JSON export for CI pipelines

---

## Real scan output

Running against a fresh AWS account with no password policy configured:

```
$ python -m auditor.cli scan all --output my-findings.json
Scanning IAM...

-- aws-policy-auditor -- IAM scan
   profile: default  |  2026-06-06T18:30:43Z
----------------------------------------------------
  ! MEDIUM    Weak password policy — minimum length below 14
           resource: account_password_policy
           detail:   No IAM password policy configured.
           cis ref:  CIS 1.8
           fix:      Set minimum password length to 14+ characters in IAM password policy.

  - LOW       Password policy does not require uppercase
           resource: account_password_policy
           detail:   No IAM password policy configured.
           cis ref:  CIS 1.9
           fix:      Enable 'require uppercase letters' in IAM password policy.

  - LOW       Password policy does not require symbols
           resource: account_password_policy
           detail:   No IAM password policy configured.
           cis ref:  CIS 1.10
           fix:      Enable 'require symbols' in IAM password policy.

  - LOW       Password reuse prevention not set
           resource: account_password_policy
           detail:   No IAM password policy configured.
           cis ref:  CIS 1.11
           fix:      Set password reuse prevention to 24 in IAM password policy.

----------------------------------------------------
  Summary
  MEDIUM    # 1
  LOW       ### 3

  Total: 4 finding(s)

Scanning S3...
  OK  No findings. All checks passed.
```

After configuring the password policy in the IAM console, re-running confirms the fixes:

```
$ python -m auditor.cli scan all --output my-findings.json
Scanning IAM...
  OK  No findings. All checks passed.
Scanning S3...
  OK  No findings. All checks passed.
```

---

## Quick start

```bash
git clone https://github.com/ContraInfinito/aws-policy-auditor
cd aws-policy-auditor
pip install -r requirements.txt
pip install -e .  # installs `auditor` CLI command
```

### Static analysis (no AWS account needed)

```bash
# Analyze a local IAM policy file
auditor analyze-policy iam --file examples/bad-iam-policy.json

# Analyze a local S3 bucket policy file
auditor analyze-policy s3 --file examples/bad-s3-policy.json --bucket my-bucket
```

### Live scan (requires AWS credentials)

```bash
# Configure credentials first
aws configure  # or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY

# Scan IAM
auditor scan iam --profile default

# Scan S3
auditor scan s3 --output s3-report.json

# Scan everything, save combined report
auditor scan all --profile my-profile --output full-report.json
```

---

## AWS Free Tier setup

You don't need to spend anything to use this tool:

1. Create an [AWS Free Tier account](https://aws.amazon.com/free/)
2. Create an IAM user with `ReadOnlyAccess` managed policy
3. Generate access keys for that user
4. Run `aws configure` with those keys
5. Run `auditor scan all`

**Note:** Read-only access is sufficient for all checks. The tool never modifies your account.

---

## Running the FastAPI service

```bash
# Development (with auto-reload)
uvicorn api.main:app --reload --port 8000

# Demo mode (no credentials needed -- returns sample findings)
DEMO_MODE=true uvicorn api.main:app --port 8000

# API docs available at http://localhost:8000/docs
```

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Health check |
| POST | `/analyze/iam` | Static IAM policy analysis |
| POST | `/analyze/s3` | Static S3 bucket policy analysis |
| GET | `/scan/iam` | Live IAM scan (credentials or DEMO_MODE) |
| GET | `/scan/s3` | Live S3 scan (credentials or DEMO_MODE) |

### Example API call

```bash
curl -X POST http://localhost:8000/analyze/iam \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "Version": "2012-10-17",
      "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }
  }'
```

---

## Deploy to Render (free tier)

1. Fork this repo
2. Create a new **Web Service** on [render.com](https://render.com)
3. Set the build command: `pip install -r requirements.txt`
4. Set the start command: `uvicorn api.main:app --host 0.0.0.0 --port $PORT`
5. Add environment variable: `DEMO_MODE=true`
6. Deploy — your public demo API is live

---

## Running tests

```bash
# All tests (no AWS credentials needed)
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=auditor --cov-report=term-missing
```

Tests use static analysis only — boto3 is never called in the test suite.

---

## Project structure

```
aws-policy-auditor/
├── auditor/
│   ├── __init__.py     # package metadata
│   ├── cli.py          # Click CLI entrypoint
│   ├── iam.py          # IAM policy analysis (boto3 + static)
│   ├── s3.py           # S3 security checks (boto3 + static)
│   ├── rules.py        # CIS benchmark rule definitions
│   └── report.py       # Terminal + JSON report formatter
├── api/
│   ├── main.py         # FastAPI application
│   └── schemas.py      # Pydantic request/response models
├── tests/
│   └── test_rules.py   # Unit tests (no boto3 required)
├── .github/workflows/
│   └── ci.yml          # GitHub Actions: lint + test
├── requirements.txt
├── setup.py
└── README.md
```

---

## CIS rules implemented

### IAM
| Rule ID | Severity | Title |
|---------|----------|-------|
| IAM-001 | CRITICAL | Root account MFA not enabled |
| IAM-002 | HIGH | Wildcard Action (`Action: *`) |
| IAM-003 | HIGH | Wildcard Resource (`Resource: *`) |
| IAM-004 | MEDIUM | Inline policy detected |
| IAM-005 | MEDIUM | Password min length < 14 |
| IAM-006 | LOW | Password policy: no uppercase |
| IAM-007 | LOW | Password policy: no symbols |
| IAM-008 | LOW | Password reuse prevention not set |
| IAM-009 | MEDIUM | NotAction / NotResource used |
| IAM-010 | MEDIUM | AssumeRole without condition |

### S3
| Rule ID | Severity | Title |
|---------|----------|-------|
| S3-001 | CRITICAL | Block Public Access disabled |
| S3-002 | CRITICAL | Bucket policy allows public read |
| S3-003 | LOW | Versioning not enabled |
| S3-004 | HIGH | Server-side encryption not configured |
| S3-005 | MEDIUM | HTTPS not enforced (no SecureTransport) |
| S3-006 | CRITICAL | ACL is public-read or public-read-write |
| S3-007 | INFO | Access logging not enabled |

---

## Author

**Mathew Josue Carballo Lopez** — [github.com/ContraInfinito](https://github.com/ContraInfinito) · [linkedin.com/in/mathewjc](https://linkedin.com/in/mathewjc)

B.Sc. Computer Engineering, Instituto Tecnológico de Costa Rica (Jun 2026)
