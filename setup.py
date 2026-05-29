from setuptools import setup, find_packages

setup(
    name="aws-policy-auditor",
    version="0.1.0",
    author="Mathew Josue Carballo Lopez",
    author_email="macarb2831@gmail.com",
    description="CIS benchmark security checks for AWS IAM and S3 policies.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ContraInfinito/aws-policy-auditor",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "boto3>=1.34.0",
        "click>=8.1.0",
        "fastapi>=0.111.0",
        "uvicorn[standard]>=0.29.0",
        "pydantic>=2.7.0",
    ],
    entry_points={
        "console_scripts": [
            "auditor=auditor.cli:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
    ],
)
