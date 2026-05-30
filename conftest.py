# conftest.py — project root
# Adds the repo root to sys.path so pytest can import `auditor` and `api`
# without requiring `pip install -e .` in CI.
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
