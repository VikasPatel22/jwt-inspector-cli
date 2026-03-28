"""Tests for the JWT security auditor."""
import time
import pytest
from jwt_inspector.auditor import audit


def test_no_issues_with_clean_token():
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "sub": "user123",
        "iss": "https://auth.example.com",
        "aud": "my-api",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    report = audit(header, payload)
    assert report.grade == "A"
    assert report.score == 100
    assert len(report.findings) == 0


def test_alg_none_is_critical():
    header = {"alg": "none"}
    payload = {"sub": "x", "exp": int(time.time()) + 3600}
    report = audit(header, payload)
    codes = [f.code for f in report.findings]
    assert "ALG_NONE" in codes
    critical = [f for f in report.findings if f.code == "ALG_NONE"]
    assert critical[0].level == "CRITICAL"


def test_expired_token_flagged():
    header = {"alg": "RS256"}
    payload = {
        "sub": "user",
        "exp": int(time.time()) - 100,
        "iss": "issuer",
        "aud": "api",
    }
    report = audit(header, payload)
    codes = [f.code for f in report.findings]
    assert "EXPIRED" in codes


def test_missing_expiry_flagged():
    header = {"alg": "RS256"}
    payload = {"sub": "user", "iss": "issuer", "aud": "api"}
    report = audit(header, payload)
    codes = [f.code for f in report.findings]
    assert "NO_EXPIRY" in codes


def test_hs256_is_medium_risk():
    header = {"alg": "HS256"}
    payload = {"sub": "user", "exp": int(time.time()) + 3600, "iss": "x", "aud": "y"}
    report = audit(header, payload)
    alg_finding = [f for f in report.findings if f.code == "WEAK_ALG"]
    assert alg_finding
    assert alg_finding[0].level == "MEDIUM"


def test_grade_degrades_with_findings():
    header = {"alg": "none"}
    payload = {"sub": "x"}
    report = audit(header, payload)
    assert report.grade in ("D", "F")
    assert report.score < 50
