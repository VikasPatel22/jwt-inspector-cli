"""
Security auditor for decoded JWTs.
Checks for common vulnerabilities and misconfigurations.
"""
import time
from dataclasses import dataclass, field
from typing import List, Literal

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

RISK_SCORES = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    level: RiskLevel
    code: str
    title: str
    detail: str
    fix: str


@dataclass
class AuditReport:
    findings: List[Finding] = field(default_factory=list)
    score: int = 0           # 0–100, higher = safer
    grade: str = "A"

    def add(self, finding: Finding):
        self.findings.append(finding)

    def finalize(self):
        if not self.findings:
            self.score = 100
            self.grade = "A"
            return

        penalty = sum(RISK_SCORES[f.level] * 8 for f in self.findings)
        self.score = max(0, 100 - penalty)

        if self.score >= 85:
            self.grade = "A"
        elif self.score >= 70:
            self.grade = "B"
        elif self.score >= 50:
            self.grade = "C"
        elif self.score >= 30:
            self.grade = "D"
        else:
            self.grade = "F"


def audit(header: dict, payload: dict) -> AuditReport:
    """Run all security checks and return a consolidated report."""
    report = AuditReport()
    now = int(time.time())

    alg = header.get("alg", "")

    # ALG: none attack
    if alg.lower() == "none":
        report.add(Finding(
            level="CRITICAL",
            code="ALG_NONE",
            title="Algorithm set to 'none'",
            detail="The 'alg: none' value disables signature verification entirely. Any server accepting this is critically vulnerable.",
            fix="Set alg to RS256 or ES256. Never accept 'none' on the server.",
        ))

    # Weak symmetric algorithm
    elif alg in ("HS256", "HS384", "HS512"):
        report.add(Finding(
            level="MEDIUM",
            code="WEAK_ALG",
            title=f"Symmetric algorithm ({alg}) in use",
            detail="HMAC-based algorithms require the same secret on both client and server, risking secret leakage.",
            fix="Prefer RS256 or ES256 (asymmetric) for public-facing tokens.",
        ))

    # Missing algorithm
    if not alg:
        report.add(Finding(
            level="HIGH",
            code="MISSING_ALG",
            title="Missing 'alg' header claim",
            detail="No algorithm specified. Servers may default to 'none' or HS256.",
            fix="Always include an explicit 'alg' claim.",
        ))

    # Expiry checks
    exp = payload.get("exp")
    if exp is None:
        report.add(Finding(
            level="HIGH",
            code="NO_EXPIRY",
            title="Token has no expiration (exp)",
            detail="Tokens without expiry are valid forever — a stolen token can never be invalidated.",
            fix="Add an 'exp' claim. Recommended: 15 minutes for access tokens.",
        ))
    elif exp < now:
        age = now - exp
        report.add(Finding(
            level="HIGH",
            code="EXPIRED",
            title="Token is expired",
            detail=f"Token expired {age} seconds ago ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))}).",
            fix="Refresh the token or generate a new one.",
        ))

    # Issued-in-future check
    iat = payload.get("iat")
    if iat and iat > now + 60:
        report.add(Finding(
            level="MEDIUM",
            code="FUTURE_IAT",
            title="Token issued in the future",
            detail=f"iat ({iat}) is {iat - now}s ahead of current time. Possible clock skew or tampering.",
            fix="Ensure server clocks are synchronized (NTP). Verify iat on acceptance.",
        ))

    # Missing issuer
    if not payload.get("iss"):
        report.add(Finding(
            level="LOW",
            code="NO_ISSUER",
            title="Missing 'iss' (issuer) claim",
            detail="Without an issuer claim, tokens from different systems may be accepted interchangeably.",
            fix="Add an 'iss' claim and validate it on the server.",
        ))

    # Missing audience
    if not payload.get("aud"):
        report.add(Finding(
            level="LOW",
            code="NO_AUDIENCE",
            title="Missing 'aud' (audience) claim",
            detail="No audience restriction means the token can be replayed against any service.",
            fix="Add an 'aud' claim and validate it matches your service identifier.",
        ))

    # Suspicious: admin / role escalation
    dangerous_claims = {"admin": True, "role": "admin", "is_admin": True, "superuser": True}
    for claim, danger_val in dangerous_claims.items():
        val = payload.get(claim)
        if val is not None and (val is True or str(val).lower() in ("admin", "true", "1")):
            report.add(Finding(
                level="MEDIUM",
                code="PRIVILEGE_CLAIM",
                title=f"Privilege claim detected: '{claim}': {val}",
                detail="Embedding privilege flags in JWT payload can be dangerous if signature is not properly verified.",
                fix="Validate privilege claims server-side from a database, not just from the token.",
            ))
            break

    report.finalize()
    return report
