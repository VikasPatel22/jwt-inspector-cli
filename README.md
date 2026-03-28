# jwt-inspector-cli

> **Decode, validate, and security-audit JWTs from the command line. Zero dependencies — pure Python stdlib.**

A security-focused CLI that dissects any JWT token and gives you a color-coded report with a letter grade (A–F), specific vulnerability findings, and actionable fixes.

---

## Install

```bash
pip install jwt-inspector
```

Or run directly from this repo:
```bash
git clone https://github.com/VikasPatel22/jwt-inspector-cli
cd jwt-inspector-cli
pip install -e .
```

---

## Usage

```bash
# Pass token directly
jwt-inspector eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.

# Pipe from another command
echo "eyJ..." | jwt-inspector

# Read from file
jwt-inspector --file token.txt

# Machine-readable JSON output
jwt-inspector --json eyJ...

# No colors (for CI)
jwt-inspector --no-color eyJ...
```

---

## Example Output

```
──────────────────────────────────────────────────
  JWT HEADER
──────────────────────────────────────────────────
  alg: "none"
  typ: "JWT"

──────────────────────────────────────────────────
  JWT PAYLOAD
──────────────────────────────────────────────────
  sub: "user123"
  exp: 1700000000  2023-11-14 22:13:20 UTC [EXPIRED]

──────────────────────────────────────────────────
  SECURITY AUDIT
──────────────────────────────────────────────────
  Grade: F   Score: 4/100

  [CRITICAL] ALG_NONE — Algorithm set to 'none'
       The 'alg: none' value disables signature verification entirely...
       → Fix: Set alg to RS256 or ES256. Never accept 'none' on the server.

  [HIGH] EXPIRED — Token is expired
       Token expired 300s ago (2023-11-14 22:13:20 UTC).
       → Fix: Refresh the token or generate a new one.
```

---

## Security Checks

| Check | Level | Description |
|-------|-------|-------------|
| `ALG_NONE` | CRITICAL | Algorithm set to `none` — disables verification |
| `WEAK_ALG` | MEDIUM | HMAC algorithm (HS256/384/512) in use |
| `MISSING_ALG` | HIGH | No algorithm field present |
| `NO_EXPIRY` | HIGH | Token has no `exp` claim |
| `EXPIRED` | HIGH | Token is past its expiry time |
| `FUTURE_IAT` | MEDIUM | Token issued in the future (clock skew / tampering) |
| `NO_ISSUER` | LOW | Missing `iss` claim |
| `NO_AUDIENCE` | LOW | Missing `aud` claim |
| `PRIVILEGE_CLAIM` | MEDIUM | Dangerous `admin`/`role` claims detected |

---

## File Structure

```
jwt-inspector-cli/
├── jwt_inspector/
│   ├── __init__.py
│   ├── decoder.py         # Base64url decode, zero dependencies
│   ├── auditor.py         # Security checks + grade calculation
│   └── cli.py             # argparse entry point + color output
├── tests/
│   └── test_auditor.py
├── pyproject.toml
└── README.md
```

---

## Run Tests

```bash
pip install pytest
pytest tests/
```

---

## License

MIT © Vikas Patel
