"""
Zero-dependency JWT decoder using only Python stdlib.
Handles base64url decoding and JSON parsing of header/payload/signature.
"""
import base64
import json


def _base64url_decode(s: str) -> bytes:
    """Decode base64url string, adding padding as needed."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def decode_jwt(token: str) -> dict:
    """
    Decode a JWT into its header, payload, and raw signature.

    Returns:
        {
            "header": {...},
            "payload": {...},
            "signature": "<hex>",
            "parts": ["<header_b64>", "<payload_b64>", "<sig_b64>"]
        }

    Raises:
        ValueError if the token is malformed.
    """
    token = token.strip()
    parts = token.split(".")

    if len(parts) != 3:
        raise ValueError(f"Invalid JWT structure: expected 3 parts, got {len(parts)}")

    header_b64, payload_b64, sig_b64 = parts

    try:
        header_bytes = _base64url_decode(header_b64)
        header = json.loads(header_bytes)
    except Exception as e:
        raise ValueError(f"Failed to decode header: {e}")

    try:
        payload_bytes = _base64url_decode(payload_b64)
        payload = json.loads(payload_bytes)
    except Exception as e:
        raise ValueError(f"Failed to decode payload: {e}")

    try:
        sig_bytes = _base64url_decode(sig_b64)
        signature_hex = sig_bytes.hex()
    except Exception:
        signature_hex = "<undecodable>"

    return {
        "header": header,
        "payload": payload,
        "signature": signature_hex,
        "parts": [header_b64, payload_b64, sig_b64],
    }
