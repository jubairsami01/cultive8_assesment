"""JSON contracts: what the model must return, and how findings look after validation."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

ATTACK_TYPES = [
    "brute_force", "credential_compromise", "sql_injection", "path_traversal", "scanning",
    "unauthorized_access", "rate_abuse", "data_exfiltration", "prompt_injection", "xss",
    "command_injection", "other",
]
SEVERITIES = ["Low", "Medium", "High", "Critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

ATTACK_LABELS = {
    "brute_force": "Brute-force login attempts",
    "credential_compromise": "Account compromise after brute force",
    "sql_injection": "SQL injection attempts",
    "path_traversal": "Path traversal attempts",
    "scanning": "Reconnaissance / vulnerability scanning",
    "unauthorized_access": "Unauthorized access attempts",
    "rate_abuse": "Abnormal request rate",
    "data_exfiltration": "Possible data exfiltration",
    "prompt_injection": "Prompt-injection text in logs",
    "xss": "Cross-site scripting attempts",
    "command_injection": "Command injection attempts",
    "other": "Other suspicious activity",
}

# JSON schema handed to llama.cpp -> grammar-constrained decoding (always valid JSON shape).
CHUNK_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "maxItems": 6,
            "items": {
                "type": "object",
                "properties": {
                    "attack_type": {"type": "string", "enum": ATTACK_TYPES},
                    "severity": {"type": "string", "enum": SEVERITIES},
                    "ip": {"type": "string", "maxLength": 45},
                    "lines": {"type": "array", "items": {"type": "integer"}, "minItems": 1, "maxItems": 15},
                    "reason": {"type": "string", "maxLength": 160},
                    "action": {"type": "string", "maxLength": 140},
                },
                "required": ["attack_type", "severity", "ip", "lines", "reason", "action"],
            },
        },
        "watch": {
            "type": "array",
            "maxItems": 3,
            "items": {
                "type": "object",
                "properties": {"ip": {"type": "string", "maxLength": 45}, "note": {"type": "string", "maxLength": 100}},
                "required": ["ip", "note"],
            },
        },
    },
    "required": ["findings", "watch"],
}

# v2: "watch" removed (v1 notes carried hallucinated facts forward; code facts are carried instead).
CHUNK_SCHEMA_V2 = {
    "type": "object",
    "properties": {"findings": CHUNK_SCHEMA["properties"]["findings"]},
    "required": ["findings"],
}


def chunk_schema(version: str) -> dict:
    return CHUNK_SCHEMA if version == "v1" else CHUNK_SCHEMA_V2


SUMMARY_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "maxLength": 700},
        "priorities": {"type": "array", "maxItems": 4, "items": {"type": "string", "maxLength": 120}},
    },
    "required": ["summary", "priorities"],
}


class ModelFinding(BaseModel):
    """One finding as returned by the model, normalised leniently."""
    attack_type: str = "other"
    severity: Literal["Low", "Medium", "High", "Critical"] = "Low"
    ip: str = "unknown"
    lines: list[int] = Field(default_factory=list)
    reason: str = ""
    action: str = ""

    @field_validator("attack_type", mode="before")
    @classmethod
    def _norm_type(cls, v):
        s = str(v or "other").strip().lower().replace(" ", "_").replace("-", "_")
        aliases = {"sqli": "sql_injection", "bruteforce": "brute_force", "brute_force_attack": "brute_force",
                   "account_compromise": "credential_compromise", "dos": "rate_abuse",
                   "directory_traversal": "path_traversal", "recon": "scanning", "reconnaissance": "scanning"}
        s = aliases.get(s, s)
        return s if s in ATTACK_TYPES else "other"

    @field_validator("severity", mode="before")
    @classmethod
    def _norm_sev(cls, v):
        s = str(v or "Low").strip().capitalize()
        return s if s in SEVERITIES else "Low"

    @field_validator("lines", mode="before")
    @classmethod
    def _norm_lines(cls, v):
        out = []
        for x in v if isinstance(v, list) else [v]:
            try:
                out.append(int(str(x).lstrip("Ll").split("-")[0]))
            except (TypeError, ValueError):
                continue
        return out

    @field_validator("ip", "reason", "action", mode="before")
    @classmethod
    def _str(cls, v):
        return str(v or "").strip()[:200]
