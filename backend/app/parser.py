"""Streaming log parser.

Reads the uploaded file line by line (never loads the whole file), groups physical lines
into log *entries* (continuation lines such as stack traces stay with their entry), and
turns each entry into a compact, token-cheap text form that keeps the original line number.

Supported formats: JSON-per-line, Apache/Nginx combined/common log, and free text
(fallback). Everything read from the log is treated as data only.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator
from urllib.parse import unquote

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
CLF_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
CONTINUATION_RE = re.compile(r"^(\s+|at\s|Caused by|Traceback|\.\.\.)")
BROWSER_UA_RE = re.compile(r"Mozilla/\d")

# Fields that carry no security signal and cost many tokens.
DROP_FIELDS = {"host", "request_id", "response_bytes", "duration_ms", "user_agent", "time",
               "timestamp", "@timestamp", "client_ip", "ip", "remote_addr", "method", "path",
               "url", "status", "level", "app", "service", "username", "user", "message", "msg"}
MAX_VALUE_CHARS = 120


@dataclass(slots=True)
class Entry:
    line_start: int
    line_end: int
    raw_len: int
    ts: str | None = None            # ISO-ish "YYYY-MM-DD HH:MM:SS"
    ip: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    user: str | None = None
    ua: str | None = None
    level: str | None = None
    source: str | None = None        # app/service
    message: str | None = None
    extra: dict = field(default_factory=dict)
    signals: list[str] = field(default_factory=list)
    fingerprint: str = ""          # hash of the raw text, used to spot duplicated entries
    compact: str = ""

    @property
    def is_error_level(self) -> bool:
        return (self.level or "").upper() in {"ERROR", "FATAL", "CRITICAL"}


def short_ua(ua: str | None) -> str | None:
    if not ua:
        return None
    if BROWSER_UA_RE.search(ua):
        return "browser"
    return ua.split()[0][:40]


def _clip(v) -> str:
    s = v if isinstance(v, str) else json.dumps(v, separators=(",", ":"))
    s = s.replace("\n", " ").replace("\r", " ")
    return s if len(s) <= MAX_VALUE_CHARS else s[:MAX_VALUE_CHARS] + "…"


def _from_json(obj: dict, e: Entry) -> None:
    def g(*keys):
        for k in keys:
            if k in obj and obj[k] not in (None, ""):
                return obj[k]
        return None

    ts = g("time", "timestamp", "@timestamp", "ts")
    if isinstance(ts, str):
        m = TS_RE.search(ts)
        e.ts = f"{m.group(1)} {m.group(2)}" if m else ts[:19]
    e.ip = g("client_ip", "ip", "remote_addr", "src_ip")
    e.method = g("method")
    e.path = g("path", "url", "uri")
    st = g("status", "status_code")
    try:
        e.status = int(st) if st is not None else None
    except (TypeError, ValueError):
        e.status = None
    e.user = g("username", "user")
    e.ua = g("user_agent", "ua")
    e.level = g("level", "severity")
    app, svc = obj.get("app"), obj.get("service")
    e.source = "/".join(str(x) for x in (app, svc) if x) or None
    e.message = g("message", "msg")
    e.extra = {k: v for k, v in obj.items() if k not in DROP_FIELDS}
    # Keep numeric fields that are security-relevant only when unusual.
    rb = obj.get("response_bytes")
    if isinstance(rb, (int, float)) and rb >= 1_000_000:
        e.extra["response_bytes"] = rb
    dur = obj.get("duration_ms")
    if isinstance(dur, (int, float)) and dur >= 5000:
        e.extra["duration_ms"] = dur


def _from_text(text: str, e: Entry) -> None:
    m = CLF_RE.match(text)
    if m:
        e.ip, e.method, e.path = m.group("ip"), m.group("method"), m.group("path")
        e.status = int(m.group("status"))
        e.user = None if m.group("user") == "-" else m.group("user")
        e.ua = m.group("ua")
        e.ts = m.group("ts")
        return
    t = TS_RE.search(text)
    if t:
        e.ts = f"{t.group(1)} {t.group(2)}"
    ip = IP_RE.search(text)
    if ip:
        e.ip = ip.group(0)
    lv = re.search(r"\b(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)\b", text)
    if lv:
        e.level = lv.group(1)
    e.message = text


def decoded_path(path: str | None) -> str | None:
    if not path:
        return path
    p = path
    for _ in range(2):  # handle double encoding (%252e -> %2e -> .)
        q = unquote(p)
        if q == p:
            break
        p = q
    return p


def build_compact(e: Entry) -> str:
    parts = [f"L{e.line_start}" + (f"-{e.line_end}" if e.line_end != e.line_start else "")]
    if e.ts:
        parts.append(e.ts[11:19] if len(e.ts) >= 19 else e.ts)
    if e.source:
        parts.append(e.source)
    if e.level and e.level.upper() not in {"INFO"}:
        parts.append(e.level.upper())
    if e.ip:
        parts.append(f"ip={e.ip}")
    if e.method or e.path:
        dp = decoded_path(e.path)
        parts.append(f"{e.method or ''} {_clip(dp or '')}".strip())
    if e.status is not None:
        parts.append(str(e.status))
    if e.user:
        parts.append(f"user={_clip(e.user)}")
    ua = short_ua(e.ua)
    if ua and ua != "browser":
        parts.append(f"ua={ua}")
    if e.message:
        parts.append(f'msg="{_clip(e.message)}"')
    for k, v in e.extra.items():
        parts.append(f"{k}={_clip(v)}")
    if e.signals:
        parts.append("[" + ",".join(e.signals) + "]")
    return " ".join(parts)


def iter_entries(path: Path) -> Iterator[Entry]:
    """Yield entries one at a time; only the current entry is held in memory."""
    current: Entry | None = None
    buf: list[str] = []

    def finish() -> Entry | None:
        if current is None:
            return None
        text = "\n".join(buf)
        stripped = text.strip()
        current.fingerprint = hashlib.blake2b(stripped.encode("utf-8", "replace"), digest_size=8).hexdigest()
        obj = None
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                obj = None
        if isinstance(obj, dict):
            _from_json(obj, current)
        else:
            _from_text(stripped, current)
        return current

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            if current is not None and CONTINUATION_RE.match(line) and not line.lstrip().startswith("{"):
                buf.append(line)
                current.line_end = n
                current.raw_len += len(line)
                continue
            done = finish()
            if done:
                yield done
            current = Entry(line_start=n, line_end=n, raw_len=len(line))
            buf = [line]
        done = finish()
        if done:
            yield done


def read_lines(path: Path, wanted: set[int], max_chars: int = 2000) -> dict[int, str]:
    """Return original text for selected line numbers (streaming, for the report UI)."""
    out: dict[int, str] = {}
    if not wanted:
        return out
    last = max(wanted)
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, raw in enumerate(fh, start=1):
            if n in wanted:
                out[n] = raw.rstrip("\n")[:max_chars]
            if n >= last:
                break
    return out
