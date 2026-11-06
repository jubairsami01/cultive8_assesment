"""Deterministic, generic security signals + running per-entity state.

These are *hints* for the local model, not verdicts. They are computed only from data
seen so far (a single forward pass), so the state at the start of part N is exactly what
"earlier parts" told us. Nothing here is specific to one log file.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

from .parser import Entry, decoded_path, short_ua

SQLI_RE = re.compile(
    r"('|\")\s*(or|and)\s+['\"\d\w]+\s*=\s*['\"\d\w]+|union(\s|\+|/\*.*?\*/)+(all\s+)?select|"
    r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(|;\s*(drop|select|insert|update|delete|shutdown)\b|"
    r"information_schema|'\s*--|\bxp_cmdshell\b",
    re.I,
)
TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|c:\\windows|%00", re.I)
XSS_RE = re.compile(r"<script|javascript:|onerror\s*=|onload\s*=", re.I)
CMD_RE = re.compile(r";\s*(cat|ls|wget|curl|nc|bash|sh)\b|\$\(|`[^`]+`|\|\s*(sh|bash)\b", re.I)
# Common recon / scanner targets (a generic wordlist, as used by scanners themselves).
RECON_RE = re.compile(
    r"/\.env\b|/\.git(/|$)|/\.svn|/\.aws|/\.ssh|/wp-admin|/wp-login|/xmlrpc\.php|/phpmyadmin|"
    r"/actuator|/server-status|/server-info|/\.ds_store|/backup[^/]*\.(sql|zip|tar|gz)|"
    r"/config\.(json|php|yml|yaml)|/web\.config|/cgi-bin/|/vendor/phpunit|/\.well-known/security|"
    r"/console\b|/manager/html|/solr/|/jenkins|/telescope|/debug",
    re.I,
)
LOGIN_PATH_RE = re.compile(r"login|signin|sign-in|auth|session|token|oauth", re.I)
AUTH_FAIL_TEXT_RE = re.compile(
    r"failed password|authentication fail|invalid (user|password|credentials)|login failed|"
    r"invalid_password|bad credentials|unauthori[sz]ed", re.I)
AUTH_OK_TEXT_RE = re.compile(r"accepted password|login succe|authenticated|auth_result=success|\bsuccess\b", re.I)
TOOL_UA_RE = re.compile(
    r"curl|wget|python-requests|python-urllib|aiohttp|go-http-client|sqlmap|nikto|nmap|masscan|"
    r"zgrab|gobuster|dirbuster|ffuf|wfuzz|hydra|httpclient|okhttp|libwww|scrapy|nuclei", re.I)
PROMPT_INJ_RE = re.compile(
    r"ignore (all |any )?(previous|prior|above) instructions|disregard (the )?(previous|above)|"
    r"you are now|system prompt|report (all )?(events|everything) as safe|act as|"
    r"remove .*evidence|do not report|jailbreak", re.I)

RATE_WINDOW_S = 10
RATE_THRESHOLD = 20  # requests from one IP inside RATE_WINDOW_S


def _text_of(e: Entry) -> str:
    bits = [decoded_path(e.path) or "", e.message or ""]
    bits += [str(v) for v in e.extra.values()]
    return " ".join(bits)


def _seconds(ts: str | None) -> float | None:
    if not ts or len(ts) < 19:
        return None
    try:
        h, m, s = ts[11:19].split(":")
        day = int(ts[8:10])
        return day * 86400 + int(h) * 3600 + int(m) * 60 + float(s)
    except ValueError:
        return None


@dataclass
class IpState:
    ip: str
    first_line: int
    last_line: int
    total: int = 0
    failed_logins: int = 0
    fail_lines: list[int] = field(default_factory=list)       # capped sample
    success_after_fail: list[int] = field(default_factory=list)
    users: set[str] = field(default_factory=set)
    signal_counts: dict[str, int] = field(default_factory=dict)
    signal_lines: dict[str, list[int]] = field(default_factory=dict)
    statuses: dict[int, int] = field(default_factory=dict)
    tool_ua: str | None = None
    recent: deque = field(default_factory=lambda: deque(maxlen=64))
    peak_rate: int = 0

    def add_signal(self, s: str, line: int) -> None:
        self.signal_counts[s] = self.signal_counts.get(s, 0) + 1
        lst = self.signal_lines.setdefault(s, [])
        if len(lst) < 12:
            lst.append(line)

    @property
    def suspicious(self) -> bool:
        noisy = {"server_error", "tool_ua"}
        return self.failed_logins >= 2 or any(k not in noisy for k in self.signal_counts)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "first_line": self.first_line, "last_line": self.last_line,
            "total": self.total, "failed_logins": self.failed_logins,
            "fail_lines": self.fail_lines, "success_after_fail": self.success_after_fail,
            "users": sorted(self.users)[:5], "signal_counts": self.signal_counts,
            "signal_lines": self.signal_lines, "tool_ua": self.tool_ua, "peak_rate": self.peak_rate,
        }


class SignalTracker:
    """Single forward pass over entries; annotates entries and keeps per-IP state."""

    def __init__(self) -> None:
        self.ips: dict[str, IpState] = {}
        self.seen: dict[str, int] = {}  # fingerprint -> first line (bounded)

    def observe(self, e: Entry) -> None:
        sig: list[str] = []
        text = _text_of(e)
        path = decoded_path(e.path) or ""
        ua = e.ua or ""

        if e.fingerprint:
            first = self.seen.get(e.fingerprint)
            if first is not None:
                sig.append(f"duplicate_of_L{first}")
            elif len(self.seen) < 200_000:
                self.seen[e.fingerprint] = e.line_start

        if SQLI_RE.search(path) or SQLI_RE.search(text):
            sig.append("sqli_pattern")
        if TRAVERSAL_RE.search(path) or TRAVERSAL_RE.search(text):
            sig.append("traversal_pattern")
        if XSS_RE.search(text):
            sig.append("xss_pattern")
        if CMD_RE.search(path):
            sig.append("cmd_injection_pattern")
        if RECON_RE.search(path):
            sig.append("recon_path")
        if PROMPT_INJ_RE.search(text):
            sig.append("prompt_injection_text")

        is_login = bool(LOGIN_PATH_RE.search(path)) or bool(e.extra.get("auth_result"))
        auth_res = str(e.extra.get("auth_result", ""))
        failed = (is_login and e.status in (401, 403)) or bool(AUTH_FAIL_TEXT_RE.search(auth_res or (e.message or "")))
        ok = (is_login and e.status is not None and 200 <= e.status < 400 and not failed
              and (e.method or "POST").upper() == "POST") or bool(re.search(r"success", auth_res, re.I))
        if failed:
            sig.append("auth_fail")
        elif ok:
            sig.append("auth_success")

        if e.status == 403 and not failed:
            sig.append("access_denied")
        if e.status == 429:
            sig.append("rate_limited")
        if re.search(r"/admin", path, re.I):
            sig.append("admin_path")
        rb = e.extra.get("response_bytes")
        if isinstance(rb, (int, float)) and rb >= 1_000_000:
            sig.append("large_response")
        if e.status is not None and e.status >= 500 or e.is_error_level:
            sig.append("server_error")
        tool = TOOL_UA_RE.search(ua)
        if tool and (sig or e.status and e.status >= 400):
            sig.append("tool_ua")

        if e.ip:
            st = self.ips.get(e.ip)
            if st is None:
                st = self.ips[e.ip] = IpState(ip=e.ip, first_line=e.line_start, last_line=e.line_start)
            st.total += 1
            st.last_line = e.line_start
            if e.status is not None:
                st.statuses[e.status] = st.statuses.get(e.status, 0) + 1
            if e.user:
                st.users.add(str(e.user))
            if tool:
                st.tool_ua = short_ua(ua)
            if failed:
                st.failed_logins += 1
                if len(st.fail_lines) < 30:
                    st.fail_lines.append(e.line_start)
            if ok and st.failed_logins >= 2:
                st.success_after_fail.append(e.line_start)
                sig.append(f"success_after_{st.failed_logins}_failures")
            # Request rate from timestamps (sliding window).
            t = _seconds(e.ts)
            if t is not None:
                st.recent.append(t)
                while st.recent and t - st.recent[0] > RATE_WINDOW_S:
                    st.recent.popleft()
                rate = len(st.recent)
                st.peak_rate = max(st.peak_rate, rate)
                if rate >= RATE_THRESHOLD:
                    sig.append(f"high_rate_{rate}_per_{RATE_WINDOW_S}s")
            riw = e.extra.get("requests_in_window")
            if isinstance(riw, (int, float)) and riw >= RATE_THRESHOLD * 3:
                if not any(s.startswith("high_rate") for s in sig):
                    sig.append("high_rate_reported")
            for s in sig:
                if not s.startswith("duplicate"):
                    st.add_signal(s.split("_per_")[0] if s.startswith("high_rate") else s, e.line_start)

        e.signals = sig

    def is_benign(self, e: Entry) -> bool:
        if e.signals:
            return False
        if e.status is not None and e.status >= 400:
            return False
        if (e.level or "").upper() not in {"", "INFO", "DEBUG"}:
            return False
        if e.ip and e.ip in self.ips and self.ips[e.ip].suspicious:
            return False
        if e.method and e.method.upper() not in {"GET", "HEAD"}:
            return False
        return True

    def snapshot(self, limit: int = 12) -> list[dict]:
        """Suspicious IPs, most notable first (used for carried context)."""
        sus = [s for s in self.ips.values() if s.suspicious]
        sus.sort(key=lambda s: (len(s.success_after_fail) > 0, s.failed_logins + sum(s.signal_counts.values())),
                 reverse=True)
        return [s.to_dict() for s in sus[:limit]]
