"""Per-part analysis helpers, cross-part memory ("carry"), validation and final merge."""
from __future__ import annotations

import json
import re
from collections import defaultdict

from pydantic import ValidationError

from .jsonrepair import parse_model_json
from .schemas import ATTACK_LABELS, SEV_RANK, SEVERITIES, ModelFinding

NOISY = {"tool_ua", "server_error", "auth_fail", "auth_success"}


def _fmt_lines(lines: list[int], keep: int = 3) -> str:
    if not lines:
        return ""
    if len(lines) <= keep + 1:
        return ",".join(f"L{n}" for n in lines)
    return f"L{lines[0]},L{lines[1]}..L{lines[-1]}"


# ---------------------------------------------------------------- carry context
def _before(s: dict, start: int) -> dict:
    """Restrict an IP snapshot to lines before `start` (the snapshot is taken while the planner
    is already reading the first entries of the new part)."""
    def cut(lines: list[int]) -> list[int]:
        return [n for n in lines if n < start]

    out = dict(s)
    out["fail_lines"] = cut(s["fail_lines"])
    later_fails = len(s["fail_lines"]) - len(out["fail_lines"])
    out["failed_logins"] = max(0, s["failed_logins"] - later_fails)
    out["success_after_fail"] = cut(s["success_after_fail"])
    out["signal_lines"], out["signal_counts"] = {}, {}
    for k, ls in s["signal_lines"].items():
        kept = cut(ls)
        if kept:
            out["signal_lines"][k] = kept
            out["signal_counts"][k] = max(len(kept), s["signal_counts"].get(k, 0) - (len(ls) - len(kept)))
    return out


def carry_lines(state: list[dict], prior_findings: list[dict], watch: dict[str, str],
                before_line: int | None = None) -> list[str]:
    """Facts known before this part, most important first. Each line is one IP."""
    best: dict[str, dict[str, str]] = defaultdict(dict)  # ip -> attack_type -> highest severity
    for f in prior_findings:
        cur = best[f["ip"]].get(f["attack_type"])
        if cur is None or SEV_RANK[f["severity"]] > SEV_RANK[cur]:
            best[f["ip"]][f["attack_type"]] = f["severity"]
    by_ip = {ip: [f"{t} {sev}" for t, sev in types.items()] for ip, types in best.items()}

    if before_line is not None:
        state = [_before(s, before_line) for s in state]
        state = [s for s in state if s["failed_logins"] or s["signal_lines"] or s["success_after_fail"]]
    out: list[tuple[int, str]] = []
    seen = set()
    for s in state:
        ip = s["ip"]
        seen.add(ip)
        bits = []
        if s["failed_logins"]:
            users = ",".join(s.get("users", [])[:2])
            bits.append(f"{s['failed_logins']} failed logins ({_fmt_lines(s['fail_lines'])})"
                        + (f" user={users}" if users else ""))
        if s["success_after_fail"]:
            bits.append(f"login SUCCESS after failures at {_fmt_lines(s['success_after_fail'])}")
        for sig, n in s["signal_counts"].items():
            if sig in NOISY or sig.startswith("success_after"):
                continue
            bits.append(f"{sig} x{n} ({_fmt_lines(s['signal_lines'].get(sig, []), 2)})")
        if s.get("tool_ua"):
            bits.append(f"ua={s['tool_ua']}")
        if by_ip.get(ip):
            bits.append("already reported: " + "; ".join(by_ip[ip]))
        if watch.get(ip):
            bits.append(f"note: {watch[ip]}")
        prio = 3 if s["success_after_fail"] else (2 if by_ip.get(ip) else 1)
        out.append((prio, f"- {ip}: " + "; ".join(bits)))
    for ip, tags in by_ip.items():  # reported IPs that the code state did not list
        if ip not in seen:
            out.append((2, f"- {ip}: already reported: " + "; ".join(tags)))
    out.sort(key=lambda t: -t[0])
    return [t[1] for t in out]


def review_lines(line_meta: dict[int, list]) -> list[str]:
    """Code-built pointer list: the tagged entries of this part, grouped by IP.
    It tells the model *where* to look; the model still decides *whether* it is an attack."""
    by_ip: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    for line, (ip, sigs) in sorted(line_meta.items()):
        for s in sigs:
            if s in ("tool_ua",) or s.startswith("duplicate_of"):
                continue
            key = "high_rate" if s.startswith("high_rate") else s
            by_ip[ip or "no-ip"][key].append(line)
    out = []
    for ip, tags in by_ip.items():
        if set(tags) == {"server_error"}:
            bits = [f"server_error x{len(tags['server_error'])} (operational?)"]
        else:
            bits = [f"{t} {_fmt_lines(ls, 3)}" + (f" ({len(ls)})" if len(ls) > 2 else "") for t, ls in tags.items()]
        out.append(f"- {ip}: " + "; ".join(bits))
    return out


# ---------------------------------------------------------------- validation
# Signals that are not attack indicators on their own: an error, a CLI user agent, or a
# normal login success (only success_after_N_failures counts) are everyday events.
OPERATIONAL_ONLY = {"server_error", "tool_ua", "auth_success"}

# Evidence-based labelling: a cited entry whose tag defines an attack type (scanner path,
# SQLi pattern, ...) is evidence for *that* type. A model finding that mixes entries of
# different specific types is split accordingly; entries without a defining tag keep the
# model's label. This catches mislabels like scanner probes reported as path_traversal, or
# failed logins reported as credential_compromise before any successful login.
SIGNAL_TYPE = {"auth_fail": "brute_force", "recon_path": "scanning", "sqli_pattern": "sql_injection",
               "traversal_pattern": "path_traversal", "prompt_injection_text": "prompt_injection",
               "xss_pattern": "xss", "cmd_injection_pattern": "command_injection"}


def _has_indicator(meta: list, attack_type: str) -> bool:
    """True if a cited line carries any attack indicator (not just an operational event)."""
    ip, sigs = meta[0], meta[1]
    real = [s for s in sigs if s not in OPERATIONAL_ONLY and not s.startswith("duplicate_of")]
    return bool(real) or (attack_type in ("rate_abuse",) and bool(ip))


def _line_type(sigs: list[str]) -> str | None:
    if any(s.startswith("success_after_") for s in sigs):
        return "credential_compromise"
    for s in ("sqli_pattern", "traversal_pattern", "cmd_injection_pattern", "xss_pattern", "prompt_injection_text",
              "recon_path", "auth_fail"):
        if s in sigs:
            return SIGNAL_TYPE[s]
    return None


def _split_by_evidence(attack_type: str, lines: list[int], line_meta: dict[int, list]) -> dict[str, list[int]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for n in lines:
        t = _line_type(line_meta[n][1]) or attack_type
        # a compromise finding may cite the failures that led to it, and an access finding
        # its denied requests: keep those with the model's type
        if attack_type == "credential_compromise" and t == "brute_force":
            t = attack_type
        groups[t].append(n)
    if attack_type == "credential_compromise" and "credential_compromise" in groups and not any(
            _line_type(line_meta[n][1]) == "credential_compromise" for n in lines):
        groups["brute_force"] = groups.pop("credential_compromise")  # no success yet -> brute force
    return groups


def validate_findings(raw_text: str, line_meta: dict[int, list], chunk_idx: int):
    """Parse + validate model output against the part it saw.

    line_meta: {line: [ip, signals]} for every entry shown to the model in this part.
    Returns (findings, watch, rejected, parse_mode). A finding is kept only if
      1. at least one cited line exists in this part,
      2. its IP appears in the cited entries (otherwise the evidence's IP is used; an IP that
         appears nowhere in the evidence is rejected as hallucinated),
      3. at least one cited entry carries an attack indicator (operational errors alone are
         not evidence of an attack).
    """
    data, mode = parse_model_json(raw_text)
    if data is None:
        return None, {}, [], mode
    findings, rejected = [], []
    items = data.get("findings", []) if isinstance(data, dict) else []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            f = ModelFinding.model_validate(item)
        except ValidationError as exc:
            rejected.append({"chunk": chunk_idx, "finding": item, "why": f"schema: {exc.errors()[0]['msg']}"})
            continue
        valid = sorted({n for n in f.lines if n in line_meta})
        if not valid:
            rejected.append({"chunk": chunk_idx, "finding": item, "why": "cited lines not in this part"})
            continue
        ips = {line_meta[n][0] for n in valid if line_meta[n][0]}
        if ips and f.ip not in ips:
            f.ip = line_meta[valid[0]][0] or next(iter(ips))  # evidence wins over the model's claim
        elif not ips and f.ip not in ("", "unknown", "n/a"):
            rejected.append({"chunk": chunk_idx, "finding": item, "why": "IP not present in cited entries"})
            continue
        if ips:
            valid = [n for n in valid if line_meta[n][0] in ("", f.ip)]
        if not any(_has_indicator(line_meta[n], f.attack_type) for n in valid):
            rejected.append({"chunk": chunk_idx, "finding": item, "why": "no attack indicator in cited entries"})
            continue
        f.ip = f.ip or "unknown"
        for atype, lines in _split_by_evidence(f.attack_type, valid, line_meta).items():
            out = f.model_dump()
            out["lines"] = lines
            out["chunk"] = chunk_idx
            if atype != f.attack_type:
                out["attack_type"], out["relabeled_from"] = atype, f.attack_type
            findings.append(out)
    watch = {}
    for w in (data.get("watch") or []) if isinstance(data, dict) else []:
        if isinstance(w, dict) and w.get("ip"):
            watch[str(w["ip"])[:45]] = str(w.get("note", ""))[:100]
    return findings, watch, rejected, mode


# ---------------------------------------------------------------- merge
CRITICAL_TYPES = {"credential_compromise", "data_exfiltration"}


def _max_sev(a: str, b: str) -> str:
    return a if SEV_RANK[a] >= SEV_RANK[b] else b


def merge_findings(all_findings: list[dict], final_state: list[dict],
                   dropped: list[dict] | None = None) -> tuple[list[dict], list[dict], list[dict]]:
    """Merge per-part findings into one deduplicated, cross-linked list.
    Findings removed by whole-file checks are appended to `dropped` (if given)."""
    dropped = dropped if dropped is not None else []
    groups: dict[tuple[str, str], dict] = {}
    for f in all_findings:
        key = (f["attack_type"], f["ip"])
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "attack_type": f["attack_type"], "label": ATTACK_LABELS.get(f["attack_type"], f["attack_type"]),
                "severity": f["severity"], "ip": f["ip"], "lines": set(), "reason": f["reason"],
                "action": f["action"], "chunks": set(), "sources": {"model"}, "reports": 0,
            }
        g["reports"] += 1
        g["lines"].update(f["lines"])
        g["chunks"].add(f["chunk"])
        if SEV_RANK[f["severity"]] > SEV_RANK[g["severity"]]:
            g["severity"], g["reason"], g["action"] = f["severity"], f["reason"], f["action"]

    state = {s["ip"]: s for s in final_state}

    # Brute force means *repeated* failures: with fewer than 3 failed logins from that IP in
    # the whole file (e.g. one typo followed by a success) the finding is not supported.
    for key in [k for k in groups if k[0] == "brute_force"]:
        s = state.get(key[1])
        if (s["failed_logins"] if s else 0) < 3:
            dropped.append({"chunk": min(groups[key]["chunks"]), "finding": {"attack_type": "brute_force", "ip": key[1]},
                            "why": f"only {s['failed_logins'] if s else 0} failed login(s) from this IP in the whole file"})
            del groups[key]

    # --- cross-part correlation (links model findings with code facts from the whole file)
    for (atype, ip), g in list(groups.items()):
        s = state.get(ip)
        if not s:
            continue
        if atype == "brute_force":
            g["lines"].update(s["fail_lines"])
            g["reason"] = (f"{s['failed_logins']} failed logins from {ip} across lines "
                           f"L{s['fail_lines'][0]}–L{s['fail_lines'][-1]}. " + g["reason"]) if s["fail_lines"] else g["reason"]
            if s["failed_logins"] >= 5 and SEV_RANK[g["severity"]] < SEV_RANK["High"]:
                g["severity"] = "High"
            if s["success_after_fail"]:
                ck = ("credential_compromise", ip)
                post = [n for sig in ("admin_path", "large_response")
                        for n in s["signal_lines"].get(sig, []) if n > s["success_after_fail"][0]]
                c = groups.get(ck)
                if c is None:
                    c = groups[ck] = {
                        "attack_type": "credential_compromise", "label": ATTACK_LABELS["credential_compromise"],
                        "severity": "Critical", "ip": ip, "lines": set(), "chunks": set(g["chunks"]),
                        "reason": "", "action": "Disable the account, revoke sessions, reset credentials, review actions taken.",
                        "sources": set(), "reports": 0,
                    }
                c["sources"].add("correlation")
                c["severity"] = "Critical"
                c["lines"].update(s["fail_lines"][:3] + s["fail_lines"][-2:] + s["success_after_fail"] + post)
                c["reason"] = (f"{s['failed_logins']} failed logins (L{s['fail_lines'][0]}–L{s['fail_lines'][-1]}) "
                               f"then a successful login at L{s['success_after_fail'][0]}"
                               + (f", followed by sensitive activity at {', '.join('L'+str(n) for n in post[:4])}" if post else "")
                               + ". Likely brute force followed by account compromise.")
                g["sources"].add("correlation")
        # Pull in matching code evidence the model saw in other parts but did not cite.
        sig_for = {"sql_injection": "sqli_pattern", "path_traversal": "traversal_pattern",
                   "scanning": "recon_path", "rate_abuse": "high_rate", "prompt_injection": "prompt_injection_text"}
        sig = sig_for.get(atype)
        if sig:
            extra = [n for k, v in s["signal_lines"].items() if k.startswith(sig) for n in v]
            if extra:
                g["lines"].update(extra)
                g["sources"].add("correlation")

    # Severity scale (as given to the model): Critical = likely successful compromise or data theft.
    for g in groups.values():
        if g["severity"] == "Critical" and g["attack_type"] not in CRITICAL_TYPES:
            g["severity"] = "High"

    findings = []
    for i, g in enumerate(sorted(groups.values(),
                                 key=lambda g: (-SEV_RANK[g["severity"]], min(g["lines"]) if g["lines"] else 0))):
        lines = sorted(g["lines"])
        findings.append({
            "id": f"F{i+1}", "attack_type": g["attack_type"], "label": g["label"], "severity": g["severity"],
            "ip": g["ip"], "lines": lines, "first_line": lines[0] if lines else None,
            "last_line": lines[-1] if lines else None, "reason": g["reason"], "action": g["action"],
            "chunks": sorted(c + 1 for c in g["chunks"]), "sources": sorted(g["sources"]), "reports": g["reports"],
        })

    # Link findings that share an actor.
    by_ip = defaultdict(list)
    for f in findings:
        by_ip[f["ip"]].append(f["id"])
    for f in findings:
        f["related"] = [x for x in by_ip[f["ip"]] if x != f["id"]]

    incidents = []
    for ip, ids in by_ip.items():
        fs = [f for f in findings if f["id"] in ids]
        sev = max((f["severity"] for f in fs), key=lambda s: SEV_RANK[s])
        lines = [n for f in fs for n in f["lines"]]
        incidents.append({"ip": ip, "severity": sev, "finding_ids": ids,
                          "types": [f["label"] for f in sorted(fs, key=lambda f: f["first_line"] or 0)],
                          "first_line": min(lines) if lines else None, "last_line": max(lines) if lines else None})
    incidents.sort(key=lambda x: (-SEV_RANK[x["severity"]], x["first_line"] or 0))

    # Code signals the model never confirmed (shown separately, never as confirmed attacks):
    # any tagged line of an IP that no finding for that IP cites as evidence.
    covered = defaultdict(set)
    for f in findings:
        covered[f["ip"]].update(f["lines"])
    unconfirmed = []
    for s in final_state:
        sigs, lines = {}, []
        for k, ls in s["signal_lines"].items():
            if k in NOISY or k.startswith("success_after"):
                continue
            missing = [n for n in ls if n not in covered[s["ip"]]]
            if missing:
                sigs[k] = len(missing)
                lines += missing
        missing_fail = [n for n in s["fail_lines"] if n not in covered[s["ip"]]]
        if len(missing_fail) >= 3:
            sigs["failed_logins"] = len(missing_fail)
            lines += missing_fail
        if sigs:
            unconfirmed.append({"ip": s["ip"], "signals": sigs, "lines": sorted(set(lines))[:30],
                                "first_line": min(lines), "last_line": max(lines)})
    return findings, incidents, unconfirmed


def severity_counts(findings: list[dict]) -> dict[str, int]:
    c = {s: 0 for s in reversed(SEVERITIES)}
    for f in findings:
        c[f["severity"]] += 1
    return c


def fallback_summary(findings: list[dict], incidents: list[dict]) -> dict:
    """Deterministic summary built from the merged findings (used when the model's summary
    fails verification)."""
    if not findings:
        return {"summary": "No attacks were identified with supporting evidence in this log.", "priorities": []}
    sc = severity_counts(findings)
    parts = []
    for inc in incidents[:4]:
        fs = sorted((f for f in findings if f["id"] in inc["finding_ids"]), key=lambda f: -SEV_RANK[f["severity"]])
        parts.append(f"{inc['ip']}: " + ", ".join(f["label"].lower() for f in fs) + f" ({inc['severity']})")
    text = (f"{len(findings)} findings from {len(incidents)} source IP(s) — "
            + ", ".join(f"{n} {s}" for s, n in sc.items() if n) + ". " + "; ".join(parts) + ".")
    seen, pri = set(), []
    for f in findings:
        if f["ip"] not in seen:
            seen.add(f["ip"])
            pri.append(f"{f['ip']}: {f['action']}")
    return {"summary": text, "priorities": pri[:4]}


# Words the summary may use for each attack type (for attribution checks).
TYPE_WORDS = {
    "brute_force": ["brute", "failed login", "password guess", "credential stuffing"],
    "credential_compromise": ["compromise", "takeover", "account access"],
    "sql_injection": ["sql"],
    "path_traversal": ["traversal", "/etc/passwd"],
    "scanning": ["scan", "reconnaissance", "recon", "probing"],
    "rate_abuse": ["rate", "flood", "dos", "request volume"],
    "prompt_injection": ["prompt"],
    "unauthorized_access": ["unauthorized", "admin"],
    "data_exfiltration": ["exfiltrat", "export"],
    "xss": ["xss", "cross-site"],
    "command_injection": ["command injection"],
}
IP_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CLAUSE_SPLIT = re.compile(r"(?<=[.;])\s+|,\s*(?:while|whereas|and while)\s+|\s+while\s+")


def _types_named(text: str) -> set[str]:
    t = text.lower()
    return {k for k, words in TYPE_WORDS.items() if any(w in t for w in words)}


def verify_summary(data: dict, findings: list[dict]) -> list[str]:
    """Return problems found in a model summary: attacks attributed to the wrong IP, or IPs
    that are not in the findings. Empty list = summary is consistent with the findings."""
    types_by_ip: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        types_by_ip[f["ip"]].add(f["attack_type"])
        if f["attack_type"] == "credential_compromise":
            types_by_ip[f["ip"]].add("brute_force")
    problems = []
    texts = [("summary", c) for c in CLAUSE_SPLIT.split(str(data.get("summary", ""))) if c.strip()]
    texts += [("priority", p) for p in data.get("priorities") or []]
    for kind, clause in texts:
        ips = IP_IN_TEXT.findall(clause)
        for ip in ips:
            if ip not in types_by_ip:
                problems.append(f"{kind}: unknown IP {ip}")
        if not ips:
            continue
        allowed = set().union(*(types_by_ip.get(ip, set()) for ip in ips))
        for t in _types_named(clause) - allowed:
            # "unauthorized"/"admin" are also natural words for a compromise
            if t == "unauthorized_access" and "credential_compromise" in allowed:
                continue
            problems.append(f"{kind}: '{t}' attributed to {', '.join(ips)}")
    return problems


def summary_input(findings: list[dict], incidents: list[dict], max_items: int = 10) -> str:
    """One line per source IP listing exactly its attack types (v2: no free-text reasons,
    which made the small model attach one IP's attacks to another)."""
    rows = []
    for inc in incidents[:max_items]:
        fs = sorted((f for f in findings if f["id"] in inc["finding_ids"]), key=lambda f: -SEV_RANK[f["severity"]])
        rows.append(f"- IP {inc['ip']} (worst: {inc['severity']}): " + ", ".join(
            f"{f['label'].lower()} [{f['severity']}, lines {f['first_line']}-{f['last_line']}]" for f in fs))
    return "Findings by source IP:\n" + "\n".join(rows)


def dumps(o) -> str:
    return json.dumps(o, separators=(",", ":"), default=list)
