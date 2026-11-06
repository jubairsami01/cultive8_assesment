"""Markdown export of the final report."""
from __future__ import annotations

import datetime as dt


def to_markdown(job: dict, r: dict) -> str:
    s = r.get("stats", {})
    when = dt.datetime.fromtimestamp(job.get("finished_at") or 0).strftime("%Y-%m-%d %H:%M")
    out = [f"# Security log analysis — {job.get('filename')}", "",
           f"_Analyzed {when} with local model {job.get('model')} (prompt {job.get('prompt_version')})._", "",
           "## Summary", "", r["summary"]["summary"], ""]
    if r["summary"].get("priorities"):
        out += ["**Priorities**", ""] + [f"1. {p}" for p in r["summary"]["priorities"]] + [""]
    out += ["| Severity | Count |", "|---|---|"] + [f"| {k} | {v} |" for k, v in r["severity_counts"].items()] + [""]
    out += ["## Findings", ""]
    for f in r["findings"]:
        lines = ", ".join(f"L{n}" for n in f["lines"][:25]) + (" …" if len(f["lines"]) > 25 else "")
        out += [f"### {f['id']} · {f['severity']} · {f['label']}", "",
                f"- **Source:** {f['ip']}",
                f"- **Evidence (lines):** {lines}",
                f"- **Why:** {f['reason']}",
                f"- **Suggested action:** {f['action']}",
                f"- **Seen in parts:** {', '.join(map(str, f['chunks']))} · detected by {', '.join(f['sources'])}"
                + (f" · related: {', '.join(f['related'])}" if f.get("related") else ""), ""]
    if r.get("unconfirmed"):
        out += ["## Signals not confirmed by the model", ""]
        for u in r["unconfirmed"]:
            out.append(f"- {u['ip']}: " + ", ".join(f"{k}×{v}" for k, v in u["signals"].items()))
        out.append("")
    if r.get("failed_parts"):
        out += [f"> Parts {', '.join(map(str, r['failed_parts']))} could not be analyzed.", ""]
    out += ["## Run statistics", "",
            f"- Lines: {s.get('lines')} · entries: {s.get('entries')} · routine entries folded: {s.get('folded')}",
            f"- Tokens: raw {s.get('raw_tokens')} → compact {s.get('compact_tokens')}",
            f"- Parts: {s.get('parts')} · model calls: {s.get('model_calls')} · avg call {s.get('avg_call_ms')} ms",
            f"- Largest call: {s.get('max_total_tokens')} / 2048 tokens"]
    return "\n".join(out) + "\n"
