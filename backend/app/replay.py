"""Re-run validation + merge on stored model replies — no model calls.

Usage (inside the api container or a dev venv):
    python -m app.replay <job_id>            # print the findings the current code would produce
    python -m app.replay <job_id> --save     # also rewrite the stored report (keeps the summary)

Useful to measure a change to validation/merging rules against a past run.
"""
from __future__ import annotations

import json
import sys

from . import analyzer
from .config import settings
from .db import DB


def replay(db: DB, job_id: str) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    job = db.job(job_id)
    if job is None:
        raise SystemExit(f"job {job_id} not found")
    meta = json.loads(job["budget_json"] or "{}")
    found, rejected = [], []
    for c in db.chunk_rows(job_id, full=True):
        if not c["raw_response"]:
            continue
        line_meta = {int(k): (v if isinstance(v, list) else [v, []]) for k, v in json.loads(c["line_ips"]).items()}
        f, _w, rej, _mode = analyzer.validate_findings(c["raw_response"], line_meta, c["idx"])
        found += f or []
        rejected += rej
    findings, incidents, unconfirmed = analyzer.merge_findings(found, meta.get("final_state", []), rejected)
    return findings, incidents, unconfirmed, rejected


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    db = DB(settings.db_path)
    job_id = sys.argv[1]
    findings, incidents, unconfirmed, rejected = replay(db, job_id)
    for f in findings:
        print(f"{f['id']:>3} {f['severity']:<8} {f['attack_type']:<22} {f['ip']:<16} "
              f"L{f['first_line']}-L{f['last_line']} parts={f['chunks']} {'+'.join(f['sources'])}")
    print(f"\nunconfirmed: {[u['ip'] for u in unconfirmed]}")
    for r in rejected:
        print(f"rejected (part {r['chunk'] + 1}): {r['finding'].get('attack_type')} {r['finding'].get('ip')} — {r['why']}")
    if "--save" in sys.argv:
        job = db.job(job_id)
        report = json.loads(job["report_json"] or "{}")
        report.update(findings=findings, incidents=incidents, unconfirmed=unconfirmed, rejected=rejected,
                      severity_counts=analyzer.severity_counts(findings))
        db.update_job(job_id, report_json=json.dumps(report))
        print("report updated")


if __name__ == "__main__":
    main()
