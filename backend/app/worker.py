"""Single background worker: one model call at a time (fits 2 vCPU / 4 GB).

Job lifecycle: queued -> planning -> running -> done | failed | cancelled.
Each part's result is committed before the next call, so restarts resume, and a failed
part never discards completed findings.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from pathlib import Path

from . import analyzer
from .config import settings
from .db import DB
from .llm import LLMClient, LLMError
from .planner import count_raw_tokens, measure_budget, part_state_json, part_text, plan_chunks
from .jsonrepair import parse_model_json
from .prompts import load_prompt
from .schemas import SUMMARY_SCHEMA, chunk_schema

log = logging.getLogger("worker")


class Worker:
    def __init__(self, db: DB, llm: LLMClient):
        self.db = db
        self.llm = llm
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self.current_job: str | None = None

    def start(self) -> None:
        # Resume: anything interrupted mid-flight goes back to the queue.
        for row in self.db.q("SELECT id FROM jobs WHERE status IN ('queued','planning','running') ORDER BY created_at"):
            self.db.x("UPDATE chunks SET status='pending' WHERE job_id=? AND status='running'", row["id"])
            self.db.update_job(row["id"], status="queued", stage="Resuming after restart")
            self.queue.put_nowait(row["id"])
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    def enqueue(self, job_id: str) -> None:
        self.db.update_job(job_id, status="queued", stage="Waiting for the model", error=None)
        self.queue.put_nowait(job_id)

    async def _loop(self) -> None:
        while True:
            job_id = await self.queue.get()
            self.current_job = job_id
            try:
                await self.run_job(job_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # never let one job kill the worker
                log.exception("job %s crashed", job_id)
                self.db.update_job(job_id, status="failed", error=f"Unexpected error: {exc}", finished_at=time.time())
            finally:
                self.current_job = None

    def _cancelled(self, job_id: str) -> bool:
        row = self.db.job(job_id)
        return row is None or row["status"] == "cancelled"

    # ------------------------------------------------------------------ job
    async def run_job(self, job_id: str) -> None:
        job = self.db.job(job_id)
        if job is None or job["status"] == "cancelled":
            return
        path = Path(job["path"])
        if not job["started_at"]:
            self.db.update_job(job_id, started_at=time.time())

        self.db.update_job(job_id, status="planning", stage="Connecting to the local model")
        await self.llm.wait_ready()

        if not self.db.one("SELECT 1 FROM chunks WHERE job_id=? LIMIT 1", job_id):
            self.db.update_job(job_id, stage="Measuring token budget")
            budget = await measure_budget(self.llm)
            self.db.update_job(job_id, stage="Counting tokens in the original file")
            raw_tokens = await count_raw_tokens(self.llm, path)
            self.db.update_job(job_id, stage="Splitting the log into parts")
            parts, stats = await plan_chunks(self.llm, path, budget)
            if not parts:
                self.db.update_job(job_id, status="failed", error="No log entries found in this file.",
                                   finished_at=time.time())
                return
            with self.db.tx() as c:
                for i, p in enumerate(parts):
                    c.execute(
                        "INSERT INTO chunks (job_id, idx, line_start, line_end, n_entries, token_count, text, line_ips,"
                        " state_json) VALUES (?,?,?,?,?,?,?,?,?)",
                        (job_id, i, p.line_start, p.line_end, p.n_entries, p.tokens, part_text(p),
                         json.dumps(p.line_ips), part_state_json(p)))
                c.execute("UPDATE jobs SET total_lines=?, total_entries=?, collapsed_entries=?, raw_tokens=?,"
                          " compact_tokens=?, n_chunks=?, budget_json=? WHERE id=?",
                          (stats["lines"], stats["entries"], stats["folded"], raw_tokens, stats["compact_tokens"],
                           len(parts), json.dumps({**budget.to_dict(), "final_state": stats["final_state"]}), job_id))

        self.db.update_job(job_id, status="running")
        rows = self.db.chunk_rows(job_id, full=True)
        n = len(rows)
        for row in rows:
            if row["status"] == "done":
                continue
            if self._cancelled(job_id):
                return
            self.db.update_job(job_id, stage=f"Analyzing part {row['idx'] + 1} of {n}")
            await self._process_chunk(job_id, row, n)

        if self._cancelled(job_id):
            return
        self.db.update_job(job_id, stage="Merging findings into one report")
        await self._finalize(job_id)

    # ------------------------------------------------------------------ one part
    def _prior(self, job_id: str, idx: int) -> tuple[list[dict], dict[str, str]]:
        findings, watch = [], {}
        for r in self.db.q("SELECT findings_json, watch_json FROM chunks WHERE job_id=? AND idx<? AND status='done'"
                           " ORDER BY idx", job_id, idx):
            findings += json.loads(r["findings_json"] or "[]")
            watch.update(json.loads(r["watch_json"] or "{}"))
        return findings, watch

    async def _build_messages(self, row, n: int, carry_budget: int) -> tuple[list[dict], int, int]:
        prior, watch = self._prior(row["job_id"], row["idx"])
        lines = analyzer.carry_lines(json.loads(row["state_json"]), prior, watch, before_line=row["line_start"])
        meta = {int(k): (v if isinstance(v, list) else [v, []]) for k, v in json.loads(row["line_ips"]).items()}
        review = "\n".join(analyzer.review_lines(meta)) or "- none"
        system = load_prompt("system")
        tmpl = load_prompt("chunk")

        def render(carry_list):
            carry = "\n".join(carry_list) if carry_list else "- nothing yet"
            return [{"role": "system", "content": system},
                    {"role": "user", "content": tmpl.format(part=row["idx"] + 1, parts=n, line_start=row["line_start"],
                                                            line_end=row["line_end"], carry=carry, review=review,
                                                            log=row["text"])}]

        # Fit carry into its budget (token-measured), most important facts first.
        kept: list[str] = []
        used = await self.llm.count_tokens(review) + 8 if "{review}" in tmpl else 0
        for ln in lines:
            t = await self.llm.count_tokens(ln) + 1
            if used + t > carry_budget:
                break
            kept.append(ln)
            used += t
        msgs = render(kept)
        prompt_tokens = await self.llm.count_chat(msgs)
        while prompt_tokens + 256 > settings.ctx_size and kept:  # never starve the reply
            kept.pop()
            msgs = render(kept)
            prompt_tokens = await self.llm.count_chat(msgs)
        max_tokens = min(settings.output_reserve, settings.ctx_size - prompt_tokens - 8)
        return msgs, prompt_tokens, max_tokens

    async def _process_chunk(self, job_id: str, row, n: int) -> None:
        idx = row["idx"]
        attempts = row["attempts"] or 0
        carry_budget = settings.carry_budget
        last_err = None
        line_ips = {int(k): (v if isinstance(v, list) else [v, []]) for k, v in json.loads(row["line_ips"]).items()}
        while attempts < settings.max_attempts:
            attempts += 1
            self.db.update_chunk(job_id, idx, status="running", attempts=attempts)
            try:
                msgs, ptoks, max_tokens = await self._build_messages(row, n, carry_budget)
                if max_tokens < 200:
                    raise LLMError("part too large for the context window", retryable=True, context_overflow=True)
                res = await self.llm.chat(msgs, chunk_schema(settings.prompt_version), max_tokens=max_tokens,
                                          temperature=0.0 if attempts == 1 else 0.2)
                findings, watch, rejected, mode = analyzer.validate_findings(res.content, line_ips, idx)
                if findings is None:
                    raise LLMError(f"model reply was not usable JSON ({mode})", retryable=True)
                self.db.update_chunk(
                    job_id, idx, status="done", error=None, latency_ms=res.latency_ms,
                    prompt_tokens=res.prompt_tokens or ptoks, completion_tokens=res.completion_tokens,
                    parse_mode=mode + ("+truncated" if res.finish_reason == "length" else ""),
                    raw_response=res.content[:4000], findings_json=findings, watch_json=watch)
                if rejected:
                    log.info("part %s: %d findings rejected by validation", idx, len(rejected))
                    self._append_rejected(job_id, rejected)
                return
            except LLMError as exc:
                last_err = str(exc)
                log.warning("job %s part %s attempt %s failed: %s", job_id, idx, attempts, exc)
                if exc.context_overflow:
                    carry_budget = carry_budget // 2
                if not exc.retryable:
                    break
                if "unreachable" in last_err or "not ready" in last_err:
                    try:
                        await self.llm.wait_ready(120)
                    except LLMError:
                        pass
                await asyncio.sleep(min(2 ** attempts, 15) + random.random())
        self.db.update_chunk(job_id, idx, status="failed", error=last_err)

    def _append_rejected(self, job_id: str, rejected: list[dict]) -> None:
        row = self.db.job(job_id)
        budget = json.loads(row["budget_json"] or "{}")
        budget.setdefault("rejected", []).extend(rejected)
        self.db.update_job(job_id, budget_json=json.dumps(budget))

    # ------------------------------------------------------------------ final report
    async def _finalize(self, job_id: str) -> None:
        job = self.db.job(job_id)
        chunks = self.db.chunk_rows(job_id, full=True)
        all_findings = [f for c in chunks for f in json.loads(c["findings_json"] or "[]")]
        meta = json.loads(job["budget_json"] or "{}")
        final_state = meta.get("final_state", [])
        dropped: list[dict] = []
        findings, incidents, unconfirmed = analyzer.merge_findings(all_findings, final_state, dropped)
        meta.setdefault("rejected", []).extend(dropped)

        summary, summary_src, summary_ms = analyzer.fallback_summary(findings, incidents), "rules", None
        summary_problems: list[str] = []
        if settings.final_summary and findings:
            self.db.update_job(job_id, stage="Writing the executive summary")
            summary_problems: list[str] = []
            try:
                msgs = [{"role": "system", "content": load_prompt("summary_system")},
                        {"role": "user", "content": analyzer.summary_input(findings, incidents)}]
                ptoks = await self.llm.count_chat(msgs)
                for attempt in range(2):  # one retry if the summary contradicts the findings
                    if ptoks + 200 > settings.ctx_size:
                        break
                    res = await self.llm.chat(msgs, SUMMARY_SCHEMA, max_tokens=min(400, settings.ctx_size - ptoks - 8),
                                              temperature=0.0 if attempt == 0 else 0.3)
                    summary_ms = (summary_ms or 0) + res.latency_ms
                    data, _ = parse_model_json(res.content)
                    if not (isinstance(data, dict) and data.get("summary")):
                        summary_problems = ["unusable JSON"]
                        continue
                    summary_problems = analyzer.verify_summary(data, findings)
                    if not summary_problems:
                        summary = {"summary": str(data["summary"])[:900],
                                   "priorities": [str(p)[:160] for p in (data.get("priorities") or [])][:4]}
                        summary_src = "model"
                        break
                    log.info("summary attempt %d rejected: %s", attempt + 1, summary_problems)
            except LLMError as exc:
                log.warning("summary failed, using fallback: %s", exc)
                summary_problems = [str(exc)]

        failed = [c["idx"] + 1 for c in chunks if c["status"] == "failed"]
        lat = [c["latency_ms"] for c in chunks if c["latency_ms"]]
        report = {
            "summary": {**summary, "source": summary_src, "latency_ms": summary_ms,
                        "rejected_reasons": summary_problems if summary_src != "model" else []},
            "severity_counts": analyzer.severity_counts(findings),
            "findings": findings,
            "incidents": incidents,
            "unconfirmed": unconfirmed,
            "rejected": meta.get("rejected", []),
            "failed_parts": failed,
            "stats": {
                "lines": job["total_lines"], "entries": job["total_entries"], "folded": job["collapsed_entries"],
                "raw_tokens": job["raw_tokens"], "compact_tokens": job["compact_tokens"], "parts": len(chunks),
                "model_calls": sum((c["attempts"] or 0) for c in chunks) + (1 if summary_ms else 0),
                "total_model_ms": sum(lat) + (summary_ms or 0), "avg_call_ms": int(sum(lat) / len(lat)) if lat else None,
                "max_prompt_tokens": max((c["prompt_tokens"] or 0) for c in chunks),
                "max_total_tokens": max(((c["prompt_tokens"] or 0) + (c["completion_tokens"] or 0)) for c in chunks),
            },
            "budget": {k: v for k, v in meta.items() if k not in ("final_state", "rejected")},
        }
        status = "done"
        err = (f"Parts {', '.join(map(str, failed))} could not be analyzed after {settings.max_attempts} attempts. "
               "Findings from the other parts are kept; you can retry the failed parts.") if failed else None
        self.db.update_job(job_id, status=status, stage="Complete", report_json=json.dumps(report),
                           finished_at=time.time(), error=err)
