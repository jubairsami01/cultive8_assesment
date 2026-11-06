"""FastAPI app: upload, start, progress (SSE), report, system stats. Serves the UI."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import psutil
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .db import DB
from .llm import LLMClient
from .parser import read_lines
from .report_md import to_markdown
from .worker import Worker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("api")

FRONTEND_DIR = Path(os.environ.get("FRONTEND_DIR", Path(__file__).resolve().parents[2] / "frontend"))
db = DB(settings.db_path)
llm = LLMClient()
worker = Worker(db, llm)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    worker.start()
    yield
    await worker.stop()
    await llm.close()


app = FastAPI(title="Local AI Security Log Analyzer", lifespan=lifespan)


def _err(status: int, msg: str, hint: str | None = None):
    raise HTTPException(status_code=status, detail={"message": msg, "hint": hint})


def _job_view(row, with_chunks: bool = True, with_report: bool = True) -> dict:
    j = {k: row[k] for k in row.keys() if k not in ("report_json", "budget_json", "path")}
    budget = json.loads(row["budget_json"] or "{}")
    j["budget"] = {k: v for k, v in budget.items() if k not in ("final_state", "rejected")}
    if with_chunks:
        chunks = [dict(c) for c in db.chunk_rows(row["id"])]
        for c in chunks:
            c["n_findings"] = len(json.loads(c.pop("findings_json") or "[]"))
        j["chunks"] = chunks
        done = [c for c in chunks if c["status"] == "done"]
        lat = [c["latency_ms"] for c in done if c["latency_ms"]]
        remaining = sum(1 for c in chunks if c["status"] in ("pending", "running"))
        j["progress"] = {
            "done": len(done), "failed": sum(1 for c in chunks if c["status"] == "failed"),
            "total": len(chunks), "avg_ms": int(sum(lat) / len(lat)) if lat else None,
            "eta_s": int(remaining * (sum(lat) / len(lat)) / 1000) if lat and remaining else None,
            "findings_so_far": sum(c["n_findings"] for c in chunks),
        }
    if with_report and row["report_json"]:
        j["report"] = json.loads(row["report_json"])
    return j


# ------------------------------------------------------------------------ API
@app.get("/api/health")
async def health():
    return {"api": "ok", "model_ready": await llm.health()}


def _mem_info() -> dict:
    me = psutil.Process()
    api_rss = me.memory_info().rss
    model_rss = 0
    for p in psutil.process_iter(["name", "cmdline", "memory_info"]):
        try:
            name = (p.info["name"] or "") + " " + " ".join(p.info["cmdline"] or [])
            if "llama-server" in name and p.info["memory_info"]:
                model_rss += p.info["memory_info"].rss
        except (psutil.Error, TypeError):
            continue
    out = {"api_mb": round(api_rss / 2**20), "model_mb": round(model_rss / 2**20) if model_rss else None,
           "limit_mb": 4096}
    out["total_mb"] = out["api_mb"] + (out["model_mb"] or 0)
    try:  # cgroup v2 numbers for this container
        cur = Path("/sys/fs/cgroup/memory.current").read_text().strip()
        mx = Path("/sys/fs/cgroup/memory.max").read_text().strip()
        out["api_cgroup_mb"] = round(int(cur) / 2**20)
        out["api_cgroup_limit_mb"] = None if mx == "max" else round(int(mx) / 2**20)
    except (OSError, ValueError):
        pass
    return out


@app.get("/api/system")
async def system():
    props = await llm.props()
    model_path = props.get("model_path") or ""
    gen = props.get("default_generation_settings", {}) or {}
    last = db.q("SELECT latency_ms, prompt_tokens, completion_tokens FROM chunks WHERE latency_ms IS NOT NULL"
                " ORDER BY updated_at DESC LIMIT 20")
    lat = [r["latency_ms"] for r in last]
    return {
        "model": {"name": settings.model_name, "file": Path(model_path).name if model_path else None,
                  "ctx": gen.get("n_ctx") or settings.ctx_size, "ready": await llm.health()},
        "memory": _mem_info(),
        "timing": {"recent_calls": len(lat), "avg_ms": int(sum(lat) / len(lat)) if lat else None,
                   "last_ms": lat[0] if lat else None},
        "busy_job": worker.current_job,
        "limits": {"ctx": settings.ctx_size, "output_reserve": settings.output_reserve,
                   "max_upload_mb": settings.max_upload_mb, "max_attempts": settings.max_attempts,
                   "call_timeout_s": settings.call_timeout_s},
    }


SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@app.post("/api/jobs", status_code=201)
async def upload(file: UploadFile = File(...)):
    name = (file.filename or "").strip()
    ext = Path(name).suffix.lower()
    if ext not in settings.allowed_ext:
        _err(415, f"“{name or 'This file'}” is not a .log or .txt file.",
             "Export your server log as plain text with a .log or .txt extension.")
    job_id = uuid.uuid4().hex[:12]
    dest = settings.upload_dir / f"{job_id}{ext}"
    limit = settings.max_upload_mb * 2**20
    size = 0
    head = b""
    try:
        with dest.open("wb") as out:  # stream to disk; the file is never held in memory
            while chunk := await file.read(256 * 1024):
                size += len(chunk)
                if size > limit:
                    raise ValueError("too_big")
                if len(head) < 65536:
                    head += chunk[: 65536 - len(head)]
                out.write(chunk)
    except ValueError:
        dest.unlink(missing_ok=True)
        _err(413, f"The file is larger than {settings.max_upload_mb} MB.", "Split the log or upload a shorter time range.")
    if size == 0 or not head.strip():
        dest.unlink(missing_ok=True)
        _err(422, "The file is empty.", "Choose a log file that contains entries.")
    if b"\x00" in head:
        dest.unlink(missing_ok=True)
        _err(422, "This looks like a binary file, not a text log.", "Upload the plain-text log, not an archive.")
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(head) - 4:  # not just a multi-byte char cut at the boundary
            dest.unlink(missing_ok=True)
            _err(422, "The file is not UTF-8 text.", "Convert the log to UTF-8 and try again.")
    db.create_job(job_id, SAFE_NAME.sub("_", name)[:120], str(dest), size, settings.model_name, settings.prompt_version)
    return _job_view(db.job(job_id))


@app.get("/api/jobs")
async def list_jobs(limit: int = 20):
    rows = db.q("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", min(limit, 100))
    return [_job_view(r, with_chunks=False, with_report=False) for r in rows]


def _get(job_id: str):
    row = db.job(job_id)
    if row is None:
        _err(404, "Analysis not found.", "It may have been removed. Upload the file again.")
    return row


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    return _job_view(_get(job_id))


@app.post("/api/jobs/{job_id}/start")
async def start(job_id: str):
    row = _get(job_id)
    if row["status"] in ("queued", "planning", "running"):
        return _job_view(row)
    if row["status"] == "done" and not row["error"]:
        _err(409, "This analysis is already complete.")
    if row["status"] in ("cancelled", "failed"):
        db.x("UPDATE chunks SET status='pending', attempts=0 WHERE job_id=? AND status!='done'", job_id)
    worker.enqueue(job_id)
    return _job_view(db.job(job_id))


@app.post("/api/jobs/{job_id}/retry")
async def retry_failed(job_id: str):
    _get(job_id)
    db.x("UPDATE chunks SET status='pending', attempts=0, error=NULL WHERE job_id=? AND status='failed'", job_id)
    worker.enqueue(job_id)
    return _job_view(db.job(job_id))


@app.post("/api/jobs/{job_id}/cancel")
async def cancel(job_id: str):
    row = _get(job_id)
    if row["status"] in ("queued", "planning", "running"):
        db.update_job(job_id, status="cancelled", stage="Stopped by user", finished_at=time.time())
    return _job_view(db.job(job_id))


@app.get("/api/jobs/{job_id}/stream")
async def stream(job_id: str):
    _get(job_id)

    async def gen():
        last = None
        idle = 0
        while True:
            row = db.job(job_id)
            if row is None:
                break
            view = _job_view(row, with_report=row["status"] in ("done", "failed", "cancelled"))
            payload = json.dumps(view, default=str)
            if payload != last:
                yield f"data: {payload}\n\n"
                last = payload
                idle = 0
            else:
                idle += 1
                if idle % 15 == 0:
                    yield ": keep-alive\n\n"
            if row["status"] in ("done", "failed", "cancelled", "uploaded"):
                break
            await asyncio.sleep(1)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/jobs/{job_id}/lines")
async def lines(job_id: str, n: str = Query(..., description="comma-separated line numbers")):
    row = _get(job_id)
    try:
        wanted = {int(x) for x in n.split(",") if x.strip()}
    except ValueError:
        _err(400, "Line numbers must be integers.")
    wanted = set(sorted(wanted)[:200])
    return {str(k): v for k, v in read_lines(Path(row["path"]), wanted).items()}


@app.get("/api/jobs/{job_id}/report.json")
async def report_json(job_id: str):
    row = _get(job_id)
    if not row["report_json"]:
        _err(409, "The report is not ready yet.")
    return JSONResponse(json.loads(row["report_json"]),
                        headers={"Content-Disposition": f'attachment; filename="report-{job_id}.json"'})


@app.get("/api/jobs/{job_id}/report.md")
async def report_md(job_id: str):
    row = _get(job_id)
    if not row["report_json"]:
        _err(409, "The report is not ready yet.")
    md = to_markdown(dict(row), json.loads(row["report_json"]))
    return PlainTextResponse(md, media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="report-{job_id}.md"'})


@app.middleware("http")
async def no_stale_ui(request, call_next):
    """UI files are tiny: always revalidate (ETag) so a redeploy is never hidden by cache."""
    resp = await call_next(request)
    if not request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.exception_handler(HTTPException)
async def http_exc(_, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
    return JSONResponse(status_code=exc.status_code, content=detail)


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="ui")
