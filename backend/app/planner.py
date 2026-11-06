"""Turn an uploaded log into token-budgeted parts ("chunks").

One streaming pass:
  entry -> signals (+ running per-IP state) -> compact text -> fold routine runs ->
  pack into parts whose *measured* token count fits the per-call budget.
Parts never split an entry and always carry their original line numbers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .config import settings
from .llm import LLMClient
from .parser import Entry, build_compact, iter_entries
from .prompts import load_prompt
from .signals import SignalTracker

MAX_COMPACT_CHARS = 900


@dataclass
class Budget:
    ctx: int
    output: int
    carry: int
    margin: int
    prompt_overhead: int

    @property
    def chunk(self) -> int:
        return self.ctx - self.output - self.carry - self.margin - self.prompt_overhead

    def to_dict(self) -> dict:
        return {"ctx": self.ctx, "output_reserve": self.output, "carry": self.carry,
                "safety_margin": self.margin, "prompt_overhead": self.prompt_overhead, "chunk": self.chunk}


@dataclass
class _Part:
    items: list[str] = field(default_factory=list)
    tokens: int = 0
    line_start: int | None = None
    line_end: int = 0
    n_entries: int = 0
    line_ips: dict[int, list] = field(default_factory=dict)  # line -> [ip, signals]
    state: list[dict] = field(default_factory=list)


async def measure_budget(llm: LLMClient) -> Budget:
    system = load_prompt("system")
    user = load_prompt("chunk").format(part=99, parts=99, line_start=99999, line_end=99999, carry="", review="", log="")
    overhead = await llm.count_chat([{"role": "system", "content": system}, {"role": "user", "content": user}])
    return Budget(settings.ctx_size, settings.output_reserve, settings.carry_budget, settings.safety_margin, overhead)


def _fold(run: list[Entry]) -> str:
    a, b = run[0].line_start, run[-1].line_end
    statuses = sorted({str(e.status) for e in run if e.status is not None})
    methods = sorted({e.method for e in run if e.method})
    ips = {e.ip for e in run if e.ip}
    desc = f"{len(run)} routine entries"
    if methods:
        desc += f" ({'/'.join(methods)}"
        desc += f" {'/'.join(statuses[:4])}" if statuses else ""
        desc += f", {len(ips)} IPs)"
    return f"L{a}-{b} ~ {desc}, no scanner hints"


async def count_raw_tokens(llm: LLMClient, path: Path, block_chars: int = 12_000) -> int:
    """Tokenize the raw file in bounded blocks (for the 'raw vs compact' statistic)."""
    total = 0
    buf: list[str] = []
    size = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            buf.append(line)
            size += len(line)
            if size >= block_chars:
                total += await llm.count_tokens("".join(buf))
                buf, size = [], 0
    if buf:
        total += await llm.count_tokens("".join(buf))
    return total


async def plan_chunks(llm: LLMClient, path: Path, budget: Budget) -> tuple[list[_Part], dict]:
    tracker = SignalTracker()
    parts: list[_Part] = []
    cur = _Part(state=[])
    run: list[Entry] = []
    stats = {"entries": 0, "folded": 0, "compact_tokens": 0, "lines": 0}

    async def add_item(text: str, line_start: int, line_end: int, n_entries: int, ips: dict[int, list]):
        nonlocal cur
        tok = await llm.count_tokens(text) + 1  # +1 for the newline joining items
        if tok > budget.chunk:  # pathological single entry: clip hard
            text = text[: budget.chunk * 2]
            tok = await llm.count_tokens(text) + 1
        if cur.items and cur.tokens + tok > budget.chunk:
            parts.append(cur)
            cur = _Part(state=tracker.snapshot())
        if cur.line_start is None:
            cur.line_start = line_start
        cur.items.append(text)
        cur.tokens += tok
        cur.line_end = line_end
        cur.n_entries += n_entries
        cur.line_ips.update(ips)
        stats["compact_tokens"] += tok

    async def flush_run():
        nonlocal run
        if not run:
            return
        if len(run) == 1 or not settings.collapse_benign:
            for e in run:
                await add_item(e.compact, e.line_start, e.line_end, 1, {e.line_start: [e.ip or "", e.signals]})
        else:
            stats["folded"] += len(run)
            await add_item(_fold(run), run[0].line_start, run[-1].line_end, len(run), {})
        run = []

    for e in iter_entries(path):
        stats["entries"] += 1
        stats["lines"] = e.line_end
        tracker.observe(e)
        e.compact = build_compact(e)[:MAX_COMPACT_CHARS]
        if settings.collapse_benign and tracker.is_benign(e):
            run.append(e)
            continue
        await flush_run()
        await add_item(e.compact, e.line_start, e.line_end, 1, {e.line_start: [e.ip or "", e.signals]})
    await flush_run()
    if cur.items:
        parts.append(cur)
    stats["final_state"] = tracker.snapshot(limit=50)
    return parts, stats


def part_text(p: _Part) -> str:
    return "\n".join(p.items)


def part_state_json(p: _Part) -> str:
    return json.dumps(p.state, separators=(",", ":"))
