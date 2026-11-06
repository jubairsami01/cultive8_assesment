"""Versioned prompt files. A tested prompt is never edited; a new version is added instead."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from ..config import settings

_DIR = Path(__file__).parent


@lru_cache(maxsize=32)
def load_prompt(name: str, version: str | None = None) -> str:
    v = version or settings.prompt_version
    path = _DIR / f"{name}_{v}.txt"
    if not path.exists():  # fall back to the newest older version of this prompt
        candidates = sorted(_DIR.glob(f"{name}_v*.txt"), key=lambda p: int(p.stem.rsplit("_v", 1)[1]))
        if not candidates:
            raise FileNotFoundError(f"prompt {name} not found")
        path = candidates[-1]
    return path.read_text(encoding="utf-8").strip()
