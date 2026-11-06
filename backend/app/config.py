"""Runtime settings, all overridable through environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    llm_url: str = os.environ.get("LLM_URL", "http://localhost:8080")
    model_name: str = os.environ.get("MODEL_NAME", "Qwen3.5-2B-Q4_K_M")
    data_dir: Path = Path(os.environ.get("DATA_DIR", "./data"))

    # --- Token budget (per model call, all counted with the model tokenizer) ---
    ctx_size: int = _int("CTX_SIZE", 2048)          # hard model context
    output_reserve: int = _int("OUTPUT_RESERVE", 420)  # max_tokens for the reply
    carry_budget: int = _int("CARRY_BUDGET", 300)    # carried facts from earlier parts
    safety_margin: int = _int("SAFETY_MARGIN", 48)   # template / rounding slack
    # chunk budget = ctx - output - carry - margin - system/instruction prompt (measured)

    # --- Reliability ---
    call_timeout_s: int = _int("CALL_TIMEOUT_S", 240)
    max_attempts: int = _int("MAX_ATTEMPTS", 3)

    # --- Uploads ---
    max_upload_mb: int = _int("MAX_UPLOAD_MB", 20)
    allowed_ext: tuple[str, ...] = (".log", ".txt")

    # --- Model call reduction ---
    # Runs of ordinary lines (no signal, status < 400, IP not under watch) are folded into
    # one summary line that keeps their line range. The model still sees that they exist.
    collapse_benign: bool = _bool("COLLAPSE_BENIGN", True)
    final_summary: bool = _bool("FINAL_SUMMARY", True)

    prompt_version: str = os.environ.get("PROMPT_VERSION", "v3")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "analyzer.db"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"


settings = Settings()
