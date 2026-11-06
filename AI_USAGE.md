# AI Usage

How AI tools were used to build this project, and how the local model is prompted at runtime.

## 1. Tools used
| Tool | Used for |
|---|---|
| Claude Code (Anthropic) | Planning, code generation, refactoring, debugging, docs drafts |
| Local model: _TBD (Qwen3.5 2B, Q4_K_M GGUF via llama.cpp)_ | All runtime log analysis (offline) |

No cloud AI is called by the application at runtime.

## 2. Workflow
_TBD — how work was split between me and the assistant, what I reviewed/verified by hand._

## 3. Key coding prompts
_TBD — 5–10 most important prompts, quoted, with what they produced._

## 4. Local model prompts
_TBD — final system and chunk prompts (see `backend/prompts/`)._

## 5. Prompt changes
_TBD — summary of iterations; full history in [docs/prompt-changelog.md](docs/prompt-changelog.md)._

## 6. Token budget plan
| Component | Tokens |
|---|---|
| System prompt | _TBD_ |
| Carried context | _TBD_ |
| Log chunk | _TBD_ |
| Reserved output | _TBD_ |
| Safety margin | _TBD_ |
| **Total** | **≤ 2,048** |

Measured with the model's own tokenizer. Benchmarks in [docs/benchmarks.md](docs/benchmarks.md).

## 7. AI mistakes fixed
| # | What went wrong | How it was caught | Fix |
|---|---|---|---|
| 1 | Planning assumed the sample log was ~20k tokens (per the brief); the raw JSONL is ~27k tokens because JSON keys/quotes tokenize heavily | Measured file size and line lengths before chunking | Added a line-compaction step before token-based splitting |

## 8. What was verified by hand
_TBD_
