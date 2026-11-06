# Benchmarks

Machine: Apple Silicon Mac, OrbStack (Docker 29.8, arm64). Containers pinned to 2 cores
(`cpuset: "0,1"`), `--threads 2`. Real 2-vCPU x86 servers will be slower per token; the
token budget does not change.

## Model server (llama.cpp b12169, Qwen3.5-2B-Q4_K_M)

| Measure | Value | How |
|---|---|---|
| Resident memory, model loaded, ctx 2048 | 1.72–1.81 GB, **flat during a full run** | `docker stats` sampled every 5 s (`--load-mode none --cache-ram 0 --ctx-checkpoints 0`) |
| Same, with llama.cpp defaults for prompt caching | grew to **2.93 GB** of the 3 GB limit after one run | `memory.stat`: anonymous memory, not page cache |
| Memory with mmap (default) | 1.32 GB | first test with `docker run --memory 3g` |
| Prompt processing | ~67 tok/s | llama.cpp `timings.prompt_per_second`, 2,022-token prompt |
| Generation | ~20 tok/s | `timings.predicted_per_second` |
| API container memory | 64–95 MB | `/api/system` (RSS and cgroup `memory.current`) |
| Total | ~1.85 GB of 4 GB | |

## Tokens (counted with the model tokenizer via `/tokenize`)

| | Tokens |
|---|---|
| Sample log, raw | 39,896 |
| After compaction + folding routine runs | 6,970 (−83 %) |
| One raw JSON line | ~165 |
| Same line compacted | ~51 |
| System prompt + header, v1 / v3 | 423 / 567 |

## Full runs on the sample log

| Run | Prompt | Where | Parts | Calls | Avg call | Total model time | Largest call (prompt+reply) |
|---|---|---|---|---|---|---|---|
| 1 | v1 | dev, model in Docker | 9 | 10 | 25.2 s | 243 s | 1,722 / 2,048 |
| 2 | v2 | dev, model in Docker | 10 | 11 | 21.8 s | 229 s | 1,640 / 2,048 |
| 3 | v3 | Docker Compose | 11 | 12 | 27.5 s | 320 s | 1,759 / 2,048 |

Memory during a full run after disabling the prompt RAM cache (sampled every ~45 s):
`llm` 1.774 → 1.811 → 1.812 → … → 1.812 GiB (flat), `api` 45–46 MiB.

Run 3 included an API container restart after part 2: parts 1–2 were kept, part 3 was
re-run (attempt 2), and the job finished normally.

Reproduce: upload the sample log in the UI, then open "Run details" in the report, or
`GET /api/jobs/<id>` for per-part `prompt_tokens`, `completion_tokens`, `latency_ms`.
