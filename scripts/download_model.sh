#!/usr/bin/env bash
# One-time setup: download the GGUF model. After this the app runs fully offline.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO="${MODEL_REPO:-unsloth/Qwen3.5-2B-GGUF}"
FILE="${MODEL_FILE:-Qwen3.5-2B-Q4_K_M.gguf}"
SHA256="${MODEL_SHA256:-aaf42c8b7c3cab2bf3d69c355048d4a0ee9973d48f16c731c0520ee914699223}"
URL="https://huggingface.co/${REPO}/resolve/main/${FILE}"

mkdir -p models
if [[ -f "models/${FILE}" ]]; then
  echo "models/${FILE} already present."
else
  echo "Downloading ${FILE} (~1.3 GB) from ${REPO} ..."
  curl -L --fail --retry 3 -C - -o "models/${FILE}.part" "${URL}"
  mv "models/${FILE}.part" "models/${FILE}"
fi

if [[ "${FILE}" == "Qwen3.5-2B-Q4_K_M.gguf" ]]; then
  echo "Verifying checksum ..."
  echo "${SHA256}  models/${FILE}" | shasum -a 256 -c -
fi
echo "Done. Start the app with: docker compose up -d"
