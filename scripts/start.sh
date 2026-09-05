#!/usr/bin/env bash
# Boot the Streamlit SOC app for a PaaS (Render injects PORT).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CHROMA_DIR="${CHROMA_DIR:-$ROOT/data/chroma}"
CACHE_DIR="${CACHE_DIR:-$ROOT/data/cache}"
mkdir -p "$CHROMA_DIR" "$CACHE_DIR"

if [ -z "$(ls -A "$CHROMA_DIR" 2>/dev/null || true)" ]; then
  echo "Chroma index empty — building knowledge base…"
  python scripts/build_kb.py
fi

PORT="${PORT:-8501}"
exec streamlit run app.py \
  --server.address 0.0.0.0 \
  --server.port "$PORT" \
  --server.headless true \
  --server.enableCORS false \
  --server.enableXsrfProtection false
