# SOC Assistant backend

## Local setup

1. Add an NVIDIA API key to `NVIDIA_API_KEY` in `.env`.
2. Install dependencies with `uv sync`.
3. Start the API with `uv run python run.py`.

The configured NVIDIA NIM model is `meta/muse-glimmer-30b` through the
OpenAI-compatible `https://integrate.api.nvidia.com/v1` endpoint. If the key is
blank or the provider cannot be initialized, chat falls back to local SOP
synthesis.

Muse Glimmer runs as an SOC agent with a `search_sops` retrieval tool. It can
ask for missing incident context or answer directly, and invokes SOP retrieval
when organisational procedures would improve the response.

The local embedding model is cached in `data/huggingface` and loaded into memory
once when each backend process starts. `--reload` starts a new process after code
changes, so seeing one weight-loading pass after a reload is expected.

API documentation is available at `http://127.0.0.1:8000/docs`.
