# terraform-security-run-task-python

Security review service for HCP Terraform run tasks. It analyzes Terraform plans with Gemini and reports security findings back to HCP Terraform.

## Project Layout

- `main.py` - FastAPI app and `/run-task` endpoint.
- `run_task.py` - signature verification, plan download, callback posting, and report formatting.
- `agents/agents.py` - Google ADK agent runner and security agent configuration.
- `agents/prompts/security.md` - security review instructions used by the agent.
- `models/` - Pydantic request, callback, and security report models.
- `test_run_task.py` - unit tests for callback formatting and HMAC signature verification.

## Requirements

- Python 3.14, as declared in `.python-version` and `pyproject.toml`.
- `uv` for dependency syncing and command execution.
- `GEMINI_API_KEY` for real Gemini-backed Google ADK agent runs.
- Optional `NGROK_AUTH_TOKEN` to expose the local FastAPI app through ngrok.

## Setup

```bash
uv sync
```

Environment variables:

```bash
HEADER_SIGNATURE_VALUE=<terraform-run-task-hmac-secret>
GEMINI_API_KEY=<gemini-api-key>
NGROK_AUTH_TOKEN=<optional-ngrok-token>
```

If `HEADER_SIGNATURE_VALUE` is not set, the app defaults to `test`. `GEMINI_API_KEY` is required when the request is not using the local `test-token` path and the Gemini agent must run. If `NGROK_AUTH_TOKEN` is unset, the app runs without opening an ngrok tunnel.

## Run

```bash
uv run fastapi dev
```

The service listens on `http://127.0.0.1:8000` and exposes `POST /run-task`.

To expose the local service to HCP Terraform, set `NGROK_AUTH_TOKEN` before starting the app. On startup, the app opens an ngrok tunnel to port 8000; use the generated public URL plus `/run-task` as the HCP Terraform run task URL.

You can also run the app directly:

```bash
uv run python main.py
```

Use the same HMAC secret in HCP Terraform and `HEADER_SIGNATURE_VALUE`.

## Test

```bash
uv run python -m unittest
```

The current tests cover security report callback serialization and raw-body HMAC signature validation.
