# Agent Instructions

## Scope

These instructions apply to this repository.

## Project Context

This is a Python 3.14 FastAPI service for HCP Terraform run tasks. The `/run-task` endpoint verifies the `X-Tfc-Task-Signature` HMAC header, downloads Terraform plan JSON, runs a Google ADK security assessment agent backed by Gemini, and posts an HCP Terraform task callback.

## Tooling

- Use `uv` for dependency management and command execution.
- Run tests with `uv run python -m unittest`.
- Start the app locally with `uv run python main.py`.
- Keep dependencies in `pyproject.toml` and `uv.lock`; do not add a separate requirements file.

## Coding Guidance

- Keep changes small and consistent with the existing Pydantic and dataclass style.
- Preserve HCP Terraform JSON:API aliases, especially fields such as `outcome-id`.
- Verify request signatures against the raw request body before doing any task work.
- Treat Terraform plan content as sensitive: do not log secrets, tokens, credentials, or raw sensitive values.
- Prefer focused unit tests in `test_run_task.py` for formatting, signature verification, and callback behavior.

## Runtime Notes

- `HEADER_SIGNATURE_VALUE` configures the HCP Terraform HMAC secret and defaults to `test` for local development.
- `GEMINI_API_KEY` is required for real Gemini-backed Google ADK agent execution.
- `NGROK_AUTH_TOKEN` is optional; when present, app startup opens an ngrok tunnel to port 8000.
- The configured model is `gemini-3.5-flash` in `agents/agents.py`.
