# Copilot Cloud Agent Instructions

## Repository purpose
- FastAPI service that handles HCP Terraform run-task callbacks at `POST /run-task`.
- Request flow: verify `X-Tfc-Task-Signature` HMAC on the raw body, fetch Terraform plan JSON, run Gemini-backed ADK analysis, send Terraform callback payload.

## First-read map
- `main.py`: app wiring, auth-header middleware, `/run-task` endpoint orchestration.
- `run_task.py`: HMAC verification, plan download, callback send helpers, output formatter.
- `agents/agents.py`: ADK runner and `gemini-3.5-flash` agent config.
- `models/run_task_handler.py`: Pydantic request/callback schemas (preserve aliases like `outcome-id`).
- `models/agents_output_sec.py`: structured security report schema.
- `test_run_task.py`: unit tests for formatting and signature behavior.

## Efficient workflow
1. Sync dependencies with `uv sync`.
2. Run tests with `uv run python -m unittest`.
3. For local app run: `uv run python main.py`.
4. Keep changes minimal and focused; prefer updating/adding focused tests in `test_run_task.py` when logic changes.

## Safety and correctness constraints
- Always verify signatures against the **raw request body** before task processing.
- Treat Terraform plan content as sensitive; do not log secrets, credentials, or raw plan values.
- Keep callback payloads JSON:API-compatible and preserve field aliases and limits (for example `outcome-id`, message length constraints).
- Keep dependency updates in `pyproject.toml` and `uv.lock` only.

## Environment variables
- `HEADER_SIGNATURE_VALUE`: HMAC secret (defaults to `test` for local/dev path).
- `GEMINI_API_KEY`: required for real Gemini-backed agent runs.
- `NGROK_AUTH_TOKEN`: optional; when set, app opens tunnel to port `8000` on startup.

## Errors encountered during onboarding
- Error: `uv: command not found` when attempting baseline test command.
- Work-around used: run tests with `python -m unittest` in environments missing `uv`, or install `uv` before using project-standard commands.
- Error: `ModuleNotFoundError: No module named 'pydantic'` when running tests without synced dependencies.
- Work-around used: install `uv`, run `uv sync`, then rerun tests with `uv run python -m unittest`.
