import json
import unittest
import hashlib
import hmac
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from models.agents_output_sec import (
    SecurityFinding,
    SecurityReport,
    SecurityStatus,
    SeverityLevel,
)
from models.run_task_handler import CallbackRequest, TaskStatus
from run_task import TEST_TOKEN, TaskRunHandler, format_output


class FormatOutputTests(unittest.TestCase):
    def test_format_output_returns_expected_callback_request_and_json(self):
        report = SecurityReport(
            status=SecurityStatus.FAILED,
            summary="Security review found one high severity issue.",
            findings=[
                SecurityFinding(
                    severity=SeverityLevel.HIGH,
                    title="Public bucket access",
                    description="S3 bucket allows public read access.",
                    resource_name="aws_s3_bucket.logs",
                    resource_type="aws_s3_bucket",
                    recommendation="Block public access on the bucket.",
                    estimated_impact="Sensitive log data may be exposed.",
                )
            ],
        )

        result = format_output(report)

        self.assertIsInstance(result, CallbackRequest)
        self.assertEqual(result.data.attributes.status, TaskStatus.FAILED)
        self.assertEqual(result.data.attributes.message, report.summary)

        assert result.data.relationships is not None
        assert result.data.relationships.outcomes is not None
        outcomes = result.data.relationships.outcomes.data
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].type, "task-result-outcomes")
        self.assertEqual(outcomes[0].attributes.outcome_id, "finding_0")
        self.assertEqual(
            outcomes[0].attributes.description,
            "S3 bucket allows public read access.",
        )
        self.assertEqual(outcomes[0].attributes.tags["Severity"][0].label, "HIGH")
        self.assertEqual(outcomes[0].attributes.tags["Severity"][0].level, "error")
        assert outcomes[0].attributes.body is not None
        self.assertIn(
            "### Resource: `aws_s3_bucket.logs` (aws_s3_bucket)",
            outcomes[0].attributes.body,
        )
        self.assertIn(
            "#### Recommendation\n```\nBlock public access on the bucket.\n```",
            outcomes[0].attributes.body,
        )

        payload = result.model_dump(by_alias=True, exclude_none=True)
        self.assertEqual(
            payload,
            {
                "data": {
                    "type": "task-results",
                    "attributes": {
                        "status": "failed",
                        "message": "Security review found one high severity issue.",
                    },
                    "relationships": {
                        "outcomes": {
                            "data": [
                                {
                                    "type": "task-result-outcomes",
                                    "attributes": {
                                        "outcome-id": "finding_0",
                                        "description": "S3 bucket allows public read access.",
                                        "tags": {
                                            "Severity": [
                                                {
                                                    "label": "HIGH",
                                                    "level": "error",
                                                }
                                            ]
                                        },
                                        "body": outcomes[0].attributes.body,
                                    },
                                }
                            ]
                        }
                    },
                }
            },
        )

        rendered_json = result.model_dump_json(by_alias=True, exclude_none=True)
        self.assertEqual(json.loads(rendered_json), payload)
        self.assertIn('"outcome-id":"finding_0"', rendered_json)

    def test_verify_header_signature_uses_raw_body_hmac(self):
        handler = TaskRunHandler(header_signature_value="secret")
        body = b'{"message":"hello"}'
        signature = hmac.new(
            key=b"secret",
            msg=body,
            digestmod=hashlib.sha512,
        ).hexdigest()

        self.assertTrue(handler.verify_header_signature(signature, body))
        self.assertFalse(handler.verify_header_signature("bad-signature", body))
        self.assertFalse(handler.verify_header_signature(None, body))


VALID_PAYLOAD = {
    "access_token": TEST_TOKEN,
    "is_speculative": False,
    "organization_name": "test-org",
    "payload_version": 1,
    "run_app_url": "https://app.terraform.io/app/test-org/runs/run-123",
    "run_created_at": "2024-01-01T00:00:00Z",
    "run_created_by": "user@example.com",
    "run_id": "run-123",
    "run_message": "Triggered via UI",
    "stage": "post_plan",
    "task_result_callback_url": "https://app.terraform.io/tasks/callback-123",
    "task_result_enforcement_level": "advisory",
    "task_result_id": "taskrs-123",
    "workspace_app_url": "https://app.terraform.io/app/test-org/workspaces/ws-123",
    "workspace_id": "ws-123",
    "workspace_name": "test-workspace",
}

HMAC_SECRET = "test"


def _sign(body: bytes, secret: str = HMAC_SECRET) -> str:
    """Compute the HMAC-SHA512 hex digest for a request body."""
    return hmac.new(
        key=secret.encode("utf-8"),
        msg=body,
        digestmod=hashlib.sha512,
    ).hexdigest()


class RunTaskEndpointTests(unittest.TestCase):
    """Integration-style tests for the POST /run-task HTTP endpoint."""

    def setUp(self):
        # Import here so patching HEADER_SIGNATURE_VALUE is already in place
        # when the module-level variable is read in each request handler.
        from main import app

        self.client = TestClient(app, raise_server_exceptions=False)

    # ------------------------------------------------------------------
    # Middleware: missing header
    # ------------------------------------------------------------------

    def test_missing_signature_header_returns_401(self):
        body = json.dumps(VALID_PAYLOAD).encode()
        response = self.client.post(
            "/run-task",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 401)

    # ------------------------------------------------------------------
    # Endpoint: invalid signature
    # ------------------------------------------------------------------

    def test_invalid_signature_returns_401(self):
        body = json.dumps(VALID_PAYLOAD).encode()
        response = self.client.post(
            "/run-task",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Tfc-Task-Signature": "not-a-valid-signature",
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"message": "Signature verification failed."})

    # ------------------------------------------------------------------
    # Endpoint: valid signature + test token (short-circuit path)
    # ------------------------------------------------------------------

    def test_valid_signature_with_test_token_returns_200(self):
        body = json.dumps(VALID_PAYLOAD).encode()
        signature = _sign(body)
        response = self.client.post(
            "/run-task",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Tfc-Task-Signature": signature,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"message": "Run Task received and verified successfully!"},
        )

    # ------------------------------------------------------------------
    # Endpoint: full flow — mock plan download, Gemini agent, callback
    # ------------------------------------------------------------------

    def test_full_flow_returns_200(self):
        payload = {**VALID_PAYLOAD, "access_token": "real-token"}
        body = json.dumps(payload).encode()
        signature = _sign(body)

        mock_report = SecurityReport(
            status=SecurityStatus.PASSED,
            summary="No security issues found.",
            findings=[],
        )

        with (
            patch(
                "run_task.TaskRunHandler.download_plan_json",
                new_callable=AsyncMock,
                return_value='{"planned_values": {}}',
            ),
            patch(
                "main.agent_runner.run",
                new_callable=AsyncMock,
                return_value=mock_report,
            ),
            patch(
                "run_task.TaskRunHandler.send_callback",
                new_callable=AsyncMock,
            ) as mock_send_callback,
        ):
            response = self.client.post(
                "/run-task",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Tfc-Task-Signature": signature,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {})
        mock_send_callback.assert_awaited_once()
        _, kwargs = mock_send_callback.call_args
        self.assertEqual(kwargs["status_task"], TaskStatus.PASSED)

    # ------------------------------------------------------------------
    # Endpoint: full flow — verify callback contains structured outcomes
    # ------------------------------------------------------------------

    def test_full_flow_callback_contains_correct_outcomes(self):
        """Agent returns a structured SecurityReport with findings; verify the
        callback is sent with a CallbackRequest whose outcomes match."""
        payload = {**VALID_PAYLOAD, "access_token": "real-token"}
        body = json.dumps(payload).encode()
        signature = _sign(body)

        mock_report = SecurityReport(
            status=SecurityStatus.FAILED,
            summary="Found one critical issue.",
            findings=[
                SecurityFinding(
                    severity=SeverityLevel.CRITICAL,
                    title="Exposed secret in environment variable",
                    description="A secret is stored in plaintext as an env var.",
                    resource_name="aws_lambda_function.api",
                    resource_type="aws_lambda_function",
                    recommendation="Use AWS Secrets Manager instead.",
                    estimated_impact="Credentials may be leaked.",
                )
            ],
        )

        with (
            patch(
                "run_task.TaskRunHandler.download_plan_json",
                new_callable=AsyncMock,
                return_value='{"planned_values": {}}',
            ),
            patch(
                "main.agent_runner.run",
                new_callable=AsyncMock,
                return_value=mock_report,
            ),
            patch(
                "run_task.TaskRunHandler.send_callback",
                new_callable=AsyncMock,
            ) as mock_send_callback,
        ):
            response = self.client.post(
                "/run-task",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Tfc-Task-Signature": signature,
                },
            )

        self.assertEqual(response.status_code, 200)
        mock_send_callback.assert_awaited_once()

        _, kwargs = mock_send_callback.call_args

        # main.py always passes status_task=PASSED; the real status is embedded
        # inside the callback_request produced by format_output.
        self.assertEqual(kwargs["status_task"], TaskStatus.PASSED)

        # callback_request must be a fully-formed CallbackRequest with outcomes
        cb: CallbackRequest = kwargs["callback_request"]
        self.assertIsInstance(cb, CallbackRequest)
        self.assertEqual(cb.data.attributes.status, TaskStatus.FAILED)
        self.assertEqual(cb.data.attributes.message, "Found one critical issue.")

        assert cb.data.relationships is not None
        assert cb.data.relationships.outcomes is not None
        outcomes = cb.data.relationships.outcomes.data
        self.assertEqual(len(outcomes), 1)

        outcome = outcomes[0]
        self.assertEqual(outcome.type, "task-result-outcomes")
        self.assertEqual(outcome.attributes.outcome_id, "finding_0")
        self.assertEqual(
            outcome.attributes.description,
            "A secret is stored in plaintext as an env var.",
        )

        # Severity tag must be present and reflect CRITICAL → error level
        severity_tags = outcome.attributes.tags.get("Severity", [])
        self.assertEqual(len(severity_tags), 1)
        self.assertEqual(severity_tags[0].label, "CRITICAL")
        self.assertEqual(severity_tags[0].level, "error")

        # Body must contain the resource identifier and recommendation block
        assert outcome.attributes.body is not None
        self.assertIn(
            "### Resource: `aws_lambda_function.api` (aws_lambda_function)",
            outcome.attributes.body,
        )
        self.assertIn(
            "#### Recommendation\n```\nUse AWS Secrets Manager instead.\n```",
            outcome.attributes.body,
        )

        # Serialised payload must use the JSON:API alias "outcome-id"
        serialised = cb.model_dump_json(by_alias=True, exclude_none=True)
        self.assertIn('"outcome-id":"finding_0"', serialised)

    # ------------------------------------------------------------------
    # Endpoint: plan download failure → 500
    # ------------------------------------------------------------------

    def test_plan_download_failure_returns_500(self):
        payload = {**VALID_PAYLOAD, "access_token": "real-token"}
        body = json.dumps(payload).encode()
        signature = _sign(body)

        with (
            patch(
                "run_task.TaskRunHandler.download_plan_json",
                new_callable=AsyncMock,
                side_effect=RuntimeError("network error"),
            ),
            patch(
                "run_task.TaskRunHandler.send_failure_callback",
                new_callable=AsyncMock,
            ) as mock_failure,
        ):
            response = self.client.post(
                "/run-task",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Tfc-Task-Signature": signature,
                },
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"message": "Failed to download plan JSON."})
        mock_failure.assert_awaited_once()

    # ------------------------------------------------------------------
    # Endpoint: agent execution failure → 500
    # ------------------------------------------------------------------

    def test_agent_failure_returns_500(self):
        payload = {**VALID_PAYLOAD, "access_token": "real-token"}
        body = json.dumps(payload).encode()
        signature = _sign(body)

        with (
            patch(
                "run_task.TaskRunHandler.download_plan_json",
                new_callable=AsyncMock,
                return_value='{"planned_values": {}}',
            ),
            patch(
                "main.agent_runner.run",
                new_callable=AsyncMock,
                side_effect=RuntimeError("gemini error"),
            ),
            patch(
                "run_task.TaskRunHandler.send_failure_callback",
                new_callable=AsyncMock,
            ) as mock_failure,
        ):
            response = self.client.post(
                "/run-task",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Tfc-Task-Signature": signature,
                },
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"message": "Agent execution failed."})
        mock_failure.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()