import json
import unittest
import hashlib
import hmac

from models.agents_output_sec import (
    SecurityFinding,
    SecurityReport,
    SecurityStatus,
    SeverityLevel,
)
from models.run_task_handler import CallbackRequest, TaskStatus
from run_task import TaskRunHandler, format_output


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


if __name__ == "__main__":
    unittest.main()