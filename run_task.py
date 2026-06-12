from dataclasses import dataclass
from typing import Optional
from models.agents_output_sec import SecurityReport
import hashlib
import hmac
import httpx

from models.run_task_handler import (
    CallbackData,
    CallbackDataAttributes,
    CallbackDataRelationships,
    CallbackRequest,
    OutcomeAttributes,
    OutcomeRelationshipObject,
    OutcomesContainer,
    RunTaskRequest,
    TagItem,
    TaskStatus,
)


TEST_TOKEN = "test-token"


@dataclass
class TaskRunHandler:
    header_signature_value: str
    task_run_request: Optional[RunTaskRequest] = None

    async def download_plan_json(self) -> str:
        """
        Downloads the plan JSON from the provided API URL in the task run request.
        Returns:
            str: The downloaded plan JSON as a string.
        Raises:
            ValueError: If the API URL or access token is missing in the task run request.
            httpx.HTTPError: If the HTTP request to download the plan JSON fails."""

        if self.task_run_request is None:
            raise ValueError("Task run request is not set.")

        if self.task_run_request.access_token == TEST_TOKEN:
            return "{}"

        if self.task_run_request.plan_json_api_url is None:
            raise ValueError("No plan JSON API URL provided in the task run request.")

        if self.task_run_request.access_token is None:
            raise ValueError("No access token provided in the task run request.")

        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            headers = {"Authorization": f"Bearer {self.task_run_request.access_token}"}
            response = await client.get(
                self.task_run_request.plan_json_api_url, headers=headers
            )
            response.raise_for_status()

        return response.text

    async def send_callback(
        self,
        status_task: TaskStatus,
        message_task: str | None = None,
        callback_request: CallbackRequest | None = None,
    ) -> None:
        """Sends a callback to the task result callback URL with the given status and message.
        Args:
            status_task (TaskStatus): The status to report back to Terraform Cloud (e.g., "success", "failure").
            message_task (str, optional): An optional message to include in the callback. Defaults to None.
            callback_request (CallbackRequest, optional): An optional custom callback request to send instead of the default format. Defaults to None.
        Raises:
            ValueError: If the task result callback URL is missing in the task run request.
            httpx.HTTPError: If the HTTP request to send the callback fails."""

        if self.task_run_request is None:
            raise ValueError("Task run request is not set.")

        if self.task_run_request.task_result_callback_url is None:
            raise ValueError(
                "No task result callback URL provided in the task run request."
            )

        if callback_request is None:
            callback_payload = CallbackRequest(
                data=CallbackData(
                    attributes=CallbackDataAttributes(
                        status=status_task, message=message_task
                    )
                )
            ).model_dump(by_alias=True, exclude_none=True)
        else:
            callback_payload = callback_request.model_dump(
                by_alias=True, exclude_none=True
            )

        async with httpx.AsyncClient() as client:
            headers = {
                "Content-Type": "application/vnd.api+json",
                "Authorization": f"Bearer {self.task_run_request.access_token}",
            }
            response = await client.patch(
                self.task_run_request.task_result_callback_url,
                json=callback_payload,
                headers=headers,
            )
            response.raise_for_status()

    async def send_success_callback(self, message: str | None = None) -> None:
        """Sends a success callback to the task result callback URL with an optional message.
        Args:
            message (str, optional): An optional message to include in the callback. Defaults to None.
            callback_request (CallbackRequest, optional): An optional custom callback request to send instead of the default format. Defaults to None."""
        await self.send_callback(status_task=TaskStatus.PASSED, message_task=message)

    async def send_failure_callback(
        self, message: str | None = None, callback_request: CallbackRequest | None = None
    ) -> None:
        """Sends a failure callback to the task result callback URL with an optional message.
        Args:
            message (str, optional): An optional message to include in the callback. Defaults to None.
            callback_request (CallbackRequest, optional): An optional custom callback request to send instead of the default format. Defaults to None."""
        await self.send_callback(
            status_task=TaskStatus.FAILED,
            message_task=message,
            callback_request=callback_request,
        )

    def verify_header_signature(self, request_signature: Optional[str], body: bytes) -> bool:
        if request_signature is None:
            return False

        hmac_key = hmac.new(
            key=bytes(self.header_signature_value, "utf-8"),
            msg=body,
            digestmod=hashlib.sha512,
        )
        return hmac.compare_digest(hmac_key.hexdigest(), request_signature)


def write_to_file(filename: str, content: str):
    """Utility function to write content to a file.
    Args:
        filename (str): The name of the file to write to.
        content (str): The content to write to the file.
    """
    with open(filename, "w") as f:
        f.write(content)


def format_output(content: SecurityReport) -> CallbackRequest:
    """Utility function to format output content, such as adding code block formatting for markdown.
    Args:
        content (SecurityReport): The content to format.
    Returns:
        CallbackRequest: The formatted callback request.
    """
    task_outcomes = []

    # Map each list item from the report into the expected Dict format
    for index, finding in enumerate(content.findings):
        outcome_key = f"finding_{index}"

        # Build clean markdown formatting for the outcome body
        markdown_body = (
            f"### Resource: `{finding.resource_name}` ({finding.resource_type})\n"
            f"**Severity:** {finding.severity.value.upper()}\n\n"
            f"#### Description\n{finding.description}\n\n"
            f"#### Recommendation\n```\n{finding.recommendation}\n```\n\n"
            f"#### Estimated Impact\n{finding.estimated_impact}"
        )

        # Create the inline relationship object matching your exact example
        outcome_obj = OutcomeRelationshipObject(
            type="task-result-outcomes",
            attributes=OutcomeAttributes.model_validate(
                {
                    "outcome-id": outcome_key,
                    "description": finding.description[:255],
                    "body": markdown_body,
                    "url": None,
                    "tags": {
                    "Severity": [
                        TagItem(
                            label=finding.severity.value.upper(),
                            level="error"
                            if finding.severity.value in ["high", "critical"]
                            else "info",
                        )
                    ]
                    },
                }
            ),
        )
        task_outcomes.append(outcome_obj)

    task_status = (
        TaskStatus.FAILED if content.status.value == TaskStatus.FAILED.value else TaskStatus.PASSED
    )

    return CallbackRequest(
        data=CallbackData(
            attributes=CallbackDataAttributes(
                status=task_status,
                message=content.summary[:500],
            ),  # Enforces the max_length=500 constraint
            relationships=CallbackDataRelationships(
                outcomes=OutcomesContainer(data=task_outcomes)
            ),
        )
    )
