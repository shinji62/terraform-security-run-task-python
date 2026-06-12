from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class TaskStage(str, Enum):
    PRE_PLAN = "pre_plan"
    POST_PLAN = "post_plan"
    PRE_APPLY = "pre_apply"


class TaskStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"


class TagItem(BaseModel):
    label: str
    level: Optional[str] = None  # e.g., "error", "info"

# --- Request Payloads (Sent by Terraform Cloud) ---

class RunTaskRequest(BaseModel):
    """Payload sent by Terraform Cloud to your Run Task handler."""
    access_token: str = Field(..., alias="access_token")
    configuration_version_download_url: str | None = Field(default=None, alias="configuration_version_download_url")
    configuration_version_id: str | None = Field(default=None, alias="configuration_version_id")
    is_speculative: bool = Field(..., alias="is_speculative")
    organization_name: str = Field(..., alias="organization_name")
    payload_version: int = Field(..., alias="payload_version")
    run_app_url: str = Field(..., alias="run_app_url")
    run_created_at: datetime = Field(..., alias="run_created_at")
    run_created_by: str = Field(..., alias="run_created_by")
    run_id: str = Field(..., alias="run_id")
    run_message: str = Field(..., alias="run_message")
    stage: str = Field(..., alias="stage")
    task_result_callback_url: str = Field(..., alias="task_result_callback_url")
    task_result_enforcement_level: str = Field(..., alias="task_result_enforcement_level")
    task_result_id: str = Field(..., alias="task_result_id")
    vcs_branch: str | None = Field(default=None, alias="vcs_branch")
    vcs_commit_url: str | None = Field(default=None, alias="vcs_commit_url")
    vcs_pull_request_url: str | None = Field(default=None, alias="vcs_pull_request_url")
    vcs_repo_url: str | None = Field(default=None, alias="vcs_repo_url")
    workspace_app_url: str = Field(..., alias="workspace_app_url")
    workspace_id: str = Field(..., alias="workspace_id")
    workspace_name: str = Field(..., alias="workspace_name")
    workspace_working_directory: str | None = Field(default=None, alias="workspace_working_directory")
    plan_json_api_url: str | None = Field(default=None, alias="plan_json_api_url")


# --- Callback Payloads (Sent back to Terraform Cloud) ---

# --- 2. Inline Outcome Attributes ---
class OutcomeAttributes(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    outcome_id: str = Field(..., alias="outcome-id")
    description: str
    tags: Dict[str, List[TagItem]] = Field(default_factory=dict)
    body: Optional[str] = None
    url: Optional[str] = None

class CallbackDataAttributes(BaseModel):
    status: TaskStatus
    message: Optional[str] = Field(default=None, max_length=500)
    url: Optional[str] = Field(default=None)

# --- 3. The Nested Outcome Object ---
class OutcomeRelationshipObject(BaseModel):
    type: str = "task-result-outcomes"
    attributes: OutcomeAttributes

# --- 4. The Outcomes Wrapper ---
class OutcomesContainer(BaseModel):
    data: List[OutcomeRelationshipObject] = Field(default_factory=list)


# --- 5. The Relationships Wrapper ---
class CallbackDataRelationships(BaseModel):
    outcomes: Optional[OutcomesContainer] = None

class CallbackData(BaseModel):
    type: str = "task-results"
    attributes: CallbackDataAttributes
    relationships: Optional[CallbackDataRelationships] = None


class CallbackRequest(BaseModel):
    """Payload you send back to the callback-url to report status."""
    data: CallbackData


# --- Generic API Error Schema ---

class ErrorSource(BaseModel):
    pointer: Optional[str] = None
    parameter: Optional[str] = None


class ErrorObject(BaseModel):
    id: Optional[str] = None
    status: Optional[str] = None
    code: Optional[str] = None
    title: str
    detail: Optional[str] = None
    source: Optional[ErrorSource] = None
    meta: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Standard JSON API error format used by Terraform Cloud."""
    errors: List[ErrorObject]