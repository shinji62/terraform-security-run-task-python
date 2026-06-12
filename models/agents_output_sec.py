# --- Enums for strict validation ---

from typing import List
from enum import Enum

from pydantic import BaseModel, Field


class SecurityStatus(str, Enum):
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

# --- Pydantic Models ---

class SecurityFinding(BaseModel):
    severity: SeverityLevel
    title: str = Field(..., description="Clear, actionable title")
    description: str = Field(..., description="Detailed explanation of the security risk")
    resource_name: str = Field(..., description="Affected resource identifier")
    resource_type: str = Field(..., description="Resource type (e.g., aws_s3_bucket)")
    recommendation: str = Field(..., description="Specific steps to remediate")
    estimated_impact: str = Field(..., description="Potential security impact if not fixed")


class SecurityReport(BaseModel):
    status: SecurityStatus
    summary: str = Field(..., description="Brief overall security assessment")
    findings: List[SecurityFinding] = Field(default_factory=list)
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0"
    )