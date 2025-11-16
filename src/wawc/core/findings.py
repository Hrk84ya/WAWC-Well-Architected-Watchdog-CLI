"""Finding data models and severity enums."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    """Finding severity levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Finding(BaseModel):
    """Represents a security or compliance finding."""

    id: str = Field(description="Unique finding identifier")
    service: str = Field(description="AWS service name")
    resource_id: str = Field(description="Resource identifier")
    region: str = Field(description="AWS region")
    severity: Severity = Field(description="Finding severity")
    title: str = Field(description="Short finding title")
    description: str = Field(description="Detailed description")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Supporting evidence")
    remediation: str = Field(description="Remediation steps")
    wa_pillars: list[str] = Field(default_factory=list, description="WA pillars")
    tags: dict[str, str] = Field(default_factory=dict, description="Additional tags")

    model_config = ConfigDict(use_enum_values=True)


class ScanResult(BaseModel):
    """Container for scan results."""

    findings: list[Finding] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)
    regions_scanned: list[str] = Field(default_factory=list)
    checks_run: list[str] = Field(default_factory=list)
