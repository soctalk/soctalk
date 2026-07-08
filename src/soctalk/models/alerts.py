"""Alert models for security events from Wazuh."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from soctalk.models.enums import Severity
from soctalk.models.observables import Observable


class AlertSource(BaseModel):
    """Source information for an alert."""

    agent_id: str = Field(..., description="Wazuh agent ID")
    agent_name: str = Field(..., description="Wazuh agent name")
    agent_ip: Optional[str] = Field(None, description="Agent IP address")


class Alert(BaseModel):
    """A security alert from Wazuh SIEM."""

    id: str = Field(..., description="Unique alert ID")
    timestamp: datetime = Field(..., description="Alert timestamp")
    severity: Severity = Field(..., description="Alert severity level")
    level: int = Field(..., ge=0, le=15, description="Wazuh alert level (0-15)")
    rule_id: Optional[str] = Field(None, description="Rule ID that triggered the alert")
    rule_description: str = Field(..., description="Description of the rule/alert")
    source: AlertSource = Field(..., description="Source agent information")
    raw_data: dict[str, Any] = Field(default_factory=dict, description="Raw alert data")
    observables: list[Observable] = Field(
        default_factory=list, description="Extracted observables"
    )
    processed: bool = Field(default=False, description="Whether alert has been processed")

    def to_summary(self) -> str:
        """Generate a human-readable summary of the alert.

        Returns:
            Summary string.
        """
        severity_emoji = {
            Severity.LOW: "🟢",
            Severity.MEDIUM: "🟡",
            Severity.HIGH: "🟠",
            Severity.CRITICAL: "🔴",
        }
        emoji = severity_emoji.get(self.severity, "⚪")

        observables_str = ""
        if self.observables:
            obs_list = [f"{o.type.value}: {o.value}" for o in self.observables[:5]]
            observables_str = f"\n   Observables: {', '.join(obs_list)}"
            if len(self.observables) > 5:
                observables_str += f" (+{len(self.observables) - 5} more)"

        return (
            f"{emoji} [{self.severity.value.upper()}] {self.rule_description}\n"
            f"   Alert ID: {self.id}\n"
            f"   Time: {self.timestamp.isoformat()}\n"
            f"   Source: {self.source.agent_name}"
            f"{observables_str}"
        )
