"""LangGraph state schema for SecOps agent."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class SupervisorDecision(BaseModel):
    """Decision output from the supervisor node."""

    next_action: str = Field(
        ...,
        description="Next action: ENRICH, INVESTIGATE, VERDICT, CLOSE",
    )
    action_reasoning: str = Field(..., description="Reasoning for the action")
    tp_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Current confidence this is a true positive (0-1)",
    )
    confidence_reasoning: str = Field(
        default="", description="Reasoning for the confidence level"
    )
    specific_instructions: Optional[str] = Field(
        None, description="Specific instructions for the next worker"
    )
