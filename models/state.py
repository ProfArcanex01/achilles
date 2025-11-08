"""
State management and data models for the Memory Forensics Agent.

This module contains the TypedDict state definition and all Pydantic models
used throughout the forensics investigation workflow.
"""

from typing import Annotated, List, Any, Optional, Dict, TypedDict
from pydantic import BaseModel, Field
from langgraph.graph.message import add_messages


class ForensicState(TypedDict): 
    """State dictionary for the forensics investigation workflow."""
    messages: Annotated[List[Any], add_messages]
    memory_dump_path: Optional[str]
    investigation_plan: Optional[str]
    investigation_stage: Optional[str]
    validation_status: Optional[str]
    validation_error: Optional[str]
    user_prompt: Optional[str]  # Custom investigation context
    os_hint: Optional[str]
    evaluation_feedback: Optional[str]  # Evaluator feedback
    success_criteria_met: Optional[bool]  # Whether success criteria are met
    user_input_needed: Optional[bool]  # Whether more user input is needed
    retry_count: Optional[int]  # Track retry attempts for plan generation
    execution_status: Optional[str]  # "completed" | "partial" | "failed" | "skipped"
    execution_results: Optional[Dict[str, Any]]  # Detailed execution results
    execution_error: Optional[str]  # Execution error message
    evidence_directory: Optional[str]  # Path to evidence directory
    execution_summary: Optional[Dict[str, Any]]  # Execution statistics summary
    analysis_results: Optional[Dict[str, Any]]  # Analysis results from output analysis
    analysis_confidence: Optional[float]  # Confidence level in analysis
    threat_score: Optional[float]  # Overall threat score
    key_indicators: Optional[List[str]]  # Key indicators found
    recommended_actions: Optional[List[str]]  # Recommended next steps


class EvaluatorOutput(BaseModel):
    """Output model for the evaluator node."""
    feedback: str = Field(description="Detailed feedback on Volatility 3 command validity and any issues found")
    success_criteria_met: bool = Field(description="True only if ALL Volatility 3 commands and plugins are valid and executable")
    user_input_needed: bool = Field(description="True if invalid commands require user clarification or plan regeneration")


class SuspiciousFinding(BaseModel):
    """Individual suspicious finding with structured details."""
    finding_type: str = Field(description="Type of finding (process, network, persistence, memory, etc.)")
    description: str = Field(description="Detailed description of the suspicious activity")
    severity: str = Field(description="Severity level: low, medium, high, critical")
    evidence: str = Field(description="Specific evidence or artifacts supporting this finding")
    score: float = Field(description="Individual threat score from 0.0 to 10.0")


class AnalysisOutput(BaseModel):
    """Analysis results from the output analysis node."""
    suspicious_findings: List[SuspiciousFinding] = Field(description="List of suspicious findings with details and severity")
    threat_score: float = Field(description="Overall threat score from 0.0 to 10.0")
    key_indicators: List[str] = Field(description="Key indicators of compromise or malicious activity")
    recommended_actions: List[str] = Field(description="Recommended next steps based on findings")
    executive_summary: str = Field(description="Executive summary of the investigation findings")
    analysis_confidence: float = Field(description="Confidence level in the analysis from 0.0 to 1.0")
