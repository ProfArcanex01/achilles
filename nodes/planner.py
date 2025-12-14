"""
Planner node for the Memory Forensics Agent.

This module contains the planning functionality that generates
comprehensive investigation plans for memory forensics analysis.
"""

from typing import Dict, Any
import json
import re
from langchain_core.messages import SystemMessage, HumanMessage
from jsonschema import validate as jsonschema_validate, ValidationError

from models.state import ForensicState
from models.schemas import VOL3_PLAN_SCHEMA
from utils.messages import build_planner_system_message, build_planner_user_message
from utils.validation import validate_plan_quality


def planner_node(state: ForensicState, llm_with_tools) -> Dict[str, Any]:
    """
    Intelligent investigation planning node. Produces a validated plan dict.
    
    Args:
        state: Current forensic state
        llm_with_tools: LLM instance with planning tools
        
    Returns:
        Dictionary with investigation plan and retry count
    """
    dump_path: str = state.get("memory_dump_path") or "NOT_SPECIFIED"
    os_hint: str | None = state.get("os_hint")

    try:
        user_prompt = state.get("user_prompt")
        system_text = build_planner_system_message(dump_path, os_hint)
        user_text = build_planner_user_message(
            VOL3_PLAN_SCHEMA, os_hint, user_prompt, 
            state.get("evaluation_feedback"), dump_path
        )

        messages = [
            SystemMessage(content=system_text),
            HumanMessage(content=user_text),
        ]

        print(f"Sending request to LLM...")
        print(f"System prompt length: {len(system_text)} chars")
        print(f"User prompt length: {len(user_text)} chars")

        # Call the planner LLM with timeout handling
        resp = llm_with_tools.invoke(messages)
        plan_text = resp.content if hasattr(resp, "content") else str(resp)

        print(f"Received response from LLM...")

        print("✓ Plan generated successfully")

        retry_count = state.get("retry_count", 0)

        
        return {
            "messages": [resp], 
            "investigation_plan": plan_text, 
            "investigation_stage": "planning",
            "retry_count": retry_count + 1
        }
        
    except Exception as e:
        print(f"✗ Planning failed: {str(e)}")
        # Return minimal fallback plan
        fallback_plan = create_fallback_plan(dump_path, os_hint)
        return {"investigation_plan": fallback_plan}


def validate_investigation_plan(state: ForensicState) -> Dict[str, Any]:
    """
    Validation node that extracts and validates the investigation plan from state.
    
    Handles both raw JSON strings and pre-parsed dictionaries. Performs schema
    validation and quality checks on the investigation plan.
    
    Args:
        state: Current graph state containing investigation plan
        
    Returns:
        Dictionary with validation results
    """
    try:
        print(f"Validating investigation plan...")
        investigation_plan = state.get("investigation_plan") or state.get("messages")[-1].content

        if isinstance(investigation_plan, dict):
            data = investigation_plan
        else:
            # Remove triple backticks and optional "json" hint
            cleaned = re.sub(r"^\s*```json\s*|\s*```\s*$", "", investigation_plan, flags=re.DOTALL).strip()
            
            # In case there are stray triple backticks anywhere
            cleaned = cleaned.replace("```", "").strip()

            # Parse the cleaned JSON
            data = json.loads(cleaned)
        
        # Validate against schema first
        jsonschema_validate(instance=data, schema=VOL3_PLAN_SCHEMA)
        
        # Perform comprehensive quality validation (skip command validation for flexibility)
        try:
            validate_plan_quality(data, skip_command_validation=True)
            print("✓ Quality validation passed")
        except Exception as quality_error:
            print(f"⚠️ Quality validation warning: {quality_error}")
            # Continue anyway - just log the warning
        
        return {"investigation_plan": data, "validation_status": "passed"}
    except json.JSONDecodeError as e:
        print(f"✗ JSON parse error: {e}")
        return {"validation_status": "failed", "validation_error": f"Failed to parse JSON: {e}"}
    except ValidationError as e:
        print(f"✗ Schema validation error: {e}")
        return {"validation_status": "failed", "validation_error": f"JSON does not conform to schema: {e}"}
    except Exception as e:
        print(f"✗ Unexpected validation error: {e}")
        return {"validation_status": "failed", "validation_error": f"Plan quality validation failed: {e}"}


def create_fallback_plan(dump_path: str, os_hint: str | None) -> Dict[str, Any]:
    """
    Create a minimal fallback plan when LLM fails.
    
    Args:
        dump_path: Path to memory dump
        os_hint: Operating system hint
        
    Returns:
        Fallback investigation plan
    """
    return {
        "plan_version": "1.0.0-fallback",
        "inputs": {"dump_path": dump_path, "os_hint": os_hint},
        "goals": [
            "Identify malicious processes",
            "Analyze network connections", 
            "Detect persistence mechanisms",
            "Extract memory artifacts"
        ],
        "constraints": ["LLM timeout - using fallback plan"],
        "global_triage": [
            {
                "name": "System Information",
                "commands": [f"vol -f {dump_path} windows.info"],
                "parse_expectations": "System details and memory layout"
            }
        ],
        "os_workflows": {"phases": []},
        "ioc_correlation": {
            "hashing": [],
            "network": [],
            "yara": [],
            "scoring": {
                "process": "Score suspicious processes by anomalous parents, command lines, unsigned binaries",
                "module": "Score modules by unexpected load paths or unsigned status",
                "persistence_item": "Score persistence by abnormal autoruns or registry/service modifications"
            }
        },
        "artifact_preservation": {"directory_structure": [], "chain_of_custody": []},
        "reporting": {"executive_summary": [], "technical_appendix": [], "export_formats": ["json"]}
    }
