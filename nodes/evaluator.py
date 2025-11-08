"""
Evaluator node for the Memory Forensics Agent.

This module contains the evaluation functionality that assesses
the quality and completeness of investigation plans.
"""

from typing import Dict, Any
from langchain_core.messages import SystemMessage, HumanMessage

from models.state import ForensicState, EvaluatorOutput
from utils.messages import build_evaluator_system_message, build_evaluator_user_message


def evaluator_node(state: ForensicState, evaluator_llm_with_output) -> Dict[str, Any]:
    """
    Evaluator node that assesses the quality and completeness of the investigation plan.
    
    Args:
        state: Current graph state containing investigation plan and validation results
        evaluator_llm_with_output: LLM instance with structured output for evaluation
        
    Returns:
        Dictionary with evaluation results
    """
    try:
        print("🔧 Validating Volatility 3 commands and plugins...")
        
        # Get the investigation plan and validation status
        investigation_plan = state.get("investigation_plan")
        validation_status = state.get("validation_status")
        user_prompt = state.get("user_prompt", "")
        
        if not investigation_plan:
            return {
                "evaluation_feedback": "No investigation plan found to evaluate",
                "success_criteria_met": False,
                "user_input_needed": True
            }
        
        # Build evaluation context
        plan_summary = ""
        if isinstance(investigation_plan, dict):
            goals = investigation_plan.get("goals", [])
            phases = investigation_plan.get("os_workflows", {}).get("phases", [])
            plan_summary = f"Plan has {len(goals)} goals and {len(phases)} investigation phases"
        else:
            plan_summary = "Investigation plan is in raw text format"
        
        system_message = build_evaluator_system_message(
            validation_status, plan_summary, state.get('os_hint', 'Unknown')
        )
        user_message = build_evaluator_user_message(
            str(investigation_plan), state.get('os_hint', 'Unknown'), user_prompt
        )
        
        evaluator_messages = [
            SystemMessage(content=system_message),
            HumanMessage(content=user_message)
        ]

        eval_result: EvaluatorOutput = evaluator_llm_with_output.invoke(evaluator_messages)
        
        print(f"✓ Command validation completed")
        print(f"  - All commands valid: {eval_result.success_criteria_met}")
        print(f"  - Requires fixes: {eval_result.user_input_needed}")
        
        return {
            "evaluation_feedback": eval_result.feedback,
            "success_criteria_met": eval_result.success_criteria_met,
            "user_input_needed": eval_result.user_input_needed
        }
        
    except Exception as e:
        print(f"✗ Evaluation error: {e}")
        return {
            "evaluation_feedback": f"Evaluation failed: {e}",
            "success_criteria_met": False,
            "user_input_needed": True
        }


def route_based_on_evaluation(state: ForensicState, max_retries: int = 3) -> str:
    """
    Routing function with retry limits and error handling.
    
    Args:
        state: Current forensic state
        max_retries: Maximum number of retry attempts
        
    Returns:
        Next node to route to
    """
    # Track retry attempts
    retry_count = state.get("retry_count", 0)
    
    # Check for validation failures first
    validation_status = state.get("validation_status")
    if validation_status == "failed":
        if retry_count >= max_retries:
            print(f"⚠️ Max retries ({max_retries}) reached. Ending with partial plan.")
            return "END"
        
        print(f"🔄 Retrying plan generation (attempt {retry_count + 1}/{max_retries})")
        return "planner"
    
    # Check evaluation results
    success_criteria_met = state.get("success_criteria_met")
    
    if success_criteria_met is True:
        print("✅ Success criteria met - proceeding to execution")
        return "execution"
    elif success_criteria_met is False:
        if retry_count >= max_retries:
            print(f"⚠️ Max retries ({max_retries}) reached. Commands may need manual review.")
            return "END"
        print(f"🔄 Retrying plan generation (attempt {retry_count + 1}/{max_retries})")
        return "planner"
    else:
        # success_criteria_met is None or undefined
        print("⚠️ Undefined evaluation result - ending workflow")
        return "END"
