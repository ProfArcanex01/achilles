"""
Execution node for the Memory Forensics Agent.

This module contains the execution functionality that runs
validated investigation plans using the VolatilityExecutor.
"""

from typing import Dict, Any
from datetime import datetime
import os

from models.state import ForensicState
from config import ForensicsConfig

def execution_node(state: ForensicState) -> Dict[str, Any]:
    """
    Execute the validated investigation plan using the enhanced VolatilityExecutor.
    
    Args:
        state: Current forensic state containing the validated investigation plan
        
    Returns:
        Dictionary containing execution results, status, and evidence directory
    """
    try:
        print("🚀 Starting Investigation Plan Execution")
        
        # Get validated plan
        plan = state.get("investigation_plan")
        if not plan:
            return {
                "execution_status": "failed",
                "execution_error": "No investigation plan found in state",
                "execution_results": None
            }
        
        # Check if plan passed validation
        validation_status = state.get("validation_status")
        if validation_status != "passed":
            return {
                "execution_status": "skipped", 
                "execution_error": f"Plan validation failed: {validation_status}",
                "execution_results": None
            }
        
        # Import and initialize executor
        from volatility_executor import VolatilityExecutor, ExecutionStatus
        
        # Create evidence directory based on case info
        memory_dump_path = state.get("memory_dump_path", "unknown_case")
        case_id = memory_dump_path.split("/")[-1].replace(".raw", "").replace(".mem", "")
        evidence_dir = f"{ForensicsConfig.evidence_base_dir}/{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        executor = VolatilityExecutor(base_output_dir=evidence_dir, shell_path=ForensicsConfig.from_env().shell_path)
        
        # Prepare execution context
        base_context = {
            "case_id": case_id,
            "memory_dump_path": memory_dump_path,
            "os_hint": state.get("os_hint"),
            "user_prompt": state.get("user_prompt"),
            "analyst": "memory_forensics_agent",
            "investigation_goals": plan.get("goals", [])
        }
        
        execution_results = {
            "execution_start": datetime.now().isoformat(),
            "case_id": case_id,
            "evidence_directory": evidence_dir,
            "global_triage": [],
            "phases": [],
            "summary": {},
            "deduplicated_commands": {}  # Track executed commands for deduplication
        }
        
        # Track executed commands to avoid duplicates
        executed_commands = {}  # command -> {"output_file": path, "result": result_dict}
        
        # Execute global triage first
        print("🎯 Executing Global Triage Phase")
        global_triage_success = 0
        global_triage_total = 0
        global_triage_skipped = 0
        
        if "global_triage" in plan:
            for triage_step in plan["global_triage"]:
                step_name = triage_step.get("name", "Unknown Triage Step")
                print(f"  📋 {step_name}")
                
                step_context = {**base_context, "phase": "global_triage", "step": step_name}
                step_results = []
                
                for cmd in triage_step.get("commands", []):
                    global_triage_total += 1
                    
                    # Check if command already executed
                    if cmd in executed_commands:
                        print(f"    ⏭️  Skipping duplicate: {cmd.split()[-1]}")
                        # Reuse previous result
                        prev_result = executed_commands[cmd]
                        step_results.append({
                            "command": cmd,
                            "status": prev_result["status"],
                            "execution_time": 0.0,  # No execution time for duplicates
                            "output_file": prev_result["output_file"],
                            "error_message": None,
                            "note": "Reused from previous execution"
                        })
                        global_triage_skipped += 1
                        if prev_result["status"] == "success":
                            global_triage_success += 1
                        continue
                    
                    result = executor.execute_volatility_command(
                        command=cmd,
                        context=step_context,
                        save_output=True,
                        category="triage"
                    )
                    
                    if result.status == ExecutionStatus.SUCCESS:
                        global_triage_success += 1
                    
                    result_dict = {
                        "command": cmd,
                        "status": result.status.value,
                        "execution_time": result.execution_time,
                        "output_file": result.output_file,
                        "error_message": result.error_message
                    }
                    
                    step_results.append(result_dict)
                    
                    # Track this command for deduplication
                    executed_commands[cmd] = {
                        "status": result.status.value,
                        "output_file": result.output_file
                    }
                
                execution_results["global_triage"].append({
                    "step_name": step_name,
                    "parse_expectations": triage_step.get("parse_expectations"),
                    "results": step_results
                })
        
        # Pass executed_commands to executor for phase deduplication
        executor.executed_commands = executed_commands
        
        # Execute main investigation phases
        print("\n🔍 Executing Investigation Phases")
        if "os_workflows" in plan and "phases" in plan["os_workflows"]:
            for phase in plan["os_workflows"]["phases"]:
                print(f"\n📂 Starting Phase: {phase.get('name', 'Unknown Phase')}")
                
                phase_result = executor.execute_investigation_phase(
                    phase=phase,
                    base_context=base_context
                )
                
                execution_results["phases"].append(phase_result)
        
        # Generate execution summary
        execution_end = datetime.now()
        execution_results["execution_end"] = execution_end.isoformat()
        
        # Calculate overall statistics
        total_commands = global_triage_total + sum(
            phase.get("summary", {}).get("total_commands", 0) 
            for phase in execution_results["phases"]
        )
        
        successful_commands = global_triage_success + sum(
            phase.get("summary", {}).get("successful_commands", 0)
            for phase in execution_results["phases"]
        )
        
        total_hits = sum(
            phase.get("summary", {}).get("total_hits", 0)
            for phase in execution_results["phases"]
        )
        
        execution_results["summary"] = {
            "total_commands": total_commands,
            "successful_commands": successful_commands,
            "success_rate": successful_commands / total_commands if total_commands > 0 else 0,
            "total_suspicious_hits": total_hits,
            "evidence_directory": evidence_dir,
            "triage_success_rate": global_triage_success / global_triage_total if global_triage_total > 0 else 0,
            "deduplicated_commands": global_triage_skipped + executor.skipped_duplicates,
            "unique_commands_executed": len(executed_commands)
        }
        
        # Save comprehensive summary
        summary_file = executor.save_execution_summary()
        execution_results["summary"]["detailed_log_file"] = summary_file
        
        # Determine overall execution status
        success_rate = execution_results["summary"]["success_rate"]
        if success_rate >= 0.8:
            execution_status = "completed"
        elif success_rate >= 0.5:
            execution_status = "partial"
        else:
            execution_status = "failed"
        
        print(f"\n✅ Investigation Execution Complete!")
        print(f"📊 Overall Success Rate: {success_rate:.1%}")
        print(f"🔍 Suspicious Hits Found: {total_hits}")
        print(f"♻️  Deduplicated Commands: {global_triage_skipped + executor.skipped_duplicates}")
        print(f"📁 Evidence Directory: {evidence_dir}")
        
        return {
            "execution_status": execution_status,
            "execution_results": execution_results,
            "evidence_directory": evidence_dir,
            "execution_summary": execution_results["summary"],
            "investigation_stage": "execution_completed"
        }
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        return {
            "execution_status": "failed",
            "execution_error": f"Failed to import VolatilityExecutor: {e}",
            "execution_results": None
        }
        
    except Exception as e:
        print(f"❌ Execution Error: {e}")
        return {
            "execution_status": "failed", 
            "execution_error": f"Execution failed: {str(e)}",
            "execution_results": None
        }


def route_after_execution(state: ForensicState) -> str:
    """Route after execution is complete."""
    execution_status = state.get("execution_status")
    
    if execution_status in ["completed", "partial"]:
        print(f"🎉 Investigation execution {execution_status} - proceeding to triage")
        return "triage"
    elif execution_status == "failed":
        print("❌ Investigation execution failed - ending workflow")
        return "END"
    elif execution_status == "skipped":
        print("⏭️ Investigation execution skipped - ending workflow")
        return "END"
    else:
        print("❓ Unknown execution status - ending workflow")
        return "END"
