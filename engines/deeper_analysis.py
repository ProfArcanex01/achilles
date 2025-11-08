"""
Deeper Analysis Engine for the Memory Forensics Agent.

This module contains the specialized engine for deeper forensics analysis
based on initial triage findings. It handles secondary analysis phases
triggered when high-threat indicators are detected.
"""

from typing import Dict, Any, List
import json
import re
from langchain_core.messages import SystemMessage, HumanMessage

from models.state import ForensicState
from utils.messages import build_deeper_analysis_system_message, build_deeper_analysis_user_message
from config.settings import DEFAULT_CONFIG


class DeeperAnalysisEngine:
    """
    Specialized engine for deeper forensics analysis based on initial triage findings.
    
    This engine handles the secondary analysis phase that's triggered when initial
    triage identifies high-threat indicators or specific suspicious findings that
    warrant focused investigation.
    """
    
    def __init__(self, parent_agent, config=None):
        """Initialize deeper analysis engine with reference to parent agent."""
        self.parent = parent_agent  # Access to shared LLMs, tools, and state
        self.config = config or DEFAULT_CONFIG
        
        # Command templates for targeted analysis based on finding types
        self.DEEPER_ANALYSIS_COMMANDS = {
            "code_injection": [
                "windows.malfind",
                "windows.hollowfind", 
                "windows.injected",
                "windows.dumpfiles --pid {pid}"
            ],
            "persistence": [
                "windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                "windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'",
                "windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx'",
                "windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'",
                "windows.registry.printkey --key 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'",
                "windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run'",
                "windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder'",
                "windows.registry.printkey --key 'Software\\Classes\\exefile\\shell\\open\\command'",
                "windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad'",
                "windows.services.svcscan",
                "windows.registry.autostart",
                "windows.scheduled_tasks"
            ],
            "network_activity": [
                "windows.netscan",
                "windows.netstat", 
                "windows.connections",
                "windows.dnsresolver"
            ],
            "process_anomalies": [
                "windows.pslist",
                "windows.pstree", 
                "windows.cmdline",
                "windows.handles --pid {pid}"
            ],
            "timeline_analysis": [
                "timeliner.timeline",
                "windows.mftscan.mftparser",
                "windows.shellbags"
            ]
        }
    
    def should_trigger_deeper_analysis(self, analysis_result: Dict[str, Any]) -> bool:
        """
        Determine if deeper analysis is warranted based on initial triage results.
        
        Args:
            analysis_result: Results from initial triage analysis
            
        Returns:
            bool: True if deeper analysis should be triggered
        """
        # High threat score threshold
        threat_score = analysis_result.get("threat_score", 0)
        if threat_score >= self.config.threat_score_threshold:
            return True
            
        # Low confidence in analysis  
        confidence = analysis_result.get("analysis_confidence", 1.0)
        if confidence < self.config.confidence_threshold:
            return True
            
        # Check for specific high-priority finding types
        findings = analysis_result.get("analysis_results", {}).get("suspicious_findings", [])
        high_priority_types = {"code_injection", "persistence", "network_activity"}
        
        for finding in findings:
            finding_type = finding.get("finding_type", "").lower()
            severity = finding.get("severity", "").lower()
            
            # High severity findings or specific types warrant deeper analysis
            if severity == "high" or any(hpt in finding_type for hpt in high_priority_types):
                return True
                
        return False
    
    def generate_deeper_analysis_plan(self, initial_findings: Dict[str, Any], state: ForensicState) -> Dict[str, Any]:
        """
        Generate intelligent, LLM-driven targeted investigation plan based on initial findings.
        
        Uses the parent agent's LLM to create adaptive analysis plans that can reason
        about complex threat patterns and generate contextually appropriate commands.
        
        Args:
            initial_findings: Results from initial triage
            state: Current forensic state
            
        Returns:
            Dict containing deeper analysis plan
        """
        try:
            # Create system and user messages
            system_message = build_deeper_analysis_system_message()
            user_message = build_deeper_analysis_user_message(initial_findings, state)
            
            planning_messages = [
                SystemMessage(content=system_message),
                HumanMessage(content=user_message)
            ]
            
            print("🧠 Generating intelligent deeper analysis plan...")
            llm_response = self.parent.planner_llm.invoke(planning_messages)
            
            # Parse LLM response to extract plan
            try:
                # Extract JSON from LLM response
                response_content = llm_response.content
                json_match = re.search(r'\{.*\}', response_content, re.DOTALL)
                
                if json_match:
                    plan_json = json_match.group()
                    plan = json.loads(plan_json)
                    
                    # Extract just the command strings for execution
                    command_list = []
                    if "targeted_commands" in plan:
                        for cmd_obj in plan["targeted_commands"]:
                            if isinstance(cmd_obj, dict) and "command" in cmd_obj:
                                command_list.append(cmd_obj["command"])
                            elif isinstance(cmd_obj, str):
                                command_list.append(cmd_obj)
                    
                    # Ensure we have the required fields for execution
                    final_plan = {
                        "plan_version": plan.get("plan_version", "llm_deeper_v1.0"),
                        "analysis_type": plan.get("analysis_type", "llm_targeted_deeper_analysis"),
                        "threat_assessment": plan.get("threat_assessment", "LLM-generated assessment"),
                        "focus_areas": plan.get("focus_areas", ["comprehensive_analysis"]),
                        "targeted_commands": command_list,
                        "investigation_strategy": plan.get("investigation_strategy", "LLM-guided targeted investigation"),
                        "llm_rationale": plan.get("targeted_commands", []),  # Store full command objects
                        "success_criteria": plan.get("success_criteria", "Enhanced threat understanding")
                    }
                    
                    print(f"✅ LLM generated plan with {len(command_list)} targeted commands")
                    return final_plan
                    
                else:
                    print("⚠️ Could not extract JSON from LLM response, falling back to rule-based")
                    return self._fallback_rule_based_plan(initial_findings.get("analysis_results", {}).get("suspicious_findings", []), state)
                    
            except (json.JSONDecodeError, KeyError) as e:
                print(f"⚠️ Error parsing LLM plan: {e}, falling back to rule-based")
                return self._fallback_rule_based_plan(initial_findings.get("analysis_results", {}).get("suspicious_findings", []), state)
                
        except Exception as e:
            print(f"❌ Error generating LLM plan: {e}, falling back to rule-based")
            return self._fallback_rule_based_plan(initial_findings.get("analysis_results", {}).get("suspicious_findings", []), state)
    
    def _fallback_rule_based_plan(self, findings: List[Dict], state: ForensicState) -> Dict[str, Any]:
        """
        Fallback rule-based plan generation if LLM approach fails.
        
        Args:
            findings: List of suspicious findings
            state: Current forensic state
            
        Returns:
            Dict containing fallback analysis plan
        """
        # Simple rule-based fallback using the original logic
        analysis_categories = set()
        target_pids = []
        
        for finding in findings:
            finding_type = finding.get("finding_type", "").lower()
            description = finding.get("description", "").lower()
            
            if "injection" in description or "inject" in description:
                analysis_categories.add("code_injection")
            elif "persistence" in description or "registry" in description:
                analysis_categories.add("persistence") 
            elif "network" in description or "connection" in description:
                analysis_categories.add("network_activity")
            elif "process" in finding_type:
                analysis_categories.add("process_anomalies")
                
            # Extract PIDs if mentioned
            evidence = finding.get("evidence", "")
            pid_matches = re.findall(r'pid[:\s]*(\d+)', evidence.lower())
            target_pids.extend(pid_matches)
        
        # Generate commands using templates
        deeper_commands = []
        for category in analysis_categories:
            commands = self.DEEPER_ANALYSIS_COMMANDS.get(category, [])
            for cmd in commands[:3]:  # Limit to avoid explosion
                if "{pid}" in cmd and target_pids:
                    for pid in target_pids[:2]:
                        deeper_commands.append(cmd.format(pid=pid))
                else:
                    deeper_commands.append(cmd)
        
        return {
            "plan_version": "fallback_v1.0",
            "analysis_type": "rule_based_fallback",
            "focus_areas": list(analysis_categories),
            "targeted_commands": deeper_commands[:8],  # Limit commands
            "investigation_strategy": "Rule-based fallback analysis"
        }
    
    def deeper_analysis_node(self, state: ForensicState) -> Dict[str, Any]:
        """
        Perform deeper analysis based on initial triage findings.
        
        Generates targeted investigation plan and executes focused commands
        to drill down into specific threats identified in initial analysis.
        """
        try:
            print("🔬 Starting Deeper Analysis Phase")
            
            # Get initial findings from triage
            analysis_results = state.get("analysis_results")
            if not analysis_results:
                print("⚠️ No triage results available for deeper analysis")
                return {"investigation_stage": "deeper_analysis_skipped"}
            
            # Generate deeper analysis plan
            deeper_plan = self.generate_deeper_analysis_plan(analysis_results, state)
            
            print(f"📋 Generated deeper analysis plan: {deeper_plan.get('analysis_type', 'unknown')}")
            print(f"🎯 Focus areas: {', '.join(deeper_plan.get('focus_areas', []))}")
            print(f"📋 Executing {len(deeper_plan.get('targeted_commands', []))} specialized commands")
            
            # Display LLM reasoning if available
            if "threat_assessment" in deeper_plan:
                print(f"🧠 LLM Assessment: {deeper_plan['threat_assessment']}")
            if "investigation_strategy" in deeper_plan:
                print(f"📈 Strategy: {deeper_plan['investigation_strategy']}")
            
            # Convert deeper analysis plan to execution format
            execution_plan = {
                "plan_version": deeper_plan.get("plan_version", "1.0"),
                "inputs": {
                    "dump_path": state.get("memory_dump_path"),
                    "os_hint": state.get("os_hint", "windows")
                },
                "global_triage": [
                    {
                        "name": "deeper_targeted_analysis",
                        "description": "Focused analysis based on initial findings",
                        "commands": deeper_plan.get("targeted_commands", [])
                    }
                ]
            }
            
            # Execute deeper analysis using existing execution infrastructure
            import os
            from volatility_executor import execute_investigation_plan
            
            evidence_directory = state.get("evidence_directory", "")
            deeper_evidence_dir = os.path.join(evidence_directory, "deeper_analysis")
            os.makedirs(deeper_evidence_dir, exist_ok=True)
            
            print("🔄 Executing deeper analysis commands...")
            execution_results = execute_investigation_plan(execution_plan, deeper_evidence_dir)
            
            # Return comprehensive results
            return {
                "deeper_analysis_plan": deeper_plan,
                "deeper_analysis_results": execution_results,
                "deeper_evidence_directory": deeper_evidence_dir,
                "investigation_stage": "deeper_analysis_completed"
            }
            
        except Exception as e:
            print(f"❌ Deeper analysis error: {e}")
            return {
                "deeper_analysis_error": str(e),
                "investigation_stage": "deeper_analysis_failed"
            }
