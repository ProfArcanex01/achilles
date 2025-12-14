"""
Message building utilities for the Memory Forensics Agent.

This module contains functions for constructing LLM messages and prompts
used throughout the investigation workflow.
"""

from typing import Dict, Any, Optional, List
import json


def build_planner_system_message(dump_path: str, os_hint: Optional[str]) -> str:
    """
    Build system message for the planner LLM.
    
    Args:
        dump_path: Path to the memory dump
        os_hint: Operating system hint (windows, linux, macos)
        
    Returns:
        System message string
    """
    base = f"Senior memory forensics investigator analyzing {dump_path} using Volatility 3.\n\n"
    
    if os_hint:
        base += f"Target OS: {os_hint}. Focus on {os_hint}-specific analysis techniques.\n"
    
    base += (
        "Create comprehensive investigation plan covering:\n"
        "1. Triage: System info, process overview, network snapshot\n"
        "2. Process: Analyze running processes, relationships, command lines\n"
        "3. Network: Examine connections, communications, potential C2\n"
        "4. Persistence: Registry (Run, RunOnce, Winlogon, StartupApproved, file associations), services, scheduled tasks, autostart\n"
        "5. Memory: Code injection, process hollowing, malware artifacts\n"
        "6. Timeline: Reconstruct sequence of events and activities\n\n"
        "Use appropriate VALID Volatility 3 plugins for each phase. Include suspicion heuristics and evidence collection."
    )
    
    return base


def build_planner_user_message(schema: Dict[str, Any], os_hint: Optional[str], 
                              user_prompt: Optional[str] = None, 
                              evaluation_feedback: Optional[str] = None,
                              dump_path: Optional[str] = None) -> str:
    """
    Build enhanced user message with key guidance and optional user context.
    
    Args:
        schema: JSON schema for the investigation plan
        os_hint: Operating system hint
        user_prompt: User's investigation context
        evaluation_feedback: Feedback from evaluation
        dump_path: Path to memory dump
        
    Returns:
        User message string
    """
    guidance = {
        "task": "Generate comprehensive Volatility 3 investigation plan JSON",
        "schema": schema,
        "requirements": {
            "goals": "4+ specific investigation objectives",
            "global_triage": "5+ quick assessment commands",
            "phases": "6 phases with 2+ steps each",
            "commands": f"Use proper vol syntax: vol -f {dump_path} plugin.name",
            "analysis": "Include parse_expectations, suspicion_heuristics, actions_on_hits"
        }
    }
    
    if os_hint:
        guidance["os_guidance"] = f"Use {os_hint}-specific plugins and focus on {os_hint} forensics techniques"
    
    if user_prompt:
        guidance["investigation_context"] = user_prompt
        guidance["note"] = "Tailor the investigation plan to the specific context provided, and use the path of the dump file to the specific context provided"

    if evaluation_feedback:
        guidance["evaluation_feedback"] = evaluation_feedback
    
    return json.dumps(guidance, indent=2)


def build_evaluator_system_message(validation_status: str, plan_summary: str, os_hint: str) -> str:
    """
    Build system message for the evaluator LLM.
    
    Args:
        validation_status: Current validation status
        plan_summary: Summary of the investigation plan
        os_hint: Target operating system
        
    Returns:
        System message string
    """
    return f"""You are a Volatility 3 command validation expert. Your primary goal is to verify that all Volatility 3 commands and plugins in the investigation plan are technically valid and executable.

VALIDATION CRITERIA (PRIORITY ORDER):
1. **Command Syntax**: All commands use correct syntax: "vol -f <path> <plugin>"
2. **Plugin Validity**: All plugins exist in Volatility 3 (e.g., windows.pslist, linux.bash, mac.mount)
3. **OS Compatibility**: Plugins match the target OS (windows.* for Windows, linux.* for Linux, etc.)
4. **Command Parameters**: Optional parameters are valid for each plugin
5. **Executable Format**: Commands can be run by a forensics analyst

Current Status:
- Validation Status: {validation_status}
- Plan Summary: {plan_summary}
- Target OS: {os_hint}

Focus PRIMARILY on command technical correctness. Report any invalid plugins, malformed commands, or OS mismatches."""


def extract_commands_from_plan(plan) -> List[str]:
    """
    Extract all Volatility commands from an investigation plan.
    
    Args:
        plan: Investigation plan (dict or string)
        
    Returns:
        List of command strings
    """
    commands = []
    
    # If plan is a string, try to parse it as dict
    if isinstance(plan, str):
        try:
            import json
            plan = json.loads(plan)
        except:
            # If parsing fails, return empty list - can't extract commands
            return []
    
    if not isinstance(plan, dict):
        return []
    
    # Extract from global triage
    for step in plan.get("global_triage", []):
        commands.extend(step.get("commands", []))
    
    # Extract from investigation phases
    for phase in plan.get("os_workflows", {}).get("phases", []):
        for step in phase.get("steps", []):
            commands.extend(step.get("commands", []))
    
    return commands


def build_evaluator_user_message(investigation_plan: str, os_hint: str, user_prompt: str) -> str:
    """
    Build user message for the evaluator LLM.
    
    Args:
        investigation_plan: The investigation plan to validate
        os_hint: Target operating system
        user_prompt: User's context
        
    Returns:
        User message string
    """
    # Extract all commands for complete validation
    commands = extract_commands_from_plan(investigation_plan)
    
    if not commands:
        # Fallback to truncated plan if command extraction fails
        return f"""Validate all Volatility 3 commands in this investigation plan:

TARGET OS: {os_hint}
USER CONTEXT: {user_prompt or "General memory forensics investigation"}

INVESTIGATION PLAN: {str(investigation_plan)[:2000]}...

CHECK EACH COMMAND FOR:
1. Correct vol syntax
2. Valid plugin names (must exist in Volatility 3)
3. OS compatibility (windows.*, linux.*, mac.* plugins)
4. Proper parameter usage

REPORT:
- Any invalid or non-existent plugins
- Commands with incorrect syntax
- OS mismatches (e.g., windows.pslist on Linux dump)
- Commands that would fail to execute

Mark success_criteria_met=True ONLY if ALL commands are technically valid and executable."""
    
    # Format commands for validation
    commands_formatted = json.dumps(commands, indent=2)
    
    return f"""Validate all Volatility 3 commands in this investigation plan:

TARGET OS: {os_hint}
USER CONTEXT: {user_prompt or "General memory forensics investigation"}

TOTAL COMMANDS TO VALIDATE: {len(commands)}

COMMANDS:
{commands_formatted}

CHECK EACH COMMAND FOR:
1. Correct vol syntax (must start with 'vol -f <path> <plugin>')
2. Valid plugin names (must exist in Volatility 3 for target OS)
3. OS compatibility (windows.* for Windows, linux.* for Linux, mac.* for macOS)
4. Proper parameter usage (no placeholders like <pid> or <path>)
5. Executable format (can be run by a forensics analyst)

VALIDATION RULES:
- Windows OS should use: windows.pslist, windows.netscan, windows.malfind, etc.
- Linux OS should use: linux.pslist, linux.bash, linux.check_afinfo, etc.
- macOS should use: mac.pslist, mac.mount, mac.bash, etc.
- Commands must be complete with actual file paths, not placeholders

REPORT:
- Any invalid or non-existent plugins
- Commands with incorrect syntax
- OS mismatches (e.g., windows.pslist on Linux dump)
- Commands with placeholders or incomplete parameters
- Commands that would fail to execute

Mark success_criteria_met=True ONLY if ALL {len(commands)} commands are technically valid and executable."""


def build_analysis_system_message() -> str:
    """
    Build system message for the analysis LLM.
    
    Returns:
        System message string
    """
    return """You are an expert memory forensics analyst specializing in threat detection and incident response. 

Your task is to analyze the results of a Volatility 3 memory forensics investigation and identify:

1. **Suspicious Findings**: Anomalous processes, network connections, persistence mechanisms, memory artifacts
2. **Threat Indicators**: Signs of malware, lateral movement, data exfiltration, persistence
3. **Attack Patterns**: Known TTPs, behavioral indicators, timeline correlation
4. **Severity Assessment**: Risk scoring based on findings severity and potential impact

**Analysis Guidelines:**
- Focus on actionable intelligence and clear threat indicators
- Provide specific evidence references from the volatility outputs
- Score threats on a 0-10 scale (0=benign, 10=critical compromise)
- Recommend concrete next steps for investigation or remediation
- Consider false positives and provide confidence assessments

**Key Areas to Examine:**
- Process anomalies (unexpected parents, suspicious command lines, unsigned binaries)
- Network activity (C2 communication, data exfiltration, lateral movement)
- Persistence mechanisms (registry changes, services, scheduled tasks)
- Memory artifacts (code injection, process hollowing, rootkits)
- Timeline correlations (sequence of malicious activities)"""


def build_analysis_user_message(state: Dict[str, Any], execution_status: str, 
                               execution_results: Dict[str, Any], 
                               evidence_directory: str, analysis_context: str,
                               chunk_info: Optional[str] = None) -> str:
    """
    Build user message for the analysis LLM.
    
    Args:
        state: Current forensic state
        execution_status: Status of execution
        execution_results: Results from execution
        evidence_directory: Path to evidence directory
        analysis_context: Context for analysis
        chunk_info: Information about chunk being analyzed
        
    Returns:
        User message string
    """
    chunk_context = f" (analyzing {chunk_info})" if chunk_info else ""
    
    return f"""Analyze the memory forensics investigation results below{chunk_context}:

**INVESTIGATION CONTEXT:**
- Memory Dump: {state.get('memory_dump_path', 'Unknown')}
- Target OS: {state.get('os_hint', 'Unknown')}
- Investigation Goals: {state.get('user_prompt', 'General malware analysis')}
- Execution Status: {execution_status}
- Success Rate: {execution_results.get('summary', {}).get('success_rate', 0):.1%}

**EXECUTION SUMMARY:**
- Total Commands: {execution_results.get('summary', {}).get('total_commands', 0)}
- Successful Commands: {execution_results.get('summary', {}).get('successful_commands', 0)}
- Suspicious Hits: {execution_results.get('summary', {}).get('total_suspicious_hits', 0)}
- Evidence Directory: {evidence_directory}

**ANALYSIS CONTEXT:**
{analysis_context}

**INSTRUCTIONS:**
Provide a comprehensive analysis focusing on:
1. Identify all suspicious findings with specific evidence
2. Calculate overall threat score (0-10) based on severity and confidence
3. List key indicators of compromise or malicious activity
4. Recommend specific next steps for investigation or remediation
5. Provide executive summary suitable for management reporting"""


def build_deeper_analysis_system_message() -> str:
    """
    Build system message for deeper analysis LLM.
    
    Returns:
        System message string
    """
    return """You are a senior digital forensics expert specializing in memory analysis and threat hunting.

You must generate ONLY executable Volatility 3 commands (no placeholders, no angle brackets, no variables) based on the provided findings and execution summary.

HARD RULES:
- NO PLACEHOLDERS in any command string. Use concrete values only (e.g., --pid 2412, not --pid <pid>).
- If a needed value (PID, offset, registry path) is unknown, add ONE short discovery command first to deterministically obtain it (e.g., windows.pstree or windows.psscan scoped), then use the result to populate all subsequent commands with literal values.
- Do NOT repeat successful triage commands unless you add clear new value (e.g., --dump, PID scoping, carving variants, or narrower keys).
- Use correct Volatility 3 plugin names (e.g., windows.svcscan, windows.scheduledtasks).
- Keep 5–10 commands total (including any discovery command).
- All commands must be copy-paste runnable on a UNIX-like shell (bash/zsh) with standard quoting.
- Prefer evidence-producing options (e.g., --dump True, -D <output_dir>) and include output directories.
- The name of the volatility command is vol -f <memory_dump_path> <plugin_name>

ANALYSIS APPROACH:
1) Parse initial triage findings and the execution summary to collect concrete identifiers (PIDs, file paths, registry keys).
2) If any required identifier is missing, propose ONE discovery command to derive it, then use its anticipated output in literal form (e.g., PID 2412).
3) Select 5–10 targeted commands total, ordered by evidence value and investigator effort.

COMMAND SELECTION GUIDELINES:
- Code injection → windows.malfind (with --pid and --dump), windows.vadinfo, windows.vadump, windows.dlllist, windows.procdump
- Process anomalies → windows.pstree (only if needed to resolve a PID), windows.handles (scoped to suspicious PIDs), windows.getsids, windows.envars
- Network → windows.sockscan (carving hidden sockets), windows.connections (only if novel scope/value)
- Persistence → windows.scheduledtasks, windows.svcscan, windows.registry.printkey (targeted keys: Run, RunOnce, RunOnceEx, Winlogon, StartupApproved, ShellServiceObjectDelayLoad, Explorer policies, file associations), windows.registry.autostart, autoruns-related keys
- Artifacts → windows.filescan (targeted grep/paths), windows.dumpfiles (by object/offset), windows.yarascan (IOC or config patterns)
- Timeline → windows.timeliner (only if correlating a specific PID/path/time window)

OUTPUT REQUIREMENT:
Return a single compact JSON object only (no commentary, no markdown) matching the schema in the user_message. Each 'command' must be fully concrete and executable."""


def build_deeper_analysis_user_message(initial_findings: Dict[str, Any], state: Dict[str, Any]) -> str:
    """
    Build user message for deeper analysis planning.
    
    Args:
        initial_findings: Results from initial triage
        state: Current forensic state
        
    Returns:
        User message string
    """
    findings = initial_findings.get("analysis_results", {}).get("suspicious_findings", [])
    threat_score = initial_findings.get("threat_score", 0)
    confidence = initial_findings.get("analysis_confidence", 1.0)
    
    # Build comprehensive context for LLM planning
    findings_summary = []
    for finding in findings:
        findings_summary.append({
            "type": finding.get("finding_type", "unknown"),
            "severity": finding.get("severity", "unknown"),
            "description": finding.get("description", ""),
            "evidence": finding.get("evidence", ""),
            "score": finding.get("score", 0)
        })
    
    return f"""Generate a deeper analysis plan for the following investigation:
    
**INITIAL TRIAGE RESULTS:**
- Threat Score: {threat_score}/10
- Analysis Confidence: {confidence}
- Memory Dump: {state.get('memory_dump_path', 'Unknown')}
- OS: {state.get('os_hint', 'Unknown')}
- Investigation Goal: {state.get('user_prompt', 'General malware analysis')}

**SUSPICIOUS FINDINGS:**
{json.dumps(findings_summary, indent=2)}

EXECUTION SUMMARY (already attempted):
{json.dumps(state.get('execution_summary', {}), indent=2)}

CONSTRAINTS:
- NO PLACEHOLDERS in any command; use literal values only.
- If a value like a PID is unknown, include ONE preceding discovery command to obtain it, then use the literal value thereafter.
- Do NOT repeat successful triage commands unless adding new value (e.g., --dump, PID scope, carving).
- Use correct plugin names for Windows.
- 5–10 commands total including any discovery step.

**OUTPUT FORMAT:**
{{
    "plan_version": "llm_deeper_v1.0",
    "analysis_type": "llm_targeted_deeper_analysis", 
    "threat_assessment": "Brief assessment of threat landscape",
    "focus_areas": ["list", "of", "key", "focus", "areas"],
    "targeted_commands": [
        {{
        "command": "complete volatility command (no placeholders, fully executable)",
        "rationale": "why this command is needed (1–2 sentences) — reference what triage already did",
        "priority": "high/medium/low",
        "expected_evidence": "short phrase/bullets of artifacts to extract"
        }}
    ],
 "investigation_strategy": "Overall approach and methodology (1–3 sentences)",
"success_criteria": "How to determine if deeper analysis succeeded (short list)"
}}"""
