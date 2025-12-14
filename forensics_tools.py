"""
Memory Forensics Tools for Digital Investigation

This module provides specialized tools for memory dump analysis using Volatility 3
and other forensics utilities. Replaces web browsing tools with forensics-specific
functionality.
"""

from dotenv import load_dotenv
import os
import requests
import subprocess
import json
import shlex
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from langchain.agents import Tool
from langchain.tools import StructuredTool
from pydantic import BaseModel, Field
from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_experimental.tools import PythonREPLTool
from langchain_community.tools import ShellTool
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field


load_dotenv(override=True)
pushover_token = os.getenv("PUSHOVER_TOKEN")
pushover_user = os.getenv("PUSHOVER_USER")
pushover_url = "https://api.pushover.net/1/messages.json"

# Initialize LLM for IOC analysis
_ioc_llm = None

def get_ioc_llm():
    """Get or initialize the LLM for IOC analysis."""
    global _ioc_llm
    if _ioc_llm is None:
        _ioc_llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    return _ioc_llm



class IOCAnalysis(BaseModel):
    """Structured output for IOC analysis."""
    suspicious_processes: List[str] = Field(description="List of suspicious processes with PIDs and details")
    network_indicators: List[str] = Field(description="Network connections, IPs, ports, domains that are suspicious") 
    file_indicators: List[str] = Field(description="Suspicious file paths, names, or locations")
    registry_indicators: List[str] = Field(description="Suspicious registry keys, values, or modifications")
    malware_signatures: List[str] = Field(description="Code injection, packed executables, or malware signatures")
    persistence_mechanisms: List[str] = Field(description="Autostart locations, scheduled tasks, services")
    behavioral_indicators: List[str] = Field(description="Process relationships, command lines, or behavior patterns")
    confidence_score: int = Field(description="Confidence level 1-10 for the IOC analysis quality")
    summary: str = Field(description="Brief summary of the most critical findings")


def validate_memory_dump(dump_path: str) -> str:
    """
    Validate if a file is a valid memory dump and extract basic metadata.
    
    Args:
        dump_path (str): Path to the memory dump file
        
    Returns:
        str: Validation result with basic metadata or error message
    """
    try:
        path = Path(dump_path)
        if not path.exists():
            return f"Error: Memory dump file not found at {dump_path}"
        
        # Check file size (memory dumps are typically large)
        file_size = path.stat().st_size
        size_mb = file_size / (1024 * 1024)
        
        # Basic file validation
        if file_size == 0:
            return "Error: Memory dump file is empty"
        
        # Try to detect OS type using Volatility
        os_detected = None
        basic_info = ""
        
        # Test different OS types in order of likelihood
        os_commands = [
            ("windows", "windows.info"),
            ("linux", "linux.banner"), 
            ("mac", "mac.banner")
        ]
        
        for os_name, command in os_commands:
            try:
                # Build safe argv (no shell=True)
                argv = ["vol", "-f", dump_path, command]
                
                result = subprocess.run(
                    argv,  # List of arguments
                    shell=False,  # SAFE: No shell interpretation
                    capture_output=True,
                    text=True,
                    timeout=30  # Shorter timeout per attempt
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    os_detected = os_name
                    basic_info = result.stdout
                    break  # Found working OS type
                    
            except subprocess.TimeoutExpired:
                continue  # Try next OS type
        
        # Return results with clear OS indication
        if os_detected:
            return f"Valid {os_detected.title()} memory dump detected!\nSize: {size_mb:.2f} MB\nOS Type: {os_detected}\nBasic Info:\n{basic_info}"
        else:
            return f"Memory dump file located (Size: {size_mb:.2f} MB). OS type could not be determined automatically."
            
    except Exception as e:
        return f"Error validating memory dump: {str(e)}"


def run_volatility_command(command: str) -> str:
    """
    Execute a Volatility 3 command safely with proper error handling.
    
    Uses safe command execution without shell=True to prevent injection attacks.
    
    Args:
        command (str): Volatility command to execute (should start with 'vol')
        
    Returns:
        str: Command output or error message
    """
    try:
        # Security check - ensure command starts with 'vol'
        if not command.strip().startswith('vol'):
            return "Error: Only Volatility commands starting with 'vol' are allowed"
        
        # Parse command safely to argv
        try:
            argv = shlex.split(command)
        except ValueError as e:
            return f"Error: Invalid command syntax - {e}"
        
        # Validate first argument
        if argv[0] not in ['vol', 'vol3']:
            return "Error: Command must start with 'vol' or 'vol3'"
        
        # Check for shell metacharacters in arguments
        dangerous_chars = ['&', '|', ';', '`', '$', '\n', '\r', '>', '<']
        for arg in argv:
            if any(char in arg for char in dangerous_chars):
                return f"Error: Suspicious character in argument: {arg}"
        
        # Execute the command safely (no shell)
        result = subprocess.run(
            argv,  # List of arguments
            shell=False,  # SAFE: No shell interpretation
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout for longer operations
        )
        
        if result.returncode != 0:
            return f"Volatility Error (exit code {result.returncode}):\n{result.stderr.strip()}"
        
        output = result.stdout.strip()
        if not output:
            return "Command executed successfully but produced no output"
            
        return output
        
    except subprocess.TimeoutExpired:
        return "Error: Volatility command timed out after 5 minutes"
    except Exception as e:
        return f"Error executing Volatility command: {str(e)}"


def extract_iocs_from_output(volatility_output: str) -> str:
    """
    Extract potential Indicators of Compromise (IOCs) from Volatility output using LLM analysis.
    
    This function uses advanced language model analysis to intelligently identify
    and categorize potential IOCs from forensics tool output, providing much more
    accurate and context-aware analysis than simple pattern matching.
    
    Args:
        volatility_output (str): Raw output from Volatility commands
        
    Returns:
        str: Comprehensive formatted analysis of potential IOCs found
    """
    try:
        if not volatility_output or volatility_output.strip() == "":
            return "No output provided for IOC analysis."
        
        # Truncate very long output to stay within token limits
        max_chars = 8000  # Conservative limit for analysis
        if len(volatility_output) > max_chars:
            volatility_output = volatility_output[:max_chars] + "\n[...OUTPUT TRUNCATED...]"
        
        llm = get_ioc_llm()
        structured_llm = llm.with_structured_output(IOCAnalysis)
        
        system_prompt = """You are a senior digital forensics analyst specializing in memory analysis and IOC identification. 
        Your task is to analyze Volatility 3 output and extract potential Indicators of Compromise (IOCs) with high accuracy.

        ANALYSIS GUIDELINES:
        1. Look for processes with suspicious characteristics:
           - Unusual process names or locations
           - Processes running from temp directories
           - Packed or obfuscated executables
           - Processes with no parent or unusual parents
           - Command-line arguments indicating malicious activity
        
        2. Identify network indicators:
           - Connections to suspicious IPs or domains
           - Unusual ports or protocols
           - C2 communication patterns
           - Large data transfers
        
        3. Find file system indicators:
           - Files in suspicious locations (%TEMP%, %APPDATA%, etc.)
           - Files with suspicious names or extensions
           - Hidden or system files in user directories
           - Recently created files in system directories
        
        4. Detect behavioral indicators:
           - Process injection techniques
           - Code hollowing or process replacement
           - Unusual process relationships
           - Privilege escalation attempts
        
        5. Registry and persistence mechanisms:
           - Autostart registry keys
           - Scheduled tasks
           - Service installations
           - DLL hijacking attempts
        
        Be specific in your findings - include PIDs, file paths, IP addresses, and other relevant details.
        Focus on HIGH-CONFIDENCE indicators that warrant investigation.
        Provide context for why each finding is suspicious.
        
        Rate your overall confidence in the analysis from 1-10 (10 being highest confidence)."""
        
        human_prompt = f"""Analyze the following Volatility forensics output and extract all potential IOCs:

        VOLATILITY OUTPUT:
        {volatility_output}
        
        Please identify and categorize all suspicious indicators with detailed explanations."""
        
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt)
        ]
        
        # Get structured IOC analysis from LLM
        ioc_analysis = structured_llm.invoke(messages)
        
        # Format the results for display
        result = "🔍 **LLM-POWERED IOC ANALYSIS**\n"
        result += "=" * 50 + "\n\n"
        
        # Summary
        result += f"**📋 ANALYSIS SUMMARY** (Confidence: {ioc_analysis.confidence_score}/10)\n"
        result += f"{ioc_analysis.summary}\n\n"
        
        # Detailed findings by category
        categories = [
            ("🚨 Suspicious Processes", ioc_analysis.suspicious_processes),
            ("🌐 Network Indicators", ioc_analysis.network_indicators),
            ("📁 File Indicators", ioc_analysis.file_indicators),
            ("⚙️ Registry Indicators", ioc_analysis.registry_indicators),
            ("🦠 Malware Signatures", ioc_analysis.malware_signatures),
            ("🔄 Persistence Mechanisms", ioc_analysis.persistence_mechanisms),
            ("🔍 Behavioral Indicators", ioc_analysis.behavioral_indicators)
        ]
        
        for category_name, indicators in categories:
            if indicators:
                result += f"**{category_name}:**\n"
                for indicator in indicators:
                    result += f"  • {indicator}\n"
                result += "\n"
        
        # If no IOCs found
        if not any(indicators for _, indicators in categories):
            result += "✅ **No significant IOCs detected** in the provided output.\n"
            result += "This could indicate either a clean system or that additional analysis is needed.\n"
        
        return result
        
    except Exception as e:
        return f"❌ **Error in LLM IOC analysis:** {str(e)}\n\nFalling back to basic pattern analysis..."


def generate_investigation_plan(dump_path: str, investigation_goal: str = "malware analysis", detected_os: str = "unknown", additional_context: str = "") -> str:
    """
    Generate an intelligent, LLM-driven investigation plan for memory dump analysis.
    
    This function uses advanced language model analysis to create tailored investigation
    plans based on the specific context, OS type, investigation goals, and any additional
    information available about the incident.
    
    Args:
        dump_path (str): Path to the memory dump file
        investigation_goal (str): Type of investigation (malware analysis, incident response, data exfiltration, etc.)
        detected_os (str): Detected operating system (windows, linux, mac, etc.)
        additional_context (str): Any additional context about the incident or system
        
    Returns:
        str: Comprehensive investigation plan with adaptive steps and commands
    """
    try:
        llm = get_ioc_llm()
        
        system_prompt = """You are a senior digital forensics investigator and memory analysis expert. 
        Your task is to create a comprehensive, adaptive investigation plan for memory dump analysis.

        PLANNING PRINCIPLES:
        1. **Adaptive Methodology**: Tailor the investigation based on the specific OS, incident type, and available context
        2. **Prioritization**: Order steps by criticality and potential evidence value
        3. **Efficiency**: Balance thoroughness with investigation timeline constraints
        4. **Volatility Expertise**: Generate appropriate Volatility 3 commands for each OS type
        5. **Evidence Preservation**: Ensure proper forensics methodology throughout

        INVESTIGATION TYPES TO CONSIDER:
        - Malware Analysis: Focus on processes, injection, persistence, network IOCs
        - Incident Response: Timeline reconstruction, lateral movement, data access patterns
        - Data Exfiltration: Network analysis, file access, encryption, compression activities
        - Insider Threat: User activity, file access patterns, credential usage
        - APT Investigation: Persistence mechanisms, C2 communications, tool artifacts
        - Compliance: Data handling, access controls, audit trail reconstruction

        OS-SPECIFIC CONSIDERATIONS:
        - Windows: Registry analysis, Windows services, NTFS artifacts, Windows APIs
        - Linux: Process trees, kernel modules, shared libraries, system calls
        - macOS: LaunchAgents/Daemons, kernel extensions, system integrity

        VOLATILITY 3 COMMAND CATEGORIES:
        - System Info: windows.info, linux.banner, mac.banner
        - Process Analysis: windows.pslist/psscan/pstree, linux.pslist, mac.pslist
        - Network: windows.netscan, linux.netstat, mac.netstat  
        - Malware Detection: windows.malfind, linux.check_afinfo, mac.check_syscalls
        - Memory Regions: windows.memmap, linux.proc.maps, mac.proc.maps
        - Registry: windows.registry.*, windows.hivelist
        - Files: windows.filescan, linux.lsmod, mac.lsmod

        OUTPUT FORMAT: Return a detailed JSON investigation plan with:
        {
          "investigation_summary": "Brief overview of the investigation approach",
          "priority_level": "High/Medium/Low based on investigation type",
          "estimated_duration": "Estimated time to complete",
          "investigation_phases": [
            {
              "phase": "Phase name",
              "description": "What this phase accomplishes",
              "steps": [
                {
                  "step_number": 1,
                  "task": "Specific task description",
                  "command": "Complete Volatility command with proper syntax",
                  "rationale": "Why this step is important",
                  "expected_artifacts": "What evidence this might reveal",
                  "priority": "High/Medium/Low"
                }
              ]
            }
          ],
          "success_criteria": "How to determine if investigation goals are met",
          "follow_up_recommendations": "Additional analysis that might be needed"
        }"""
        
        human_prompt = f"""Create a comprehensive investigation plan for the following memory dump analysis:

        **INVESTIGATION DETAILS:**
        - Memory Dump Path: {dump_path}
        - Investigation Goal: {investigation_goal}
        - Detected OS: {detected_os}
        - Additional Context: {additional_context if additional_context else "None provided"}

        Please generate a detailed, adaptive investigation plan that:
        1. Accounts for the specific OS type and investigation goal
        2. Provides appropriate Volatility 3 commands for the detected system
        3. Prioritizes steps based on potential evidence value
        4. Includes rationale for each investigative step
        5. Suggests follow-up analysis based on potential findings

        Focus on creating an intelligent, context-aware plan rather than a generic template."""
        
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt)
        ]
        
        # Get intelligent plan from LLM
        response = llm.invoke(messages)
        print(response)
        plan_content = response.content
        
        # Try to parse as JSON to validate structure, but return the full content
        try:
            parsed_plan = json.loads(plan_content)
            return json.dumps(parsed_plan, indent=2)
        except json.JSONDecodeError:
            # If not valid JSON, wrap in a basic structure
            fallback_plan = {
                "investigation_summary": f"LLM-generated plan for {investigation_goal}",
                "plan_content": plan_content,
                "generated_timestamp": str(datetime.now()),
                "note": "Generated by AI forensics planner"
            }
            return json.dumps(fallback_plan, indent=2)
        
    except Exception as e:
        # Fallback to a basic plan if LLM fails
        fallback_steps = [
            {
                "step": 1,
                "task": "Validate memory dump and extract system info",
                "command": f"vol -f {dump_path} windows.info" if detected_os.lower() == "windows" else f"vol -f {dump_path} linux.banner",
                "rationale": "Essential first step to understand the system context"
            },
            {
                "step": 2, 
                "task": "Analyze running processes",
                "command": f"vol -f {dump_path} windows.pslist" if detected_os.lower() == "windows" else f"vol -f {dump_path} linux.pslist",
                "rationale": "Identify active processes and potential anomalies"
            }
        ]
        
        fallback_plan = {
            "investigation_summary": f"Fallback plan for {investigation_goal} (LLM planning failed)",
            "error": str(e),
            "basic_steps": fallback_steps,
            "note": "Generated using fallback planning due to LLM error"
        }
        
        return json.dumps(fallback_plan, indent=2)


def push(text: str) -> str:
    """
    Send a push notification to the user about investigation progress.
    
    Args:
        text (str): Message to send
        
    Returns:
        str: Success or error message
    """
    try:
        if not pushover_token or not pushover_user:
            return "Push notifications not configured (missing tokens)"
            
        response = requests.post(pushover_url, data={
            "token": pushover_token, 
            "user": pushover_user, 
            "message": f"[Forensics] {text}"
        })
        
        if response.status_code == 200:
            return "Push notification sent successfully"
        else:
            return f"Failed to send push notification: {response.status_code}"
            
    except Exception as e:
        return f"Error sending push notification: {str(e)}"


def get_file_tools() -> List[Tool]:
    """
    Get file management tools configured for forensics work.
    
    Returns:
        List[Tool]: File management tools
    """
    # Use sandbox directory for forensics outputs
    toolkit = FileManagementToolkit(root_dir="sandbox")
    return toolkit.get_tools()


def get_shell_tools() -> List[Tool]:
    """
    Get shell tools for system operations.
    
    Returns:
        List[Tool]: Shell command tools
    """
    return [ShellTool()]


async def forensics_tools() -> List[Tool]:
    """
    Get all forensics-specific tools for memory dump analysis.
    
    Returns:
        List[Tool]: Complete set of forensics tools
    """
    # Core forensics tools
    dump_validator = Tool(
        name="validate_memory_dump",
        func=validate_memory_dump,
        description="Validate a memory dump file and extract basic metadata. Provide the full path to the memory dump file."
    )
    
    volatility_runner = Tool(
        name="run_volatility",
        func=run_volatility_command,
        description="Execute Volatility 3 commands for memory analysis. Command must start with 'vol'. Example: 'vol -f /path/to/dump windows.pslist'"
    )
    
    ioc_extractor = Tool(
        name="extract_iocs",
        func=extract_iocs_from_output,
        description="Use advanced LLM analysis to extract and categorize Indicators of Compromise (IOCs) from Volatility command output. Provides intelligent analysis of suspicious processes, network connections, file indicators, malware signatures, and behavioral patterns with confidence scoring."
    )
    
    class InvestigationPlanInput(BaseModel):
        dump_path: str = Field(description="Path to the memory dump file")
        investigation_goal: str = Field(default="malware analysis", description="Type of investigation (malware analysis, incident response, data exfiltration, etc.)")
        detected_os: str = Field(default="unknown", description="Detected operating system (windows, linux, mac, etc.)")
        additional_context: str = Field(default="", description="Any additional context about the incident or system")
    
    plan_generator = StructuredTool(
        name="generate_investigation_plan",
        func=generate_investigation_plan,
        args_schema=InvestigationPlanInput,
        description="Generate an intelligent, LLM-driven investigation plan for memory dump analysis. Provide dump path, investigation type (e.g., 'malware analysis', 'incident response', 'data exfiltration'), detected OS type, and any additional context. Creates adaptive plans with OS-specific Volatility commands, prioritized steps, and detailed rationale for each investigative action."
    )
    
    push_tool = Tool(
        name="send_investigation_alert",
        func=push,
        description="Send a push notification about forensics investigation progress or critical findings."
    )
    
    
    # Get supporting tools
    file_tools = get_file_tools()
    shell_tools = get_shell_tools()
    
    # Python REPL for data analysis
    python_repl = PythonREPLTool()
    
    # Combine all tools
    all_tools = [
        dump_validator,
        volatility_runner,
        ioc_extractor,
        plan_generator,
        push_tool,
        python_repl
    ] + file_tools + shell_tools
    
    return all_tools
