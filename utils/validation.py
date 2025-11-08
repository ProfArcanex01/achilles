"""
Validation utilities for the Memory Forensics Agent.

This module contains functions for validating investigation plans,
commands, and ensuring quality standards are met.
"""

from typing import Dict, Any, List
import re


def validate_plan_quality(plan: Dict[str, Any], skip_command_validation: bool = False) -> None:
    """
    Validate the quality and comprehensiveness of the investigation plan.
    
    Args:
        plan: The parsed investigation plan dictionary
        skip_command_validation: If True, skip command validation entirely
    
    Raises:
        ValueError: If the plan fails quality checks
    """
    errors = []
    
    # Check goals comprehensiveness (relaxed for minimal prompts)
    goals = plan.get("goals", [])
    if len(goals) < 2:
        errors.append(f"Insufficient goals: {len(goals)} (minimum 2 required)")
    
    # Check global triage (relaxed for minimal prompts)
    global_triage = plan.get("global_triage", [])
    if len(global_triage) < 1:
        errors.append(f"No global triage steps: {len(global_triage)} (minimum 1 required)")
    
    # Validate volatility commands in global triage (very permissive)
    if not skip_command_validation:
        for step in global_triage:
            commands = step.get("commands", [])
            for cmd in commands:
                # Only reject obviously invalid commands
                if not is_reasonable_command(cmd):
                    errors.append(f"Invalid volatility command in global triage: {cmd}")
    
    # Check OS workflows
    os_workflows = plan.get("os_workflows", {})
    phases = os_workflows.get("phases", [])
    
    # Check for essential phase coverage (more flexible matching)
    required_phase_keywords = [
        ["triage", "initial", "baseline"],
        ["process", "execution"],
        ["network", "connection", "communication"],
        ["persistence", "autostart", "startup"],
        ["memory", "artifact", "injection"],
        ["timeline", "temporal", "chronological"]
    ]
    
    phase_names = [phase.get("name", "").lower() for phase in phases]
    missing_phases = []
    
    for i, keyword_group in enumerate(required_phase_keywords):
        if not any(any(keyword in name for keyword in keyword_group) for name in phase_names):
            phase_type = ["Triage", "Process", "Network", "Persistence", "Memory", "Timeline"][i]
            missing_phases.append(f"{phase_type} analysis (keywords: {keyword_group})")
    
    if missing_phases:
        errors.append(f"Missing required phases: {missing_phases}")
    
    # Validate each phase has sufficient steps (relaxed for minimal prompts)
    for phase in phases:
        steps = phase.get("steps", [])
        if len(steps) < 1:
            errors.append(f"Phase '{phase.get('name')}' has no steps: {len(steps)} (minimum 1)")
        
        # Validate volatility commands in each step
        for step in steps:
            commands = step.get("commands", [])
            if not commands:
                errors.append(f"Step '{step.get('name')}' in phase '{phase.get('name')}' has no commands")
            
            if not skip_command_validation:
                for cmd in commands:
                    # Very permissive command validation
                    if not is_reasonable_command(cmd):
                        errors.append(f"Invalid volatility command: {cmd}")
            
            # Check for required fields (with flexible validation)
            step_name = step.get("name", "Unknown")
            
            if not step.get("parse_expectations"):
                errors.append(f"Step '{step_name}' missing parse_expectations")
            
            # Suspicion heuristics are critical for analysis steps
            if not step.get("suspicion_heuristics") and any(keyword in step_name.lower() 
                for keyword in ["analysis", "investigation", "detection", "hunting"]):
                errors.append(f"Analysis step '{step_name}' missing suspicion_heuristics")
    
    # Check IOC correlation
    ioc_correlation = plan.get("ioc_correlation", {})
    required_ioc_sections = ["hashing", "network", "yara", "scoring"]
    for section in required_ioc_sections:
        if section not in ioc_correlation:
            errors.append(f"Missing IOC correlation section: {section}")
        elif section == "scoring":
            scoring = ioc_correlation[section]
            required_scoring = ["process", "module", "persistence_item"]
            for score_type in required_scoring:
                if score_type not in scoring:
                    errors.append(f"Missing scoring criteria: {score_type}")
    
    # Check artifact preservation
    artifact_preservation = plan.get("artifact_preservation", {})
    if not artifact_preservation.get("directory_structure"):
        errors.append("Missing directory structure for artifact preservation")
    if not artifact_preservation.get("chain_of_custody"):
        errors.append("Missing chain of custody procedures")
    
    # Check reporting structure
    reporting = plan.get("reporting", {})
    if not reporting.get("executive_summary"):
        errors.append("Missing executive summary requirements")
    if not reporting.get("technical_appendix"):
        errors.append("Missing technical appendix requirements")
    
    export_formats = reporting.get("export_formats", [])
    if not export_formats:
        errors.append("No export formats specified")
    elif len(export_formats) < 2:
        # Warning but not error for single format
        pass
    
    if errors:
        raise ValueError("Plan quality validation failed:\n" + "\n".join(f"- {error}" for error in errors))


def is_reasonable_command(command: str) -> bool:
    """
    Very permissive validation that accepts almost any reasonable command.
    
    Args:
        command: The command string to validate
        
    Returns:
        bool: True if command appears reasonable, False otherwise
    """
    if not command or not isinstance(command, str):
        return False
    
    command = command.strip()
    
    # Empty commands are not valid
    if not command or command.isspace():
        return False
    
    # Reject obviously invalid patterns only
    invalid_patterns = [
        "PLACEHOLDER", "TODO", "FIXME", "INSERT_", "CHANGE_THIS", 
        "REPLACE_ME", "YOUR_", "EXAMPLE_", "SAMPLE_"
    ]
    
    command_upper = command.upper()
    for pattern in invalid_patterns:
        if pattern in command_upper:
            return False
    
    # Accept anything that looks like a command or plugin name
    # - Has letters (not just numbers/symbols)
    # - Reasonable length
    # - Not just whitespace
    if len(command) >= 2 and any(c.isalpha() for c in command):
        return True
    
    return False


class VolatilityCommandValidator:
    """Enhanced command validation with plugin checking."""
    
    VALID_PLUGINS = {
        'windows': [
            'pslist', 'pstree', 'psxview', 'netscan', 'netstat', 'malfind',
            'handles', 'dlllist', 'cmdline', 'filescan', 'mutantscan',
            'svcscan', 'modules', 'modscan', 'ssdt', 'driverscan',
            'devicetree', 'privs', 'envars', 'verinfo', 'enumfunc',
            'apihooks', 'idt', 'gdt', 'threads', 'thrdscan', 'callbacks',
            'driverirp', 'unloadedmodules', 'atoms', 'atomscan',
            'clipboard', 'consoles', 'cmdscan', 'shellbags', 'shimcache',
            'userassist', 'registry.printkey', 'registry.hivelist',
            'registry.hivescan', 'hashdump', 'lsadump', 'cachedump'
        ],
        'linux': [
            'bash', 'mount', 'lsmod', 'lsof', 'pslist', 'pstree',
            'netstat', 'ifconfig', 'arp', 'route', 'check_afinfo',
            'check_creds', 'check_fop', 'check_idt', 'check_syscall',
            'check_modules', 'check_tty', 'keyboard_notifiers',
            'check_inline_kernel', 'hidden_modules', 'truecrypt_master',
            'truecrypt_passphrase', 'find_file', 'linux_enumerate_files'
        ],
        'mac': [
            'mount', 'bash', 'pslist', 'pstree', 'netstat', 'lsof',
            'ifconfig', 'arp', 'route', 'check_syscall', 'check_mig',
            'check_trap_table', 'dmesg', 'machine_info', 'version',
            'truecrypt_master', 'truecrypt_passphrase', 'find_file'
        ]
    }
    
    def validate_command(self, command: str, os_hint: str) -> Dict[str, Any]:
        """
        Validate command with detailed feedback.
        
        Args:
            command: Command to validate
            os_hint: Target operating system
            
        Returns:
            Validation result dictionary
        """
        result = {
            "valid": False,
            "issues": [],
            "suggestions": []
        }
        
        if not command or not isinstance(command, str):
            result["issues"].append("Command is empty or not a string")
            return result
        
        command = command.strip()
        
        # Basic syntax check
        if not command.startswith("vol"):
            result["issues"].append("Command should start with 'vol' or 'vol3'")
            result["suggestions"].append("Use: vol -f <dump_file> <plugin>")
        
        # Check for obvious placeholders
        if not is_reasonable_command(command):
            result["issues"].append("Command contains placeholder text")
        
        # Plugin validation
        if os_hint and os_hint.lower() in self.VALID_PLUGINS:
            valid_plugins = self.VALID_PLUGINS[os_hint.lower()]
            
            # Extract plugin name from command
            parts = command.split()
            if len(parts) >= 3:  # vol -f dump_file plugin_name
                plugin_candidate = parts[2].split('.')[0]  # Handle nested plugins like windows.pslist
                
                if plugin_candidate not in valid_plugins:
                    result["issues"].append(f"Plugin '{plugin_candidate}' not valid for {os_hint}")
                    similar_plugins = [p for p in valid_plugins if plugin_candidate.lower() in p.lower()]
                    if similar_plugins:
                        result["suggestions"].append(f"Similar plugins: {', '.join(similar_plugins[:3])}")
        
        # If no major issues, mark as valid
        if not result["issues"]:
            result["valid"] = True
        
        return result
