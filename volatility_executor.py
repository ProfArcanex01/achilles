"""
Enhanced Volatility Command Executor for Investigation Plan Execution

This module provides comprehensive command execution capabilities for memory forensics
investigations, with proper error handling, logging, and context preservation.
"""

import subprocess
import shlex
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum


class ExecutionStatus(Enum):
    """Execution status enumeration."""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    PARTIAL = "partial"


@dataclass
class CommandResult:
    """Structured result from command execution."""
    command: str
    status: ExecutionStatus
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    timestamp: datetime
    file_hash: Optional[str] = None
    output_file: Optional[str] = None
    error_message: Optional[str] = None


class VolatilityExecutor:
    """Enhanced Volatility command executor with context awareness."""
    
    def __init__(self, base_output_dir: str = "./forensics_output", timeout: int = 600, shell_path: Optional[str] = None):
        """
        Initialize the executor.
        
        Args:
            base_output_dir: Base directory for storing command outputs
            timeout: Default timeout for commands in seconds (10 minutes)
            shell_path: Shell to use for command execution (None = system default /bin/sh)
        """
        self.base_output_dir = Path(base_output_dir)
        self.timeout = timeout
        self.shell_path = shell_path
        self.execution_log = []
        
        # Command deduplication tracking
        self.executed_commands = {}  # Populated by execution node
        self.skipped_duplicates = 0  # Count of skipped duplicate commands
        
        # Create output directory structure
        self.base_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create evidence directories based on common forensics phases
        self.evidence_dirs = {
            "triage": self.base_output_dir / "01_triage",
            "processes": self.base_output_dir / "02_processes", 
            "network": self.base_output_dir / "03_network",
            "persistence": self.base_output_dir / "04_persistence",
            "memory": self.base_output_dir / "05_memory",
            "timeline": self.base_output_dir / "06_timeline",
            "iocs": self.base_output_dir / "07_iocs",
            "logs": self.base_output_dir / "logs"
        }
        
        for dir_path in self.evidence_dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)

    def execute_volatility_command(
        self, 
        command: str, 
        context: Optional[Dict[str, Any]] = None,
        save_output: bool = True,
        category: str = "general"
    ) -> CommandResult:
        """
        Execute a single Volatility command with enhanced error handling and logging.
        
        Uses safe command execution (no shell=True) to prevent injection attacks.
        
        Args:
            command: Volatility command to execute
            context: Additional context (phase, step, heuristics, etc.)
            save_output: Whether to save output to file
            category: Category for organizing output files
            
        Returns:
            CommandResult with execution details
        """
        start_time = time.time()
        timestamp = datetime.now()
        
        # Security validation
        if not self._is_safe_command(command):
            return CommandResult(
                command=command,
                status=ExecutionStatus.FAILED,
                stdout="",
                stderr="Security validation failed",
                exit_code=-1,
                execution_time=0,
                timestamp=timestamp,
                error_message="Command failed security validation"
            )
        
        # Parse command to argv (safe execution without shell)
        try:
            argv = self._parse_command_to_argv(command)
        except ValueError as e:
            return CommandResult(
                command=command,
                status=ExecutionStatus.FAILED,
                stdout="",
                stderr=f"Command parsing failed: {e}",
                exit_code=-1,
                execution_time=0,
                timestamp=timestamp,
                error_message=f"Failed to parse command: {e}"
            )
        
        try:
            print(f"🔧 Executing: {command}")
            
            # Execute command WITHOUT shell (safer)
            result = subprocess.run(
                argv,  # List of arguments, not string
                shell=False,  # SAFE: No shell interpretation
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            execution_time = time.time() - start_time
            
            # Determine status
            if result.returncode == 0:
                status = ExecutionStatus.SUCCESS
                error_message = None
            else:
                status = ExecutionStatus.FAILED
                error_message = f"Command exited with code {result.returncode}"
            
            # Save output if requested
            output_file = None
            file_hash = None
            if save_output and result.stdout.strip():
                output_file = self._save_command_output(
                    command, result.stdout, category, timestamp
                )
                file_hash = self._calculate_hash(result.stdout)
            
            # Create result
            cmd_result = CommandResult(
                command=command,
                status=status,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                execution_time=execution_time,
                timestamp=timestamp,
                file_hash=file_hash,
                output_file=str(output_file) if output_file else None,
                error_message=error_message
            )
            
            # Log execution
            self._log_execution(cmd_result, context)
            
            print(f"✅ Completed in {execution_time:.2f}s - Status: {status.value}")
            
            return cmd_result
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            cmd_result = CommandResult(
                command=command,
                status=ExecutionStatus.TIMEOUT,
                stdout="",
                stderr=f"Command timed out after {self.timeout} seconds",
                exit_code=-1,
                execution_time=execution_time,
                timestamp=timestamp,
                error_message=f"Timeout after {self.timeout}s"
            )
            self._log_execution(cmd_result, context)
            print(f"⏰ Command timed out after {self.timeout}s")
            return cmd_result
            
        except Exception as e:
            execution_time = time.time() - start_time
            cmd_result = CommandResult(
                command=command,
                status=ExecutionStatus.FAILED,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                execution_time=execution_time,
                timestamp=timestamp,
                error_message=f"Exception: {str(e)}"
            )
            self._log_execution(cmd_result, context)
            print(f"❌ Exception: {str(e)}")
            return cmd_result

    def execute_investigation_phase(
        self, 
        phase: Dict[str, Any], 
        base_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a complete investigation phase with all its steps.
        
        Args:
            phase: Phase dictionary from investigation plan
            base_context: Base context to include with all commands
            
        Returns:
            Dictionary with phase execution results
        """
        phase_name = phase.get("name", "Unknown Phase")
        phase_start = time.time()
        
        print(f"\n🎯 Starting Phase: {phase_name}")
        print("=" * 60)
        
        phase_results = {
            "phase_name": phase_name,
            "start_time": datetime.now().isoformat(),
            "steps": [],
            "summary": {}
        }
        
        # Execute each step in the phase
        for step_idx, step in enumerate(phase.get("steps", [])):
            step_name = step.get("name", f"Step {step_idx + 1}")
            print(f"\n📋 Step: {step_name}")
            
            # Prepare step context
            step_context = {
                "phase": phase_name,
                "step": step_name,
                "step_index": step_idx,
                "parse_expectations": step.get("parse_expectations"),
                "suspicion_heuristics": step.get("suspicion_heuristics"),
                "actions_on_hits": step.get("actions_on_hits"),
                "evidence_outputs": step.get("evidence_outputs")
            }
            
            if base_context:
                step_context.update(base_context)
            
            # Execute all commands in the step
            step_results = []
            for cmd in step.get("commands", []):
                # Check if this command was already executed (deduplication)
                if hasattr(self, 'executed_commands') and cmd in self.executed_commands:
                    print(f"    ⏭️  Skipping duplicate: {cmd.split()[-1]}")
                    # Create a CommandResult from cached data
                    cached = self.executed_commands[cmd]
                    result = CommandResult(
                        command=cmd,
                        status=ExecutionStatus(cached["status"]),
                        stdout="",  # Don't need to load content
                        stderr="",
                        exit_code=0 if cached["status"] == "success" else 1,
                        execution_time=0.0,
                        timestamp=datetime.now(),
                        output_file=cached["output_file"],
                        error_message=None
                    )
                    self.skipped_duplicates += 1
                else:
                    result = self.execute_volatility_command(
                        command=cmd,
                        context=step_context,
                        save_output=True,
                        category=self._get_category_from_phase(phase_name),
                    )
                    
                    # Track this command for future deduplication
                    if hasattr(self, 'executed_commands'):
                        self.executed_commands[cmd] = {
                            "status": result.status.value,
                            "output_file": result.output_file
                        }
                
                step_results.append(result)
            
            # Apply suspicion heuristics if available
            hits = self._apply_heuristics(step_results, step.get("suspicion_heuristics", []))
            
            phase_results["steps"].append({
                "step_name": step_name,
                "commands_executed": len(step_results),
                "successful_commands": len([r for r in step_results if r.status == ExecutionStatus.SUCCESS]),
                "suspicious_hits": len(hits),
                "results": [self._result_to_dict(r) for r in step_results],
                "hits": hits
            })
        
        # Phase summary
        phase_time = time.time() - phase_start
        total_commands = sum(len(step["results"]) for step in phase_results["steps"])
        successful_commands = sum(step["successful_commands"] for step in phase_results["steps"])
        total_hits = sum(step["suspicious_hits"] for step in phase_results["steps"])
        
        phase_results["summary"] = {
            "execution_time": phase_time,
            "total_commands": total_commands,
            "successful_commands": successful_commands,
            "success_rate": successful_commands / total_commands if total_commands > 0 else 0,
            "total_hits": total_hits,
            "end_time": datetime.now().isoformat()
        }
        
        print(f"\n✅ Phase Complete: {successful_commands}/{total_commands} commands successful")
        print(f"🔍 Suspicious hits found: {total_hits}")
        print(f"⏱️  Phase time: {phase_time:.2f}s")
        
        return phase_results

    def _is_safe_command(self, command: str) -> bool:
        """
        Validate command safety with strict rules.
        
        Returns True only if command is a valid Volatility command
        with no shell injection risks.
        """
        command = command.strip().lower()
        
        # Must start with vol or vol3
        if not (command.startswith('vol ') or command.startswith('vol3 ')):
            return False
        
        # Blacklist dangerous shell patterns
        dangerous_patterns = [
            '&&', '||', ';', '|', '`', '$', 
            'rm ', 'del ', 'format', 'fdisk',
            '>', '>>', 'wget', 'curl', 'nc ',
            '\n', '\r'  # No newlines
        ]
        
        return not any(pattern in command for pattern in dangerous_patterns)

    def _parse_command_to_argv(self, command: str) -> List[str]:
        """
        Parse command string into safe argv list.
        
        Converts "vol -f dump.raw windows.info" to ["vol", "-f", "dump.raw", "windows.info"]
        
        Args:
            command: Command string to parse
            
        Returns:
            List of command arguments (argv)
            
        Raises:
            ValueError: If command format is invalid
        """
        import shlex
        
        # Use shlex to properly handle quoted arguments
        try:
            parts = shlex.split(command)
        except ValueError as e:
            raise ValueError(f"Invalid command syntax: {e}")
        
        if not parts:
            raise ValueError("Empty command")
        
        # Validate first argument is vol/vol3
        if parts[0] not in ['vol', 'vol3']:
            raise ValueError(f"Command must start with 'vol' or 'vol3', got: {parts[0]}")
        
        # Validate no suspicious arguments
        for part in parts:
            # Check for shell metacharacters in individual args
            if any(char in part for char in ['&', '|', ';', '`', '$', '\n', '\r']):
                raise ValueError(f"Suspicious character in argument: {part}")
        
        return parts

    def _sanitize_command(self, command: str) -> str:
        """
        Sanitize command string (deprecated - use _parse_command_to_argv instead).
        
        Kept for backwards compatibility but prefer argv parsing.
        """
        return command.strip()

    def _save_command_output(
        self, 
        command: str, 
        output: str, 
        category: str, 
        timestamp: datetime
    ) -> Path:
        """Save command output to appropriate directory."""
        # Create safe filename from command
        cmd_part = command.split()[-1] if command.split() else "unknown"
        safe_cmd = "".join(c for c in cmd_part if c.isalnum() or c in "._-")
        
        # Get appropriate directory
        output_dir = self.evidence_dirs.get(category, self.evidence_dirs["logs"])
        
        # Create filename with timestamp
        timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp_str}_{safe_cmd}.txt"
        
        output_file = output_dir / filename
        
        # Write output
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"Command: {command}\n")
            f.write(f"Timestamp: {timestamp.isoformat()}\n")
            f.write("=" * 60 + "\n")
            f.write(output)
        
        return output_file

    def _calculate_hash(self, content: str) -> str:
        """Calculate SHA256 hash of content for integrity."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def _log_execution(self, result: CommandResult, context: Optional[Dict[str, Any]]):
        """Log command execution details."""
        log_entry = {
            "timestamp": result.timestamp.isoformat(),
            "command": result.command,
            "status": result.status.value,
            "execution_time": result.execution_time,
            "exit_code": result.exit_code,
            "output_file": result.output_file,
            "context": context
        }
        
        self.execution_log.append(log_entry)
        
        # Also save to log file
        log_file = self.evidence_dirs["logs"] / "execution_log.jsonl"
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + "\n")

    def _get_category_from_phase(self, phase_name: str) -> str:
        """Map phase name to output category."""
        phase_lower = phase_name.lower()
        
        if "triage" in phase_lower or "initial" in phase_lower:
            return "triage"
        elif "process" in phase_lower:
            return "processes"
        elif "network" in phase_lower:
            return "network"
        elif "persistence" in phase_lower:
            return "persistence"
        elif "memory" in phase_lower or "inject" in phase_lower:
            return "memory"
        elif "timeline" in phase_lower:
            return "timeline"
        else:
            return "general"

    def _apply_heuristics(self, results: List[CommandResult], heuristics: List[str]) -> List[Dict[str, Any]]:
        """Apply suspicion heuristics to command results."""
        hits = []
        
        for result in results:
            if result.status != ExecutionStatus.SUCCESS:
                continue
                
            for heuristic in heuristics:
                if self._check_heuristic(result.stdout, heuristic):
                    hits.append({
                        "command": result.command,
                        "heuristic": heuristic,
                        "timestamp": result.timestamp.isoformat(),
                        "evidence_file": result.output_file
                    })
        
        return hits

    def _check_heuristic(self, output: str, heuristic: str) -> bool:
        """Simple heuristic checking - can be enhanced with regex or AI."""
        heuristic_lower = heuristic.lower()
        output_lower = output.lower()
        
        # Simple keyword matching - in production, use more sophisticated methods
        keywords = ["unusual", "suspicious", "anomal", "inject", "hollow", "malicious"]
        return any(keyword in heuristic_lower for keyword in keywords) and len(output_lower) > 100

    def _result_to_dict(self, result: CommandResult) -> Dict[str, Any]:
        """Convert CommandResult to dictionary for serialization."""
        return {
            "command": result.command,
            "status": result.status.value,
            "exit_code": result.exit_code,
            "execution_time": result.execution_time,
            "timestamp": result.timestamp.isoformat(),
            "output_file": result.output_file,
            "file_hash": result.file_hash,
            "error_message": result.error_message,
            "output_length": len(result.stdout) if result.stdout else 0
        }

    def save_execution_summary(self) -> str:
        """Save comprehensive execution summary."""
        summary_file = self.evidence_dirs["logs"] / f"execution_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        summary = {
            "execution_start": self.execution_log[0]["timestamp"] if self.execution_log else None,
            "execution_end": datetime.now().isoformat(),
            "total_commands": len(self.execution_log),
            "successful_commands": len([log for log in self.execution_log if log["status"] == "success"]),
            "failed_commands": len([log for log in self.execution_log if log["status"] == "failed"]),
            "timeout_commands": len([log for log in self.execution_log if log["status"] == "timeout"]),
            "total_execution_time": sum(log["execution_time"] for log in self.execution_log),
            "evidence_directories": {k: str(v) for k, v in self.evidence_dirs.items()},
            "detailed_log": self.execution_log
        }
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        return str(summary_file)


# Convenience function for simple usage
def execute_volatility_command(command: str, output_dir: str = "./forensics_output", shell_path: Optional[str] = None) -> CommandResult:
    """
    Simple function to execute a single Volatility command.
    
    Args:
        command: Volatility command to execute
        output_dir: Directory to save outputs
        
    Returns:
        CommandResult with execution details
    """
    executor = VolatilityExecutor(base_output_dir=output_dir, shell_path=shell_path)
    return executor.execute_volatility_command(command)


# Example usage function
def execute_investigation_plan(plan: Dict[str, Any], output_dir: str = "./forensics_output") -> Dict[str, Any]:
    """
    Execute a complete investigation plan.
    
    Args:
        plan: Investigation plan dictionary
        output_dir: Base output directory
        
    Returns:
        Comprehensive execution results
    """
    executor = VolatilityExecutor(base_output_dir=output_dir)
    
    # Execute global triage first
    print("🚀 Starting Investigation Plan Execution")
    print("=" * 80)
    
    results = {
        "plan_version": plan.get("plan_version"),
        "execution_start": datetime.now().isoformat(),
        "global_triage": [],
        "phases": [],
        "summary": {}
    }
    
    # Execute global triage
    if "global_triage" in plan:
        print("\n🎯 Executing Global Triage")
        for triage_step in plan["global_triage"]:
            for cmd in triage_step.get("commands", []):
                result = executor.execute_volatility_command(
                    command=cmd,
                    context={"type": "global_triage", "step": triage_step.get("name")},
                    category="triage"
                )
                results["global_triage"].append(executor._result_to_dict(result))
    
    # Execute main phases
    if "os_workflows" in plan and "phases" in plan["os_workflows"]:
        for phase in plan["os_workflows"]["phases"]:
            phase_result = executor.execute_investigation_phase(phase)
            results["phases"].append(phase_result)
    
    # Generate summary
    results["execution_end"] = datetime.now().isoformat()
    results["summary_file"] = executor.save_execution_summary()
    
    print(f"\n🎉 Investigation Plan Execution Complete!")
    print(f"📁 Evidence saved to: {executor.base_output_dir}")
    print(f"📊 Summary saved to: {results['summary_file']}")
    
    return results
