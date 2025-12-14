"""
OS Detection node for the Memory Forensics Agent.

This module contains the OS detection functionality that runs before planning
to ensure the correct OS is identified and passed to the planner.

REFACTORED: Now uses the existing validate_memory_dump function from forensics_tools
to avoid code duplication.
"""

from typing import Dict, Any
import re
from pathlib import Path

from models.state import ForensicState


def detect_os_node(state: ForensicState) -> Dict[str, Any]:
    """
    Fast OS detection before planning to ensure correct plugin selection.
    
    This node runs before the planner to detect the target OS of the memory dump.
    It uses the existing validate_memory_dump function and extracts OS info.
    
    Args:
        state: Current forensic state containing memory_dump_path
        
    Returns:
        Dictionary with detected os_hint
    """
    try:
        # Get memory dump path
        dump_path = state.get("memory_dump_path")
        current_os_hint = state.get("os_hint")
        
        # If user already provided OS hint and it's valid, use it
        if current_os_hint and current_os_hint.lower() in ["windows", "linux", "macos", "mac"]:
            normalized_os = current_os_hint.lower()
            if normalized_os == "mac":
                normalized_os = "macos"
            print(f"✅ Using user-provided OS hint: {normalized_os}")
            return {"os_hint": normalized_os}
        
        # Validate dump path exists
        if not dump_path:
            print("⚠️ No memory dump path provided - skipping OS detection")
            return {"os_hint": "unknown"}
        
        path = Path(dump_path)
        if not path.exists():
            print(f"⚠️ Memory dump not found at {dump_path} - skipping OS detection")
            return {"os_hint": "unknown"}
        
        print(f"🔍 Detecting OS type for: {dump_path}")
        
        # Use the existing validate_memory_dump function
        # Import here to avoid circular dependencies
        from forensics_tools import validate_memory_dump
        
        validation_result = validate_memory_dump(dump_path)
        
        # Parse the result to extract OS
        os_detected = extract_os_from_validation(validation_result)
        
        # Return detected OS or unknown
        if os_detected and os_detected != "unknown":
            print(f"✅ Detected OS: {os_detected}")
            return {"os_hint": os_detected}
        else:
            print("⚠️ Could not detect OS automatically - proceeding with 'unknown'")
            return {"os_hint": "unknown"}
            
    except Exception as e:
        print(f"❌ OS detection error: {e}")
        return {"os_hint": state.get("os_hint", "unknown")}


def extract_os_from_validation(validation_result: str) -> str:
    """
    Extract OS type from validate_memory_dump result string.
    
    Args:
        validation_result: String result from validate_memory_dump
        
    Returns:
        OS name ("windows", "linux", "macos") or "unknown"
    """
    if not validation_result or not isinstance(validation_result, str):
        return "unknown"
    
    # Look for "OS Type: <os_name>" pattern
    os_match = re.search(r'OS Type:\s*(\w+)', validation_result, re.IGNORECASE)
    if os_match:
        os_name = os_match.group(1).lower()
        # Normalize "mac" to "macos"
        if os_name == "mac":
            os_name = "macos"
        return os_name
    
    # Fallback: Check for OS keywords in the result
    result_lower = validation_result.lower()
    if "windows" in result_lower:
        return "windows"
    elif "linux" in result_lower:
        return "linux"
    elif "mac" in result_lower or "macos" in result_lower:
        return "macos"
    
    return "unknown"


def fast_os_detection(dump_path: str) -> str:
    """
    Quick OS detection helper function.
    
    This is a convenience function that wraps validate_memory_dump
    for quick standalone OS detection.
    
    Args:
        dump_path: Path to memory dump
        
    Returns:
        Detected OS name or "unknown"
    """
    if not dump_path or not Path(dump_path).exists():
        return "unknown"
    
    try:
        from forensics_tools import validate_memory_dump
        result = validate_memory_dump(dump_path)
        return extract_os_from_validation(result)
    except Exception:
        return "unknown"
