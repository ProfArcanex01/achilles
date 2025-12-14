"""
OS Detection node for the Memory Forensics Agent.

This module contains the OS detection functionality that runs before planning
to ensure the correct OS is identified and passed to the planner.
"""

from typing import Dict, Any
import subprocess
import shlex
from pathlib import Path

from models.state import ForensicState


def detect_os_node(state: ForensicState) -> Dict[str, Any]:
    """
    Fast OS detection before planning to ensure correct plugin selection.
    
    This node runs before the planner to detect the target OS of the memory dump.
    It tries different Volatility plugins (windows.info, linux.banner, mac.banner)
    to determine which OS the dump is from.
    
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
        
        # Try to detect OS type using Volatility
        os_detected = None
        
        # Test different OS types in order of likelihood
        os_commands = [
            ("windows", "windows.info"),
            ("linux", "linux.banner"), 
            ("macos", "mac.banner")
        ]
        
        for os_name, command in os_commands:
            try:
                print(f"   Testing {os_name}...", end=" ")
                result = subprocess.run(
                    f"vol -f {shlex.quote(dump_path)} {command}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30  # 30 second timeout per attempt
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    os_detected = os_name
                    print(f"✓")
                    print(f"✅ Detected OS: {os_detected}")
                    break  # Found working OS type
                else:
                    print(f"✗")
                    
            except subprocess.TimeoutExpired:
                print(f"⏱️ (timeout)")
                continue  # Try next OS type
            except Exception as e:
                print(f"✗ ({str(e)[:30]})")
                continue
        
        # Return detected OS or unknown
        if os_detected:
            return {"os_hint": os_detected}
        else:
            print("⚠️ Could not detect OS automatically - proceeding with 'unknown'")
            return {"os_hint": "unknown"}
            
    except Exception as e:
        print(f"❌ OS detection error: {e}")
        return {"os_hint": state.get("os_hint", "unknown")}


def fast_os_detection(dump_path: str) -> str:
    """
    Quick OS detection helper function.
    
    Args:
        dump_path: Path to memory dump
        
    Returns:
        Detected OS name or "unknown"
    """
    if not dump_path or not Path(dump_path).exists():
        return "unknown"
    
    os_commands = [
        ("windows", "windows.info"),
        ("linux", "linux.banner"), 
        ("macos", "mac.banner")
    ]
    
    for os_name, command in os_commands:
        try:
            result = subprocess.run(
                f"vol -f {shlex.quote(dump_path)} {command}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return os_name
                
        except:
            continue
    
    return "unknown"
