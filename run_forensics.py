#!/usr/bin/env python3
"""
Entry point script for the Memory Forensics Agent.

This script properly sets up the Python path and runs the forensics agent.
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path to allow absolute imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Now we can import and run the forensics agent
if __name__ == "__main__":
    try:
        import asyncio
        from forensics_agent import main
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error running forensics agent: {e}")
        sys.exit(1)
