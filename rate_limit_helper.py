#!/usr/bin/env python3
"""
Rate Limiting Helper for Memory Forensics Agent

This script provides utilities to help manage OpenAI rate limits during analysis.
"""

import os
import time
from typing import Dict, Any

def set_rate_limit_env_vars():
    """Set environment variables for optimal rate limiting."""
    env_vars = {
        'FORENSICS_MAX_CHUNK_TOKENS': '15000',  # Smaller chunks
        'FORENSICS_RATE_LIMIT_DELAY': '2.0',    # 2 second base delay
        'FORENSICS_MAX_RATE_LIMIT_DELAY': '30.0', # Max 30 second delay
        'FORENSICS_MAX_RETRIES': '5',           # More retries
        'FORENSICS_ANALYZER_MODEL': 'gpt-4o-mini', # Use cheaper model
    }
    
    for key, value in env_vars.items():
        os.environ[key] = value
        print(f"Set {key}={value}")

def check_rate_limit_status():
    """Check current rate limit configuration."""
    from config.settings import DEFAULT_CONFIG
    
    print("Current Rate Limiting Configuration:")
    print(f"  Max Chunk Tokens: {DEFAULT_CONFIG.max_chunk_tokens:,}")
    print(f"  Max Retries: {DEFAULT_CONFIG.max_retries}")
    print(f"  Rate Limit Delay: {DEFAULT_CONFIG.rate_limit_delay}s")
    print(f"  Max Rate Limit Delay: {DEFAULT_CONFIG.max_rate_limit_delay}s")
    print(f"  Analyzer Model: {DEFAULT_CONFIG.analyzer_model}")
    print(f"  Fallback Model: {DEFAULT_CONFIG.fallback_analyzer_model}")

def estimate_analysis_time(total_tokens: int, chunk_size: int = 15000) -> Dict[str, Any]:
    """Estimate analysis time based on token count and rate limits."""
    num_chunks = (total_tokens + chunk_size - 1) // chunk_size  # Ceiling division
    
    # Conservative estimates
    time_per_chunk = 10  # seconds (including API call + delay)
    total_time = num_chunks * time_per_chunk
    
    return {
        "total_tokens": total_tokens,
        "estimated_chunks": num_chunks,
        "estimated_time_seconds": total_time,
        "estimated_time_minutes": total_time / 60,
        "estimated_time_hours": total_time / 3600
    }

if __name__ == "__main__":
    print("🔧 Memory Forensics Agent - Rate Limiting Helper")
    print("=" * 50)
    
    # Set optimal environment variables
    print("\n1. Setting optimal rate limiting environment variables...")
    set_rate_limit_env_vars()
    
    # Check current configuration
    print("\n2. Current configuration:")
    check_rate_limit_status()
    
    # Example time estimation
    print("\n3. Time estimation examples:")
    examples = [50000, 100000, 200000, 500000]
    for tokens in examples:
        estimate = estimate_analysis_time(tokens)
        print(f"  {tokens:,} tokens: ~{estimate['estimated_chunks']} chunks, "
              f"{estimate['estimated_time_minutes']:.1f} minutes")
    
    print("\n✅ Rate limiting configuration optimized!")
    print("\n💡 Tips:")
    print("  - Use smaller chunk sizes for faster processing")
    print("  - Consider using gpt-4o-mini for analysis (cheaper, higher rate limits)")
    print("  - The system will automatically retry with exponential backoff")
    print("  - Failed chunks can be resumed on subsequent runs")
