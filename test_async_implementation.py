#!/usr/bin/env python3
"""
Quick test script to verify async parallel chunk implementation.
Tests configuration loading and basic async functionality.
"""

import sys
import asyncio
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_configuration():
    """Test that configuration loads correctly."""
    print("🧪 Testing configuration loading...")
    
    from config import ForensicsConfig
    
    # Test default config
    config = ForensicsConfig()
    assert hasattr(config, 'chunk_concurrency'), "Missing chunk_concurrency attribute"
    assert config.chunk_concurrency == 2, f"Default concurrency should be 2, got {config.chunk_concurrency}"
    print(f"   ✅ Default concurrency: {config.chunk_concurrency}")
    
    # Test custom config
    custom_config = ForensicsConfig(chunk_concurrency=3)
    assert custom_config.chunk_concurrency == 3, f"Custom concurrency should be 3, got {custom_config.chunk_concurrency}"
    print(f"   ✅ Custom concurrency: {custom_config.chunk_concurrency}")
    
    # Test from_env
    import os
    os.environ['FORENSICS_CHUNK_CONCURRENCY'] = '4'
    env_config = ForensicsConfig.from_env()
    assert env_config.chunk_concurrency == 4, f"Env concurrency should be 4, got {env_config.chunk_concurrency}"
    print(f"   ✅ Environment concurrency: {env_config.chunk_concurrency}")
    
    print("✅ Configuration tests passed!\n")

def test_imports():
    """Test that all imports work correctly."""
    print("🧪 Testing imports...")
    
    try:
        from forensics_agent import MemoryForensicsAgent
        print("   ✅ forensics_agent imported")
        
        from config import ForensicsConfig
        print("   ✅ config imported")
        
        import asyncio
        import random
        print("   ✅ asyncio and random imported")
        
        print("✅ Import tests passed!\n")
        return True
    except Exception as e:
        print(f"   ❌ Import failed: {e}\n")
        return False

def test_agent_initialization():
    """Test that agent initializes with new config."""
    print("🧪 Testing agent initialization...")
    
    from forensics_agent import MemoryForensicsAgent
    from config import ForensicsConfig
    
    # Default initialization
    agent = MemoryForensicsAgent()
    assert agent.config.chunk_concurrency == 2, f"Agent should have concurrency=2, got {agent.config.chunk_concurrency}"
    print(f"   ✅ Agent initialized with default concurrency: {agent.config.chunk_concurrency}")
    
    # Custom config initialization
    custom_config = ForensicsConfig(chunk_concurrency=3)
    custom_agent = MemoryForensicsAgent(config=custom_config)
    assert custom_agent.config.chunk_concurrency == 3, f"Agent should have concurrency=3, got {custom_agent.config.chunk_concurrency}"
    print(f"   ✅ Agent initialized with custom concurrency: {custom_agent.config.chunk_concurrency}")
    
    print("✅ Agent initialization tests passed!\n")

def test_async_methods_exist():
    """Test that async methods are defined."""
    print("🧪 Testing async method definitions...")
    
    from forensics_agent import MemoryForensicsAgent
    import inspect
    
    agent = MemoryForensicsAgent()
    
    # Check for async methods
    assert hasattr(agent, '_analyze_chunks_parallel'), "Missing _analyze_chunks_parallel method"
    assert asyncio.iscoroutinefunction(agent._analyze_chunks_parallel), "_analyze_chunks_parallel should be async"
    print("   ✅ _analyze_chunks_parallel is async")
    
    assert hasattr(agent, '_analyze_single_chunk_async'), "Missing _analyze_single_chunk_async method"
    assert asyncio.iscoroutinefunction(agent._analyze_single_chunk_async), "_analyze_single_chunk_async should be async"
    print("   ✅ _analyze_single_chunk_async is async")
    
    print("✅ Async method tests passed!\n")

async def test_semaphore_creation():
    """Test that semaphore can be created with config value."""
    print("🧪 Testing semaphore creation...")
    
    from forensics_agent import MemoryForensicsAgent
    from config import ForensicsConfig
    
    config = ForensicsConfig(chunk_concurrency=2)
    agent = MemoryForensicsAgent(config=config)
    
    # Create a semaphore like in the code
    semaphore = asyncio.Semaphore(agent.config.chunk_concurrency)
    
    # Test acquiring and releasing
    async with semaphore:
        print(f"   ✅ Semaphore acquired (concurrency={agent.config.chunk_concurrency})")
    
    print("   ✅ Semaphore released")
    print("✅ Semaphore tests passed!\n")

async def test_jitter():
    """Test random jitter generation."""
    print("🧪 Testing jitter generation...")
    
    import random
    
    # Generate 10 jitter values
    jitters = [random.uniform(0.5, 1.5) for _ in range(10)]
    
    # Check all are in range
    assert all(0.5 <= j <= 1.5 for j in jitters), "Some jitter values out of range"
    print(f"   ✅ Generated 10 jitter values: {[f'{j:.2f}' for j in jitters[:5]]}...")
    
    # Check they're different (randomness)
    assert len(set(jitters)) > 5, "Jitter values should be random"
    print("   ✅ Jitter values are randomized")
    
    print("✅ Jitter tests passed!\n")

def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("Async Parallel Chunk Analysis - Verification Tests")
    print("=" * 60)
    print()
    
    try:
        # Synchronous tests
        test_configuration()
        if not test_imports():
            print("❌ Critical import failure - stopping tests")
            return False
        
        test_agent_initialization()
        test_async_methods_exist()
        
        # Async tests
        asyncio.run(test_semaphore_creation())
        asyncio.run(test_jitter())
        
        # Summary
        print("=" * 60)
        print("🎉 All tests passed successfully!")
        print("=" * 60)
        print()
        print("Next steps:")
        print("  1. Test with actual memory dump:")
        print("     python run_forensics.py /path/to/dump.raw")
        print()
        print("  2. Monitor for parallel chunk processing:")
        print("     Look for: 'Performing parallel chunked analysis'")
        print()
        print("  3. Tune concurrency if needed:")
        print("     export FORENSICS_CHUNK_CONCURRENCY=3")
        print()
        
        return True
        
    except AssertionError as e:
        print(f"❌ Test failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
