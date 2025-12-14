"""
Configuration settings for the Memory Forensics Agent.

This module contains configuration classes that centralize all configurable
parameters and support environment variable overrides.
"""

import os
from dataclasses import dataclass
from typing import Optional, Union
from pathlib import Path

@dataclass
class ForensicsConfig:
    """Configuration class for Memory Forensics Agent settings."""
    
    # Analysis settings
    max_chunk_tokens: int = 20000  # Reduced to stay under rate limits
    max_retries: int = 5
    rate_limit_delay: float = 1.0  # Base delay for rate limiting
    max_rate_limit_delay: float = 60.0  # Maximum delay
    chunk_concurrency: int = 2  # Max concurrent chunk analyses (2 = safe for most tiers)
    
    # LLM settings
    llm_timeout: int = 120
    llm_temperature: float = 0.0
    llm_max_tokens: int = 4000
    
    # Models
    planner_model: str = "gpt-4o"
    evaluator_model: str = "gpt-4o-mini" 
    analyzer_model: str = "gpt-4o"
    fallback_analyzer_model: str = "gpt-4o-mini"  # Fallback for rate limiting


    # Evidence storage
    evidence_base_dir: Union[str, Path] = str(Path(__file__).parent.parent / "forensics_evidence")
    
    # Execution settings
    shell_path: Optional[str] = None  # Shell for command execution (None = system default /bin/sh)
    volatility_timeout: int = 600  # Timeout for volatility commands in seconds
    
    # Thresholds for deeper analysis
    threat_score_threshold: float = 7.0
    confidence_threshold: float = 0.8
    
    @classmethod
    def from_env(cls) -> 'ForensicsConfig':
        """Load configuration from environment variables."""
        return cls(
            max_chunk_tokens=int(os.getenv('FORENSICS_MAX_CHUNK_TOKENS', 20000)),
            max_retries=int(os.getenv('FORENSICS_MAX_RETRIES', 5)),
            rate_limit_delay=float(os.getenv('FORENSICS_RATE_LIMIT_DELAY', 1.0)),
            max_rate_limit_delay=float(os.getenv('FORENSICS_MAX_RATE_LIMIT_DELAY', 60.0)),
            chunk_concurrency=int(os.getenv('FORENSICS_CHUNK_CONCURRENCY', 2)),
            llm_timeout=int(os.getenv('FORENSICS_LLM_TIMEOUT', 120)),
            llm_temperature=float(os.getenv('FORENSICS_LLM_TEMPERATURE', 0.0)),
            llm_max_tokens=int(os.getenv('FORENSICS_LLM_MAX_TOKENS', 4000)),
            planner_model=os.getenv('FORENSICS_PLANNER_MODEL', 'gpt-4o'),
            evaluator_model=os.getenv('FORENSICS_EVALUATOR_MODEL', 'gpt-4o-mini'),
            analyzer_model=os.getenv('FORENSICS_ANALYZER_MODEL', 'gpt-4o'),
            fallback_analyzer_model=os.getenv('FORENSICS_FALLBACK_ANALYZER_MODEL', 'gpt-4o-mini'),
            evidence_base_dir=os.getenv('FORENSICS_EVIDENCE_DIR', str(Path(__file__).parent.parent / "forensics_evidence")),
            shell_path=os.getenv('FORENSICS_SHELL_PATH'),  # e.g., '/bin/zsh', '/bin/bash'
            volatility_timeout=int(os.getenv('FORENSICS_VOLATILITY_TIMEOUT', 600)),
            threat_score_threshold=float(os.getenv('FORENSICS_THREAT_THRESHOLD', 7.0)),
            confidence_threshold=float(os.getenv('FORENSICS_CONFIDENCE_THRESHOLD', 0.8))
        )


# Default configuration instance
DEFAULT_CONFIG = ForensicsConfig()
