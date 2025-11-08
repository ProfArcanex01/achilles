"""
Utilities package for the Memory Forensics Agent.

This package contains utility functions for tokens, validation, messages,
and other common operations used throughout the system.
"""

from utils.tokens import count_tokens, split_text_by_tokens, estimate_response_tokens
from utils.validation import validate_plan_quality, is_reasonable_command, VolatilityCommandValidator
from utils.messages import (
    build_planner_system_message,
    build_planner_user_message,
    build_evaluator_system_message,
    build_evaluator_user_message,
    build_analysis_system_message,
    build_analysis_user_message,
    build_deeper_analysis_system_message,
    build_deeper_analysis_user_message
)

__all__ = [
    # Token utilities
    'count_tokens',
    'split_text_by_tokens', 
    'estimate_response_tokens',
    
    # Validation utilities
    'validate_plan_quality',
    'is_reasonable_command',
    'VolatilityCommandValidator',
    
    # Message builders
    'build_planner_system_message',
    'build_planner_user_message',
    'build_evaluator_system_message',
    'build_evaluator_user_message',
    'build_analysis_system_message',
    'build_analysis_user_message',
    'build_deeper_analysis_system_message',
    'build_deeper_analysis_user_message'
]
