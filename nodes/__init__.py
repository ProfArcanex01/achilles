"""
Nodes package for the Memory Forensics Agent.

This package contains all the individual workflow nodes that make up
the forensics investigation pipeline.
"""

from nodes.planner import planner_node, validate_investigation_plan, create_fallback_plan
from nodes.evaluator import evaluator_node, route_based_on_evaluation
from nodes.execution import execution_node, route_after_execution
from nodes.os_detection import detect_os_node, fast_os_detection

__all__ = [
    # OS Detection nodes
    'detect_os_node',
    'fast_os_detection',
    
    # Planner nodes
    'planner_node',
    'validate_investigation_plan', 
    'create_fallback_plan',
    
    # Evaluator nodes
    'evaluator_node',
    'route_based_on_evaluation',
    
    # Execution nodes
    'execution_node',
    'route_after_execution'
]
