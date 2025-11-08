"""
Schema definitions for the Memory Forensics Agent.

This module contains the JSON schema for Volatility 3 investigation plans
and other validation schemas used throughout the system.
"""

from typing import Dict, Any

VOL3_PLAN_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Volatility3 Memory Investigation Plan",
    "type": "object",
    "required": [
        "plan_version",
        "inputs",
        "goals",
        "constraints",
        "global_triage",
        "os_workflows",
        "ioc_correlation",
        "artifact_preservation",
        "reporting"
    ],
    "properties": {
        "plan_version": {"type": "string"},
        "inputs": {
            "type": "object",
            "required": ["dump_path"],
            "properties": {
                "dump_path": {"type": "string"},
                "os_hint": {"type": "string", "enum": ["windows", "linux", "macos"]},
                "volatility_path": {"type": "string"},
                "ioc_set": {
                    "type": "object",
                    "properties": {
                        "hashes": {"type": "array", "items": {"type": "string"}},
                        "domains": {"type": "array", "items": {"type": "string"}},
                        "ips": {"type": "array", "items": {"type": "string"}},
                        "yara_rules": {"type": "array", "items": {"type": "string"}}
                    }
                }
            }
        },
        "goals": {"type": "array", "items": {"type": "string"}},
        "constraints": {"type": "array", "items": {"type": "string"}},
        "global_triage": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "commands", "parse_expectations"],
                "properties": {
                    "name": {"type": "string"},
                    "commands": {"type": "array", "items": {"type": "string"}},
                    "parse_expectations": {"type": "string"},
                    "success_criteria": {"type": "string"}
                }
            }
        },
        "os_workflows": {
            "type": "object",
            "required": ["phases"],
            "properties": {
                "phases": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "steps"],
                        "properties": {
                            "name": {"type": "string"},
                            "steps": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["name", "commands", "parse_expectations"],
                                    "properties": {
                                        "name": {"type": "string"},
                                        "commands": {"type": "array", "items": {"type": "string"}},
                                        "parse_expectations": {"type": "string"},
                                        "suspicion_heuristics": {"type": "array", "items": {"type": "string"}},
                                        "actions_on_hits": {"type": "array", "items": {"type": "string"}},
                                        "evidence_outputs": {"type": "array", "items": {"type": "string"}}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "ioc_correlation": {
            "type": "object",
            "required": ["hashing", "network", "yara", "scoring"],
            "properties": {
                "hashing": {"type": "array", "items": {"type": "string"}},
                "network": {"type": "array", "items": {"type": "string"}},
                "yara": {"type": "array", "items": {"type": "string"}},
                "scoring": {
                    "type": "object",
                    "required": ["process", "module", "persistence_item"],
                    "properties": {
                        "process": {"type": "string"},
                        "module": {"type": "string"},
                        "persistence_item": {"type": "string"}
                    }
                }
            }
        },
        "artifact_preservation": {
            "type": "object",
            "required": ["directory_structure", "chain_of_custody"],
            "properties": {
                "directory_structure": {"type": "array", "items": {"type": "string"}},
                "chain_of_custody": {"type": "array", "items": {"type": "string"}}
            }
        },
        "reporting": {
            "type": "object",
            "required": ["executive_summary", "technical_appendix", "export_formats"],
            "properties": {
                "executive_summary": {"type": "array", "items": {"type": "string"}},
                "technical_appendix": {"type": "array", "items": {"type": "string"}},
                "export_formats": {"type": "array", "items": {"type": "string", "enum": ["json", "csv", "pdf", "md"]}}
            }
        }
    }
}
