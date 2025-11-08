"""
Main Memory Forensics Agent - Clean Modular Entry Point

This is the main entry point for the Memory Forensics Agent system.
It integrates all the modular components into a cohesive investigation workflow.
"""

import asyncio
from typing import Dict, Any, List

from langchain_openai import ChatOpenAI
from langchain_community.tools import ShellTool
from langgraph.graph import StateGraph, START, END
from dotenv import load_dotenv

# Import our modular components
from models import ForensicState, EvaluatorOutput, AnalysisOutput
from config import ForensicsConfig
from nodes import (
    planner_node, validate_investigation_plan,
    evaluator_node, route_based_on_evaluation,
    execution_node, route_after_execution
)
from engines import DeeperAnalysisEngine
from utils import count_tokens
from forensics_tools import forensics_tools

load_dotenv(override=True)


class MemoryForensicsAgent:
    """
    Clean, modular Memory Forensics Agent.
    
    This agent orchestrates the complete memory forensics investigation workflow
    using extracted modular components for maintainability and flexibility.
    """
    
    def __init__(self, config: ForensicsConfig = None):
        """
        Initialize the Memory Forensics Agent.
        
        Args:
            config: Configuration object (uses defaults if None)
        """
        self.config = config or ForensicsConfig.from_env()
        
        # LLM instances will be initialized in setup_llm()
        self.planner_llm = None
        self.evaluator_llm = None  
        self.analyzer_llm = None
        self.graph = None
        self.tools = None
        
        # Initialize specialized analysis engine
        self.deeper_analysis_engine = DeeperAnalysisEngine(self, self.config)
        
    async def setup_llm(self):
        """Initialize all LLM instances and tools."""
        # Get forensics tools
        self.tools = await forensics_tools()
        
        planning_tools = [t for t in self.tools if getattr(t, "name", "") in {}]
        deeper_tools = [ShellTool()]
        
        # Initialize LLMs with configuration
        self.planner_llm = ChatOpenAI(
            model=self.config.planner_model,
            temperature=self.config.llm_temperature,
            max_tokens=self.config.llm_max_tokens,
            timeout=self.config.llm_timeout,
            max_retries=1,
        ).bind_tools(planning_tools)
        
        self.evaluator_llm = ChatOpenAI(
            model=self.config.evaluator_model,
            temperature=self.config.llm_temperature
        ).with_structured_output(EvaluatorOutput, method="function_calling")
        
        self.analyzer_llm = ChatOpenAI(
            model=self.config.analyzer_model,
            temperature=0.1,
            max_tokens=2000
        ).with_structured_output(AnalysisOutput, method="function_calling")
        
        await self.build_graph()
        
    async def build_graph(self):
        """Build the investigation workflow graph."""
        graph_builder = StateGraph(ForensicState)
        
        # Register nodes with LLM binding
        graph_builder.add_node("planner", self._planner_wrapper)
        graph_builder.add_node("validate_plan", validate_investigation_plan)
        graph_builder.add_node("evaluator", self._evaluator_wrapper)
        graph_builder.add_node("execution", execution_node)
        graph_builder.add_node("triage", self._triage_wrapper)
        graph_builder.add_node("deeper_analysis", self._deeper_analysis_wrapper)
        
        # Define the flow: START → planner → validate_plan → evaluator → execution → triage → deeper_analysis → END
        graph_builder.add_edge(START, "planner")
        graph_builder.add_edge("planner", "validate_plan")
        graph_builder.add_edge("validate_plan", "evaluator")
        
        # Conditional routing from evaluator
        graph_builder.add_conditional_edges(
            "evaluator", 
            lambda state: route_based_on_evaluation(state, self.config.max_retries),
            {"planner": "planner", "execution": "execution", "END": END}
        )
        
        # Conditional routing from execution to triage
        graph_builder.add_conditional_edges(
            "execution",
            route_after_execution,
            {"triage": "triage", "END": END}
        )
        
        # Conditional routing from triage to deeper analysis or end
        graph_builder.add_conditional_edges(
            "triage",
            self._route_after_analysis,
            {"deeper_analysis": "deeper_analysis", "END": END}
        )
        
        # Deeper analysis always routes to END when complete
        graph_builder.add_edge("deeper_analysis", END)
        
        # Set entry point
        graph_builder.set_entry_point("planner")
        self.graph = graph_builder.compile()
        
    def _planner_wrapper(self, state: ForensicState) -> Dict[str, Any]:
        """Wrapper to inject LLM into planner node."""
        return planner_node(state, self.planner_llm)
        
    def _evaluator_wrapper(self, state: ForensicState) -> Dict[str, Any]:
        """Wrapper to inject LLM into evaluator node."""
        return evaluator_node(state, self.evaluator_llm)
        
    def _triage_wrapper(self, state: ForensicState) -> Dict[str, Any]:
        """Wrapper for triage analysis node."""
        return self._triage_node(state)
        
    def _deeper_analysis_wrapper(self, state: ForensicState) -> Dict[str, Any]:
        """Wrapper for deeper analysis node with chunked analysis."""
        # Execute the deeper analysis plan
        deeper_results = self.deeper_analysis_engine.deeper_analysis_node(state)
        
        # If execution was successful, perform chunked analysis on results
        if (deeper_results.get("investigation_stage") == "deeper_analysis_completed" 
            and "deeper_analysis_results" in deeper_results):
            
            execution_results = deeper_results["deeper_analysis_results"]
            deeper_evidence_dir = deeper_results.get("deeper_evidence_directory", "")
            
            # Gather analysis context from deeper execution results
            analysis_context = self._gather_analysis_context(execution_results, deeper_evidence_dir)
            
            # Perform chunked analysis on deeper results
            enhanced_analysis = self._perform_chunked_analysis(
                analysis_context, state, "deeper_completed", execution_results, deeper_evidence_dir
            )
            
            # Correlate with initial findings for comprehensive report
            if enhanced_analysis and enhanced_analysis.get("analysis_results"):
                print(f"🎯 Deeper analysis complete - Enhanced threat score: {enhanced_analysis.get('threat_score', 0):.1f}")
                
                # Save enhanced results
                self._save_single_analysis_result(enhanced_analysis, deeper_evidence_dir, state)
                
                # Merge the enhanced analysis with deeper results
                return {
                    **enhanced_analysis,
                    "investigation_stage": "deeper_analysis_completed",
                    "deeper_analysis_plan": deeper_results.get("deeper_analysis_plan"),
                    "deeper_evidence_directory": deeper_evidence_dir
                }
        
        # Return original results if no enhancement was possible
        return deeper_results
        
    def _route_after_analysis(self, state: ForensicState) -> str:
        """Route after analysis completion."""
        investigation_stage = state.get("investigation_stage")
        threat_score = state.get("threat_score", 0)
        
        if investigation_stage != "analysis_completed":
            print("⚠️ Analysis incomplete - ending workflow")
            return "END"
            
        # Check if deeper analysis should be triggered
        analysis_result = {
            "threat_score": threat_score,
            "analysis_confidence": state.get("analysis_confidence", 1.0),
            "analysis_results": state.get("analysis_results")
        }
        
        if self.deeper_analysis_engine.should_trigger_deeper_analysis(analysis_result):
            print(f"🔍 Triggering deeper analysis (threat score: {threat_score}/10)")
            print("   - High threat indicators detected")
            print("   - Initiating targeted investigation...")
            return "deeper_analysis"
        else:
            print(f"✅ Analysis completed with threat score: {threat_score}/10")
            print("🏁 Memory forensics investigation workflow complete")
            return "END"
    
    def _triage_node(self, state: ForensicState) -> Dict[str, Any]:
        """
        Analyze the execution results to identify suspicious findings and generate threat intelligence.
        
        Args:
            state: Current forensic state containing execution results and evidence directory
            
        Returns:
            Dict containing analysis results, threat scores, and recommendations
        """
        try:
            print("🔍 Starting Results Analysis Phase")
            
            # Get execution results and evidence directory
            execution_results = state.get("execution_results")
            evidence_directory = state.get("evidence_directory")
            execution_status = state.get("execution_status")
            
            if not execution_results or execution_status not in ["completed", "partial"]:
                return {
                    "analysis_results": None,
                    "analysis_confidence": 0.0,
                    "threat_score": 0.0,
                    "key_indicators": [],
                    "recommended_actions": ["Investigation execution incomplete - no results to analyze"],
                    "investigation_stage": "analysis_failed"
                }
            
            # Parse execution results to gather file outputs
            analysis_context = self._gather_analysis_context(execution_results, evidence_directory)
            
            # Check if we need chunked analysis due to token limits
            analysis_result = self._perform_chunked_analysis(
                analysis_context, state, execution_status, execution_results, evidence_directory
            )
            
            # Save the analysis results
            self._save_single_analysis_result(analysis_result, evidence_directory, state)
            
            print("✅ Triage analysis completed")
            return {
                "analysis_results": analysis_result.get("analysis_results"),
                "analysis_confidence": analysis_result.get("analysis_confidence", 0.8),
                "threat_score": analysis_result.get("threat_score", 5.0),
                "key_indicators": analysis_result.get("key_indicators", []),
                "recommended_actions": analysis_result.get("recommended_actions", []),
                "investigation_stage": "analysis_completed"
            }
            
        except Exception as e:
            print(f"❌ Triage analysis error: {e}")
            return {
                "analysis_results": None,
                "analysis_confidence": 0.0,
                "threat_score": 0.0,
                "key_indicators": [],
                "recommended_actions": [f"Triage analysis failed: {e}"],
                "investigation_stage": "analysis_failed"
            }
    
    def _perform_chunked_analysis(self, analysis_context: str, state: ForensicState, 
                                 execution_status: str, execution_results: Dict[str, Any], 
                                 evidence_directory: str) -> Dict[str, Any]:
        """
        Perform analysis with chunking if context is too large.
        
        Args:
            analysis_context: Full analysis context string
            state: Current forensic state
            execution_status: Status of execution
            execution_results: Results from execution
            evidence_directory: Path to evidence directory
            
        Returns:
            Combined analysis results from all chunks
        """
        try:
            from utils.tokens import count_tokens
            import time
            
            # Check token count for the full context
            total_tokens = count_tokens(analysis_context)
            max_chunk_tokens = self.config.max_chunk_tokens
            
            if total_tokens <= max_chunk_tokens:
                # Single analysis - context fits in one request
                print(f"📊 Performing single analysis ({total_tokens:,} tokens)")
                return self._analyze_single_chunk(analysis_context, state, execution_status, execution_results, evidence_directory)
            
            # Chunked analysis needed
            chunks = self._split_analysis_context(analysis_context, max_chunk_tokens)
            
            # Save chunks to files for resumability and debugging
            chunk_metadata = self._save_chunks_to_files(chunks, evidence_directory, state)
            
            print(f"📊 Performing chunked analysis:")
            print(f"   - Total context: {total_tokens:,} tokens")
            print(f"   - Number of chunks: {len(chunks)}")
            print(f"   - Max chunk size: {max_chunk_tokens:,} tokens")
            print(f"   - Chunks saved to: {chunk_metadata.get('chunks_directory', 'N/A')}")
            
            # Check for existing results from previous runs
            existing_results = self._load_existing_chunk_results(chunk_metadata.get('chunks_directory', ''))
            
            # Analyze each chunk (skip if already completed)
            chunk_results = []
            for i, chunk in enumerate(chunks, 1):
                chunk_tokens = count_tokens(chunk)
                chunk_id = f"chunk_{i:03d}"
                
                # Check if this chunk was already analyzed
                if chunk_id in existing_results:
                    print(f"♻️  Chunk {i}/{len(chunks)} already analyzed - loading existing results...")
                    chunk_results.append(existing_results[chunk_id])
                    continue
                
                print(f"🔍 Analyzing chunk {i}/{len(chunks)} ({chunk_tokens:,} tokens)...")
                
                # Add delay between chunks to prevent rate limit bursts
                if i > 1:  # Skip delay for first chunk
                    delay = min(2.0, chunk_tokens / 10000)  # 2s max, scaled by chunk size
                    print(f"⏳ Waiting {delay:.1f}s to prevent rate limiting...")
                    time.sleep(delay)
                
                chunk_result = self._analyze_single_chunk(
                    chunk, state, execution_status, execution_results, 
                    evidence_directory, chunk_info=f"chunk {i} of {len(chunks)}"
                )
                
                if chunk_result.get("analysis_results"):
                    # Save individual chunk result for resumability
                    self._save_chunk_result(chunk_result, chunk_id, chunk_metadata.get('chunks_directory', ''))
                    chunk_results.append(chunk_result)
                    print(f"   ✅ Chunk {i} completed - Threat Score: {chunk_result.get('threat_score', 0):.1f}")
                else:
                    print(f"   ⚠️ Chunk {i} failed")
            
            # Combine results from all chunks
            if chunk_results:
                print("🔗 Combining analysis results from all chunks...")
                combined_result = self._combine_chunk_results(chunk_results, state, evidence_directory)
                
                # Save combined results metadata
                self._save_chunked_analysis_metadata(chunk_metadata, combined_result, evidence_directory)
                
                return combined_result
            else:
                print("❌ All chunks failed analysis")
                return {
                    "analysis_results": None,
                    "analysis_confidence": 0.0,
                    "threat_score": 0.0,
                    "key_indicators": [],
                    "recommended_actions": ["All analysis chunks failed"]
                }
                
        except Exception as e:
            print(f"❌ Chunked analysis error: {e}")
            return {
                "analysis_results": None,
                "analysis_confidence": 0.0,
                "threat_score": 0.0,
                "key_indicators": [],
                "recommended_actions": [f"Analysis error: {str(e)}"]
            }
    
    def _split_analysis_context(self, context: str, max_chunk_tokens: int) -> List[str]:
        """Split analysis context into manageable chunks."""
        from utils.tokens import count_tokens
        
        lines = context.split('\n')
        chunks = []
        current_chunk = []
        current_tokens = 0
        
        for line in lines:
            line_tokens = count_tokens(line)
            
            if current_tokens + line_tokens > max_chunk_tokens and current_chunk:
                # Start new chunk
                chunks.append('\n'.join(current_chunk))
                current_chunk = [line]
                current_tokens = line_tokens
            else:
                current_chunk.append(line)
                current_tokens += line_tokens
        
        # Add final chunk
        if current_chunk:
            chunks.append('\n'.join(current_chunk))
        
        return chunks
    
    def _analyze_single_chunk(self, analysis_context: str, state: ForensicState, 
                             execution_status: str, execution_results: Dict[str, Any], 
                             evidence_directory: str, chunk_info: str = None) -> Dict[str, Any]:
        """Analyze a single chunk of context with rate limiting."""
        from utils.messages import build_analysis_system_message, build_analysis_user_message
        from langchain_core.messages import SystemMessage, HumanMessage
        import time
        import re
        
        for attempt in range(self.config.max_retries):
            try:
                system_message = build_analysis_system_message()
                user_message = build_analysis_user_message(
                    state, execution_status, execution_results, evidence_directory, 
                    analysis_context, chunk_info
                )
                
                analysis_messages = [
                    SystemMessage(content=system_message),
                    HumanMessage(content=user_message)
                ]
                
                # Use the analyzer LLM to get structured output
                analysis_result: AnalysisOutput = self.analyzer_llm.invoke(analysis_messages)
                
                return {
                    "analysis_results": {
                        "suspicious_findings": [finding.model_dump() for finding in analysis_result.suspicious_findings],
                        "executive_summary": analysis_result.executive_summary
                    },
                    "threat_score": analysis_result.threat_score,
                    "key_indicators": analysis_result.key_indicators,
                    "recommended_actions": analysis_result.recommended_actions,
                    "analysis_confidence": analysis_result.analysis_confidence
                }
                
            except Exception as e:
                error_str = str(e)
                
                # Check if it's a rate limit error
                if "429" in error_str and "rate_limit_exceeded" in error_str:
                    # Extract wait time from error message
                    wait_match = re.search(r'Please try again in (\d+(?:\.\d+)?)s', error_str)
                    if wait_match:
                        wait_time = float(wait_match.group(1))
                    else:
                        # Exponential backoff
                        wait_time = min(
                            self.config.rate_limit_delay * (2 ** attempt),
                            self.config.max_rate_limit_delay
                        )
                    
                    print(f"⏳ Rate limit hit, waiting {wait_time:.1f}s before retry {attempt + 1}/{self.config.max_retries}")
                    time.sleep(wait_time)
                    continue
                else:
                    # Non-rate-limit error
                    print(f"❌ Analysis error: {e}")
                    return {
                        "analysis_results": {"error": str(e)},
                        "threat_score": 0.0,
                        "key_indicators": [],
                        "recommended_actions": [f"Analysis failed: {e}"],
                        "analysis_confidence": 0.0
                    }
        
        # All retries exhausted
        print(f"❌ Analysis failed after {self.config.max_retries} attempts due to rate limiting")
        return {
            "analysis_results": {"error": f"Rate limit exceeded after {self.config.max_retries} retries"},
            "threat_score": 0.0,
            "key_indicators": [],
            "recommended_actions": ["Rate limit exceeded - consider reducing chunk size or using different model"],
            "analysis_confidence": 0.0
        }
    
    def _combine_chunk_results(self, chunk_results: List[Dict[str, Any]], 
                              state: ForensicState, evidence_directory: str) -> Dict[str, Any]:
        """Combine results from multiple chunks into a single analysis."""
        if not chunk_results:
            return {"analysis_results": None, "threat_score": 0.0}
        
        # Combine all findings
        all_findings = []
        all_indicators = []
        all_actions = []
        threat_scores = []
        confidence_scores = []
        
        for result in chunk_results:
            analysis_results = result.get("analysis_results", {})
            if isinstance(analysis_results, dict) and "suspicious_findings" in analysis_results:
                all_findings.extend(analysis_results["suspicious_findings"])
            
            all_indicators.extend(result.get("key_indicators", []))
            all_actions.extend(result.get("recommended_actions", []))
            threat_scores.append(result.get("threat_score", 0.0))
            confidence_scores.append(result.get("analysis_confidence", 0.0))
        
        # Calculate overall scores
        avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        # Remove duplicates
        unique_indicators = list(set(all_indicators))
        unique_actions = list(set(all_actions))
        
        return {
            "analysis_results": {
                "suspicious_findings": all_findings,
                "executive_summary": f"Combined analysis of {len(chunk_results)} chunks identified {len(all_findings)} findings"
            },
            "threat_score": avg_threat_score,
            "key_indicators": unique_indicators,
            "recommended_actions": unique_actions,
            "analysis_confidence": avg_confidence
        }
    
    def _gather_analysis_context(self, execution_results: Dict[str, Any], evidence_directory: str) -> str:
        """
        Gather relevant context from execution results and evidence files for analysis.
        
        Args:
            execution_results: Results from the execution phase
            evidence_directory: Path to evidence directory with output files
            
        Returns:
            Formatted string with analysis context
        """
        import os
        
        context_parts = []
        
        # Add global triage summary
        if "global_triage" in execution_results:
            context_parts.append("**GLOBAL TRIAGE RESULTS:**")
            for triage_step in execution_results["global_triage"]:
                step_name = triage_step.get("step_name", "Unknown")
                results = triage_step.get("results", [])
                successful_commands = len([r for r in results if r.get("status") == "SUCCESS"])
                context_parts.append(f"- {step_name}: {successful_commands}/{len(results)} commands successful")
        
        # Add phase execution summary
        if "phases" in execution_results:
            context_parts.append("\n**INVESTIGATION PHASES:**")
            for phase in execution_results["phases"]:
                phase_name = phase.get("phase_name", "Unknown")
                summary = phase.get("summary", {})
                hits = summary.get("total_hits", 0)
                success_rate = summary.get("success_rate", 0)
                context_parts.append(f"- {phase_name}: {success_rate:.1%} success rate, {hits} suspicious hits")
        
        # Add file content samples if available
        if evidence_directory and os.path.exists(evidence_directory):
            context_parts.append("\n**SAMPLE OUTPUT FILES:**")
            
            # Look for key output files and include samples
            sample_files = []
            for root, dirs, files in os.walk(evidence_directory):
                for file in files:  
                    if file.endswith('.txt'):  # Include all .txt files for analysis
                        sample_files.append(os.path.join(root, file))
            deduplicated_sample_files = []
            for sample_file in sample_files:  # Include all files for comprehensive analysis

                plugin_name = sample_file.split("_")[-1]
                #some of the plugins might have been run multiple times, so we need to deduplicate them
                if plugin_name not in deduplicated_sample_files:    
                    deduplicated_sample_files.append(plugin_name)
                else:
                    continue
                    
                try:
                    relative_path = os.path.relpath(sample_file, evidence_directory)
                    with open(sample_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()  
                    context_parts.append(f"\n--- {relative_path} (sample) ---")
                    context_parts.append(content)
                except Exception as e:
                    context_parts.append(f"- {relative_path}: Could not read file ({e})")
        
        return "\n".join(context_parts)

    def _save_chunks_to_files(self, chunks: List[str], evidence_directory: str, state: ForensicState) -> Dict[str, Any]:
        """
        Save analysis chunks to individual files for resumability and debugging.
        
        Args:
            chunks: List of context chunks
            evidence_directory: Base evidence directory
            state: Current forensic state
            
        Returns:
            Dictionary with chunk metadata including file paths
        """
        try:
            import os
            import json
            from datetime import datetime
            from utils.tokens import count_tokens
            
            # Create chunks subdirectory
            chunks_dir = os.path.join(evidence_directory, "analysis_chunks")
            os.makedirs(chunks_dir, exist_ok=True)
            
            # Create metadata for this chunked analysis
            chunk_metadata = {
                "timestamp": datetime.now().isoformat(),
                "chunks_directory": chunks_dir,
                "total_chunks": len(chunks),
                "memory_dump_path": state.get('memory_dump_path'),
                "os_hint": state.get('os_hint'),
                "user_prompt": state.get('user_prompt'),
                "chunk_files": []
            }
            
            # Save each chunk to a separate file
            for i, chunk in enumerate(chunks, 1):
                chunk_id = f"chunk_{i:03d}"
                chunk_file = os.path.join(chunks_dir, f"{chunk_id}.txt")
                
                with open(chunk_file, 'w', encoding='utf-8') as f:
                    f.write(chunk)
                
                chunk_info = {
                    "chunk_id": chunk_id,
                    "file_path": chunk_file,
                    "token_count": count_tokens(chunk),
                    "character_count": len(chunk)
                }
                chunk_metadata["chunk_files"].append(chunk_info)
            
            # Save chunk metadata
            metadata_file = os.path.join(chunks_dir, "chunks_metadata.json")
            with open(metadata_file, 'w') as f:
                json.dump(chunk_metadata, f, indent=2)
            
            print(f"💾 Saved {len(chunks)} chunks to: {chunks_dir}")
            return chunk_metadata
            
        except Exception as e:
            print(f"⚠️ Error saving chunks: {e}")
            return {"chunks_directory": "", "total_chunks": len(chunks)}

    def _load_existing_chunk_results(self, chunks_directory: str) -> Dict[str, Dict[str, Any]]:
        """
        Load existing chunk analysis results for resumability.
        
        Args:
            chunks_directory: Directory containing chunk results
            
        Returns:
            Dictionary mapping chunk_id to analysis results
        """
        try:
            import os
            import json
            
            existing_results = {}
            
            if not chunks_directory or not os.path.exists(chunks_directory):
                return existing_results
            
            # Look for existing chunk result files
            for file in os.listdir(chunks_directory):
                if file.startswith("chunk_") and file.endswith("_result.json"):
                    chunk_id = file.replace("_result.json", "")
                    result_file = os.path.join(chunks_directory, file)
                    
                    try:
                        with open(result_file, 'r') as f:
                            chunk_result = json.load(f)
                            existing_results[chunk_id] = chunk_result
                    except Exception as e:
                        print(f"⚠️ Error loading chunk result {file}: {e}")
            
            if existing_results:
                print(f"♻️  Found {len(existing_results)} existing chunk results")
            
            return existing_results
            
        except Exception as e:
            print(f"⚠️ Error loading existing chunk results: {e}")
            return {}

    def _save_chunk_result(self, chunk_result: Dict[str, Any], chunk_id: str, chunks_directory: str):
        """
        Save individual chunk analysis result for resumability.
        
        Args:
            chunk_result: Analysis result for this chunk
            chunk_id: Unique identifier for the chunk
            chunks_directory: Directory to save chunk results
        """
        try:
            import os
            import json
            from datetime import datetime
            
            if not chunks_directory:
                return
            
            result_file = os.path.join(chunks_directory, f"{chunk_id}_result.json")
            
            # Add metadata to chunk result
            chunk_data = {
                "timestamp": datetime.now().isoformat(),
                "chunk_id": chunk_id,
                "analysis_results": chunk_result.get("analysis_results"),
                "threat_score": chunk_result.get("threat_score"),
                "analysis_confidence": chunk_result.get("analysis_confidence")
            }
            
            with open(result_file, 'w') as f:
                json.dump(chunk_data, f, indent=2)
            
        except Exception as e:
            print(f"⚠️ Error saving chunk result {chunk_id}: {e}")

    def _save_chunked_analysis_metadata(self, chunk_metadata: Dict[str, Any], 
                                       combined_result: Dict[str, Any], evidence_directory: str):
        """
        Save metadata about the chunked analysis process.
        
        Args:
            chunk_metadata: Metadata from chunk creation
            combined_result: Final combined analysis result
            evidence_directory: Evidence directory path
        """
        try:
            import os
            import json
            from datetime import datetime
            
            # Create analysis results directory
            results_dir = os.path.join(evidence_directory, "analysis_results")
            os.makedirs(results_dir, exist_ok=True)
            
            # Prepare combined metadata
            metadata = {
                "analysis_type": "chunked_analysis",
                "timestamp": datetime.now().isoformat(),
                "chunk_metadata": chunk_metadata,
                "combined_results": {
                    "threat_score": combined_result.get("threat_score"),
                    "analysis_confidence": combined_result.get("analysis_confidence"),
                    "total_findings": len(combined_result.get("analysis_results", {}).get("suspicious_findings", [])),
                    "key_indicators_count": len(combined_result.get("key_indicators", [])),
                    "recommended_actions_count": len(combined_result.get("recommended_actions", []))
                }
            }
            
            # Save metadata
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            metadata_file = os.path.join(results_dir, f"chunked_analysis_metadata_{timestamp_str}.json")
            
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"💾 Chunked analysis metadata saved to: {metadata_file}")
            
        except Exception as e:
            print(f"⚠️ Error saving chunked analysis metadata: {e}")
    
    def _save_single_analysis_result(self, analysis_result: Dict[str, Any], 
                                   evidence_directory: str, state: ForensicState):
        """Save single analysis result to file."""
        import json
        import os
        from datetime import datetime
        
        try:
            # Create analysis results directory
            analysis_dir = os.path.join(evidence_directory, "analysis_results")
            os.makedirs(analysis_dir, exist_ok=True)
            
            # Save analysis result
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_file = os.path.join(analysis_dir, f"triage_analysis_{timestamp}.json")
            
            with open(result_file, 'w') as f:
                json.dump(analysis_result, f, indent=2, default=str)
            
            print(f"📄 Analysis results saved to: {result_file}")
            
        except Exception as e:
            print(f"⚠️ Failed to save analysis results: {e}")
        
    async def investigate(
        self, 
        memory_dump_path: str, 
        os_hint: str = None, 
        user_prompt: str = None
    ) -> Dict[str, Any]:
        """
        Run a complete memory forensics investigation.
        
        Args:
            memory_dump_path: Path to the memory dump file
            os_hint: Operating system hint (windows, linux, macos)
            user_prompt: Custom investigation context
            
        Returns:
            Dictionary containing investigation results
        """
        if not self.graph:
            await self.setup_llm()
            
        # Create initial state
        initial_state = ForensicState(
            messages=[],
            memory_dump_path=memory_dump_path,
            os_hint=os_hint,
            user_prompt=user_prompt,
            retry_count=0
        )
        
        print(f"🔍 Starting Memory Forensics Investigation")
        print(f"📁 Memory Dump: {memory_dump_path}")
        print(f"🖥️ OS Hint: {os_hint or 'Auto-detect'}")
        print(f"🎯 Investigation Context: {user_prompt or 'General analysis'}")
        print(f"{'='*60}")
        
        try:
            # Run the complete workflow
            final_state = await self.graph.ainvoke(initial_state)
            
            # Extract results
            results = {
                "investigation_completed": True,
                "memory_dump_path": memory_dump_path,
                "os_hint": os_hint,
                "user_prompt": user_prompt,
                "validation_status": final_state.get("validation_status"),
                "success_criteria_met": final_state.get("success_criteria_met"),
                "execution_status": final_state.get("execution_status"),
                "execution_results": final_state.get("execution_results"),
                "evidence_directory": final_state.get("evidence_directory"),
                "execution_summary": final_state.get("execution_summary")
            }
            
            # Print summary
            self._print_investigation_summary(results)
            
            return results
            
        except Exception as e:
            print(f"❌ Investigation failed: {e}")
            return {
                "investigation_completed": False,
                "error": str(e),
                "memory_dump_path": memory_dump_path
            }
            
    def _print_investigation_summary(self, results: Dict[str, Any]):
        """Print a summary of the investigation results."""
        print(f"\n{'='*60}")
        print(f"🎉 INVESTIGATION COMPLETE")
        print(f"{'='*60}")
        
        validation_status = results.get("validation_status")
        success_criteria_met = results.get("success_criteria_met")
        execution_status = results.get("execution_status")
        
        print(f"✅ Validation Status: {validation_status}")
        print(f"✅ Commands Valid: {success_criteria_met}")
        print(f"✅ Execution Status: {execution_status}")
        
        if execution_summary := results.get("execution_summary"):
            print(f"\n📊 EXECUTION STATISTICS:")
            print(f"   Commands Run: {execution_summary.get('total_commands', 0)}")
            print(f"   Success Rate: {execution_summary.get('success_rate', 0):.1%}")
            print(f"   Suspicious Hits: {execution_summary.get('total_suspicious_hits', 0)}")
            
        evidence_dir = results.get("evidence_directory")
        if evidence_dir:
            print(f"\n📁 Evidence Directory: {evidence_dir}")
            
        print(f"\n✨ Investigation workflow completed successfully!")

    def _save_single_analysis_result(self, analysis_result: Dict[str, Any], evidence_directory: str, state: ForensicState):
        """
        Save analysis result to a JSON file. Works for both single and final combined analysis results.
        
        Args:
            analysis_result: Complete analysis result dictionary
            evidence_directory: Directory to save the results in
            state: Current forensic state for context
        """
        try:
            import os
            import json
            from datetime import datetime
            from utils import count_tokens
            
            # Create analysis results directory
            results_dir = os.path.join(evidence_directory, "analysis_results")
            os.makedirs(results_dir, exist_ok=True)
            
            # Determine analysis type based on context
            total_tokens = count_tokens(state.get('analysis_context', ''))
            analysis_type = "deeper_analysis" if "deeper" in evidence_directory else "single_analysis"
            if total_tokens > 25000:
                analysis_type = "combined_analysis"
            
            # Prepare result data with metadata
            result_data = {
                "timestamp": datetime.now().isoformat(),
                "analysis_type": analysis_type,
                "memory_dump_path": state.get('memory_dump_path', 'Unknown'),
                "os_hint": state.get('os_hint', 'Unknown'),
                "user_prompt": state.get('user_prompt', 'General malware analysis'),
                "analysis_results": analysis_result.get("analysis_results"),
                "threat_score": analysis_result.get("threat_score"),
                "analysis_confidence": analysis_result.get("analysis_confidence"),
                "key_indicators": analysis_result.get("key_indicators"),
                "recommended_actions": analysis_result.get("recommended_actions"),
                "investigation_stage": analysis_result.get("investigation_stage")
            }
            
            # Save with timestamp in filename for uniqueness
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_file = os.path.join(results_dir, f"deeper_analysis_{timestamp_str}.json")
            
            with open(result_file, 'w') as f:
                json.dump(result_data, f, indent=2)
            
            print(f"💾 Deeper analysis results saved to: {result_file}")
            
        except Exception as e:
            print(f"⚠️ Error saving deeper analysis result: {e}")


# Convenience function for quick investigations
async def run_investigation(
    memory_dump_path: str,
    os_hint: str = None, 
    user_prompt: str = None,
    config: ForensicsConfig = None
) -> Dict[str, Any]:
    """
    Convenience function to run a complete investigation.
    
    Args:
        memory_dump_path: Path to memory dump
        os_hint: Operating system hint
        user_prompt: Investigation context
        config: Custom configuration
        
    Returns:
        Investigation results
    """
    agent = MemoryForensicsAgent(config)
    return await agent.investigate(memory_dump_path, os_hint, user_prompt)


# Example usage and testing
async def main():
    """Example usage of the modular Memory Forensics Agent."""
    
    test_cases = [
        {
            "name": "Windows Ransomware Investigation",
            "memory_dump_path":"/sandbox/memdump.mem", 
            "os_hint": "windows",
            "user_prompt": "Investigate potential malware infection incident - identify attack vector and persistence mechanisms and write a detailed analysis of the findings with evidence"
        }
    ]
    
    print("🚀 Testing Modular Memory Forensics Agent")
    print("="*50)
    
    for test_case in test_cases:
        print(f"\n🧪 Test Case: {test_case['name']}")
        
        try:
            # Use the convenience function
            results = await run_investigation(
                memory_dump_path=test_case["memory_dump_path"],
                os_hint=test_case["os_hint"],
                user_prompt=test_case["user_prompt"]
            )
            
            if results.get("investigation_completed"):
                print(f"✅ Test case completed successfully")
            else:
                print(f"❌ Test case failed: {results.get('error')}")
                
        except Exception as e:
            print(f"❌ Test case error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
