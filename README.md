# Memory Forensics Agent with AI-Powered Analysis

## Overview

The Memory Forensics Agent is an advanced, production-ready LangGraph-based system that automates memory forensics investigations using Volatility 3. It combines intelligent planning, robust execution, and AI-powered threat analysis with chunked processing capabilities to handle large-scale forensics evidence.

## Key Features

### 🧠 **AI-Powered Investigation Planning**
- LLM-generated comprehensive investigation plans
- OS-specific analysis techniques
- Adaptive planning based on user context
- Volatility 3 command validation

### 🔧 **Robust Execution Engine**
- Professional Volatility command execution
- Suspicion heuristics application
- Evidence organization and chain of custody
- Comprehensive execution logging

### 🔍 **Advanced Chunked Analysis**
- **Token-aware processing** for large evidence files
- **Resumable analysis** with chunk persistence
- **Intelligent context splitting** preserving logical boundaries
- **Parallel chunk processing** with progress tracking

### 📊 **Professional Reporting**
- Structured threat intelligence output
- Executive summaries for management
- Actionable recommendations
- Confidence scoring and threat assessment

## Architecture

### Workflow Pipeline
```
START → planner → validate_plan → evaluator → execution → triage → END
```

### Core Components

1. **Planner Node**: Generates investigation plans using LLM
2. **Validator Node**: Schema and quality validation
3. **Evaluator Node**: Volatility command verification
4. **Execution Node**: Professional evidence collection
5. **Triage Node**: AI-powered threat analysis with chunking

## Chunked Analysis System

### Problem Solved
Large memory dumps can generate evidence that exceeds LLM token limits (128k tokens). The chunked analysis system automatically handles this by:

1. **Token Detection**: Uses tiktoken to accurately count tokens
2. **Intelligent Splitting**: Preserves logical boundaries in context
3. **Parallel Processing**: Analyzes chunks independently
4. **Result Combination**: Merges findings into comprehensive report
5. **Resumability**: Saves progress for interrupted analyses

### Chunk Persistence Architecture

```
forensics_evidence/
└── Challenge_YYYYMMDD_HHMMSS/
    ├── analysis_chunks/
    │   ├── chunk_001.txt          # Raw chunk content
    │   ├── chunk_002.txt          
    │   ├── chunk_003.txt          
    │   ├── chunks_metadata.json   # Chunk information
    │   ├── analysis_metadata.json # Combined results metadata
    │   └── results/
    │       ├── chunk_001_result.json  # Individual chunk analysis
    │       ├── chunk_002_result.json  
    │       └── chunk_003_result.json  
    ├── analysis_report.json       # Final combined report
    └── [other evidence directories]
```

## Usage

### Basic Investigation

```python
import asyncio
from pra_vol_test import MemoryForensicsAgent

async def investigate_memory_dump():
    agent = MemoryForensicsAgent()
    await agent.setup_llm()
    
    state = {
        "memory_dump_path": "/path/to/memory.raw",
        "os_hint": "windows",
        "user_prompt": "Ransomware incident - identify attack vector"
    }
    
    result = await agent.graph.ainvoke(state)
    return result

# Run investigation
result = asyncio.run(investigate_memory_dump())
```

### Resumable Chunked Analysis

If an analysis is interrupted, simply re-run with the same parameters:

```python
# First run - processes chunks 1-5, then fails
result1 = await agent.graph.ainvoke(state)

# Resume run - automatically detects existing chunks 1-5, continues from chunk 6
result2 = await agent.graph.ainvoke(state)
```

The system will automatically:
- Detect existing chunk files and results
- Skip already-completed chunks
- Continue from the last incomplete chunk
- Combine all results (existing + new) into final report

## Configuration

### Token Limits
```python
# In _perform_chunked_analysis method
max_chunk_tokens = 25000  # Conservative limit per chunk
```

### Chunk Strategy
The system uses intelligent splitting:
- Preserves line boundaries
- Maintains logical sections (headers, data blocks)
- Balances chunk sizes for optimal processing

### LLM Configuration
```python
# Analysis LLM setup
self.analysis_llm_with_output = ChatOpenAI(
    model="gpt-4o",
    temperature=0.1,
    max_tokens=2000
).with_structured_output(AnalysisOutput, method="function_calling")
```

## Output Structure

### Analysis Report Format
```json
{
  "timestamp": "2025-09-22T22:07:47.123456",
  "analysis_results": {
    "suspicious_findings": [
      {
        "finding_type": "process",
        "description": "Suspicious memory activity in explorer.exe",
        "severity": "high", 
        "evidence": "Malfind output showing suspicious memory region",
        "score": 8.0
      }
    ],
    "threat_score": 7.0,
    "key_indicators": [
      "Code injection in explorer.exe",
      "Unusual registry modifications"
    ],
    "recommended_actions": [
      "Isolate affected system",
      "Analyze injected code"
    ],
    "executive_summary": "Investigation revealed high-risk compromise...",
    "analysis_confidence": 0.85,
    "analysis_method": "chunked_analysis",
    "total_chunks_analyzed": 5
  }
}
```

### Chunk Metadata
```json
{
  "analysis_type": "chunked_analysis",
  "timestamp": "2025-09-22T22:07:47.123456",
  "chunk_summary": {
    "total_chunks": 5,
    "chunks_directory": "./analysis_chunks",
    "successful_chunks": 5
  },
  "combined_results_summary": {
    "overall_threat_score": 7.0,
    "total_findings": 12,
    "unique_indicators": 8,
    "analysis_confidence": 0.85
  }
}
```

## State Management

### ForensicState Variables
```python
class ForensicState(TypedDict):
    # Core investigation
    memory_dump_path: Optional[str]
    investigation_plan: Optional[str]
    os_hint: Optional[str]
    user_prompt: Optional[str]
    
    # Validation & execution
    validation_status: Optional[str]
    execution_status: Optional[str]
    execution_results: Optional[Dict[str, Any]]
    evidence_directory: Optional[str]
    
    # Analysis results
    analysis_results: Optional[Dict[str, Any]]
    threat_score: Optional[float]
    analysis_confidence: Optional[float]
    key_indicators: Optional[List[str]]
    recommended_actions: Optional[List[str]]
    
    # Workflow control
    retry_count: Optional[int]
    success_criteria_met: Optional[bool]
    investigation_stage: Optional[str]
```

## Advanced Features

### Resumability Benefits

1. **Cost Optimization**: Avoid re-analyzing expensive chunks
2. **Time Efficiency**: Resume from interruption point
3. **Debugging**: Inspect individual chunk content and results
4. **Audit Trail**: Complete record of analysis progression

### Intelligent Chunk Combination

The system intelligently merges chunk results:

```python
# Threat scoring: Takes maximum score across chunks
overall_threat_score = max(threat_scores)

# Confidence: Averages confidence across chunks  
overall_confidence = sum(confidence_scores) / len(confidence_scores)

# Findings: Combines and deduplicates across chunks
unique_indicators = list(set(all_indicators))
```

### Progress Tracking

```
📊 Performing chunked analysis:
   - Total context: 201,605 tokens
   - Number of chunks: 8
   - Max chunk size: 25,000 tokens
   - Chunks saved to: ./forensics_evidence/Challenge_20250922_220747/analysis_chunks
♻️  Found 3 existing chunk results
♻️  Chunk 1/8 already analyzed - loading existing results...
🔍 Analyzing chunk 4/8 (24,987 tokens)...
   ✅ Chunk 4 completed - Threat Score: 7.2
🔗 Combining analysis results from all chunks...
✅ Combined Analysis Complete!
```

## Error Handling

### Chunk-Level Resilience
- Individual chunk failures don't stop entire analysis
- Failed chunks are logged and skipped
- Partial results still provide valuable intelligence

### Network Interruption Recovery
- All chunk content saved to disk before analysis
- Individual results saved immediately after completion
- Resume capability handles any interruption gracefully

### Token Limit Management
- Automatic detection of oversized contexts
- Conservative chunking to prevent API errors
- Graceful fallback for edge cases

## Best Practices

### Investigation Planning
1. **Provide context**: Use descriptive `user_prompt` for better planning
2. **Specify OS**: Include `os_hint` for targeted analysis
3. **Review plans**: Check generated plans before execution

### Performance Optimization
1. **Monitor token usage**: Large evidence files benefit from chunking
2. **Resume capability**: Use for long-running investigations
3. **Resource management**: Ensure adequate disk space for chunk storage

### Security Considerations
1. **Evidence integrity**: Maintain chain of custody documentation
2. **Data protection**: Secure evidence directories appropriately
3. **Access control**: Limit access to sensitive forensics data

## Troubleshooting

### Common Issues

**Token Limit Errors**
- Solution: Chunked analysis automatically handles this

**Interrupted Analysis** 
- Solution: Re-run with same parameters to resume

**Missing Dependencies**
- Ensure `volatility_executor.py` is available
- Install required packages: `tiktoken`, `langchain-openai`

**Chunk Loading Failures**
- Check filesystem permissions
- Verify evidence directory structure

### Debug Information

Enable verbose logging to troubleshoot:
```python
# The system automatically provides detailed progress logs
# Check console output for chunk processing status
# Examine individual chunk files for content verification
```

## Dependencies

```bash
pip install langchain-openai
pip install tiktoken
pip install pydantic
pip install jsonschema
```

## Future Enhancements

1. **Parallel Chunk Processing**: Process multiple chunks simultaneously
2. **Smart Chunk Prioritization**: Analyze high-priority chunks first
3. **Incremental Updates**: Update analysis as new evidence arrives
4. **Cross-Investigation Correlation**: Link findings across cases

## Support

For issues or questions about the Memory Forensics Agent:
1. Check chunk metadata files for debugging information
2. Review individual chunk content for analysis accuracy
3. Examine execution logs for detailed workflow information
4. Verify Volatility command compatibility and execution

---

This documentation covers the complete Memory Forensics Agent system with emphasis on the advanced chunked analysis capabilities that enable processing of large-scale forensics evidence while maintaining resumability and comprehensive threat intelligence reporting.

