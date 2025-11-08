# Technical Implementation Guide: Chunked Analysis System

## Overview

This guide provides technical details on the chunked analysis implementation for the Memory Forensics Agent, focusing on token management, resumability, and the underlying architecture.

## Core Architecture

### Token Management System

#### Token Counting
```python
def count_tokens(text: str) -> int:
    """Count tokens using tiktoken for GPT-4 accuracy."""
    encoding = tiktoken.encoding_for_model("gpt-4o")
    return len(encoding.encode(text))
```

#### Chunking Strategy
- **Conservative Limit**: 25,000 tokens per chunk (leaves room for system/user messages)
- **Total Context Limit**: 128,000 tokens (GPT-4 limit)
- **Intelligent Splitting**: Preserves logical boundaries

### Chunk Splitting Algorithm

```python
def _split_analysis_context(self, context: str, max_chunk_tokens: int) -> List[str]:
    """
    Line-based splitting with token awareness:
    1. Split on line boundaries
    2. Track token count per line
    3. Start new chunk when limit approached
    4. Handle oversized single lines gracefully
    """
```

**Key Features:**
- Preserves data integrity by splitting on line boundaries
- Real-time token counting for accurate chunk sizing
- Handles edge cases (oversized lines, empty content)

## Persistence Layer

### File Structure Design

```
analysis_chunks/
├── chunk_001.txt              # Raw content chunks
├── chunk_002.txt
├── chunk_003.txt
├── chunks_metadata.json       # Chunk catalog
├── analysis_metadata.json     # Final analysis summary
└── results/
    ├── chunk_001_result.json   # Individual analysis results
    ├── chunk_002_result.json
    └── chunk_003_result.json
```

### Metadata Schema

#### Chunks Metadata
```json
{
  "timestamp": "2025-09-22T22:07:47.123456",
  "chunks_directory": "/path/to/chunks",
  "total_chunks": 5,
  "memory_dump_path": "/path/to/dump.raw",
  "os_hint": "windows",
  "user_prompt": "Investigation context",
  "chunk_files": [
    {
      "chunk_id": "chunk_001",
      "file_path": "/path/to/chunk_001.txt",
      "token_count": 24987,
      "character_count": 89234
    }
  ]
}
```

#### Individual Chunk Results
```json
{
  "timestamp": "2025-09-22T22:08:15.654321",
  "chunk_id": "chunk_001", 
  "analysis_results": {
    "suspicious_findings": [...],
    "threat_score": 7.2,
    "key_indicators": [...],
    "recommended_actions": [...],
    "executive_summary": "...",
    "analysis_confidence": 0.85
  },
  "threat_score": 7.2,
  "analysis_confidence": 0.85,
  "key_indicators": [...],
  "recommended_actions": [...]
}
```

## Resumability Implementation

### Detection Logic
```python
def _load_existing_chunk_results(self, chunks_directory: str) -> Dict[str, Dict[str, Any]]:
    """
    Scan results directory for completed chunks:
    1. Check for results/ subdirectory
    2. Load all chunk_*_result.json files
    3. Map chunk_id to analysis results
    4. Return dictionary for quick lookup
    """
```

### Resume Workflow
1. **Chunk Generation**: Split context into chunks (always consistent)
2. **Existing Results Check**: Scan for previously completed chunks
3. **Skip Logic**: Load existing results, skip analysis for completed chunks
4. **Continue Processing**: Analyze only remaining chunks
5. **Result Combination**: Merge existing + new results

### Benefits of Resumability
- **Cost Efficiency**: Avoid re-analyzing expensive API calls
- **Time Savings**: Skip completed work (can save hours on large dumps)
- **Debugging**: Inspect individual chunk content and results
- **Fault Tolerance**: Handle network interruptions gracefully

## Result Combination Algorithm

### Aggregation Strategy

```python
def _combine_chunk_results(self, chunk_results: List[Dict[str, Any]], ...):
    """
    Intelligent combination of chunk results:
    
    1. Threat Scoring: max(all_chunk_scores)
       - Takes highest threat level found
       - Conservative approach for security
    
    2. Confidence: avg(all_confidences) 
       - Average confidence across chunks
       - Balanced assessment
    
    3. Findings: combine + deduplicate
       - All suspicious findings preserved
       - Duplicates removed by content similarity
    
    4. Indicators: unique set
       - IOCs combined from all chunks
       - Automatic deduplication
    
    5. Actions: unique set
       - All recommendations preserved
       - Duplicates removed
    """
```

### Executive Summary Generation
```python
# Automated summary based on combined results
high_severity_findings = [f for f in all_findings if f.get('severity') in ['high', 'critical']]
executive_summary = f"""
Memory forensics investigation revealed {len(all_findings)} suspicious findings 
across {len(chunk_results)} analysis phases. 
{len(high_severity_findings)} high-severity threats identified.
Overall threat score: {overall_threat_score:.1f}/10 
Confidence: {overall_confidence:.1%}
"""
```

## Performance Considerations

### Memory Management
- **Streaming Processing**: Chunks processed one at a time
- **Immediate Persistence**: Results saved after each chunk
- **Memory Cleanup**: Large context released after chunking

### API Efficiency  
- **Conservative Chunking**: Prevents token limit errors
- **Parallel Potential**: Architecture supports future parallel processing
- **Rate Limiting**: Built-in retry logic for API limitations

### Storage Optimization
- **Compressed Storage**: Text files compress well
- **Selective Retention**: Can implement cleanup policies
- **Metadata Indexing**: Fast lookup of existing results

## Error Handling & Edge Cases

### Chunk-Level Failures
```python
# Individual chunk failure doesn't stop entire analysis
if chunk_result.get("analysis_results"):
    chunk_results.append(chunk_result["analysis_results"])
    print(f"✅ Chunk {i} completed")
else:
    print(f"⚠️ Chunk {i} failed")
    # Continue with remaining chunks
```

### Oversized Content Handling
- **Line-based splitting** prevents mid-sentence breaks
- **Fallback strategies** for extremely long single lines
- **Token counting validation** before API calls

### Filesystem Resilience
- **Directory creation** with error handling
- **Permission checks** before file operations
- **Atomic writes** to prevent corruption

## Integration Points

### LangGraph Integration
```python
def triage_node(self, state: ForensicState) -> Dict[str, Any]:
    """
    Main entry point for chunked analysis:
    1. Extract context from execution results
    2. Determine if chunking needed
    3. Execute chunked or single analysis
    4. Return results in standard format
    """
```

### State Management
- **Transparent Integration**: Chunking invisible to workflow
- **Standard Output**: Same result format regardless of chunking
- **Progress Tracking**: Enhanced logging for chunk progress

## Monitoring & Debugging

### Progress Visualization
```
📊 Performing chunked analysis:
   - Total context: 201,605 tokens
   - Number of chunks: 8  
   - Max chunk size: 25,000 tokens
   - Chunks saved to: ./analysis_chunks
♻️  Found 3 existing chunk results
🔍 Analyzing chunk 4/8 (24,987 tokens)...
   ✅ Chunk 4 completed - Threat Score: 7.2
🔗 Combining analysis results from all chunks...
```

### Debug Information Available
1. **Chunk Content**: Raw text in `chunk_*.txt` files
2. **Token Counts**: Exact token usage per chunk  
3. **Individual Results**: Per-chunk analysis in JSON format
4. **Timing Data**: Timestamps for each processing step
5. **Error Logs**: Detailed error messages with context

### Performance Metrics
- **Total Processing Time**: End-to-end analysis duration
- **Chunk Success Rate**: Percentage of successful chunk analyses
- **Token Efficiency**: Actual vs theoretical token usage
- **Resume Effectiveness**: Time saved through resumability

## Future Enhancements

### Planned Improvements
1. **Parallel Processing**: Process multiple chunks simultaneously
2. **Smart Prioritization**: High-value chunks analyzed first
3. **Incremental Analysis**: Update results as new evidence arrives
4. **Cross-Case Correlation**: Link findings across investigations

### Scalability Considerations
- **Distributed Processing**: Multi-machine chunk processing
- **Database Backend**: Replace file-based storage for large scale
- **Caching Layer**: Intelligent result caching and reuse
- **API Optimization**: Batch processing and connection pooling

## Code Examples

### Custom Chunk Processing
```python
# Override chunk size for specific cases
max_chunk_tokens = 15000  # Smaller chunks for complex analysis

# Force chunking even for small contexts
if force_chunking or total_tokens > max_chunk_tokens:
    return self._perform_chunked_analysis(...)
```

### Manual Resume
```python
# Load specific chunk results for debugging
chunks_dir = "/path/to/analysis_chunks"
existing_results = agent._load_existing_chunk_results(chunks_dir)
print(f"Found {len(existing_results)} completed chunks")
```

### Custom Result Combination
```python
# Implement custom combination logic
def custom_combine_results(chunk_results):
    # Custom threat scoring algorithm
    weighted_scores = [r['threat_score'] * r['confidence'] for r in chunk_results]
    overall_score = sum(weighted_scores) / len(weighted_scores)
    return overall_score
```

## Best Practices

### Implementation Guidelines
1. **Always validate** token counts before API calls
2. **Save immediately** after successful chunk processing
3. **Handle failures gracefully** - partial results are valuable
4. **Monitor progress** - provide clear user feedback
5. **Preserve metadata** - essential for debugging and auditing

### Performance Tips
1. **Optimize chunk size** based on content complexity
2. **Implement cleanup** for old chunk files
3. **Monitor disk usage** - chunks can be large
4. **Consider compression** for long-term storage

### Security Considerations
1. **Secure storage** - chunks contain sensitive evidence
2. **Access controls** - limit who can read chunk content
3. **Audit trails** - log all chunk access and modifications
4. **Data retention** - implement appropriate retention policies

---

This technical guide provides the implementation details necessary to understand, maintain, and extend the chunked analysis system for large-scale memory forensics investigations.

