# Achilles Memory Forensics Agent - Comprehensive Analysis

## Executive Summary

**Achilles** is a sophisticated, production-ready AI-powered memory forensics agent that automates complete memory dump investigations using Volatility 3. It combines intelligent planning, robust execution, and AI-powered threat analysis with advanced chunked processing to handle large-scale forensics evidence.

---

## 1. Architecture Overview

### 1.1 Core Design Pattern
- **Framework**: LangGraph (state machine workflow)
- **LLM Integration**: LangChain with OpenAI (multiple specialized models)
- **State Management**: TypedDict-based state passing between nodes
- **Modularity**: Clean separation of concerns across nodes, engines, and utilities

### 1.2 Workflow Graph Structure

```
START 
  → planner (generate investigation plan)
  → validate_plan (schema & quality validation)
  → evaluator (validate Volatility commands)
  → [conditional routing]
      ├─→ planner (retry if validation fails)
      ├─→ execution (execute Volatility commands)
      └─ END (max retries exceeded)
  → execution (run investigation plan)
  → triage (analyze execution results)
  → [conditional routing]
      ├─→ deeper_analysis (if threat_score ≥ 7.0)
      └─→ END (if threat_score < 7.0)
  → deeper_analysis (targeted investigation)
  → END
```

---

## 2. Core Components Deep Dive

### 2.1 MemoryForensicsAgent Class (`forensics_agent.py`)

**Purpose**: Main orchestrator that coordinates all investigation phases.

**Key Responsibilities**:
- Initializes and manages LLM instances (planner, evaluator, analyzer)
- Builds and compiles the LangGraph workflow
- Handles chunked analysis for large evidence sets
- Manages evidence persistence and resumability
- Coordinates triage and deeper analysis phases

**Key Methods**:

#### `setup_llm()` (lines 58-86)
- Initializes three specialized LLM instances:
  - **Planner LLM**: `gpt-4o` with tool binding for planning
  - **Evaluator LLM**: `gpt-4o-mini` with structured output for validation
  - **Analyzer LLM**: `gpt-4o` with structured output for threat analysis
- Loads forensics tools and binds them appropriately
- Triggers graph building after LLM setup

#### `build_graph()` (lines 91-134)
- Constructs the LangGraph state machine
- Registers 6 nodes: planner, validate_plan, evaluator, execution, triage, deeper_analysis
- Defines conditional routing logic:
  - Evaluator → planner (retry) | execution (proceed) | END (max retries)
  - Execution → triage (success) | END (failure)
  - Triage → deeper_analysis (high threat) | END (low threat)

#### `_triage_node()` (lines 212-270)
- **Purpose**: Analyze execution results to identify threats
- **Process**:
  1. Gathers analysis context from execution results and evidence files
  2. Checks token count - triggers chunked analysis if needed
  3. Performs analysis (single or chunked)
  4. Returns structured threat intelligence

#### `_perform_chunked_analysis()` (lines 272-376)
- **Critical Feature**: Handles large evidence sets exceeding token limits
- **Process**:
  1. Counts tokens in full context
  2. Splits context into manageable chunks (max 20k tokens each)
  3. Saves chunks to disk for resumability
  4. Checks for existing chunk results (resume capability)
  5. Analyzes each chunk with rate limiting
  6. Combines results from all chunks
  7. Saves metadata and combined results

**Key Innovation**: Resumable chunked analysis prevents re-processing expensive chunks on interruption.

#### `_gather_analysis_context()` (lines 523-586)
- Collects evidence from multiple sources:
  - Global triage summaries
  - Phase execution summaries
  - All `.txt` output files from evidence directory
- **Deduplication Logic**: Prevents duplicate plugin outputs (lines 567-575)
- Returns formatted context string for LLM analysis

### 2.2 Planner Node (`nodes/planner.py`)

**Purpose**: Generate comprehensive investigation plans using LLM.

**Workflow**:
1. Builds system and user messages with investigation context
2. Invokes planner LLM with tool binding
3. Extracts plan from LLM response
4. Returns plan in state

**Validation** (`validate_investigation_plan`, lines 74-123):
- Parses JSON from LLM response (handles markdown code blocks)
- Validates against JSON schema (`VOL3_PLAN_SCHEMA`)
- Performs quality validation (with flexible command validation)
- Returns validation status

**Fallback Mechanism**: If LLM fails, generates minimal fallback plan (lines 126-167)

### 2.3 Evaluator Node (`nodes/evaluator.py`)

**Purpose**: Validate Volatility 3 commands before execution.

**Process**:
1. Extracts investigation plan from state
2. Builds evaluation context
3. Invokes evaluator LLM with structured output (`EvaluatorOutput`)
4. Returns validation feedback

**Structured Output**:
```python
class EvaluatorOutput:
    feedback: str  # Detailed validation feedback
    success_criteria_met: bool  # All commands valid?
    user_input_needed: bool  # Requires fixes?
```

**Routing Logic** (`route_based_on_evaluation`, lines 83-122):
- If validation failed → retry planner (up to max_retries)
- If success criteria met → proceed to execution
- If max retries exceeded → END workflow

### 2.4 Execution Node (`nodes/execution.py`)

**Purpose**: Execute validated investigation plan using VolatilityExecutor.

**Process**:
1. Validates plan exists and passed validation
2. Creates evidence directory with timestamp
3. Executes global triage commands
4. Executes investigation phases
5. Generates execution summary with statistics
6. Determines execution status (completed/partial/failed)

**Output Structure**:
- `execution_results`: Detailed results per command
- `evidence_directory`: Path to organized evidence
- `execution_summary`: Statistics (success rate, suspicious hits, etc.)

**Status Determination**:
- `completed`: Success rate ≥ 80%
- `partial`: Success rate ≥ 50%
- `failed`: Success rate < 50%

### 2.5 Deeper Analysis Engine (`engines/deeper_analysis.py`)

**Purpose**: Perform targeted investigation when high-threat indicators detected.

**Trigger Conditions** (`should_trigger_deeper_analysis`, lines 74-106):
- Threat score ≥ 7.0 (configurable threshold)
- Analysis confidence < 0.8
- High-severity findings (code_injection, persistence, network_activity)

**Plan Generation** (`generate_deeper_analysis_plan`, lines 108-179):
- **LLM-Driven**: Uses planner LLM to generate intelligent, adaptive plans
- **Context-Aware**: Considers initial findings and threat patterns
- **Fallback**: Rule-based plan if LLM fails

**Command Templates** (lines 34-72):
- Pre-defined command sets for different threat categories:
  - Code injection: malfind, hollowfind, injected
  - Persistence: registry keys, services, scheduled tasks
  - Network: netscan, netstat, connections
  - Process anomalies: pslist, pstree, cmdline

**Execution** (`deeper_analysis_node`, lines 233-302):
1. Generates targeted plan based on initial findings
2. Converts plan to execution format
3. Executes commands in separate evidence directory
4. Returns comprehensive results

---

## 3. State Management

### 3.1 ForensicState TypedDict (`models/state.py`)

**Core Investigation Fields**:
- `memory_dump_path`: Path to memory dump file
- `investigation_plan`: Generated investigation plan (dict or JSON string)
- `os_hint`: Operating system hint (windows/linux/macos)
- `user_prompt`: Custom investigation context

**Validation & Execution Fields**:
- `validation_status`: "passed" | "failed"
- `execution_status`: "completed" | "partial" | "failed" | "skipped"
- `execution_results`: Detailed execution results dict
- `evidence_directory`: Path to evidence storage
- `execution_summary`: Statistics summary

**Analysis Fields**:
- `analysis_results`: Structured analysis results
- `threat_score`: Overall threat score (0.0-10.0)
- `analysis_confidence`: Confidence level (0.0-1.0)
- `key_indicators`: List of key IOCs
- `recommended_actions`: List of recommended next steps

**Workflow Control**:
- `retry_count`: Number of retry attempts
- `success_criteria_met`: Boolean flag
- `investigation_stage`: Current stage identifier

### 3.2 Pydantic Models

**EvaluatorOutput**: Structured validation results
**AnalysisOutput**: Structured threat analysis results
**SuspiciousFinding**: Individual finding with severity, evidence, score

---

## 4. Advanced Features

### 4.1 Chunked Analysis System

**Problem Solved**: Large memory dumps generate evidence exceeding LLM token limits (128k tokens).

**Solution Architecture**:

1. **Token Detection**: Uses tiktoken to accurately count tokens
2. **Intelligent Splitting**: Preserves logical boundaries (line-based)
3. **Persistence**: Saves chunks to disk before analysis
4. **Resumability**: Detects and loads existing chunk results
5. **Rate Limiting**: Delays between chunks to prevent API throttling
6. **Result Combination**: Merges findings from all chunks

**File Structure**:
```
forensics_evidence/
└── Challenge_YYYYMMDD_HHMMSS/
    ├── analysis_chunks/
    │   ├── chunk_001.txt
    │   ├── chunk_002.txt
    │   ├── chunks_metadata.json
    │   └── chunk_001_result.json
    └── analysis_results/
        └── chunked_analysis_metadata_*.json
```

**Resumability Benefits**:
- Cost optimization (skip completed chunks)
- Time efficiency (resume from interruption)
- Debugging (inspect individual chunks)
- Audit trail (complete analysis record)

### 4.2 Rate Limiting & Error Handling

**Rate Limit Handling** (`_analyze_single_chunk`, lines 405-479):
- Detects 429 errors from API
- Extracts wait time from error message
- Implements exponential backoff
- Retries up to `max_retries` times

**Chunk-Level Resilience**:
- Individual chunk failures don't stop entire analysis
- Failed chunks logged and skipped
- Partial results still provide value

### 4.3 Evidence Organization

**Directory Structure**:
- Timestamped case directories
- Organized by investigation phase (01_triage, 02_processes, etc.)
- Separate directories for deeper analysis
- Comprehensive logging in `logs/` subdirectory

**Chain of Custody**:
- Timestamps on all evidence files
- Execution summaries with metadata
- Analysis results with full context

---

## 5. Configuration System

### 5.1 ForensicsConfig (`config/settings.py`)

**Analysis Settings**:
- `max_chunk_tokens`: 20,000 (conservative limit)
- `max_retries`: 5
- `rate_limit_delay`: 1.0s (base delay)
- `max_rate_limit_delay`: 60.0s (maximum delay)

**LLM Settings**:
- `planner_model`: "gpt-4o"
- `evaluator_model`: "gpt-4o-mini"
- `analyzer_model`: "gpt-4o"
- `llm_temperature`: 0.0 (deterministic)
- `llm_max_tokens`: 4000

**Thresholds**:
- `threat_score_threshold`: 7.0 (triggers deeper analysis)
- `confidence_threshold`: 0.8

**Environment Variable Support**: All settings can be overridden via `.env` file

---

## 6. Data Flow

### 6.1 Investigation Flow

1. **Input**: Memory dump path, OS hint, user prompt
2. **Planning**: LLM generates investigation plan
3. **Validation**: Schema and quality checks
4. **Evaluation**: Volatility command validation
5. **Execution**: Volatility commands run, evidence collected
6. **Triage**: AI analyzes evidence, generates threat intelligence
7. **Deeper Analysis** (conditional): Targeted investigation if high threat
8. **Output**: Comprehensive JSON reports and summaries

### 6.2 Analysis Context Flow

```
Execution Results
  ↓
_gather_analysis_context()
  ↓
Formatted Context String
  ↓
Token Count Check
  ↓
[If > max_chunk_tokens]
  ↓
_split_analysis_context()
  ↓
Chunk List
  ↓
Save Chunks to Disk
  ↓
Analyze Each Chunk
  ↓
Combine Results
  ↓
Final Analysis Report
```

---

## 7. Key Design Decisions

### 7.1 Multiple Specialized LLMs
- **Rationale**: Different tasks require different model capabilities
- **Planner**: Needs creativity and tool use → `gpt-4o`
- **Evaluator**: Simple validation → `gpt-4o-mini` (cost-effective)
- **Analyzer**: Complex threat analysis → `gpt-4o`

### 7.2 Chunked Analysis
- **Rationale**: Real-world memory dumps generate massive evidence
- **Implementation**: Line-based splitting preserves logical boundaries
- **Resumability**: Critical for long-running investigations

### 7.3 Conditional Deeper Analysis
- **Rationale**: Not all investigations need deep dive
- **Trigger**: Threat score threshold (configurable)
- **Benefit**: Cost and time efficiency

### 7.4 Structured Output
- **Rationale**: Ensures consistent, parseable results
- **Implementation**: Pydantic models with LangChain structured output
- **Benefit**: Type safety and validation

---

## 8. Strengths & Capabilities

### 8.1 Production-Ready Features
✅ Comprehensive error handling and retry logic
✅ Rate limiting and API throttling protection
✅ Resumable chunked analysis
✅ Detailed logging and evidence preservation
✅ Flexible configuration system
✅ Modular, maintainable architecture

### 8.2 AI-Powered Intelligence
✅ LLM-driven investigation planning
✅ Adaptive deeper analysis based on findings
✅ Intelligent threat scoring and confidence assessment
✅ Context-aware command generation

### 8.3 Scalability
✅ Handles large evidence sets via chunking
✅ Token-aware processing
✅ Efficient resource management

---

## 9. Potential Improvements

### 9.1 Identified Areas
1. **Parallel Chunk Processing**: Currently sequential, could parallelize
2. **Smart Chunk Prioritization**: Analyze high-priority chunks first
3. **Incremental Updates**: Update analysis as new evidence arrives
4. **Cross-Investigation Correlation**: Link findings across cases

### 9.2 Code Quality Observations
- **Line 63**: Empty set `{}` for planning_tools filter - may be intentional
- **Line 885**: Duplicate `_save_single_analysis_result` method definition
- **Deduplication Logic** (lines 567-575): Could be more robust

---

## 10. Usage Patterns

### 10.1 Basic Investigation
```python
from forensics_agent import run_investigation

result = await run_investigation(
    memory_dump_path="/path/to/memory.raw",
    os_hint="windows",
    user_prompt="Ransomware incident investigation"
)
```

### 10.2 Custom Configuration
```python
from forensics_agent import MemoryForensicsAgent
from config import ForensicsConfig

config = ForensicsConfig(
    max_chunk_tokens=25000,
    threat_score_threshold=6.0
)

agent = MemoryForensicsAgent(config)
await agent.setup_llm()
result = await agent.investigate(...)
```

---

## 11. Technical Stack

- **Python 3.12+**
- **LangChain**: LLM integration and tool binding
- **LangGraph**: Workflow orchestration
- **Pydantic**: Data validation and schemas
- **Volatility 3**: Memory forensics framework
- **tiktoken**: Token counting (via LangChain)
- **python-dotenv**: Environment configuration

---

## 12. Conclusion

Achilles is a sophisticated, well-architected memory forensics agent that successfully combines:
- **AI Intelligence**: LLM-driven planning and analysis
- **Robustness**: Comprehensive error handling and resumability
- **Scalability**: Chunked processing for large evidence sets
- **Production Quality**: Professional evidence organization and reporting

The modular design, clear separation of concerns, and advanced features like resumable chunked analysis make it a production-ready solution for automated memory forensics investigations.

