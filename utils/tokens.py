"""
Token counting utilities for the Memory Forensics Agent.

This module provides functions for counting tokens to manage LLM context limits
and implement intelligent chunking strategies.
"""

import tiktoken
from typing import List


def count_tokens(text: str, model: str = "gpt-4o") -> int:
    """
    Count tokens in text using tiktoken.
    
    Args:
        text: Text to count tokens for
        model: Model name for encoding selection
        
    Returns:
        Number of tokens in the text
    """
    try:
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(text))
    except KeyError:
        # Fallback to cl100k_base encoding if model not found
        encoding = tiktoken.get_encoding("cl100k_base")
        return len(encoding.encode(text))


def split_text_by_tokens(text: str, max_tokens: int, model: str = "gpt-4o") -> List[str]:
    """
    Split text into chunks based on token limits while preserving logical boundaries.
    
    Args:
        text: Text to split
        max_tokens: Maximum tokens per chunk
        model: Model name for encoding selection
        
    Returns:
        List of text chunks
    """
    chunks = []
    lines = text.split('\n')
    current_chunk = []
    current_tokens = 0
    
    for line in lines:
        line_tokens = count_tokens(line + '\n', model)
        
        # If adding this line would exceed the limit, start a new chunk
        if current_tokens + line_tokens > max_tokens and current_chunk:
            chunks.append('\n'.join(current_chunk))
            current_chunk = [line]
            current_tokens = line_tokens
        else:
            current_chunk.append(line)
            current_tokens += line_tokens
    
    # Add the last chunk if it has content
    if current_chunk:
        chunks.append('\n'.join(current_chunk))
    
    return chunks


def estimate_response_tokens(prompt_tokens: int, max_response_tokens: int = 4000) -> int:
    """
    Estimate how many tokens will be available for the response.
    
    Args:
        prompt_tokens: Number of tokens in the prompt
        max_response_tokens: Maximum tokens the model can generate
        
    Returns:
        Estimated available response tokens
    """
    # Leave some buffer for safety
    buffer = 100
    available = max_response_tokens - buffer
    return max(0, available - prompt_tokens)
