"""Utility functions for the C2 manager application."""
from __future__ import annotations

import re


def strip_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape sequences from text.
    
    Args:
        text: Input text potentially containing ANSI escape codes
        
    Returns:
        Cleaned text without ANSI escape sequences
    """
    # Remove terminal title sequences like ]0;... (OSC sequences)
    # These often start without ESC (using \x1b] which becomes just ])
    text = re.sub(r'\x1b\][0-9];[^\x07\x1b]*[\x07\x1b]', '', text)
    text = re.sub(r'\][0-9];[^\x07\x1b]*\x07', '', text)
    text = re.sub(r'\][0-9];[^\\]*\\', '', text)
    
    # Pattern to match ANSI escape sequences
    ansi_escape = re.compile(r'''
        \x1B  # ESC
        (?:   # 7-bit C1 Fe (except CSI)
            [@-Z\\-_]
        |     # or [ for CSI, followed by control sequence
            \[
            [0-?]*  # Parameter bytes
            [ -/]*  # Intermediate bytes
            [@-~]   # Final byte
        )
    ''', re.VERBOSE)
    
    # Remove ANSI escape sequences
    text = ansi_escape.sub('', text)
    
    # Also remove CSI sequences that may start with just [
    text = re.sub(r'\[[0-9;]*[a-zA-Z]', '', text)
    
    # Remove bell character
    text = text.replace('\x07', '')
    
    # Remove carriage returns and excessive newlines
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    
    return text.strip()


def clean_shell_output(text: str) -> str:
    """
    Clean shell output for display.
    
    Args:
        text: Raw shell output
        
    Returns:
        Cleaned and formatted output
    """
    text = strip_ansi_codes(text)
    
    # Remove duplicate prompts
    lines = text.split('\n')
    cleaned_lines = []
    
    for line in lines:
        # Skip empty lines or lines with just prompt
        if line.strip() and not re.match(r'^[\$\#\>]\s*$', line.strip()):
            cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)
