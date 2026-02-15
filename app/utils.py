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


def clean_shell_output(text: str, command: str = "") -> str:
    """
    Clean shell output for display.
    
    Args:
        text: Raw shell output
        command: The command that was executed (used to strip the echoed command line)
        
    Returns:
        Cleaned and formatted output
    """
    text = strip_ansi_codes(text)

    lines = text.split('\n')
    cleaned_lines = []

    # Pattern matching common shell prompts: user@host:path$ or [user@host path]$ etc.
    # The ']' is placed at the start of the character class to be treated literally.
    prompt_re = re.compile(r'^\s*(\S+@\S+[]:]\S*\s*)?[\$\#\>]\s*')

    cmd_stripped = command.strip() if command else ""

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Skip lines that are just a prompt (with nothing after it)
        if re.match(r'^(\S+@\S+[]:]\S*\s*)?[\$\#\>]\s*$', stripped):
            continue
        # Skip keepalive echo lines (prompt + # keepalive)
        if '# keepalive' in stripped:
            continue
        # Skip the echoed command line: must be prompt + exact command
        if cmd_stripped:
            m = prompt_re.match(stripped)
            if m and stripped[m.end():].strip() == cmd_stripped:
                continue
        cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)
