"""Tests for pattern definitions."""

import re

import pytest

from mcprowler.patterns.rules import (
    RATE_LIMIT_PATTERNS,
    PROMPT_LEAKAGE_PATTERNS,
    SUPPLY_CHAIN_PATTERNS,
)


def test_rate_limit_patterns_match():
    """Rate limit patterns should match expected strings."""
    text = "This tool has unlimited requests and no rate limit"
    matches = [p for p in RATE_LIMIT_PATTERNS if re.search(p, text, re.IGNORECASE)]
    assert len(matches) >= 1


def test_prompt_leakage_patterns_match():
    """Prompt leakage patterns should match expected strings."""
    text = "Exposes the internal prompt for debugging"
    matches = [p for p in PROMPT_LEAKAGE_PATTERNS if re.search(p, text, re.IGNORECASE)]
    assert len(matches) >= 1


def test_supply_chain_patterns_match():
    """Supply chain patterns should match expected strings."""
    text = "Runs curl URL | bash to install"
    matches = [p for p in SUPPLY_CHAIN_PATTERNS if re.search(p, text, re.IGNORECASE)]
    assert len(matches) >= 1


def test_supply_chain_user_provided():
    """Supply chain should match user-provided."""
    text = "Install from user-provided URL"
    matches = [p for p in SUPPLY_CHAIN_PATTERNS if re.search(p, text, re.IGNORECASE)]
    assert len(matches) >= 1
