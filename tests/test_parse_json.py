"""Unit tests for the model-independent JSON extractor — no API key required."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from src.llm import extract_json_object, parse_structured


class Toy(BaseModel):
    next_agent: str
    reason: str


def test_fenced_json() -> None:
    text = '```json\n{"next_agent": "log_monitor", "reason": "start"}\n```'
    obj = parse_structured(Toy, text)
    assert obj.next_agent == "log_monitor"
    assert obj.reason == "start"


def test_json_with_prose() -> None:
    text = (
        "Sure, here you go:\n"
        '{"next_agent": "threat_intel", "reason": "IOCs present"}\n'
        "Hope that helps."
    )
    obj = parse_structured(Toy, text)
    assert obj.next_agent == "threat_intel"


def test_nested_braces_inside_strings() -> None:
    text = '{"next_agent": "FINISH", "reason": "done {with} braces"}'
    obj = parse_structured(Toy, text)
    assert "braces" in obj.reason


def test_unbalanced_raises() -> None:
    with pytest.raises(ValueError, match="unbalanced"):
        extract_json_object('{"next_agent": "x", "reason":')


def test_no_object_raises() -> None:
    with pytest.raises(ValueError, match="no JSON object"):
        extract_json_object("there is nothing structured here")


def test_empty_raises() -> None:
    with pytest.raises(ValueError, match="empty"):
        extract_json_object("")
