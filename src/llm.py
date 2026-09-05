"""OpenRouter ChatOpenAI factory and a model-independent structured-output helper.

No tool-calling, no response_format, no with_structured_output() on the demo path.
Any model that can emit text is enough."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import TypeVar

from langchain_core.output_parsers import PydanticOutputParser
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, ValidationError

from src.config import (
    HTTP_REFERER,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_MODEL,
    USE_NATIVE_STRUCTURED_OUTPUT,
    X_TITLE,
)

T = TypeVar("T", bound=BaseModel)

FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


class StructuredOutputError(Exception):
    """Raised after the initial parse and one repair round-trip both fail."""

    def __init__(self, message: str, raw: str = "", error: str = ""):
        super().__init__(message)
        self.raw = raw
        self.error = error


def get_llm(*, streaming: bool = False) -> ChatOpenAI:
    if not OPENROUTER_API_KEY:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not set. Copy .env.example to .env and add a key."
        )
    return ChatOpenAI(
        model=OPENROUTER_MODEL,
        api_key=OPENROUTER_API_KEY,
        base_url=OPENROUTER_BASE_URL,
        temperature=0,
        streaming=streaming,
        default_headers={
            "HTTP-Referer": HTTP_REFERER,
            "X-Title": X_TITLE,
        },
    )


def extract_json_object(text: str) -> str:
    """Strip markdown fences and surrounding prose; return the outermost `{...}`."""
    if not text:
        raise ValueError("empty model output")
    stripped = text.strip()
    fence = FENCE_RE.search(stripped)
    if fence:
        stripped = fence.group(1).strip()
    start = stripped.find("{")
    if start == -1:
        raise ValueError("no JSON object found in model output")
    return _outermost_object(stripped, start)


def _outermost_object(text: str, start: int) -> str:
    depth = 0
    in_str = False
    escape = False
    for i, ch in enumerate(text[start:], start=start):
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise ValueError("unbalanced JSON object in model output")


def parse_structured(schema: type[T], text: str) -> T:
    raw = extract_json_object(text)
    return schema.model_validate_json(raw)


def _format_instructions(schema: type[BaseModel]) -> str:
    parser = PydanticOutputParser(pydantic_object=schema)
    return (
        parser.get_format_instructions()
        + "\n\nReply with the JSON object and nothing else. "
        "No markdown fences, no commentary."
    )


def _invoke_text(prompt: str) -> str:
    msg = get_llm().invoke(prompt)
    content = msg.content
    if isinstance(content, str):
        return content
    return "".join(
        block.get("text", "") if isinstance(block, dict) else str(block)
        for block in content
    )


def _repair(schema: type[T], bad: str, error: str) -> T:
    prompt = (
        "Your previous reply was not valid JSON for the required schema.\n"
        f"Validation error:\n{error}\n\n"
        f"Previous reply:\n{bad}\n\n"
        "Return corrected JSON only — a single object matching this schema:\n"
        f"{_format_instructions(schema)}"
    )
    fixed = _invoke_text(prompt)
    return parse_structured(schema, fixed)


def structured(schema: type[T], prompt: str, **variables: object) -> T:
    """Render `prompt` with `variables`, force JSON, parse, one repair if needed."""
    body = prompt.format(**variables) if variables else prompt
    full = f"{body.rstrip()}\n\n{_format_instructions(schema)}"

    if USE_NATIVE_STRUCTURED_OUTPUT:
        llm = get_llm()
        try:
            return llm.with_structured_output(schema).invoke(full)  # type: ignore[return-value]
        except Exception as exc:  # noqa: BLE001 — fall back to the text path
            last_error = str(exc)
            try:
                return _repair(schema, "", last_error)
            except (ValidationError, ValueError) as repair_exc:
                raise StructuredOutputError(
                    "native structured output and repair both failed",
                    raw="",
                    error=str(repair_exc),
                ) from repair_exc

    raw = _invoke_text(full)
    try:
        return parse_structured(schema, raw)
    except (ValidationError, ValueError) as exc:
        try:
            return _repair(schema, raw, str(exc))
        except (ValidationError, ValueError) as repair_exc:
            raise StructuredOutputError(
                "structured output parse failed after repair",
                raw=raw,
                error=str(repair_exc),
            ) from repair_exc


def structured_stream(
    schema: type[T],
    prompt: str,
    on_token: Callable[[str], None] | None = None,
    **variables: object,
) -> T:
    """Stream tokens, then run the same parse/repair pipeline as `structured`."""
    body = prompt.format(**variables) if variables else prompt
    full = f"{body.rstrip()}\n\n{_format_instructions(schema)}"
    chunks: list[str] = []
    for piece in get_llm(streaming=True).stream(full):
        token = piece.content if isinstance(piece.content, str) else ""
        if token:
            chunks.append(token)
            if on_token:
                on_token(token)
    raw = "".join(chunks)
    try:
        return parse_structured(schema, raw)
    except (ValidationError, ValueError) as exc:
        try:
            return _repair(schema, raw, str(exc))
        except (ValidationError, ValueError) as repair_exc:
            raise StructuredOutputError(
                "structured output parse failed after repair",
                raw=raw,
                error=str(repair_exc),
            ) from repair_exc


def stream_text(prompt: str, **variables: object) -> Iterator[str]:
    """Yield markdown/prose tokens. Used by Incident Response for the live plan."""
    body = prompt.format(**variables) if variables else prompt
    for piece in get_llm(streaming=True).stream(body):
        token = piece.content if isinstance(piece.content, str) else ""
        if token:
            yield token
