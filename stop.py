#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "redis",
#     "httpx",
#     "pondside @ file:///Pondside/Basement/SDK",
# ]
# ///
"""
Alpha Stop hook.

Fires when the assistant is done responding (no more tool calls, response complete).
This is the "end of turn" signal—the hook that feeds Intro 2.0.

Workflow:
1. Get last-read position from Redis (transcript:position:{session_id})
2. Read transcript from that position to EOF
3. Parse JSONL, extract user and assistant messages
4. Call Intro 2.0 /stop endpoint with the turn messages
5. Update position in Redis

Input (via stdin): JSON with session_id, transcript_path, etc.
Output (via stdout): Empty (no additional context needed)
"""

import json
import logging
import os
import sys
from pathlib import Path

import httpx
import redis
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.context import attach

from pondside.telemetry import init, get_tracer

# Initialize telemetry
init("stop-hook")
logger = logging.getLogger(__name__)
tracer = get_tracer()

# Redis connection
REDIS_URL = os.environ.get("REDIS_URL", "redis://alpha-pi:6379")

# Intro 2.0 API - runs on primer
INTRO_URL = os.environ.get("INTRO_URL", "http://localhost:8100")


def classify_line(line: str) -> dict | None:
    """Parse a JSONL line and extract the interesting bits.

    Returns a dict with:
        - type: The message type (user, assistant, system, etc.)
        - role: The message role if present
        - content_types: List of content block types (text, tool_use, tool_result)
        - raw: The original JSON

    Returns None if the line can't be parsed.
    """
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    msg_type = data.get("type")
    message = data.get("message", {})
    role = message.get("role")

    # Extract content block types
    content = message.get("content", [])
    if isinstance(content, str):
        content_types = ["text"]
    elif isinstance(content, list):
        content_types = list({block.get("type", "text") for block in content if isinstance(block, dict)})
    else:
        content_types = []

    return {
        "type": msg_type,
        "role": role,
        "content_types": content_types,
        "raw": data,
    }


def extract_text_content(message: dict) -> str:
    """Extract text content from a message dict."""
    content = message.get("content", [])

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        texts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(block.get("text", ""))
        return "\n".join(texts)

    return ""


def read_transcript(transcript_path: str, start_pos: int) -> tuple[int, list[dict]]:
    """Read new lines from transcript starting at position.

    Returns (new_position, list_of_classified_lines).
    """
    path = Path(transcript_path)
    if not path.exists():
        logger.warning(f"Transcript not found: {transcript_path}")
        return start_pos, []

    try:
        with open(path, "r") as f:
            f.seek(start_pos)
            content = f.read()
            new_pos = f.tell()

        if not content:
            return new_pos, []

        lines = []
        for line in content.strip().split("\n"):
            if line:
                classified = classify_line(line)
                if classified:
                    lines.append(classified)

        return new_pos, lines

    except Exception as e:
        logger.error(f"Error reading transcript: {e}")
        return start_pos, []


def extract_turn_messages(lines: list[dict]) -> list[dict]:
    """Extract user and assistant messages from classified lines for Intro 2.0.

    Returns list of {"role": "user"|"assistant", "content": "..."}.
    """
    turn = []
    for classified in lines:
        # The transcript format uses role as the type field
        msg_type = classified["type"]
        role = classified["role"]

        # Accept both formats: type="message" with role, or type=role directly
        if msg_type == "message":
            if role not in ("user", "assistant"):
                continue
        elif msg_type in ("user", "assistant"):
            role = msg_type
        else:
            continue

        text = extract_text_content(classified["raw"].get("message", {}))
        if text:
            turn.append({"role": role, "content": text})

    return turn


def call_intro_stop(session_id: str, turn: list[dict], traceparent: str = ""):
    """Call Intro 2.0 /stop endpoint (fire and forget).

    Args:
        session_id: Session identifier
        turn: List of turn messages
        traceparent: W3C traceparent header for context propagation
    """
    if not turn:
        return

    try:
        headers = {"Content-Type": "application/json"}
        if traceparent:
            headers["traceparent"] = traceparent

        with httpx.Client(timeout=5.0) as client:
            response = client.post(
                f"{INTRO_URL}/stop",
                json={"session_id": session_id, "turn": turn},
                headers=headers,
            )
            if response.status_code == 202:
                logger.info(f"Intro 2.0 /stop accepted for session {session_id[:8]}")
            else:
                logger.warning(f"Intro 2.0 /stop returned {response.status_code}")
    except Exception as e:
        # Don't crash the hook if Intro is down
        logger.warning(f"Intro 2.0 /stop failed: {e}")


def main():
    # Read input from stdin BEFORE creating spans
    try:
        input_data = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        input_data = {}

    session_id = input_data.get("session_id", "")
    transcript_path = input_data.get("transcript_path", "")

    if not session_id or not transcript_path:
        logger.warning("Missing session_id or transcript_path")
        print("{}")
        return

    # Try to get parent context from Redis (set by UserPromptSubmit)
    parent_context = None
    try:
        r_sync = redis.from_url(REDIS_URL, decode_responses=True)
        traceparent = r_sync.get(f"turn_context:{session_id}")
        if traceparent:
            carrier = {"traceparent": traceparent}
            parent_context = TraceContextTextMapPropagator().extract(carrier=carrier)
    except Exception:
        pass  # Fall back to no parent context

    # Create span with parent context (or as root if none found)
    with tracer.start_as_current_span("stop-hook", context=parent_context) as span:
        span.set_attribute("session_id", session_id[:8] if session_id else "none")

        logger.info(f"Stop hook: session={session_id[:8]}, transcript={transcript_path}")

        try:
            r = redis.from_url(REDIS_URL, decode_responses=True)

            # Get last-read position
            # If not set, SessionStart didn't run (edge case)—seek to EOF and start fresh
            # This prevents firehosing Intro with the entire transcript history
            position_key = f"transcript:position:{session_id}"
            stored_pos = r.get(position_key)

            if stored_pos is None:
                # No position set—seek to EOF, store it, and skip this turn
                # (SessionStart should have set this, but handle the edge case)
                eof_pos = Path(transcript_path).stat().st_size
                r.set(position_key, eof_pos)
                logger.info(f"No position found, seeded to EOF ({eof_pos})")
                print("{}")
                return

            start_pos = int(stored_pos)

            # Read new content from transcript
            new_pos, lines = read_transcript(transcript_path, start_pos)

            span.set_attribute("lines_read", len(lines))
            span.set_attribute("start_pos", start_pos)
            span.set_attribute("end_pos", new_pos)

            if lines:
                logger.info(f"Read {len(lines)} lines from pos {start_pos} to {new_pos}")

                # Call Intro 2.0 /stop with turn messages (ONLY for Alpha pattern)
                # Intro is Alpha's metacognitive layer - it shouldn't watch Iota or other patterns
                loom_pattern = os.environ.get("LOOM_PATTERN")

                if loom_pattern == "alpha":
                    turn = extract_turn_messages(lines)
                    if turn:
                        call_intro_stop(session_id, turn, traceparent or "")
                        span.set_attribute("intro2_turn_messages", len(turn))
                else:
                    logger.debug(f"Skipping Intro (pattern is {loom_pattern}, not alpha)")

            else:
                logger.info(f"No new content (pos {start_pos} -> {new_pos})")

            # Update position for next time
            r.set(position_key, new_pos)

            # NOTE: Legacy Redis publish removed 2026-01-21
            # Original Intro subscribed to events:{session_id} for stop signals
            # Now using Intro 2.0 HTTP /stop endpoint directly (line 268)

        except Exception as e:
            logger.error(f"Error: {e}")
            span.record_exception(e)

        # No output needed
        print("{}")


if __name__ == "__main__":
    main()
