#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "redis",
#     "logfire",
#     "httpx",
# ]
# ///
"""
Alpha UserPromptSubmit hook - one hook to rule them all.

Creates the root span for this turn and outputs metadata for the Deliverator
to extract and promote to HTTP headers. Also fetches memories from Intro
and includes them in the metadata payload for the Loom to inject.

Architecture:
1. Create a ROOT span (turn:{session_id}) - the "bar tab"
2. Fetch memories from Intro API (if available)
3. Serialize traceparent for context propagation
4. Output DELIVERATOR_METADATA JSON block with memories included
5. Write traceparent to Redis for Stop hook to join the trace

The Loom extracts memories from metadata and injects them as content blocks
AFTER the user message. Loom strips metadata before forwarding to Anthropic.

Input (via stdin): JSON with session_id, prompt, transcript_path, etc.
Output (via stdout): JSON with hookSpecificOutput containing metadata
"""

import json
import os
import sys

import httpx
import logfire
import redis
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# Configuration
REDIS_URL = os.environ.get("REDIS_URL", "redis://alpha-pi:6379")
INTRO_URL = os.environ.get("INTRO_URL", "http://localhost:8100")

# The canary that marks our metadata block
CANARY = "DELIVERATOR_METADATA_UlVCQkVSRFVDSw"

# Initialize Logfire
# Scrubbing disabled - too aggressive (redacts "session", "auth", etc.)
# Our logs are authenticated with 30-day retention; acceptable risk for debugging visibility
# CRITICAL: send_to_logfire="if-token-present" disables console output
# Without this, Logfire writes colored logs to stdout which breaks hook JSON output
logfire.configure(
    service_name="user-prompt-submit",
    scrubbing=False,
    send_to_logfire="if-token-present",
    console=False,  # Explicitly disable console output
)


def fetch_memories(prompt: str, session_id: str) -> tuple[list[dict], list[str]]:
    """Fetch memories from Intro API.

    Returns (memories, queries) or ([], []) on error.
    Each memory is a dict with: id, created_at, content
    """
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                f"{INTRO_URL}/prompt",
                json={"message": prompt, "session_id": session_id},
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("memories", []), data.get("queries", [])
    except Exception as e:
        logfire.debug("Failed to fetch memories from Intro", error=str(e))
    return [], []


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("{}")
        sys.exit(0)

    session_id = input_data.get("session_id", "")
    prompt = input_data.get("prompt", "")
    transcript_path = input_data.get("transcript_path", "")
    source = input_data.get("source", "unknown")  # "alpha" or "iota" etc.
    machine = input_data.get("machine", {})

    if not session_id or not prompt:
        print("{}")
        sys.exit(0)

    short_session = session_id[:8] if session_id else "unknown"

    # Truncate prompt for span name - first 50 chars, single line
    prompt_preview = prompt[:50].replace("\n", " ").strip()
    if len(prompt) > 50:
        prompt_preview += "…"

    # ==========================================================
    # ROOT SPAN: The "bar tab" - everything downstream is a child
    # Span name IS the prompt preview - makes traces easy to find
    # ==========================================================
    with logfire.span(
        prompt_preview,
        _level="info",
    ) as span:
        span.set_attribute("session.id", session_id)
        span.set_attribute("transcript.path", transcript_path)
        span.set_attribute("prompt.length", len(prompt))
        span.set_attribute("source", source)
        if machine:
            span.set_attribute("machine.fqdn", machine.get("fqdn", ""))

        # Log the prompt (truncated for sanity)
        logfire.info(
            "User prompt received",
            session=short_session,
            source=source,
            prompt_preview=prompt[:200] + "..." if len(prompt) > 200 else prompt,
        )

        # ==========================================================
        # Fetch memories from Intro
        # ==========================================================
        memories, queries = fetch_memories(prompt, session_id)
        if memories:
            logfire.info(
                "Fetched memories",
                session=short_session,
                count=len(memories),
                queries=queries,
            )
            span.set_attribute("memories.count", len(memories))
            span.set_attribute("memories.queries", queries)

        # Serialize context for propagation
        # Logfire wraps OTel, so we can still use TraceContextTextMapPropagator
        headers = {}
        TraceContextTextMapPropagator().inject(headers)
        traceparent = headers.get("traceparent", "")

        parts = traceparent.split("-")
        trace_id = parts[1] if len(parts) >= 3 else ""

        span.set_attribute("trace.id", trace_id)
        span.set_attribute("traceparent", traceparent)

        # Write traceparent to Redis for Stop hook to join this trace
        try:
            r = redis.from_url(REDIS_URL)
            r.set(f"turn_context:{session_id}", traceparent, ex=300)
        except Exception as e:
            logfire.warning("Failed to write traceparent to Redis", error=str(e))

        # ==========================================================
        # Build metadata for the Deliverator
        # ==========================================================
        metadata = {
            "canary": CANARY,
            "session_id": session_id,
            "traceparent": traceparent,
        }

        # Pattern selection: LOOM_PATTERN env var controls which pattern the Great Loom uses
        # e.g., LOOM_PATTERN=iota for Iota, LOOM_PATTERN=passthrough for direct Claude access
        loom_pattern = os.environ.get("LOOM_PATTERN")
        if loom_pattern:
            metadata["pattern"] = loom_pattern

        # Include memories in metadata for the Loom to inject
        # Each memory has: id, created_at, content
        if memories:
            metadata["memories"] = memories
            metadata["memory_queries"] = queries

        output = {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": json.dumps(metadata),
            }
        }
        print(json.dumps(output))

    # Force flush before exit - critical for short-lived scripts
    logfire.force_flush()
    sys.exit(0)


if __name__ == "__main__":
    main()
