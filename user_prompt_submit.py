#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "redis",
#     "logfire",
#     "httpx",
#     "pendulum",
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
import pendulum
import redis
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# Configuration
REDIS_URL = os.environ.get("REDIS_URL", "redis://alpha-pi:6379")
INTRO_URL = os.environ.get("INTRO_URL", "http://localhost:8100")

# The canary that marks our metadata block
CANARY = "DELIVERATOR_METADATA_UlVCQkVSRFVDSw"

# Human session tracking for Routines
HUMAN_SESSION_KEY = "routine:human_session"
HUMAN_SESSION_TTL = 24 * 60 * 60  # 24 hours

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

    Injects traceparent header so Intro's spans become children of this hook's span.
    """
    try:
        # Inject current trace context into headers for distributed tracing
        headers = {}
        TraceContextTextMapPropagator().inject(headers)

        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                f"{INTRO_URL}/prompt",
                json={"message": prompt, "session_id": session_id},
                headers=headers,
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
        # Parse pattern and client from ANTHROPIC_CUSTOM_HEADERS
        # Headers are newline-separated: "x-loom-client: duckpond\nx-loom-pattern: alpha"
        # ==========================================================
        custom_headers = os.environ.get("ANTHROPIC_CUSTOM_HEADERS", "")
        loom_pattern = None
        loom_client = None

        for line in custom_headers.split("\n"):
            line = line.strip()
            if line.lower().startswith("x-loom-pattern:"):
                loom_pattern = line.split(":", 1)[1].strip()
            elif line.lower().startswith("x-loom-client:"):
                loom_client = line.split(":", 1)[1].strip()

        # Fallback to env var for backwards compatibility (e.g., LOOM_PATTERN=alpha claude)
        if not loom_pattern:
            loom_pattern = os.environ.get("LOOM_PATTERN")

        # ==========================================================
        # Fetch memories from Intro (ONLY for Alpha pattern)
        # Intro is Alpha's metacognitive layer - it shouldn't watch Iota or other patterns
        # ==========================================================
        memories, queries = [], []

        if loom_pattern == "alpha":
            memories, queries = fetch_memories(prompt, session_id)
        else:
            logfire.debug("Skipping Intro (pattern is not alpha)", pattern=loom_pattern)

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

            # ==========================================================
            # Human session tracking for Routines
            # ==========================================================
            # Only store session ID if this is a Duckpond session.
            # This enables the "to self" routine to fork from the day's conversation.
            # (loom_client already parsed above from ANTHROPIC_CUSTOM_HEADERS)
            if loom_client == "duckpond":
                r.setex(HUMAN_SESSION_KEY, HUMAN_SESSION_TTL, session_id)
                logfire.debug("Stored human session", session=short_session)

        except Exception as e:
            logfire.warning("Failed to write traceparent to Redis", error=str(e))

        # ==========================================================
        # Build metadata for the Deliverator
        # ==========================================================
        # PSO-8601 timestamp: "Mon Jan 27 2026, 12:32 PM"
        sent_at = pendulum.now("America/Los_Angeles").format("ddd MMM D YYYY, h:mm A")

        metadata = {
            "canary": CANARY,
            "session_id": session_id,
            "traceparent": traceparent,
            "sent_at": sent_at,
        }

        # Pattern selection: LOOM_PATTERN env var controls which pattern the Great Loom uses
        # e.g., LOOM_PATTERN=iota for Iota, LOOM_PATTERN=passthrough for direct Claude access
        # (loom_pattern already fetched above for Intro gating)
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
