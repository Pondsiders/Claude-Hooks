#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "redis",
#     "logfire",
# ]
# ///
"""
Alpha UserPromptSubmit hook - Deliverator metadata injection.

Creates the root span for this turn and outputs metadata for the Deliverator
to extract and promote to HTTP headers.

Architecture:
1. Create a ROOT span (turn:{session_id}) - the "bar tab"
2. Serialize traceparent for context propagation
3. Output DELIVERATOR_METADATA JSON block
4. Write traceparent to Redis for Stop hook to join the trace

Memory injection is handled by a separate hook (memories.py).

Input (via stdin): JSON with session_id, prompt, transcript_path, etc.
Output (via stdout): JSON with hookSpecificOutput containing metadata
"""

import json
import os
import sys

import logfire
import redis
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# Configuration
REDIS_URL = os.environ.get("REDIS_URL", "redis://alpha-pi:6379")

# The canary that marks our metadata block
CANARY = "DELIVERATOR_METADATA_UlVCQkVSRFVDSw"

# Initialize Logfire
# Scrubbing disabled - too aggressive (redacts "session", "auth", etc.)
# Our logs are authenticated with 30-day retention; acceptable risk for debugging visibility
logfire.configure(
    service_name="user-prompt-submit",
    scrubbing=False,
)


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

    # ==========================================================
    # ROOT SPAN: The "bar tab" - everything downstream is a child
    # ==========================================================
    with logfire.span(
        "turn {short_session}",
        short_session=short_session,
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
