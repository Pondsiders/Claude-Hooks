#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "redis",
#     "opentelemetry-api",
#     "opentelemetry-sdk",
#     "opentelemetry-exporter-otlp-proto-http",
# ]
# ///
"""
Alpha UserPromptSubmit hook - Deliverator metadata injection.

Creates the root span for this turn and outputs metadata for the Deliverator
to extract and promote to HTTP headers.

Architecture:
1. Create a ROOT span (user-turn:{session_id}) - the "bar tab"
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

import redis
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator


# Configuration
REDIS_URL = os.environ.get("REDIS_URL", "redis://alpha-pi:6379")

# The canary that marks our metadata block
CANARY = "DELIVERATOR_METADATA_UlVCQkVSRFVDSw"


def init_otel():
    """Initialize OpenTelemetry with OTLP exporter to Parallax."""
    resource = Resource.create({"service.name": "user-prompt-submit"})
    provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter(endpoint="http://alpha-pi:4318/v1/traces")
    provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    return trace.get_tracer("user-prompt-submit")


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("{}")
        sys.exit(0)

    session_id = input_data.get("session_id", "")
    prompt = input_data.get("prompt", "")
    transcript_path = input_data.get("transcript_path", "")

    if not session_id or not prompt:
        print("{}")
        sys.exit(0)

    tracer = init_otel()
    short_session = session_id[:8] if session_id else "unknown"

    # ==========================================================
    # ROOT SPAN: The "bar tab" - everything downstream is a child
    # ==========================================================
    with tracer.start_as_current_span(f"turn:{short_session}") as root_span:
        root_span.set_attribute("session.id", session_id)
        root_span.set_attribute("transcript.path", transcript_path)
        root_span.set_attribute("prompt", prompt[:500])
        root_span.set_attribute("prompt.length", len(prompt))

        # Serialize context for propagation
        headers = {}
        TraceContextTextMapPropagator().inject(headers)
        traceparent = headers.get("traceparent", "")

        parts = traceparent.split("-")
        trace_id = parts[1] if len(parts) >= 3 else ""

        root_span.set_attribute("trace.id", trace_id)
        root_span.set_attribute("traceparent", traceparent)

        # Write traceparent to Redis for Stop hook to join this trace
        try:
            r = redis.from_url(REDIS_URL)
            r.set(f"turn_context:{session_id}", traceparent, ex=300)
        except Exception:
            pass

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

    # Force flush before exit
    trace.get_tracer_provider().force_flush()
    sys.exit(0)


if __name__ == "__main__":
    main()
