#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pondside @ file:///Pondside/Basement/SDK",
#     "redis",
#     "logfire",
#     "pendulum",
# ]
# ///
"""
Alpha SessionStart hook.

Handles all session start events (startup, resume, clear, compact).

KEY FEATURE: On compact, injects Deliverator metadata so the Loom knows
to apply AlphaPattern. This ensures the continuation prompt gets rewritten
to "stop and check in" instead of "continue without asking questions."

The problem this solves:
- UserPromptSubmit doesn't fire for SDK-generated continuation prompts
- Without metadata, the Loom defaults to PassthroughPattern
- PassthroughPattern doesn't rewrite continuation instructions
- Alpha plows ahead without checking in after compaction

The fix:
- SessionStart:compact fires BEFORE the continuation request is built
- We inject the same metadata payload that UserPromptSubmit would
- Deliverator promotes x-loom-pattern header
- Loom applies AlphaPattern with continuation rewriting

Other responsibilities:
1. Exports CLAUDE_SESSION_ID to the environment (via hook-0.sh)
2. Seeds transcript position for Stop hook

BRUTE FORCE FIX (Jan 17, 2026):
Claude Code has a bug where on resume, CLAUDE_ENV_FILE points to a NEW
ephemeral directory instead of the original session's directory. So we
ignore CLAUDE_ENV_FILE entirely and write directly to:
    ~/.claude/session-env/{session_id}/hook-0.sh

Input (via stdin): JSON with session_id, transcript_path, source, etc.
Output (via stdout): JSON with hookSpecificOutput.additionalContext
"""

import json
import logging
import os
from pathlib import Path
import sys

import logfire
import pendulum
import redis
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from pondside.telemetry import init, get_tracer

# Redis connection
REDIS_URL = os.environ.get("REDIS_URL", "redis://alpha-pi:6379")

# The canary that marks our metadata block (must match user_prompt_submit.py)
CANARY = "DELIVERATOR_METADATA_UlVCQkVSRFVDSw"

# Initialize telemetry
init("session-start-hook")
logger = logging.getLogger(__name__)
tracer = get_tracer()


def seed_transcript_position(session_id: str, transcript_path: str) -> bool:
    """Seed the transcript position to EOF so Stop hook only captures new content.

    This runs at session start (fresh or resume). By setting the position to EOF,
    we ensure the Stop hook only publishes content from THIS session, not the
    entire transcript history (which would firehose Intro after a compaction).

    Returns True if successful, False otherwise.
    """
    if not transcript_path:
        logger.warning("No transcript_path provided, skipping position seed")
        return False

    path = Path(transcript_path)
    if not path.exists():
        logger.warning(f"Transcript not found: {transcript_path}")
        return False

    try:
        # Get file size (EOF position)
        eof_position = path.stat().st_size

        # Store in Redis
        r = redis.from_url(REDIS_URL, decode_responses=True)
        position_key = f"transcript:position:{session_id}"
        r.set(position_key, eof_position)

        logger.info(f"Seeded transcript position to {eof_position} for session {session_id[:8]}")
        return True
    except Exception as e:
        logger.error(f"Failed to seed transcript position: {e}")
        return False


def setup_environment(session_id: str) -> bool:
    """Write session ID to the correct hook file for subsequent Bash commands.

    BRUTE FORCE: We ignore CLAUDE_ENV_FILE entirely because on resume it points
    to a new ephemeral directory. Instead, we write directly to:
        ~/.claude/session-env/{session_id}/hook-0.sh

    This ensures the environment is set up correctly for BOTH fresh starts
    and resumed sessions.

    Returns True if successful, False otherwise.
    """
    # Construct the path ourselves using the REAL session_id
    session_env_dir = Path.home() / ".claude" / "session-env" / session_id
    hook_file = session_env_dir / "hook-0.sh"

    try:
        # Create the directory if it doesn't exist
        session_env_dir.mkdir(parents=True, exist_ok=True)

        # Write session ID export
        # We overwrite rather than append to keep it idempotent
        hook_file.write_text(f'export CLAUDE_SESSION_ID="{session_id}"\n')

        logger.info(f"Wrote CLAUDE_SESSION_ID to {hook_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to write hook file: {e}")
        return False


def build_deliverator_metadata(session_id: str, span) -> str | None:
    """Build the Deliverator metadata payload for pattern routing.

    This is the same format as user_prompt_submit.py uses, so the
    Deliverator can extract and promote to HTTP headers.

    Returns JSON string or None if we can't build it.
    """
    if not session_id:
        return None

    # Get pattern from environment (same as user_prompt_submit.py)
    loom_pattern = os.environ.get("LOOM_PATTERN")
    if not loom_pattern:
        logger.warning("LOOM_PATTERN not set, can't build metadata")
        return None

    # Generate traceparent for distributed tracing
    # This creates a new trace for the compact continuation
    headers = {}
    TraceContextTextMapPropagator().inject(headers)
    traceparent = headers.get("traceparent", "")

    if traceparent:
        span.set_attribute("traceparent", traceparent)

    # Build metadata payload
    # PSO-8601 timestamp: "Mon Jan 27 2026, 12:32 PM"
    sent_at = pendulum.now("America/Los_Angeles").format("ddd MMM D YYYY, h:mm A")

    metadata = {
        "canary": CANARY,
        "session_id": session_id,
        "traceparent": traceparent,
        "pattern": loom_pattern,
        "sent_at": sent_at,
    }

    logger.info(f"Built Deliverator metadata: pattern={loom_pattern}, session={session_id[:8]}")
    return json.dumps(metadata)


def main():
    # Initialize Logfire for distributed tracing
    # Must happen before we try to inject traceparent
    logfire.configure(
        service_name="session-start-hook",
        scrubbing=False,
        send_to_logfire="if-token-present",
        console=False,
    )

    with tracer.start_as_current_span("session-start") as span:
        # Read input from stdin
        try:
            input_data = json.loads(sys.stdin.read())
        except json.JSONDecodeError:
            input_data = {}

        session_id = input_data.get("session_id", "")
        source = input_data.get("source", "unknown")
        transcript_path = input_data.get("transcript_path", "")

        # Log the invocation
        span.set_attribute("session_id", session_id[:8] if session_id else "none")
        span.set_attribute("source", source)
        logger.info(f"SessionStart: session={session_id[:8] if session_id else 'none'}, source={source}")

        # --- Task 1: Environment setup ---
        env_ok = setup_environment(session_id) if session_id else False
        span.set_attribute("env_setup", env_ok)

        # --- Task 2: Seed transcript position ---
        # This ensures Stop hook only captures content from THIS turn, not history
        pos_ok = seed_transcript_position(session_id, transcript_path) if session_id and transcript_path else False
        span.set_attribute("position_seeded", pos_ok)

        # --- Task 3: Build additional context ---
        additional_context = None

        # ON COMPACT: Inject Deliverator metadata so Loom applies AlphaPattern
        # This is the fix for the continuation prompt gap
        if source == "compact":
            logger.info("Compact detected - injecting Deliverator metadata for pattern routing")
            span.set_attribute("inject_metadata", True)
            additional_context = build_deliverator_metadata(session_id, span)
            if additional_context:
                logger.info("Metadata payload ready for Deliverator extraction")
            else:
                logger.warning("Failed to build metadata - continuation will use PassthroughPattern")

        # --- Output ---
        if additional_context:
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": additional_context
                }
            }
        else:
            output = {}

        print(json.dumps(output))

    # Force flush telemetry before exit
    logfire.force_flush()


if __name__ == "__main__":
    main()
