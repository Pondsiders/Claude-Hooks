#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pondside @ file:///Pondside/Basement/SDK",
#     "redis",
# ]
# ///
"""
Alpha SessionStart hook.

The ONE SessionStart hook that does everything:
1. Exports CLAUDE_SESSION_ID to the environment (via hook-0.sh)
2. (Future) Fetches last memory, weather, todos, etc.

This hook is idempotent—it may be called multiple times for the same session
(on resume, compact, etc.) and should handle that gracefully.

BRUTE FORCE FIX (Jan 17, 2026):
Claude Code has a bug where on resume, CLAUDE_ENV_FILE points to a NEW
ephemeral directory instead of the original session's directory. So we
ignore CLAUDE_ENV_FILE entirely and write directly to:
    ~/.claude/session-env/{session_id}/hook-0.sh

This ensures environment variables are available regardless of whether
it's a fresh start or a resume.

Input (via stdin): JSON with session_id, transcript_path, source, etc.
Output (via stdout): JSON with hookSpecificOutput.additionalContext
"""

import json
import logging
import os
from pathlib import Path
import sys

import redis

from pondside.telemetry import init, get_tracer

# Redis connection
REDIS_URL = os.environ.get("REDIS_URL", "redis://alpha-pi:6379")

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


def main():
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
        # (Future: fetch last memory, weather, todos, etc.)
        context_parts = []

        # For now, just confirm we're alive
        # context_parts.append(f"Session: {session_id[:8]}... ({source})")

        # --- Output ---
        if context_parts:
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": "\n".join(context_parts)
                }
            }
        else:
            output = {}

        print(json.dumps(output))


if __name__ == "__main__":
    main()
