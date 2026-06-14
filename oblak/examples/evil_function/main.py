"""Deliberately unsafe example - NEGATIVE test case for the Code Verifier.

This file is NOT meant to run on the platform. It exists only so the verification
pipeline can be demonstrated rejecting unsafe code: it uses `os.system` and `eval`,
both of which are on the verifier's forbidden-call list. Deploying this function and
triggering verification must result in status REJECTED (HTTP 422).

The payloads are harmless on purpose (a simple echo and a trivial arithmetic eval);
the point is detection, not impact.
"""

import os


def handler(event: dict | None = None) -> int:
    # Forbidden: spawning a process through the shell.
    os.system("echo this-should-be-rejected")
    # Forbidden: dynamic code execution.
    return eval("1 + 1")
