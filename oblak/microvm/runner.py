from __future__ import annotations

import glob
import importlib.util
import io
import json
import os
import sys
import traceback


def run(code_dir: str, event: dict) -> dict:
    artifact_dir = os.path.dirname(code_dir)
    for sp in glob.glob(os.path.join(artifact_dir, "venv", "lib", "python*", "site-packages")):
        if sp not in sys.path:
            sys.path.insert(0, sp)
    sys.path.insert(0, code_dir)

    spec = importlib.util.spec_from_file_location("user_main", f"{code_dir}/main.py")
    mod = importlib.util.module_from_spec(spec)

    captured_out = io.StringIO()
    captured_err = io.StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = captured_out, captured_err

    return_value = None
    return_code = 0
    try:
        spec.loader.exec_module(mod)
        return_value = mod.handler(event)
    except SystemExit as exc:
        return_code = exc.code if isinstance(exc.code, int) else 1
    except Exception:
        traceback.print_exc()
        return_code = 1
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr

    return {
        "stdout": captured_out.getvalue(),
        "stderr": captured_err.getvalue(),
        "return_value": return_value,
        "return_code": return_code,
    }


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: runner.py <code_dir> <event_json>",
                          "return_code": 2}))
        sys.exit(2)

    code_dir = sys.argv[1]
    try:
        event = json.loads(sys.argv[2])
    except json.JSONDecodeError:
        event = {}

    result = run(code_dir, event)
    print(json.dumps(result))
