from __future__ import annotations

import json
import os
import socket
import subprocess
import sys

HOST_CID = 2
RESULT_PORT = 52
CODE_DRIVE = "/dev/vdb"
MOUNT_POINT = "/mnt/artifact"


def mount_code_drive() -> None:
    os.makedirs(MOUNT_POINT, exist_ok=True)
    subprocess.run(
        ["mount", "-o", "ro", CODE_DRIVE, MOUNT_POINT],
        check=True,
    )


def connect_to_host() -> socket.socket:
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.connect((HOST_CID, RESULT_PORT))
    return sock


def main() -> None:
    try:
        mount_code_drive()
    except Exception as exc:
        sys.stderr.write(f"mount failed: {exc}\n")
        os.system("reboot -f")
        return

    sys.path.insert(0, "/")
    from microvm import runner

    sock = connect_to_host()
    try:
        raw = b""
        while not raw.endswith(b"\n"):
            raw += sock.recv(1024)
        event = json.loads(raw.decode())

        code_dir = os.path.join(MOUNT_POINT, "code")
        result = runner.run(code_dir, event)
        sock.sendall(json.dumps(result).encode())
    except Exception as exc:
        error_payload = {"error": str(exc), "return_code": 1,
                         "stdout": "", "stderr": "", "return_value": None}
        sock.sendall(json.dumps(error_payload).encode())
    finally:
        sock.close()

    os.system("reboot -f")


if __name__ == "__main__":
    main()
