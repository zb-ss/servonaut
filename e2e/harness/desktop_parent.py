"""Stand-in for the desktop window process: start the desktop child, then wait.

A journey runs this file as its own process (``python desktop_parent.py
<startup-timeout>``) so it can kill it the way a crashing window dies, and
then check that the child notices and exits. It starts the child through the
product's launcher exactly as the window does, prints one JSON line with the
child's origin, session token and pid, and then waits until its standard
input closes.

Standard library and Servonaut only: it runs as a guarded child process, not
inside the test suite.
"""

from __future__ import annotations

import json
import os
import socket
import sys

from servonaut.desktop.model import SecretToken
from servonaut.desktop.process_tree import launch_and_handshake_desktop_child


def main() -> int:
    startup_timeout = float(sys.argv[1])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    token = SecretToken.generate()
    tree, ready = launch_and_handshake_desktop_child(
        [sys.executable, "-m", "servonaut.desktop.child"],
        origin=origin,
        token=token,
        listener=listener,
        startup_timeout=startup_timeout,
        env=dict(os.environ),
    )
    listener.close()
    print(
        json.dumps({"origin": ready.origin, "token": token.encoded_value(), "pid": tree.pid}),
        flush=True,
    )
    sys.stdin.read()
    tree.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
