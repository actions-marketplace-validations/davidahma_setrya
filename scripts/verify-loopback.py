"""Assert loopback works and an off-host connection is blocked."""

import errno
import socket

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    with socket.create_connection(listener.getsockname(), timeout=1):
        pass

with socket.socket() as external:
    external.settimeout(1)
    error = external.connect_ex(("192.0.2.1", 443))
    if error not in {errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH}:
        raise SystemExit(f"off-host socket was not blocked by policy or routing (errno {error})")

print("Network policy verified: loopback works and off-host routing is disabled", flush=True)
