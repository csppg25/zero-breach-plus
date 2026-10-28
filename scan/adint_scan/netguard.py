"""Runtime enforcement of doctrine D2: never contact an indicator.

D2 is the most important rule in the project. Resolving a C&C domain, or opening
any connection, would announce a possible victim to the people running the
infrastructure. The tool is a local string-matching tool; it has no reason to
touch the network at all.

We do not merely *intend* not to resolve anything — we make it impossible. While a
scan runs inside `no_network()`, every name-resolution and outbound-connection
entry point in the `socket` module raises `NetworkContactAttempt`. A bug that tried
to resolve an IOC would crash loudly instead of leaking a signal.

This does NOT block `subprocess` (OS pipes, not Python sockets), so the host
module can still read the LOCAL DNS resolver cache via PowerShell — reading an
already-cached entry resolves nothing.

The IOC-update path (not implemented here) is the one explicitly-invoked network
operation the spec allows; it must run OUTSIDE this guard and verify a signature.
"""

from __future__ import annotations

import contextlib
import socket
from typing import List


class NetworkContactAttempt(RuntimeError):
    """Raised when scan code tries to resolve a name or open a connection."""


# Functions on the socket module that perform resolution or egress.
_BLOCKED = (
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "getnameinfo",
    "create_connection",
)


class _Recorder:
    def __init__(self) -> None:
        self.attempts: List[str] = []

    def trip(self, what: str) -> None:
        self.attempts.append(what)
        raise NetworkContactAttempt(
            "D2 violation: scan code attempted network contact via {}. "
            "The scanner must never resolve or connect to an indicator.".format(what))


@contextlib.contextmanager
def no_network():
    """Context manager that disables all socket-level resolution and egress."""
    recorder = _Recorder()
    saved = {}

    for name in _BLOCKED:
        if hasattr(socket, name):
            saved[name] = getattr(socket, name)

            def make(fn_name):
                def blocked(*_a, **_k):
                    recorder.trip("socket." + fn_name)
                return blocked
            setattr(socket, name, make(name))

    # Methods on the socket OBJECT that open a connection or send egress. sendto
    # and sendmsg matter because a UDP datagram needs no prior connect(): without
    # them a bug could still push bytes to a resolver or a C&C over UDP.
    _SOCK_METHODS = ("connect", "connect_ex", "sendto", "sendmsg", "sendall",
                     "send")
    saved_methods = {}
    for mname in _SOCK_METHODS:
        if hasattr(socket.socket, mname):
            saved_methods[mname] = getattr(socket.socket, mname)

            def make_method(m):
                def blocked(self, *_a, **_k):
                    recorder.trip("socket.socket." + m)
                return blocked
            setattr(socket.socket, mname, make_method(mname))

    try:
        yield recorder
    finally:
        for name, fn in saved.items():
            setattr(socket, name, fn)
        for mname, fn in saved_methods.items():
            setattr(socket.socket, mname, fn)
