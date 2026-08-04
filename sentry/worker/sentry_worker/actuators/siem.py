"""SIEM emitter — CEF, LEEF, or Splunk HEC.

A tool that demands its own console gets checked on Mondays. The security team
already watches something; these events go there.

Delivery is TCP syslog with a bounded in-process spool. A SIEM that is down must
not stall a pipeline run and must not silently swallow the alerts raised while
it was — so the spool holds them, the counter says how many, and the drain
happens on the next successful send.
"""

from __future__ import annotations

import json
import socket
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sentry_core.config import settings

VERSION = "siem-1.0.0"

VENDOR = "SENTRY"
PRODUCT = "APILifecycle"
DEVICE_VERSION = "1.0"

#: Event severities, 0-10 in CEF's scale.
#:
#: A control being applied is a 4 and a zombie carrying customer data is a 9,
#: because an analyst triaging a queue needs the two to sort differently. Every
#: event at the same severity is the same as no severity at all.
SEVERITY = {
    "ZOMBIE_CRITICAL": 9,
    "RESURRECTION_ALERT": 9,
    "SHADOW_DETECTED": 8,
    "QUARANTINE_HIT": 8,
    "HONEYPOT_PROBE": 7,
    "CONTROL_APPLIED": 4,
    "DECOMMISSION_PHASE": 3,
}


@dataclass
class Event:
    name: str
    message: str
    endpoint_id: str | None = None
    method: str | None = None
    path: str | None = None
    service: str | None = None
    src: str | None = None
    cdri: float | None = None
    frameworks: list[str] = field(default_factory=list)
    time_to_breach_d: int | None = None
    extra: dict = field(default_factory=dict)

    @property
    def severity(self) -> int:
        return SEVERITY.get(self.name, 5)


def _escape_cef(value: str) -> str:
    """CEF extension values escape backslash, equals and newline.

    An unescaped ``=`` in a path splits one field into two and silently corrupts
    every field after it in the record — the parser does not complain, it just
    reads the wrong thing.
    """
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\n", " ").replace("\r", " "))


def _escape_header(value: str) -> str:
    """Header fields are pipe-delimited, so a pipe must be escaped."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def to_cef(e: Event) -> str:
    ext: list[str] = []
    if e.service:
        ext.append(f"dst={_escape_cef(e.service)}")
    if e.src:
        ext.append(f"src={_escape_cef(e.src)}")
    if e.method:
        ext.append(f"requestMethod={_escape_cef(e.method)}")
    if e.path:
        ext.append(f"request={_escape_cef(e.path)}")
    if e.cdri is not None:
        ext.append(f"cs1Label=CDRI cs1={e.cdri:.3f}")
    if e.frameworks:
        ext.append(f"cs2Label=Frameworks cs2={_escape_cef(';'.join(e.frameworks))}")
    if e.endpoint_id:
        ext.append(f"cs3Label=Endpoint cs3={_escape_cef(e.endpoint_id)}")
    if e.time_to_breach_d is not None:
        ext.append(f"cn1Label=TimeToBreachDays cn1={e.time_to_breach_d}")
    for k, v in e.extra.items():
        ext.append(f"{k}={_escape_cef(v)}")

    header = "|".join([
        "CEF:0", VENDOR, PRODUCT, DEVICE_VERSION,
        _escape_header(e.name), _escape_header(e.message), str(e.severity),
    ])
    return header + "|" + " ".join(ext)


def to_leef(e: Event) -> str:
    """QRadar's format. Tab-delimited attributes, not space-delimited."""
    attrs = {
        "cat": e.name, "sev": str(e.severity), "msg": e.message,
    }
    if e.service:
        attrs["dst"] = e.service
    if e.src:
        attrs["src"] = e.src
    if e.method:
        attrs["requestMethod"] = e.method
    if e.path:
        attrs["request"] = e.path
    if e.cdri is not None:
        attrs["cdri"] = f"{e.cdri:.3f}"
    if e.endpoint_id:
        attrs["endpointId"] = e.endpoint_id
    if e.frameworks:
        attrs["frameworks"] = ";".join(e.frameworks)
    attrs.update({k: str(v) for k, v in e.extra.items()})

    header = "|".join(["LEEF:2.0", VENDOR, PRODUCT, DEVICE_VERSION, e.name])
    body = "\t".join(f"{k}={str(v).replace(chr(9), ' ')}" for k, v in attrs.items())
    return header + "|" + body


def to_hec(e: Event) -> str:
    """Splunk HTTP Event Collector envelope."""
    return json.dumps({
        "time": datetime.now(timezone.utc).timestamp(),
        "sourcetype": "sentry:apilifecycle",
        "event": {
            "name": e.name, "severity": e.severity, "message": e.message,
            "endpoint_id": e.endpoint_id, "method": e.method, "path": e.path,
            "service": e.service, "src": e.src, "cdri": e.cdri,
            "frameworks": e.frameworks,
            "time_to_breach_d": e.time_to_breach_d, **e.extra,
        },
    }, separators=(",", ":"))


FORMATTERS = {"cef": to_cef, "leef": to_leef, "hec": to_hec}


def format_event(e: Event, fmt: str | None = None) -> str:
    return FORMATTERS[(fmt or settings.siem_format).lower()](e)


class Emitter:
    """Bounded spool over a TCP syslog sink.

    The spool is what makes an unavailable SIEM a delay rather than a data loss,
    and bounding it is what stops that delay becoming an unbounded memory leak.
    Overflow drops the *oldest* and counts it: the newest alert is the one an
    analyst most likely still needs, and a silent overwrite would make the estate
    look quieter than it is.
    """

    def __init__(self, host: str | None = None, port: int | None = None,
                 fmt: str | None = None, spool_max: int | None = None) -> None:
        self.host = host if host is not None else settings.siem_host
        self.port = port or settings.siem_port
        self.fmt = fmt or settings.siem_format
        self.spool_max = spool_max or settings.siem_spool_max

        self._spool: deque[str] = deque(maxlen=self.spool_max)
        self._lock = threading.Lock()
        self.sent = 0
        self.dropped = 0
        self.failures = 0

    @property
    def configured(self) -> bool:
        return bool(self.host)

    @property
    def spooled(self) -> int:
        with self._lock:
            return len(self._spool)

    def _send_line(self, line: str) -> None:
        with socket.create_connection((self.host, self.port), timeout=5) as sock:
            sock.sendall(line.encode("utf-8") + b"\n")

    def emit(self, event: Event) -> bool:
        """Format, then deliver or spool. Returns whether it reached the sink."""
        line = format_event(event, self.fmt)

        if not self.configured:
            # No sink configured is not a failure to report — it is a
            # deployment that has not wired one. The event is spooled so
            # /operations/siem can show what would have been sent.
            with self._lock:
                before = len(self._spool)
                self._spool.append(line)
                if len(self._spool) == before == self.spool_max:
                    self.dropped += 1
            return False

        try:
            self._send_line(line)
        except OSError:
            self.failures += 1
            with self._lock:
                before = len(self._spool)
                self._spool.append(line)
                if len(self._spool) == before == self.spool_max:
                    self.dropped += 1
            return False

        self.sent += 1
        self.drain()
        return True

    def drain(self) -> int:
        """Flush the spool. Returns how many went.

        Stops at the first failure and leaves the rest spooled, in order: a
        sink that just refused one line will refuse the next hundred, and
        hammering it is not recovery.
        """
        if not self.configured:
            return 0
        flushed = 0
        while True:
            with self._lock:
                if not self._spool:
                    return flushed
                line = self._spool[0]
            try:
                self._send_line(line)
            except OSError:
                self.failures += 1
                return flushed
            with self._lock:
                if self._spool and self._spool[0] == line:
                    self._spool.popleft()
            self.sent += 1
            flushed += 1

    def stats(self) -> dict:
        return {
            "configured": self.configured,
            "host": self.host, "port": self.port, "format": self.fmt,
            "sent": self.sent, "spooled": self.spooled,
            "dropped": self.dropped, "failures": self.failures,
        }

    def peek(self, n: int = 20) -> list[str]:
        with self._lock:
            return list(self._spool)[-n:]


#: Process-wide emitter. The spool has to outlive a single pipeline run for a
#: drain-on-recovery to mean anything.
_default: Emitter | None = None


def default_emitter() -> Emitter:
    global _default
    if _default is None:
        _default = Emitter()
    return _default


def reset_default() -> None:
    """Test seam. A spool shared between tests is a test that passes because of
    the one before it."""
    global _default
    _default = None
