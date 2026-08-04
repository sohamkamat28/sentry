"""Redis: live counters, the scan lock, and the stage 03 graph cache.

Everything in here is a cache or a coordination primitive, and nothing in here is
a system of record. That is the invariant the module exists to hold: a flushed
Redis must cost throughput and liveness, never a fact. Every read has a
Postgres-derived answer behind it, so the degraded path returns a smaller number
rather than a wrong one.

Two consequences are deliberate:

* Counters are advisory. ``observed()`` increments a key with a TTL of two
  virtual days; the console's capture stream reads it to avoid querying a
  partitioned table at 200 rows/s. The authoritative count is always
  ``SELECT count(*) FROM observation``, and the API says which one it served.
* A failed Redis call is swallowed and counted, not raised. An unreachable cache
  taking down the ingest hot path would convert a convenience dependency into an
  availability one — the exact inversion the readiness semantics in
  design/02-PLATFORM-SERVICES.md rule out.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator

from .config import settings

#: Set when a Redis operation has failed since the process started. Surfaced on
#: /readyz so a silently degraded cache is visible rather than inferred from a
#: counter that stopped moving.
_failures = 0
_failure_lock = threading.Lock()

_client: Any | None = None
_client_lock = threading.Lock()


def _note_failure() -> None:
    global _failures
    with _failure_lock:
        _failures += 1


def failures() -> int:
    return _failures


def client() -> Any | None:
    """The shared connection pool, or None when Redis is not configured.

    Built lazily and once. Constructing a client per call is what turns a cache
    into a source of connection exhaustion under the load this is meant to
    absorb.
    """
    global _client
    if _client is not None:
        return _client
    if not settings.redis_url:
        return None
    with _client_lock:
        if _client is not None:
            return _client
        try:
            import redis

            _client = redis.Redis.from_url(
                settings.redis_url,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
                health_check_interval=30,
            )
        except Exception:  # noqa: BLE001
            _note_failure()
            return None
    return _client


def ping() -> bool:
    c = client()
    if c is None:
        return False
    try:
        return bool(c.ping())
    except Exception:  # noqa: BLE001
        _note_failure()
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Live counters
# ─────────────────────────────────────────────────────────────────────────────
def observed(vday: int, source: str, n: int = 1) -> None:
    """Count n captures for a vday and a source.

    Called on the ingest hot path, so it must not raise and must not block for
    long: both timeouts on the client are 2s, and a failure is counted and
    dropped. Losing a counter increment loses a console tick; propagating the
    error would lose the batch.
    """
    c = client()
    if c is None:
        return
    ttl = settings.sensitive_ttl_seconds
    try:
        pipe = c.pipeline(transaction=False)
        pipe.incrby(f"live:obs:{vday}", n)
        pipe.expire(f"live:obs:{vday}", ttl)
        pipe.incrby(f"live:src:{source}", n)
        pipe.expire(f"live:src:{source}", ttl)
        pipe.execute()
    except Exception:  # noqa: BLE001
        _note_failure()


def live_counts(vday: int, sources: list[str]) -> dict[str, int] | None:
    """Counters for a vday, or None when the cache cannot answer.

    None and zero are different answers and the caller has to be able to tell
    them apart: zero is "nothing was captured", None is "ask Postgres". Folding
    the second into the first is how an outage comes to look like an idle
    estate.
    """
    c = client()
    if c is None:
        return None
    try:
        pipe = c.pipeline(transaction=False)
        pipe.get(f"live:obs:{vday}")
        for s in sources:
            pipe.get(f"live:src:{s}")
        got = pipe.execute()
    except Exception:  # noqa: BLE001
        _note_failure()
        return None
    out = {"total": int(got[0] or 0)}
    for name, raw in zip(sources, got[1:]):
        out[name] = int(raw or 0)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Graph cache
# ─────────────────────────────────────────────────────────────────────────────
GRAPH_CACHE_TTL_S = 600


def put_graph(vday: int, node_link: dict) -> bool:
    c = client()
    if c is None:
        return False
    try:
        c.setex(f"graph:{vday}", GRAPH_CACHE_TTL_S, json.dumps(node_link))
        return True
    except Exception:  # noqa: BLE001
        _note_failure()
        return False


def get_graph(vday: int) -> dict | None:
    c = client()
    if c is None:
        return None
    try:
        raw = c.get(f"graph:{vday}")
    except Exception:  # noqa: BLE001
        _note_failure()
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        # A corrupt cache entry is not a corrupt graph. Stage 09 rebuilds from
        # call_edge, which is where the edges actually live.
        return None


# ─────────────────────────────────────────────────────────────────────────────
# The scan lock
# ─────────────────────────────────────────────────────────────────────────────
class NotAcquired(RuntimeError):
    """Another cycle holds the lock. The caller skips and counts."""


#: A vhour in wall seconds. Fractional at demonstration scale.
VHOUR_S = settings.vclock_scale_seconds / 24.0

SCAN_INTERVAL_S = max(1.0, settings.scan_interval_vhours * VHOUR_S)

#: The lock outlives one interval but not many. Too short and an overrunning
#: cycle loses its own lock to the next tick — the concurrency the lock exists to
#: prevent. Too long and a killed worker wedges the schedule until it expires.
#:
#: Defined beside the lock rather than in ``sentry_worker.tasks`` because the API
#: takes the same lock on the manual scan route, and importing ``tasks`` to reach
#: a constant would construct a Celery app inside the web process. Two entry
#: points into one cycle must agree on the TTL, so there is one definition.
SCAN_LOCK_TTL_S = int(max(30, SCAN_INTERVAL_S * 10))


def _owner_token() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{time.time():.0f}"


@contextmanager
def scan_lock(*, ttl_s: int, key: str = "lock:scan") -> Iterator[str]:
    """Serialise pipeline cycles across every worker in the deployment.

    Stage ordering is enforced per-cycle, not across concurrent cycles: two
    overlapping passes both satisfy their dependency checks and then interleave
    their writes, so stage 06 in one cycle can read stage 05's output from the
    other. That is not a race the DAG can catch, which is why it is excluded
    here instead.

    The lock carries a TTL so a worker killed mid-cycle does not wedge the
    schedule permanently, and releases only if it still owns the token — a cycle
    that overran its TTL must not delete the lock a successor legitimately took.

    With no Redis configured this yields without excluding anything, and says so
    by yielding an empty token. A single-worker deployment is the common case for
    the prototype and refusing to run at all would be the wrong trade; a
    multi-worker deployment without Redis has no broker either, so there is no
    second worker to race with.
    """
    c = client()
    if c is None:
        yield ""
        return

    token = _owner_token()
    try:
        got = c.set(key, token, nx=True, ex=max(1, ttl_s))
    except Exception:  # noqa: BLE001
        _note_failure()
        # An unreachable Redis must not silently disable serialisation and let
        # two cycles interleave. Skipping is the safe direction: the next tick
        # retries, and the skip is counted.
        raise NotAcquired("redis unreachable, cannot serialise the cycle") from None

    if not got:
        raise NotAcquired("another cycle holds the scan lock")

    try:
        yield token
    finally:
        # Compare-and-delete. Plain DEL here is the classic bug: an overrunning
        # holder wakes up after its TTL expired, deletes the lock its successor
        # now owns, and the two run concurrently — the exact condition the lock
        # exists to prevent.
        try:
            c.eval(
                "if redis.call('get', KEYS[1]) == ARGV[1] then "
                "return redis.call('del', KEYS[1]) else return 0 end",
                1, key, token,
            )
        except Exception:  # noqa: BLE001
            _note_failure()


# ─────────────────────────────────────────────────────────────────────────────
# Cross-process counters
# ─────────────────────────────────────────────────────────────────────────────
# The worker has no HTTP listener, so a prometheus_client Counter inside it is
# unscrapeable. These are the counters a worker increments and the API exposes on
# /metrics: Redis is the only thing both processes can see. They carry no TTL —
# a monotonic counter that expires produces a negative rate at the scraper.
def bump(metric: str, n: int = 1) -> None:
    c = client()
    if c is None:
        return
    try:
        c.incrby(f"metric:{metric}", n)
    except Exception:  # noqa: BLE001
        _note_failure()


def counters(names: list[str]) -> dict[str, int]:
    """Values for the named counters. Absent keys read as zero, which is correct:
    a counter that has never been incremented is at zero."""
    c = client()
    if c is None:
        return {}
    try:
        pipe = c.pipeline(transaction=False)
        for n in names:
            pipe.get(f"metric:{n}")
        got = pipe.execute()
    except Exception:  # noqa: BLE001
        _note_failure()
        return {}
    return {n: int(v or 0) for n, v in zip(names, got)}


def reset_for_tests() -> None:
    """Drop the cached client so a test can point at a different Redis."""
    global _client, _failures
    with _client_lock:
        _client = None
    with _failure_lock:
        _failures = 0
