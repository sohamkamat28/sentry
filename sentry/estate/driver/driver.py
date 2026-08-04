"""Reference estate traffic driver.

Generates real HTTPS requests against the estate services on a virtual clock.
Traffic is real, TLS is real, capture is real; only the wall-clock interval
between observations is compressed.

The driver reads the vclock row from Postgres — the same row the platform reads —
so generation and analysis cannot drift apart. It writes to no other table.
"""

from __future__ import annotations

import argparse
import asyncio
import math
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml

BUSINESS_HOURS = [0, 0, 0, 0, 0, 1, 2, 4, 7, 9, 10, 10, 9, 9, 10, 9, 7, 5, 3, 2, 1, 1, 0, 0]
FLAT_HOURS = [1] * 24


@dataclass
class Profile:
    base_rate: int = 0
    weekly: list[float] = field(default_factory=lambda: [1.0] * 7)
    hourly: str = "flat"
    trend: str = "flat"
    growth_pct_per_vday: float = 0.0
    decay_start_vday: int | None = None
    decay_half_life_vdays: int = 7
    silent_from_vday: int | None = None
    schedule: str | None = None
    burst: int = 0

    def calls_for(self, vday: int) -> int:
        """Calls to issue on this vday.

        The weekly factor is applied here, which is exactly what makes the
        forecast's deseasonalisation necessary downstream: without it, a window
        ending on a weekend trough reads a rising endpoint as declining.
        """
        if self.schedule == "quarterly":
            # Silent for 89 vdays at a stretch. A 30-day window would call this
            # dead; the 90-day window is what keeps it alive.
            return self.burst if vday % 90 == 0 else 0

        if self.silent_from_vday is not None and vday >= self.silent_from_vday:
            return 0

        rate = float(self.base_rate)

        if self.trend == "growth":
            rate *= (1.0 + self.growth_pct_per_vday / 100.0) ** vday
        elif self.trend == "decay" and self.decay_start_vday is not None:
            if vday >= self.decay_start_vday:
                elapsed = vday - self.decay_start_vday
                rate *= 0.5 ** (elapsed / max(1, self.decay_half_life_vdays))

        rate *= self.weekly[vday % 7]
        return max(0, int(round(rate)))

    def hour_weights(self) -> list[int]:
        return BUSINESS_HOURS if self.hourly == "business_hours" else FLAT_HOURS


@dataclass
class ServiceSpec:
    service: str
    endpoints: list[str]
    profile: Profile
    criticality: str = "CUSTOMER"
    calls: list[str] = field(default_factory=list)
    registered_in_gateway: bool = True
    in_repository: bool = True
    internet_reachable: bool = False

    @property
    def base_url(self) -> str:
        host = os.getenv(f"HOST_{self.service.upper().replace('-', '_')}", self.service)
        return f"https://{host}:8443"


def load_spec(path: Path) -> tuple[list[ServiceSpec], list[dict]]:
    raw = yaml.safe_load(path.read_text())
    services = []
    for s in raw["services"]:
        p = Profile(**(s.get("profile") or {}))
        services.append(ServiceSpec(
            service=s["service"], endpoints=s["endpoints"], profile=p,
            criticality=s.get("criticality", "CUSTOMER"),
            calls=s.get("calls", []),
            registered_in_gateway=s.get("registered_in_gateway", True),
            in_repository=s.get("in_repository", True),
            internet_reachable=s.get("internet_reachable", False),
        ))
    return services, raw.get("events", [])


def current_vday(database_url: str) -> int:
    """Read the shared clock. The driver never writes it."""
    import sqlalchemy as sa

    engine = sa.create_engine(database_url)
    with engine.connect() as c:
        row = c.execute(sa.text(
            "SELECT epoch_wall, scale_seconds, paused_vday FROM vclock WHERE id = 1"
        )).first()
    if row is None:
        return 0
    epoch, scale, paused = row
    if paused is not None:
        return int(paused)
    from datetime import datetime, timezone

    if epoch.tzinfo is None:
        epoch = epoch.replace(tzinfo=timezone.utc)
    elapsed = (datetime.now(timezone.utc) - epoch).total_seconds()
    return max(0, math.floor(elapsed / scale))


class Driver:
    def __init__(self, services: list[ServiceSpec], events: list[dict],
                 database_url: str, scale_seconds: int, concurrency: int = 16) -> None:
        self.services = services
        self.events = sorted(events, key=lambda e: e["vday"])
        self.database_url = database_url
        self.scale_seconds = scale_seconds
        self.sem = asyncio.Semaphore(concurrency)
        self.fired: set[int] = set()
        self.rng = random.Random(20260726)

    async def run_vday(self, client: httpx.AsyncClient, vday: int) -> dict[str, int]:
        """Issue one vday of traffic, spread across the compressed interval."""
        issued: dict[str, int] = {}
        tasks = []
        for spec in self.services:
            n = spec.profile.calls_for(vday)
            if n <= 0:
                continue
            # Scale to what fits in the compressed window; the shape is what
            # matters to the analysis, not the absolute count.
            emit = max(1, min(n, int(self.scale_seconds * 4)))
            issued[spec.service] = emit
            for _ in range(emit):
                path = self.rng.choice(spec.endpoints)
                tasks.append(self._call(client, spec, path))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return issued

    async def _call(self, client: httpx.AsyncClient, spec: ServiceSpec, endpoint: str) -> None:
        method, _, path = endpoint.partition(" ")
        path = path.replace("{id}", str(self.rng.randint(10_000, 99_999)))
        async with self.sem:
            try:
                await client.request(method, f"{spec.base_url}{path}", timeout=5.0)
            except Exception:
                # A service being down is the estate's problem, not the driver's.
                pass

    def events_for(self, vday: int) -> list[dict]:
        out = [e for e in self.events if e["vday"] == vday and e["vday"] not in self.fired]
        for e in out:
            self.fired.add(e["vday"])
        return out


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profiles", default=str(Path(__file__).parent / "profiles.yaml"))
    ap.add_argument("--database-url", default=os.getenv("DATABASE_URL", ""))
    ap.add_argument("--scale", type=int, default=int(os.getenv("VCLOCK_SCALE_SECONDS", "30")))
    ap.add_argument("--until", type=int, default=240)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the traffic plan without issuing requests")
    args = ap.parse_args()

    services, events = load_spec(Path(args.profiles))
    driver = Driver(services, events, args.database_url, args.scale)

    if args.dry_run:
        print(f"{'vday':>5}  {'total':>8}  events")
        for vday in range(0, args.until + 1, 10):
            total = sum(s.profile.calls_for(vday) for s in services)
            evs = [e["action"] for e in events if e["vday"] == vday]
            print(f"{vday:>5}  {total:>8}  {', '.join(evs)}")
        return

    async with httpx.AsyncClient(verify=False) as client:
        while True:
            vday = current_vday(args.database_url) if args.database_url else 0
            if vday > args.until:
                print(f"reached vday {vday}, stopping")
                return
            for e in driver.events_for(vday):
                print(f"[vday {vday}] event: {e['action']} -> {e.get('target')}")
            issued = await driver.run_vday(client, vday)
            print(f"[vday {vday}] issued {sum(issued.values())} requests "
                  f"across {len(issued)} services")
            await asyncio.sleep(max(1, args.scale // 3))


if __name__ == "__main__":
    asyncio.run(main())
