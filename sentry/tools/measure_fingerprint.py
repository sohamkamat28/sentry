"""What the field shingles are worth, measured on captured traffic.

Builds the real profile for every live endpoint through the runner's own
`_behaviour_profile`, then scores the resurrection pair — `/api/v1/legacy-balance`
and its redeployment `/api/v2/balance-v2` — against every other endpoint, twice:
once with the `field:` shingles the classifier now produces and once with that
group stripped, which is exactly the fingerprint this system had before.

The number that matters is not the true-pair score on its own. It is the margin
between it and the nearest unrelated endpoint, because that margin is what a
threshold has to sit inside.
"""

import sys

import pathlib

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "worker"))
sys.path.insert(0, str(_ROOT / "core"))

from sentry_core.db import SessionLocal
from sentry_core.models import Endpoint
from sentry_worker import runner
from sentry_worker.engines import fingerprint
from sqlalchemy import select

TRUE_PAIR = ("/api/v1/legacy-balance", "/api/v2/balance-v2")


def jaccard(a, b):
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def strip_fields(sh: list[str]) -> set[str]:
    return {s for s in sh if not s.startswith("field:")}


with SessionLocal() as db:
    eps = db.execute(select(Endpoint)).scalars().all()  # retired included: the origin is retired by definition

    profiles = {}
    for ep in eps:
        p = runner._behaviour_profile(db, ep)
        if not p["observations"]:
            continue
        profiles[ep.path_template] = (ep, p, fingerprint.behavioural_shingles(p))

origin = next((v for k, v in profiles.items() if k == TRUE_PAIR[0]), None)
target = next((v for k, v in profiles.items() if k == TRUE_PAIR[1]), None)

if origin is None or target is None:
    print(f"pair not both present: origin={origin is not None} target={target is not None}")
    print("available:", sorted(profiles))
    raise SystemExit(1)

_, oprof, osh = origin
_, tprof, tsh = target

print(f"origin  {TRUE_PAIR[0]}  obs={oprof['observations']}")
print(f"  fields: {oprof['response_fields']}")
print(f"target  {TRUE_PAIR[1]}  obs={tprof['observations']}")
print(f"  fields: {tprof['response_fields']}")
print()

for label, proj in (("with field: shingles", set), ("without (the old fingerprint)", strip_fields)):
    o, t = proj(osh), proj(tsh)
    true_score = jaccard(set(o), set(t))

    worst_name, worst = None, 0.0
    for path, (_, _, sh) in profiles.items():
        if path in TRUE_PAIR:
            continue
        s = jaccard(set(o), set(proj(sh)))
        if s > worst:
            worst_name, worst = path, s

    verdict = "DETECTED" if true_score >= 0.85 else "MISSED"
    print(f"{label}:")
    print(f"  true pair            {true_score:.3f}   [{verdict} at threshold 0.85]")
    print(f"  nearest false match  {worst:.3f}   {worst_name}")
    print(f"  margin               {true_score - worst:+.3f}")
    print()
