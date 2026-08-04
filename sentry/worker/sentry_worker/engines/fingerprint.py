"""Stage 12 — behavioural fingerprints and resurrection detection.

The fingerprint is keyed on **what an endpoint does**, never on where it lives.

An earlier build included path tokens in the shingle set. A redeployment under a
new path — the exact thing this detector exists to catch — scored 0.583 against
a 0.85 threshold, because the one property a rename changes was weighted
heavily. The path is the attacker's variable; it is excluded by construction and
a test asserts no path token can leak in.
"""

from __future__ import annotations

import pickle

from datasketch import MinHash, MinHashLSH

from sentry_core.config import settings

VERSION = "fp-1.0.0"

#: Keys deliberately excluded from the shingle set. Enforced by
#: test_no_path_token_leaks_into_the_shingle_set.
EXCLUDED_KEYS = frozenset({"path_template", "path", "path_raw", "url", "route", "host"})


def _hour_shape_band(hour_shape: list[int]) -> list[str]:
    """Summarise the daily rhythm in a bounded number of shingles.

    This emitted one shingle per hour — twenty-four of them — and that made the
    rhythm roughly seventy per cent of a thirty-three-shingle set by sheer
    cardinality. Jaccard has no notion of feature groups: it counts members. So
    any two endpoints driven by the same traffic pattern shared twenty-plus
    shingles before a single discriminating property was considered, and five
    unrelated endpoints in the reference estate scored above the 0.85 threshold
    against a retired one.

    A redeployed endpoint serves the same *shape* at a different volume, and the
    shape is what has to survive. Three shingles carry it — when the peaks are,
    how much of the day is busy, and the coarse class — which is comparable to
    what every other feature group contributes.
    """
    total = sum(hour_shape) or 1
    peaks, active = [], 0
    for hour, v in enumerate(hour_shape):
        share = v / total
        if share >= 0.10:
            peaks.append(hour)
        if share >= 0.03:
            active += 1

    if not peaks:
        shape = "flat"
    elif active <= 3:
        shape = "burst"
    elif all(8 <= h <= 18 for h in peaks):
        shape = "business-hours"
    elif any(h < 6 for h in peaks):
        shape = "overnight"
    else:
        shape = "spread"

    # The *count* of peaks, not which clock hours they fall in.
    #
    # Absolute peak hours made the fingerprint depend on when the redeployment
    # happened: the same handler brought back up an hour later peaked at 14
    # instead of 13, and that one token was the difference between detecting a
    # resurrection and missing it. Where in the day an endpoint is busy is still
    # captured, coarsely and robustly, by the rhythm class below — which is what
    # separates an overnight batch from a business-hours API without pinning the
    # signature to a wall clock.
    return [
        f"peakcount:{_bucket(len(peaks), (0, 1, 3, 6))}",
        f"activehours:{_bucket(active, (0, 2, 6, 12, 18))}",
        f"rhythm:{shape}",
    ]


#: Prefix the agent's identity resolver uses when it cannot name a workload,
#: followed by a container id. Mirrors looksLikeContainerID in
#: agent/internal/identity.
_UNRESOLVED_PREFIX = "container:"


def _is_unresolved_caller(caller: str) -> bool:
    name = caller.strip().lower()
    if name.startswith(_UNRESOLVED_PREFIX):
        return True
    bare = name.split(":")[-1]
    return len(bare) in (12, 64) and all(c in "0123456789abcdef" for c in bare)


def _bucket(n: int, edges: tuple[int, ...]) -> str:
    for e in edges:
        if n <= e:
            return f"<={e}"
    return f">{edges[-1]}"


def behavioural_shingles(profile: dict) -> list[str]:
    """Build the shingle set from behaviour only.

    ``profile`` may carry path fields — callers pass whole endpoint records — and
    they are ignored rather than trusted to be absent.
    """
    sh: list[str] = []

    sh.append(f"method:{profile.get('method', '')}")

    for field in sorted(profile.get("response_fields", []) or []):
        sh.append(f"field:{field}")

    for dc in sorted(profile.get("data_classes", []) or []):
        sh.append(f"class:{dc}")

    # Callers, but only ones with a name.
    #
    # When the identity resolver cannot name a workload it falls back to the
    # container id, which is unique per container and never recurs. Such a
    # shingle can only ever appear on one side of a comparison, so it subtracts
    # from every similarity score it touches while carrying no information about
    # behaviour — it is noise with a cost. A caller set that is entirely
    # unresolved contributes nothing, which is the honest outcome.
    for caller in sorted(profile.get("callers", []) or []):
        if _is_unresolved_caller(caller):
            continue
        sh.append(f"caller:{caller}")

    hour_shape = profile.get("hour_shape") or [0] * 24
    sh.extend(_hour_shape_band(list(hour_shape)))

    sh.append(f"auth:{profile.get('auth', 'none')}")
    sh.append(f"authmiss:{profile.get('auth_missing_band', 'none')}")

    # An unmeasured feature is omitted, not emitted as "unknown".
    #
    # Jaccard counts shared members, so `respsize:unknown` on both sides of a
    # comparison reads as agreement — when what it actually records is that
    # neither side was measured. On an estate where the sensor captures no
    # payload sizes that put two identical tokens into every pair, and two
    # unrelated endpoints scored 0.9167 against a retired one on the strength
    # of what nobody had observed.
    #
    # The same rule the console renders with: absent is not a value.
    for key, prefix in (("req_size_band", "reqsize"), ("resp_size_band", "respsize")):
        band = profile.get(key)
        if band and band != "unknown":
            sh.append(f"{prefix}:{band}")

    # Defensive: nothing derived from a path may survive into the set.
    return [s for s in sh if not any(k in s.lower() for k in ("path", "url", "route"))]


def build_minhash(shingles: list[str], num_perm: int | None = None) -> MinHash:
    m = MinHash(num_perm=num_perm or settings.minhash_perm)
    for s in shingles:
        m.update(s.encode())
    return m


def similarity(a: list[str] | MinHash, b: list[str] | MinHash) -> float:
    ma = a if isinstance(a, MinHash) else build_minhash(a)
    mb = b if isinstance(b, MinHash) else build_minhash(b)
    return float(ma.jaccard(mb))


def exact_jaccard(a: list[str], b: list[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)


def serialise(m: MinHash) -> bytes:
    return pickle.dumps(m, protocol=pickle.HIGHEST_PROTOCOL)


def deserialise(blob: bytes) -> MinHash:
    return pickle.loads(blob)


class ResurrectionIndex:
    """LSH index over retired-endpoint fingerprints.

    Rebuilt from the ``fingerprint`` table on startup, so a flushed cache costs a
    rebuild and never a silently empty result.
    """

    def __init__(self, threshold: float | None = None, num_perm: int | None = None) -> None:
        self.threshold = threshold if threshold is not None else settings.resurrection_threshold
        self.num_perm = num_perm or settings.minhash_perm
        self._lsh = MinHashLSH(threshold=self.threshold, num_perm=self.num_perm)
        self._hashes: dict[str, MinHash] = {}
        self._shingles: dict[str, set[str]] = {}
        self._paths: dict[str, str] = {}

    def insert(self, endpoint_id: str, shingles: list[str], origin_path: str) -> None:
        m = build_minhash(shingles, self.num_perm)
        if endpoint_id in self._hashes:
            self._lsh.remove(endpoint_id)
        self._lsh.insert(endpoint_id, m)
        self._hashes[endpoint_id] = m
        # Kept alongside the hash so the reported similarity can be exact. The
        # shingle sets are tens of strings, not thousands; there is no reason to
        # decide on an estimate when the exact answer is this cheap.
        self._shingles[endpoint_id] = set(shingles)
        self._paths[endpoint_id] = origin_path

    def query(self, shingles: list[str]) -> list[dict]:
        """Candidates via LSH, then **exact** Jaccard on the shortlist.

        The reported similarity is exact set Jaccard, not the MinHash estimate.

        This mattered in practice. A redeployment of a retired endpoint under a
        new path scored 0.857 exactly — above the 0.85 threshold — and was
        missed, because the decision was taken on the MinHash approximation,
        whose standard error at 128 permutations is about 1/sqrt(128) ≈ 0.088.
        The threshold sits well inside that error band, so whether a genuine
        resurrection alerted came down to hash luck, and the same pair could
        alert on one run and not the next.

        MinHash and LSH keep their job: reducing an estate-sized comparison to a
        shortlist in sub-linear time. What they must not do is decide.
        """
        m = build_minhash(shingles, self.num_perm)
        hits = set(self._lsh.query(m))
        target = set(shingles)
        results = []
        for eid, stored in self._shingles.items():
            union = target | stored
            sim = (len(target & stored) / len(union)) if union else 1.0
            results.append({
                "endpoint_id": eid,
                "origin_path": self._paths.get(eid, ""),
                "similarity": round(sim, 4),
                "estimated": round(float(m.jaccard(self._hashes[eid])), 4),
                "lsh_hit": eid in hits,
                "alert": sim >= self.threshold,
            })
        return sorted(results, key=lambda r: -r["similarity"])

    def __len__(self) -> int:
        return len(self._hashes)
