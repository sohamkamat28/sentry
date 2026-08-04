# Stage 12 — Honeypot & Resurrection Detection

Retired endpoints keep answering. Every caller is intelligence, and a redeployment under a new name still matches.

---

## 1. Scope

**Owns:** the `honeypot` service, `probe` capture, `fingerprint` computation, LSH indexing, `resurrection_alert`.

**Does not own:** retirement. Stage 11 activates the honeypot as the last step of Phase D.

---

## 2. Why the false-positive rate is structurally near zero

No legitimate caller can reach a decommissioned endpoint. By construction, the sunset sequence has already published notices, throttled or migrated traffic, run a 30-vday quarantine in which every remaining caller was named and contacted, and returned 410. A request arriving after all of that is either an attacker or a dependency that survived every stage designed to surface it — and both are worth an alert.

---

## 3. Deployment unit

`honeypot/` — Go, stateless, horizontally scalable. Kong routes retired paths to it. It never touches the estate; it only receives.

---

## 4. Response generation

A retired endpoint returns a plausible `200 OK`, not a 404.

### 4.1 Shape from the real endpoint

The response schema observed before retirement is captured at Phase D and stored in `fingerprint.features`. The honeypot generates values matching that shape, so the response is structurally indistinguishable from the original.

### 4.2 The four guardrails

A bank returning fabricated financial data is a fair thing to be challenged on. Four constraints make it defensible, and all four are implemented, not merely stated in a policy document.

| Guardrail | Implementation |
|---|---|
| **Activated only after full retirement** | The honeypot route is created only in Phase D, after 410 has been served through the whole sequence. `honeypot/internal/routes` refuses to serve a path whose `endpoint.retired` is false — checked against the database at route load, not assumed |
| **Synthetic and non-resolvable** | Account numbers are drawn from a reserved range (`SYNTHETIC_ACCOUNT_PREFIX`, default `9999`) that maps to no real customer. Names come from a fixed fictional list. Amounts are generated. `honeypot/internal/synth` has no database connection to any customer system — it cannot emit a real value because it cannot read one |
| **Watermarked** | Every response carries a unique token embedded in a benign field and recorded in `probe.watermark`. If a fabricated account number appears in a leak, it is traceable to the exact probe interaction. The honeypot is leak-attribution evidence, not merely a decoy |
| **Recorded and signed off** | Activation is written into the Decommission Safety Certificate under a one-time legal sign-off policy (`policy_setting.honeypot_legal_signoff`), agreed once with the institution rather than approved per endpoint. Without that policy record present, Phase D refuses to activate the honeypot and completes with 410 instead |

The last row matters: the guardrail is enforced by the code path, so an institution that has not signed off gets a working decommission with no honeypot rather than a honeypot nobody authorised.

---

## 5. Probe capture

Every request is recorded:

| Field | Source |
|---|---|
| `source_ip` | Connection, `X-Forwarded-For` honoured only from trusted proxies |
| `source_asn`, `geo` | Offline MaxMind-format database, no external lookup |
| `headers` | Full set — user agent, auth attempts, scanner signatures |
| `body_sha256` | Digest only; probe bodies are never stored in cleartext |
| `session_fp` | Hash of (IP, user agent, TLS fingerprint) linking multi-request sessions |
| `watermark` | The token served in that response |

Writes go through a buffered channel with a bounded queue; a flood cannot block responses or exhaust memory. Overflow drops and counts, and the count is visible.

Rate limiting is deliberately **not** applied to honeypot routes. Slowing an attacker down would reduce the intelligence collected, which is the opposite of the objective.

---

## 6. Resurrection detection

### 6.1 The fingerprint

Captured at Phase D, before behaviour changes. Keyed on **what the endpoint does**, not where it lives.

| Feature group | Shingles |
|---|---|
| Response schema | Sorted field paths and types from observed responses |
| Data classes | The set from `endpoint.data_classes` |
| Caller profile | Set of calling service ids |
| Call rhythm | Bucketed hour-of-day histogram shape |
| Auth pattern | Auth scheme plus the missing-auth ratio band |
| Payload profile | Bucketed request and response size bands |
| Method | The HTTP method |

**Path tokens are excluded.** An earlier build included them, and a redeployment under a new path — the exact thing being detected — scored 0.583 against a 0.85 threshold, because the one thing a rename changes was weighted heavily in the comparison. The fingerprint keys on behaviour precisely because the path is the attacker's variable.

### 6.2 MinHash and LSH

```python
from datasketch import MinHash, MinHashLSH

m = MinHash(num_perm=128)
for shingle in behavioural_shingles(ep):
    m.update(shingle.encode())

lsh = MinHashLSH(threshold=RESURRECTION_THRESHOLD, num_perm=128)  # 0.85
lsh.insert(ep.id, m)
```

The index is rebuilt into Redis on startup from `fingerprint` rows and updated on each retirement. LSH gives sub-linear candidate lookup; exact Jaccard similarity is then computed on candidates only.

### 6.3 Scan on registration

Every newly registered endpoint is fingerprinted and queried against the index:

```python
def scan(new_ep) -> list[Candidate]:
    m = fingerprint(new_ep)
    candidates = lsh.query(m)                      # sub-linear
    scored = [(cid, m.jaccard(load(cid))) for cid in candidates]
    for cid, sim in scored:
        if sim >= RESURRECTION_THRESHOLD:
            raise_alert(new_ep, cid, sim)
    return sorted(scored, key=lambda x: -x[1])
```

Runs at stage 03 endpoint creation and on the 6-vhour cycle for endpoints created outside a scan.

An alert names the retired endpoint's original path, so the operator sees `/api/v2/maturity-v2 matches retired /internal/maturity at 1.00` — the rename made visible.

---

## 7. Data model delta

Writes `probe`, `fingerprint`, `resurrection_alert`, `endpoint.honeypot_active`.

---

## 8. API surface

| Route | Role | Purpose |
|---|---|---|
| `GET /api/v1/threat` | `viewer` | Active honeypots, probe volume, unique sources, sample response |
| `GET /api/v1/threat/probes` | `viewer` | Probe stream, filterable by endpoint, IP, ASN |
| `GET /api/v1/threat/resurrection-scan` | `viewer` | Current alerts with similarity and matched origin |
| `GET /api/v1/threat/fingerprint/{endpoint_id}` | `viewer` | Feature set and shingles, for audit |
| `POST /api/v1/threat/rescan` | `analyst` | Re-run the index against all endpoints |

```json
{
  "honeypots_active": 17,
  "probes_total": 412,
  "unique_sources": 23,
  "fingerprints": 17,
  "alerts": [
    {"new_endpoint": "GET /api/v2/maturity-v2", "origin_path": "/internal/maturity",
     "similarity": 1.0, "threshold": 0.85, "lsh_hit": true}
  ],
  "sample_response": {"status": 200, "body": {...}, "watermark": "wm_7a2c…"}
}
```

Metric tiles render `—` while a scan is in flight. Showing `0` before results arrive reads as "none found", which is a different claim from "not yet known".

---

## 9. Configuration

| Variable | Default | Notes |
|---|---|---|
| `RESURRECTION_THRESHOLD` | `0.85` | Jaccard similarity |
| `MINHASH_PERM` | `128` | Permutations |
| `SYNTHETIC_ACCOUNT_PREFIX` | `9999` | Reserved, non-resolvable range |
| `HONEYPOT_QUEUE` | `10000` | Probe buffer depth |
| `GEOIP_DB_PATH` | — | Offline; absent → `geo` null |
| `HONEYPOT_TRUSTED_PROXIES` | — | CIDRs whose `X-Forwarded-For` is honoured |

---

## 10. Failure modes

| Condition | Behaviour |
|---|---|
| Legal sign-off policy absent | Honeypot not activated. Phase D completes with 410. Logged and shown in the console |
| `endpoint.retired` false | Honeypot refuses the route. A live endpoint can never be served synthetic data |
| Probe queue full | Oldest dropped, counted, response still served. Capture degradation is visible |
| Redis LSH unavailable | Rebuilt from `fingerprint` on next scan; scan returns `503 dependency` meanwhile, never an empty result presented as "no matches" |
| GeoIP absent | `geo` null; everything else captured |
| Fingerprint missing at Phase D | Retirement blocks — without a fingerprint there is no resurrection detection, and retiring without one silently removes the capability |

---

## 11. Security and compliance

- **RBAC**: reads `viewer`; rescan `analyst`.
- **Audit**: `honeypot.activated` (with the legal sign-off reference), `resurrection.alerted`.
- **Isolation**: the honeypot service has no route to any estate database or internal service. Compromising it yields nothing.
- **Data protection**: probe bodies hashed, never stored. Synthetic values map to no customer.
- **Frameworks**: NYDFS Part 500 (forensic trail for probes against retired endpoints); DORA Art 9 (threat-led testing).

---

## 12. Tests

**Unit**
- Synthetic generator emits only reserved-range account numbers across 10 000 samples.
- Watermark is unique per response and recoverable from the body.
- **Fingerprint stability**: the same endpoint at a different path yields similarity ≥ 0.95. **This is the regression test for the path-token weighting defect.**
- Two behaviourally different endpoints score below threshold.
- MinHash Jaccard matches exact Jaccard within tolerance.

**Integration**
- Retiring an endpoint activates a honeypot route; a request receives 200 with synthetic data and creates a `probe` row.
- With the legal sign-off policy removed, Phase D leaves 410 in place and no honeypot.
- A route for a non-retired endpoint is refused.
- Re-registering a retired endpoint under a new path raises an alert at similarity ≥ threshold.
- Redis flushed → LSH rebuilt from Postgres → the same alert is produced.

**E2E**
- Retire `legacy-balance`, probe it with `curl`, see the probe in the console with source IP and watermark.
- Redeploy the same service on a new path; the resurrection alert names the original.

---

## 13. Acceptance criteria

- [ ] Honeypots activate only in Phase D, only for retired endpoints, only with the sign-off policy present.
- [ ] Every synthetic value comes from the reserved range; no real customer data is reachable by the service.
- [ ] Every response is watermarked and the watermark is stored with the probe.
- [ ] Probe capture records IP, ASN, headers and session fingerprint; bodies are hashed only.
- [ ] The fingerprint excludes path tokens, and a renamed redeployment still matches above threshold.
- [ ] Alerts name the original retired path.
- [ ] The LSH index survives a Redis flush by rebuilding from Postgres.
- [ ] Loading state is never rendered as a zero result.
