# 90 — Reference Estate

Real services, speaking real TLS, that SENTINEL has no prior knowledge of.

---

## 1. Why this exists

The predecessor build generated its estate with a seed function. Endpoints existed because code created rows; discovery "found" them by flipping a boolean on a row it had written itself. Every downstream number was therefore a restatement of the seed.

This directory replaces that with running software. `estate/` is a set of containerised services that serve HTTPS, call each other, expose a SOAP interface, go quiet, come back under new names, and expose one endpoint that no registry and no repository knows about. SENTINEL is pointed at them with an empty database and discovers what is there.

**The estate does not import from, or link against, anything in the platform.** It has no access to SENTINEL's database. The only channel between them is the kernel, the gateway, and the repositories — exactly as in a real deployment. This isolation is what makes the discovery result meaningful, and it is enforced by `estate/` being a separate compose project on its own network with no shared volumes.

---

## 2. Services

Twelve services, chosen so that every classification cell, every blast tier and every collector path is genuinely exercised.

| Service | Language / TLS | Purpose in the estate |
|---|---|---|
| `core-accounts` | Java 21 / Spring Boot, OpenSSL 3.0 | Documented north–south traffic through Kong. High volume, well-governed. The `OWNED`/`ACTIVE` baseline |
| `core-deposits` | Java 21 / Spring Boot, OpenSSL 3.0 | Calls `core-accounts` east–west. Creates graph depth |
| `payments-upi` | Go 1.23 / crypto/tls | Exercises the Go TLS uprobe path. `PAYMENT` criticality |
| `payments-rtgs` | Go 1.23 / crypto/tls | `SETTLEMENT` criticality — tightest latency budget, throttle-exempt |
| `cards-auth` | Node 20 / OpenSSL 3.0 | Returns card data. Exercises `CARD`/`CVV` detection |
| `finacle-bridge` | Python 3.12 / `spyne` SOAP over TLS | Publishes a real WSDL. The legacy collector's target |
| `kyc-service` | Python 3.12 / Flask, OpenSSL 1.1.1 | Returns Aadhaar and PAN. Exercises `AADHAAR`/`PAN` detection and an older OpenSSL layout |
| `recon-quarterly` | Python 3.12 batch | Fires only on virtual-clock quarter boundaries. **Must never be classified `ZOMBIE`** |
| `legacy-balance` | Python 3.12 / Flask, TLS 1.0 | Goes silent at vday 40. Becomes the through-line zombie |
| `nostro-sync` | Python 3.12 / Flask, no auth, TLS 1.0 | Second zombie. Reaches CRITICAL CDRI. The remediation demo target |
| `shadow-fx-rate` | Node 20 / OpenSSL 3.0 | **Never registered in Kong. Absent from every scanned repository.** Called directly by `payments-upi`. Only the kernel sensor can find it |
| `partner-gateway` | Go 1.23 | External-facing, internet-reachable. Exercises `internet_reachable` |

### Deliberate posture variation

Every risk indicator has services on both sides of it, so CDRI produces a distribution rather than a constant:

| Property | Services |
|---|---|
| No authentication | `nostro-sync`, `shadow-fx-rate`, `legacy-balance` |
| Basic auth | `finacle-bridge`, `kyc-service` |
| OAuth 2.0 | `core-accounts`, `core-deposits`, `payments-upi` |
| mTLS | `payments-rtgs` |
| TLS 1.0 | `legacy-balance`, `nostro-sync` |
| TLS 1.2 | `kyc-service`, `finacle-bridge` |
| TLS 1.3 | everything else |
| Sensitive data in responses | `kyc-service` (AADHAAR, PAN), `cards-auth` (CARD, CVV), `core-accounts` (ACCOUNT_NO) |
| No rate limiting | `legacy-balance`, `nostro-sync`, `shadow-fx-rate`, `kyc-service` |

### Deliberate ownership variation

To exercise all four rungs of the ownership ladder:

| Service | Ladder outcome |
|---|---|
| `core-accounts` | `CODEOWNERS` entry — rung 1, confidence 1.00 |
| `payments-upi` | No CODEOWNERS; git history has a current author — rung 2, confidence 0.75 |
| `legacy-balance` | git author present in history but **absent from the HR directory** — departed owner, `reachable=false`, escalation to department head |
| `nostro-sync` | No CODEOWNERS, no repository at all — rung 4, null gateway metadata → unresolved |
| `shadow-fx-rate` | Nothing anywhere — unresolved, `SHADOW` |

---

## 3. The virtual clock

`estate/driver/` generates traffic against a virtual clock shared with the platform through Postgres.

```
vday(t) = floor((t - epoch_wall) / scale_seconds)
```

`VCLOCK_SCALE=30` compresses one day into 30 seconds; a 90-day lifecycle plays out in 45 minutes. `VCLOCK_SCALE=86400` makes it real time, and the same driver then produces a genuine daily profile.

The driver reads `vclock` from Postgres — the same row the platform reads — so traffic generation and analysis cannot drift apart. It does not write to any other table.

**What is compressed and what is not.** Time is compressed. Traffic is real HTTP over real TLS. Capture is real kernel instrumentation. Classification, scoring and forecasting run on genuinely observed data. Nothing about the analysis is simulated; only the wall-clock interval between observations differs from production.

---

## 4. Traffic profiles

`estate/driver/profiles.yaml` defines per-endpoint shape. The driver realises them as actual requests.

```yaml
- service: core-accounts
  endpoints: [GET /api/v1/accounts/{id}, GET /api/v1/accounts/{id}/balance]
  profile:
    base_rate: 1200          # calls per vday
    weekly: [1.0,1.0,1.0,1.0,0.95,0.35,0.25]   # Mon–Sun
    hourly: business_hours
    trend: flat

- service: legacy-balance
  endpoints: [GET /api/v1/legacy-balance]
  profile:
    base_rate: 40
    weekly: [1.0,1.0,1.0,1.0,0.9,0.3,0.2]
    trend: decay
    decay_start_vday: 25
    decay_half_life_vdays: 6
    silent_from_vday: 40      # last call — becomes ZOMBIE at vday 130

- service: recon-quarterly
  endpoints: [POST /api/v1/recon/statutory]
  profile:
    schedule: quarterly       # vdays 0, 90, 180, 270
    burst: 240

- service: payments-upi
  endpoints: [POST /api/v1/upi/collect, POST /api/v1/upi/pay]
  profile:
    base_rate: 8000
    weekly: [1.0,1.0,1.0,1.0,1.1,0.8,0.7]
    trend: growth
    growth_pct_per_vday: 0.4  # rising — must NOT be flagged pre-zombie
```

Three profiles carry specific test weight:

- **`payments-upi` grows.** Its volume rises while its weekly cycle dips at weekends. A forecast that does not deseasonalise will read the weekend trough as decline and flag it. It must not be flagged.
- **`recon-quarterly` is silent for 89 vdays at a stretch.** A 30-day window classifies it dead. It must stay `ACTIVE`.
- **`legacy-balance` decays then stops.** It should be flagged pre-zombie around vday 34 and classified `ZOMBIE` at vday 130.

---

## 5. Scripted events

`estate/driver/events.yaml` triggers state changes at defined vdays, so the full lifecycle is exercised without manual intervention.

| vday | Event |
|---|---|
| 25 | `legacy-balance` traffic begins decaying |
| 40 | `legacy-balance` stops entirely |
| 55 | `nostro-sync` stops |
| 60 | An unregistered client begins calling `shadow-fx-rate` from a new source |
| 90 | `recon-quarterly` fires its second burst — the endpoint the naive window would have killed |
| 130 | `legacy-balance` crosses 90 vdays of silence → `ZOMBIE` |
| 145 | `nostro-sync` crosses → `ZOMBIE` |
| 200 | **Resurrection**: `legacy-balance-v2` deploys at `/api/v2/balance-lookup`, same behaviour, new path |
| 210 | An external scanner probes retired endpoints — real requests from a separate container |

The resurrection at vday 200 is a genuinely redeployed service with the same response schema, the same caller profile, and the same data classes — the actual scenario the fingerprint is designed to catch, not a synthetic similarity value fed to the matcher.

---

## 6. Repositories

`estate/repos/` contains git repositories the code collector scans. They are real repositories with real commit history, generated at estate build time by `estate/repos/build.sh`:

- Route definitions in the framework idiom for each language, so tree-sitter has genuine ASTs to parse.
- Commit history spanning the analysis window, with authors matching the ownership scenarios in §2.
- `CODEOWNERS` present in `core-accounts` only.
- **No repository for `nostro-sync` or `shadow-fx-rate`** — that absence is what makes them ungoverned.

The HR directory is a JSON file served by `estate/hr-stub/`, implementing the same contract as an LDAP or Workday lookup. `legacy-balance`'s git author is absent from it, which is what produces the departed-owner path.

---

## 7. Kong registration

`estate/kong/config.yaml` is applied declaratively at startup and registers every service **except** `shadow-fx-rate`.

That omission is the entire point. `shadow-fx-rate` receives real traffic from `payments-upi` over TLS, directly, never traversing Kong. The gateway collector cannot see it. The code collector cannot see it. Only the kernel sensor can — and that is the demonstration that gateway-only tooling has a structural blind spot, made by observation rather than by assertion.

---

## 8. What good looks like

Expected state after a full run to vday 240, asserted by the acceptance test in [93](93-VERIFICATION.md):

| Metric | Expected |
|---|---|
| Endpoints discovered | 40–60 |
| Discovered by `ebpf` only | ≥ 1 (`shadow-fx-rate`) |
| `ZOMBIE` | ≥ 2 (`legacy-balance`, `nostro-sync`) |
| `SHADOW` | ≥ 1 |
| `ORPHANED` | ≥ 2 |
| `recon-quarterly` lifecycle | `ACTIVE` — never `ZOMBIE` |
| `payments-upi` pre-zombie | `false` — never flagged |
| `CRITICAL` CDRI | 2–6 |
| Pre-zombie flagged | < 25 % of active endpoints |
| Blast tier distribution | Spread across at least three tiers |
| Resurrection alerts | ≥ 1 after vday 200 |
| Probes captured | ≥ 1 after vday 210 |

These are ranges, not fixed numbers. The estate is real software under a real scheduler, and exact call counts vary between runs. A design that demanded an exact figure would be describing a seed function again.

---

## 9. Configuration

| Variable | Default | Notes |
|---|---|---|
| `VCLOCK_SCALE` | `30` | Wall seconds per vday. `86400` for real time |
| `ESTATE_PROFILE` | `full` | `full` \| `minimal` (4 services, for CI) |
| `DRIVER_CONCURRENCY` | `16` | Parallel request workers |
| `HR_STUB_PORT` | `8090` | |

`minimal` exists because the full estate is too heavy for a CI runner. It keeps `core-accounts`, `legacy-balance`, `shadow-fx-rate` and `recon-quarterly` — enough to exercise discovery, shadow detection, the zombie path and the quarterly false-positive guard.

---

## 10. Acceptance criteria

- [ ] `docker compose -f estate/compose.yaml up` brings up all twelve services, each serving TLS.
- [ ] The estate has no network route to SENTINEL's database and no shared volume.
- [ ] SENTINEL starting against an empty database discovers the estate with no manual registration.
- [ ] `shadow-fx-rate` is discovered by the kernel sensor and by nothing else.
- [ ] `recon-quarterly` never classifies as `ZOMBIE` across a 240-vday run.
- [ ] `payments-upi` is never flagged pre-zombie.
- [ ] `legacy-balance` classifies `ZOMBIE` within 3 vdays of vday 130.
- [ ] The vday-200 redeployment raises a resurrection alert above threshold.
- [ ] The vday-210 scanner produces probe rows with real source IPs.
- [ ] Two full runs produce results within the ranges in §8 without either matching exactly.
