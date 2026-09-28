# ATTACKS.md — the defense study sheet

One page per question the professor is likely to ask. All numbers are measured
by `12_defense_demo.py` (see `results_poc.txt`), not asserted.

---

## 1. The system in two sentences

> **Tier 1 (rules)** checks *who may speak*: ID allowlist, DLC, per-ID rate limit —
> static membership written at design time.
> **Tier 2 (AI)** checks *whether what was said is physically possible and behaviorally
> consistent*: 24 features per 100 ms window, Random Forest (50 trees, 72 KB), trained
> on honest traffic + attack runs.

Why the bus and not the radios: CAN arbitration IDs are **claims, not proofs** — no
source authentication, CRC is not adversarial integrity, anyone on the bus is a peer.
RC/MAVLink/GNSS each have their own trust flaws, and 3 of the 5 attacker arrival paths
(supply chain, OTA, companion-computer pivot) never touch a radio at all. The bus is
the one chokepoint every attack must cross.

## 2. Seven attacks, seven different lies

| attack | the lie | wire (candump) | caught by | measured |
|---|---|---|---|---|
| injection | *identity* — badge nobody issued | `00000123#DEADBEEF01020304` | T1 allowlist | 20/20 dropped |
| flood | *importance* — priority, zero content | `10040405#00000000000000` ×1 ms | T1 rate limit | 1000/1000 dropped |
| masquerade | *value* — +500 m in one frame | `10040405#C672BA470400C0` | T2 `baro_dalt_max_m` | 33/34 win, ~27 ms |
| drift | *rate* — +2 m/s, every frame plausible | `10040405#2CE6C5470400C0` (0.045 m/f) | T2 `baro_climb_mps` | 34/34 win, ~49 ms |
| shadow | *uniqueness* — two speakers, one ID | real + mirror `808EC347…` at +6 ms | T2 cnt/dt doubling + dAlt ±100 m | 34/34 win, ~104 ms |
| replay | *time* — real bytes, wrong moment | identical bytes at t and t+20 s | T2 seams only | 2/34 win = **named ceiling** |
| trojan/OTA | *ownership* — real node, new master | `102885E3…` trigger, then sink −2 m/s | T1 drops trigger; T2 catches sink | 36/44 win, ~110 ms |

Base rate: **0 false alarms** in 30 s of honest traffic (299 windows).

## 3. Shadow is NOT replay (the axis is time, not payload)

- **Replay** = a *recording*: old bytes, one voice, cadence perfect. Content genuinely
  real — only the moment is wrong. Attacker needs zero protocol knowledge.
- **Shadow** = a *live parallel speaker*: mirror computed fresh from the current frame
  (`p − 1200 Pa` → +100 m), synchronized to now. Two voices, same instant. Dangerous
  precisely because every fake value is plausible *right now*.
- Consequence: shadow leaves a doubled pulse (cnt 5→10, dt 20→10 ms) — deafening.
  Replay leaves no impossible value at all — that's why replay is the hard one and
  shadow is not.

## 4. What the AI actually computes (24 features / 100 ms window)

Per sensor (baro 50 Hz, speed 20 Hz, GPS 10 Hz, rpm 5 Hz): frame count, mean/std of
inter-arrival time, max byte delta. Plus physics: max altitude jump inside the window
(`baro_dalt_max_m`), implied climb rate, GPS-lat / speed / rpm deltas. The forest
learned where honest windows end — feature importances: dalt 0.38, cnt 0.36, dt 0.17.
Detection = the next window boundary after the lie starts → **latency ≈ 1 window
(~100 ms)**, measured 27–110 ms.

Training data = labeled by construction: the injection scripts are ground truth.
Event-level labeling matters: in a masquerade run only windows containing a spike
carry the lie (relabeled by `baro_dalt_max_m > 5 m`); honest-by-construction windows
stay negative. Drift/trojan windows are all-lie (rate rewrite) → label 1.

## 5. Honest boundaries (volunteer these before being asked)

1. **Replay middle passes** (2/34 seam windows). Real values + real cadence defeat
   every current feature. Fix, already scoped: payload-novelty / baro-vs-GPS-speed
   residual column. Saying "we know our boundary and the fix" > pretending.
2. **Drift below the learned envelope passes** (boundary ≈ 1–2 m/s in this envelope;
   real max climb 0.29 m/s). Trade-off is FPR vs threshold — cross-sensor residuals
   are the path to tightening it.
3. **Flood costs availability anyway**: during the 1 s flood, 49 honest frames were
   also dropped (bus contention). Rules stop the *injection*; only bus design
   (gateways, segmented buses) bounds the denial.
4. **Trojan is caught the moment it lies (≤1 window), never before** — nothing on the
   wire changes at takeover time. That's defense-in-depth: Tier-1 dropped the OTA
   trigger AND Tier-2 caught the compromised node's behavior.
5. Offline mode replays recorded traffic through the real pipeline code — same
   functions as the live gateway, no mock verdicts. Live mode on the Pi adds kernel
   RX timestamps and real pacing.

## 6. Demo commands

```bash
python 12_defense_demo.py --save results_poc.txt        # offline (mac) - the scorecard
sudo python 12_defense_demo.py --mode live              # Pi, vcan0, real time
python 12_defense_demo.py --train                       # rebuild the model on-board
python gateway_bridge.py --rules-only                   # the failure-log demo:
                                                        # masquerade spikes [FORWARDED]
python gateway_bridge.py --model model_window_drift.pkl # live TIER2 verdicts
```

Story order: benign (quiet) → injection → flood (Tier 1's two kills) → masquerade
spike through `--rules-only` (the hole, = failure log) → same attack with Tier 2 on
(the catch) → drift → shadow → replay (ceiling, say it before he does) → trojan.

## 7. Q&A one-liners

- *"CAN specifies the sender?"* — No. Arbitration ID = priority, not identity.
- *"What does an attacker physically need?"* — Any device that emits CAN frames plus
  one point of electrical access: supply chain, OTA, companion pivot, or a physical
  splice. No "second remote."
- *"Why not sign frames?"* — CAN-FD SEC/OEM PKI exists but costs frames + latency +
  key infra per node; a monitoring plane works on the deployed fleet today.
- *"Why ML, not more rules?"* — Rules encode membership; the attacks that matter
  violate *physics and behavior*, whose thresholds aren't constants (envelope, rhythm,
  novelty, baseline drift). Also: the +500 m "rule" IS a 1-feature model — the forest
  rediscovers it (importance 0.38) and generalizes past it.
- *"Is the AI perfect?"* — No. Measured boundary, named ceiling (replay), known next
  feature. 0 false alarms on the honest envelope is the operating point.
