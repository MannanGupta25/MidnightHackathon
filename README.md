# ZeroWatch — Midnight Hackathon 2026

Privacy-preserving threat intelligence sharing for critical infrastructure operators, built on [Midnight](https://midnight.network/).

## What it does

Critical infrastructure operators (utilities, railways, nuclear plants) get hit by coordinated cyberattacks and cannot warn each other — sharing reveals network topology, triggers regulatory liability, and tips off attackers.

ZeroWatch uses Midnight's zero-knowledge proofs to let operators correlate attack signatures without exposing raw data:

1. Each operator's NIDS generates an alert
2. The alert is hashed locally (never leaves the device)
3. Only the ZK proof goes on-chain via a Compact contract
4. If two operators post the same hash, the contract fires a `MATCH` event
5. Both operators are notified — without seeing each other's raw alert

**Prize target:** AI Track — "process sensitive data without exposing underlying information"

## Design doc

See [ZeroWatch-design-20260515.md](./ZeroWatch-design-20260515.md) for full architecture, Compact pseudocode, alert schema, 48hr build plan, and demo script.

## Toolchain

- [Compact](https://docs.midnight.network/compact) smart contract language
- `compact` compiler v0.5.1 — install: `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/midnightntwrk/compact/releases/latest/download/compact-installer.sh | sh`
- TypeScript operator agents
- Midnight testnet

## Reference

The `bboard-reference/` directory contains the [example-bboard](https://github.com/midnightntwrk/example-bboard) from Midnight — the closest analog to the ZeroWatch contract (ledger state + witness functions). The `submitAlert` circuit adapts the bulletin board's message posting pattern to accept a `Bytes32` hash instead of a string.

## Build plan

| Hours | Milestone |
|-------|-----------|
| 0–4   | Toolchain gate: deploy bulletin board to testnet |
| 4–12  | `submitAlert` Compact circuit + `computeAlertHash` witness |
| 12–20 | TypeScript operator agents (two instances) |
| 20–30 | Python simulation (match + no-match scenarios) |
| 30–40 | HTML dashboard (two operator panels, MATCH fires red alert) |
| 40–48 | Demo rehearsal, fallback video, Devpost submission |

## Fallback (Approach B)

If matching contract is too complex by hour 12: switch to attestation-only (`submitAttestation` circuit). Weaker story, still demonstrates ZK + SCADA + Midnight.
