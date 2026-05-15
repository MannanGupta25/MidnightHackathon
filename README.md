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

## Where Midnight technologies are used

### 1. Compact — the smart contract language (`contract/src/zerowatch.compact`)

The entire on-chain privacy model is written in Compact, Midnight's ZK-native contract language.

**`ledger` declaration** — Compact's `ledger` keyword marks the `alertRegistry` map as public on-chain state. Every key and value in this map is visible to anyone reading the chain, but the map only ever stores hashes, never raw alert data:

```compact
export ledger alertRegistry: Map<Bytes<32>, AlertRecord>;
```

**`witness` functions** — Compact's `witness` keyword declares functions whose implementations live off-chain in the TypeScript agent. The circuit calls them during proof generation but their inputs never appear in the public transaction. This is the core privacy boundary: `computeAlertHash` accesses the operator's raw alert (protocol, anomaly class, time bucket) entirely inside the agent process and returns only a hash.

```compact
witness computeAlertHash(): Bytes<32>;
witness localOperatorKey(): Bytes<32>;
```

**`disclose()`** — Compact enforces at compile time that any witness return value flowing into public ledger state must be explicitly wrapped in `disclose()`. This prevents accidental leakage of private data. ZeroWatch uses it for both the alert hash and the operator identity:

```compact
const alertHash  = disclose(computeAlertHash());
const operatorId = disclose(persistentHash<Bytes<32>>(localOperatorKey()));
```

**`persistentHash<T>()`** — a Compact built-in that hashes a value deterministically in a way that is stable across proof executions. Used to derive a public `operatorId` from the operator's raw private key without ever writing the key to the ledger.

**`export circuit`** — the `submitAlert` circuit is the only state-transition function in the contract. Compact compiles it into a ZK-provable circuit: calling it from the TypeScript agent generates a zero-knowledge proof that the hash was computed correctly, which the Midnight network verifies before accepting the transaction.

---

### 2. `compact` compiler (`contract/package.json`)

The `compact compile` command (version manager v0.5.1, compiler v0.31.0) compiles `zerowatch.compact` into:

- **Prover/verifier keys** (`keys/submitAlert.prover`, `keys/submitAlert.verifier`) — the cryptographic artifacts used to generate and verify ZK proofs for `submitAlert`
- **ZKIR bytecode** (`zkir/submitAlert.zkir`, `submitAlert.bzkir`) — the intermediate representation of the circuit
- **TypeScript bindings** (`contract/index.js`, `index.d.ts`) — type-safe wrappers that the agent imports to call the circuit

---

### 3. `@midnight-ntwrk/compact-runtime` (`agent/src/simulator.ts`)

The compact-runtime package is the in-process execution engine for Compact circuits. ZeroWatch uses it to run the `submitAlert` circuit locally without a blockchain connection:

- `Contract<PrivateState>` — wraps the compiled contract and wires in the TypeScript witness implementations
- `createConstructorContext` / `contract.initialState()` — initialises the empty `alertRegistry` ledger
- `contract.impureCircuits.submitAlert(circuitContext)` — executes the circuit in-process, updating ledger state and returning the new context
- `QueryContext` / `ledger()` — reads the current `alertRegistry` map after each circuit execution
- `CostModel` / `CircuitContext` — the runtime's bookkeeping types for tracking circuit execution state and gas costs

This is what makes the offline simulation and the HTTP server possible: the full Compact circuit runs inside Node.js, producing the same ledger state transitions as it would on the Midnight testnet.

---

### 4. `WitnessContext<Ledger, PrivateState>` (`agent/src/witnesses.ts`)

The TypeScript witness implementations receive a `WitnessContext` from `@midnight-ntwrk/compact-runtime` each time the circuit calls them. This context gives the witness function access to:

- `privateState` — the operator's local private state (key + alert fields), which never leaves the agent process
- `ledger` — the current on-chain ledger state (read-only, for witnesses that need to inspect public state)
- `contractAddress` — the deployed contract's address

The witness returns a `[newPrivateState, returnValue]` tuple. Compact-runtime threads the return value into the circuit execution while keeping the private state isolated from the proof transcript.

---

### Summary

| Layer | Midnight technology | Role |
|---|---|---|
| Contract | Compact language | Defines ZK circuit, ledger schema, witness interface |
| Contract | `disclose()` | Enforces compile-time privacy boundary |
| Contract | `persistentHash<T>()` | Derives public operator ID without leaking private key |
| Contract | `compact` compiler | Produces prover/verifier keys + TypeScript bindings |
| Agent | `compact-runtime` — `Contract` + `impureCircuits` | Executes circuit in-process; runs proofs locally |
| Agent | `compact-runtime` — `WitnessContext` | Injects private alert data into the circuit at proof time |
| Agent | `compact-runtime` — `QueryContext` / `ledger()` | Reads on-chain state after each circuit execution |
