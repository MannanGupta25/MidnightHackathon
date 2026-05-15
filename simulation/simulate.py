#!/usr/bin/env python3
"""
ZeroWatch Simulation Driver

Programmatically runs two SCADA threat intelligence scenarios against the
ZeroWatch contract simulation server and writes a structured results log.

SCENARIO 1 — MATCH (coordinated attack):
  Operator alpha:  MODBUS / FUNCTION_CODE_SCAN / bucket T
  Operator beta:   MODBUS / FUNCTION_CODE_SCAN / bucket T   <-- same hash -> MATCH

SCENARIO 2 — NO MATCH (unrelated incidents):
  Operator gamma:  MODBUS / WRITE_TO_COIL / bucket T
  Operator delta:  DNP3   / READ_ALL       / bucket T        <-- different hash

Usage:
  # Start the server first (separate terminal):
  #   npm run server --workspace=agent
  #
  python3 simulate.py [--server http://localhost:3001] [--save results.json]

  # Or start the server automatically:
  python3 simulate.py --autostart
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# ── CLI args ──────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="ZeroWatch simulation driver")
parser.add_argument("--server",    default="http://localhost:3001",
                    help="ZeroWatch server URL (default: http://localhost:3001)")
parser.add_argument("--save",      default="results.json",
                    help="Write structured results to this file (default: results.json)")
parser.add_argument("--autostart", action="store_true",
                    help="Start the Node.js server automatically")
parser.add_argument("--bucket",    type=int, default=None,
                    help="Override time bucket (default: current 15-min bucket)")
args = parser.parse_args()

SERVER  = args.server.rstrip("/")
BUCKET  = args.bucket if args.bucket is not None else int(time.time() // (15 * 60))

# ── Formatting helpers ────────────────────────────────────────────────────────

W = 64
DIV   = "─" * W
THICK = "=" * W

def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"

def hdr(title: str) -> None:
    print(f"\n{THICK}")
    print(f"  {title}")
    print(THICK)

def step(label: str, msg: str) -> None:
    print(f"  [{ts()}] {label:<14} {msg}")

def divider() -> None:
    print(DIV)

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def http_post(path: str, body: dict) -> dict:
    url  = SERVER + path
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())

def http_get(path: str) -> dict:
    with urllib.request.urlopen(SERVER + path, timeout=10) as resp:
        return json.loads(resp.read())

def wait_for_server(max_wait: float = 10.0) -> bool:
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        try:
            http_get("/state")
            return True
        except Exception:
            time.sleep(0.3)
    return False

# ── Server lifecycle ──────────────────────────────────────────────────────────

_server_proc: subprocess.Popen | None = None

def start_server() -> None:
    global _server_proc
    root = Path(__file__).resolve().parents[1]
    cmd  = ["node", "--loader", "ts-node/esm", "src/server.ts"]
    _server_proc = subprocess.Popen(
        cmd,
        cwd=root / "agent",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"  Started server (pid {_server_proc.pid}) — waiting for ready...")
    if not wait_for_server():
        print("  ERROR: server did not start in time.")
        _server_proc.terminate()
        sys.exit(1)
    print(f"  Server ready at {SERVER}")

def stop_server() -> None:
    if _server_proc:
        _server_proc.terminate()

# ── Single operator alert submission ─────────────────────────────────────────

def submit_alert(
    operator_id: str,
    protocol: str,
    anomaly_class: str,
    time_bucket: int,
    results_log: list,
) -> bool:
    """POST an alert, print result, append to results_log. Returns matched flag."""
    step(operator_id, f"NIDS alert: {protocol}/{anomaly_class}")
    step(operator_id, "Hash computed locally — raw data stays in process.")

    payload = {
        "operatorId":   operator_id,
        "protocol":     protocol,
        "anomalyClass": anomaly_class,
        "timeBucket":   time_bucket,
    }

    resp    = http_post("/alert", payload)
    matched = resp.get("matched", False)
    event   = resp.get("event", {})

    results_log.append({
        "operator":    operator_id,
        "protocol":    protocol,
        "anomalyClass": anomaly_class,
        "timeBucket":  time_bucket,
        "matched":     matched,
        "event":       event,
        "ts":          ts(),
    })

    if matched:
        step(operator_id, "submitAlert -> matched=TRUE")
    else:
        step(operator_id, "submitAlert -> matched=false (waiting for peer)")

    return matched

# ── Scenarios ─────────────────────────────────────────────────────────────────

def run_scenario_1(results: dict) -> None:
    hdr("SCENARIO 1 — COORDINATED ATTACK (MATCH expected)")
    print(f"  Two operators report the same MODBUS anomaly in 15-min bucket {BUCKET}.")
    print(f"  Neither shares raw alert data — only the ZK hash goes on-chain.")
    divider()

    log: list = []
    http_post("/reset", {})
    step("server", "Contract reset — empty alertRegistry.")
    divider()

    submit_alert("plant-alpha", "MODBUS", "FUNCTION_CODE_SCAN", BUCKET, log)
    divider()

    matched = submit_alert("plant-beta", "MODBUS", "FUNCTION_CODE_SCAN", BUCKET, log)
    divider()

    state = http_get("/state")

    if matched:
        print()
        print(THICK)
        print("  *** COORDINATED ATTACK DETECTED — MATCH CONFIRMED ***")
        print(THICK)
        print(f"  Signature : MODBUS|FUNCTION_CODE_SCAN|{BUCKET}")
        print("  Both plant-alpha and plant-beta flagged identical anomaly.")
        print("  Raw SCADA packet data was never shared between operators.")
        print(THICK)
    else:
        print("  UNEXPECTED: no match fired.")

    results["scenario_1"] = {
        "description": "Coordinated MODBUS scan — two operators, same signature",
        "expected":    "match",
        "outcome":     "match" if matched else "no_match",
        "timeBucket":  BUCKET,
        "events":      log,
        "ledger":      state.get("entries", []),
    }

def run_scenario_2(results: dict) -> None:
    hdr("SCENARIO 2 — UNRELATED INCIDENTS (NO MATCH expected)")
    print(f"  One operator sees a MODBUS write; the other sees a DNP3 read.")
    print(f"  Different alert signatures — no false positive should fire.")
    divider()

    log: list = []
    http_post("/reset", {})
    step("server", "Contract reset — empty alertRegistry.")
    divider()

    submit_alert("plant-gamma", "MODBUS", "WRITE_TO_COIL", BUCKET, log)
    divider()

    matched = submit_alert("plant-delta", "DNP3", "READ_ALL", BUCKET, log)
    divider()

    state = http_get("/state")

    entry_count = len(state.get("entries", []))
    any_matched = any(e.get("matched") for e in state.get("entries", []))

    if not any_matched and entry_count == 2:
        print()
        print(THICK)
        print("  No match — two distinct hashes, zero false positives.")
        print(THICK)
        print(f"  plant-gamma:  MODBUS/WRITE_TO_COIL hash -> entry 1")
        print(f"  plant-delta:  DNP3/READ_ALL hash       -> entry 2")
        print("  Registry contains 2 unmatched entries, as expected.")
        print(THICK)
    else:
        outcome = "false_positive" if any_matched else "unexpected_state"
        print(f"  UNEXPECTED outcome: {outcome}")

    results["scenario_2"] = {
        "description": "Unrelated incidents — MODBUS write vs DNP3 read",
        "expected":    "no_match",
        "outcome":     "no_match" if not any_matched else "false_positive",
        "timeBucket":  BUCKET,
        "events":      log,
        "ledger":      state.get("entries", []),
    }

# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(results: dict) -> None:
    hdr("SIMULATION SUMMARY")
    for key, scenario in results.items():
        if key == "meta":
            continue
        passed = scenario["expected"] == scenario["outcome"]
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {scenario['description']}")
        print(f"        Expected: {scenario['expected']}  |  Got: {scenario['outcome']}")
    print()

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print()
    print(THICK)
    print("  ZeroWatch — Simulation Driver")
    print(f"  Server   : {SERVER}")
    print(f"  Bucket   : {BUCKET}  ({datetime.fromtimestamp(BUCKET * 15 * 60, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')})")
    print(f"  Save to  : {args.save}")
    print(THICK)

    if args.autostart:
        start_server()
    else:
        print("\n  Checking server...", end=" ")
        if not wait_for_server(max_wait=3.0):
            print("not reachable.")
            print(f"  Start it with:  npm run server --workspace=agent")
            print(f"  Or re-run with: python3 simulate.py --autostart")
            sys.exit(1)
        print("OK")

    results: dict = {
        "meta": {
            "run_at":    datetime.now(timezone.utc).isoformat(),
            "server":    SERVER,
            "timeBucket": BUCKET,
        }
    }

    try:
        run_scenario_1(results)
        time.sleep(0.2)
        run_scenario_2(results)
    finally:
        if args.autostart:
            stop_server()

    print_summary(results)

    out = Path(args.save)
    if not out.is_absolute():
        out = Path(__file__).parent / out
    out.write_text(json.dumps(results, indent=2))
    print(f"  Results saved to {out}\n")


if __name__ == "__main__":
    main()
