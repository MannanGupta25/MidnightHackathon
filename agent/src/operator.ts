/**
 * ZeroWatch Operator Agent CLI
 *
 * Run two instances in separate terminals to demonstrate real-time MATCH detection:
 *
 *   Terminal 1:  OPERATOR_ID=plant-alpha npm run operator --workspace=agent
 *   Terminal 2:  OPERATOR_ID=plant-beta  npm run operator --workspace=agent
 *
 * When both operators submit the same alert signature, the contract fires a
 * MATCH event and BOTH terminals display the coordinated attack notification.
 *
 * Override alert fields via env vars:
 *   PROTOCOL      (default: MODBUS)
 *   ANOMALY_CLASS (default: FUNCTION_CODE_SCAN)
 *   TIME_BUCKET   (default: current 15-min bucket)
 *   SERVER_URL    (default: http://localhost:3001)
 */

import { WebSocket } from 'ws';
import type { ServerEvent } from './server.js';

const OPERATOR_ID   = process.env.OPERATOR_ID   ?? 'operator-unknown';
const PROTOCOL      = process.env.PROTOCOL      ?? 'MODBUS';
const ANOMALY_CLASS = process.env.ANOMALY_CLASS ?? 'FUNCTION_CODE_SCAN';
const TIME_BUCKET   = process.env.TIME_BUCKET   ?? String(Math.floor(Date.now() / (15 * 60 * 1000)));
const SERVER_URL    = process.env.SERVER_URL    ?? 'http://localhost:3001';
const WS_URL        = SERVER_URL.replace(/^http/, 'ws');

const divider = '─'.repeat(60);

function log(msg: string): void {
  console.log(`[${OPERATOR_ID}] ${msg}`);
}

// ── WebSocket — listen for events from any operator ───────────────────────────

function connectWebSocket(): void {
  const ws = new WebSocket(WS_URL);

  ws.on('open', () => {
    log('Connected to ZeroWatch server. Listening for MATCH events...');
  });

  ws.on('message', (raw: Buffer) => {
    let event: ServerEvent;
    try {
      event = JSON.parse(raw.toString()) as ServerEvent;
    } catch {
      return;
    }

    if (event.type === 'match') {
      console.log('');
      console.log(divider);
      console.log('*** COORDINATED ATTACK DETECTED — MATCH CONFIRMED ***');
      console.log(divider);
      console.log(`  Signature   : ${event.protocol}|${event.anomalyClass}|${event.timeBucket}`);
      console.log(`  Confirmed by: ${event.operatorId}`);
      console.log(`  Time        : ${new Date(event.timestamp).toISOString()}`);
      console.log('  Raw alert data was never shared — only the ZK hash.');
      console.log(divider);
      console.log('');
    } else if (event.type === 'alert_submitted') {
      log(`Alert registered by ${event.operatorId} (${event.protocol}|${event.anomalyClass}). Waiting for second operator...`);
    } else if (event.type === 'reset') {
      log('Contract reset — fresh state.');
    }
  });

  ws.on('error', (err: Error) => {
    log(`WebSocket error: ${err.message}. Is the server running? (npm run server --workspace=agent)`);
    process.exit(1);
  });

  ws.on('close', () => {
    log('Connection closed.');
    process.exit(0);
  });
}

// ── HTTP — submit this operator's alert ───────────────────────────────────────

async function submitAlert(): Promise<void> {
  log(`NIDS alert received: ${PROTOCOL}|${ANOMALY_CLASS}|${TIME_BUCKET}`);
  log('Computing hash locally — raw alert data stays in this process.');

  const body = JSON.stringify({
    operatorId: OPERATOR_ID,
    protocol: PROTOCOL,
    anomalyClass: ANOMALY_CLASS,
    timeBucket: TIME_BUCKET,
  });

  const res = await fetch(`${SERVER_URL}/alert`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    log(`Server error: ${text}`);
    return;
  }

  const data = (await res.json()) as { matched: boolean };
  if (data.matched) {
    log('submitAlert returned matched=true (you were the confirming operator).');
  } else {
    log('Alert submitted. Hash recorded on contract — waiting for second operator.');
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

connectWebSocket();

// Brief delay so WebSocket is established before we POST
setTimeout(() => {
  submitAlert().catch((err: Error) => {
    log(`Failed to submit alert: ${err.message}`);
    log(`Is the server running? Start it with: npm run server --workspace=agent`);
    process.exit(1);
  });
}, 300);
