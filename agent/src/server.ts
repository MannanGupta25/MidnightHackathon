import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import express, { type Request, type Response } from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import { setNetworkId, type NetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { ZeroWatchSimulator } from './simulator.js';
import { createPrivateState, currentTimeBucket } from './witnesses.js';

setNetworkId('undeployed' as NetworkId);

// ── Types ─────────────────────────────────────────────────────────────────────

export type ServerEvent =
  | { type: 'alert_submitted'; operatorId: string; protocol: string; anomalyClass: string; timeBucket: string; timestamp: number }
  | { type: 'match'; operatorId: string; protocol: string; anomalyClass: string; timeBucket: string; timestamp: number }
  | { type: 'reset'; timestamp: number }
  | { type: 'state'; entries: LedgerEntry[]; timestamp: number };

type LedgerEntry = {
  hash: string;
  operatorId: string;
  matched: boolean;
};

// ── State ──────────────────────────────────────────────────────────────────────

// Shared contract state — represents the on-chain alertRegistry ledger.
// In a real deployment this lives on Midnight; here we run it in-process.
let sim = newSimulator();

function newSimulator(): ZeroWatchSimulator {
  // Initialize with a dummy private state — just sets up the empty Map ledger.
  return new ZeroWatchSimulator(
    createPrivateState(randomBytes(32), 'INIT', 'INIT', 0n),
  );
}

function ledgerEntries(): LedgerEntry[] {
  return [...sim.getLedger().alertRegistry].map(([hash, record]) => ({
    hash: Buffer.from(hash).toString('hex'),
    operatorId: Buffer.from(record.operatorId).toString('hex'),
    matched: record.matched,
  }));
}

// ── WebSocket broadcast ────────────────────────────────────────────────────────

const clients = new Set<WebSocket>();

function broadcast(event: ServerEvent): void {
  const msg = JSON.stringify(event);
  for (const ws of clients) {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  }
}

// ── Express routes ─────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use((_req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// Reset contract to empty state.
app.post('/reset', (_req: Request, res: Response) => {
  sim = newSimulator();
  broadcast({ type: 'reset', timestamp: Date.now() });
  res.json({ ok: true });
});

// Operator submits an alert.
// Body: { operatorId: string, protocol: string, anomalyClass: string, timeBucket?: number }
app.post('/alert', (req: Request, res: Response) => {
  const { operatorId, protocol, anomalyClass } = req.body as Record<string, string>;
  const timeBucket: bigint =
    req.body.timeBucket != null ? BigInt(req.body.timeBucket) : currentTimeBucket();

  if (!operatorId || !protocol || !anomalyClass) {
    res.status(400).json({ error: 'operatorId, protocol, and anomalyClass are required' });
    return;
  }

  // Each operator has their own unique private key; we derive one deterministically
  // from operatorId for demo repeatability.
  const operatorKey = Buffer.from(
    operatorId.padEnd(32, '\0').slice(0, 32),
    'binary',
  ) as unknown as Uint8Array;
  const state = createPrivateState(new Uint8Array(operatorKey), protocol, anomalyClass, timeBucket);
  sim.switchOperator(state);
  const ledger = sim.submitAlert();

  const entries = [...ledger.alertRegistry];
  const matched = entries.some(([, r]) => r.matched);

  const event: ServerEvent = matched
    ? { type: 'match', operatorId, protocol, anomalyClass, timeBucket: String(timeBucket), timestamp: Date.now() }
    : { type: 'alert_submitted', operatorId, protocol, anomalyClass, timeBucket: String(timeBucket), timestamp: Date.now() };

  broadcast(event);
  res.json({ matched, event });
});

// Current ledger state snapshot.
app.get('/state', (_req: Request, res: Response) => {
  res.json({ entries: ledgerEntries(), timestamp: Date.now() });
});

// ── Server startup ─────────────────────────────────────────────────────────────

const server = createServer(app);
const wss = new WebSocketServer({ server });

wss.on('connection', (ws: WebSocket) => {
  clients.add(ws);
  ws.on('close', () => clients.delete(ws));

  // Send current state snapshot on connect so dashboard can hydrate.
  const stateEvent: ServerEvent = { type: 'state', entries: ledgerEntries(), timestamp: Date.now() };
  ws.send(JSON.stringify(stateEvent));
});

const PORT = Number(process.env.PORT ?? 3001);
server.listen(PORT, () => {
  console.log(`ZeroWatch server  http://localhost:${PORT}`);
  console.log(`WebSocket         ws://localhost:${PORT}`);
  console.log('');
  console.log('  POST /reset   — clear contract state');
  console.log('  POST /alert   — submit operator alert  { operatorId, protocol, anomalyClass, timeBucket? }');
  console.log('  GET  /state   — current ledger snapshot');
  console.log('');
  console.log('Waiting for operators...');
});
