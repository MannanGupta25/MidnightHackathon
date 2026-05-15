import { randomBytes } from 'node:crypto';
import { setNetworkId, type NetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { ZeroWatchSimulator } from './simulator.js';
import { createPrivateState, currentTimeBucket } from './witnesses.js';

// Local simulation mode — no blockchain required.
// For testnet deployment, replace with MidnightWalletProvider + deployContract.
setNetworkId('undeployed' as NetworkId);

// Alert parameters read from environment or defaulted to a realistic SCADA scenario.
const PROTOCOL     = process.env.PROTOCOL     ?? 'MODBUS';
const ANOMALY_CLASS = process.env.ANOMALY_CLASS ?? 'FUNCTION_CODE_SCAN';
const TIME_BUCKET  = process.env.TIME_BUCKET != null
  ? BigInt(process.env.TIME_BUCKET)
  : currentTimeBucket();

const divider = '─'.repeat(60);

console.log('\nZeroWatch — Privacy-Preserving Threat Intelligence');
console.log(divider);
console.log(`Alert signature : ${PROTOCOL}|${ANOMALY_CLASS}|${TIME_BUCKET}`);
console.log(`Time bucket     : ${TIME_BUCKET} (15-min window)`);
console.log(divider);

// --- Operator A submits first ---
const operatorAKey = randomBytes(32);
const stateA = createPrivateState(operatorAKey, PROTOCOL, ANOMALY_CLASS, TIME_BUCKET);
const sim = new ZeroWatchSimulator(stateA);

console.log('\n[Operator A] NIDS alert received. Computing hash locally...');
console.log('[Operator A] Raw alert data NEVER leaves this process.');
console.log('[Operator A] Submitting ZK proof + hash to contract...');
const ledgerA = sim.submitAlert();

const entriesA = [...ledgerA.alertRegistry];
console.log(`[Operator A] Registry entries : ${entriesA.length}`);
console.log(`[Operator A] Match status     : ${entriesA[0]?.[1]?.matched ?? false}`);

// --- Operator B submits same alert (coordinated attack scenario) ---
const operatorBKey = randomBytes(32);
const stateB = createPrivateState(operatorBKey, PROTOCOL, ANOMALY_CLASS, TIME_BUCKET);
sim.switchOperator(stateB);

console.log('\n[Operator B] NIDS alert received. Computing hash locally...');
console.log('[Operator B] Raw alert data NEVER leaves this process.');
console.log('[Operator B] Submitting ZK proof + hash to contract...');
const ledgerB = sim.submitAlert();

const entriesB = [...ledgerB.alertRegistry];
const matched = entriesB[0]?.[1]?.matched ?? false;
console.log(`[Operator B] Registry entries : ${entriesB.length}`);
console.log(`[Operator B] Match status     : ${matched}`);

// --- Result ---
console.log('\n' + divider);
if (matched) {
  console.log('*** COORDINATED ATTACK DETECTED — MATCH CONFIRMED ***');
  console.log(divider);
  console.log(`Signature  : ${PROTOCOL}|${ANOMALY_CLASS}|${TIME_BUCKET}`);
  console.log('Both operators observed the same attack pattern.');
  console.log('Raw alert data was never shared — only the ZK hash.');
} else {
  console.log('No match yet. Waiting for a second operator to confirm...');
}
console.log(divider + '\n');

// --- No-match scenario demo ---
console.log('\n--- No-Match Scenario (different attack types) ---');

const stateC = createPrivateState(randomBytes(32), 'MODBUS', 'WRITE_TO_COIL', TIME_BUCKET);
const stateD = createPrivateState(randomBytes(32), 'DNP3',   'READ_ALL',       TIME_BUCKET);

const sim2 = new ZeroWatchSimulator(stateC);
console.log('[Operator C] Submitting MODBUS/WRITE_TO_COIL alert...');
const ledgerC = sim2.submitAlert();
sim2.switchOperator(stateD);
console.log('[Operator D] Submitting DNP3/READ_ALL alert...');
const ledgerD = sim2.submitAlert();

const entriesD = [...ledgerD.alertRegistry];
const noMatch = entriesD.every(([, record]) => !record.matched);
console.log(`Registry entries : ${entriesD.length} (distinct hashes — no overlap)`);
console.log(`Any match        : ${!noMatch}`);
console.log(noMatch ? 'No match — operators saw different attack types. No false positive.' : 'UNEXPECTED MATCH');
console.log('');
