import { createHash } from 'node:crypto';
import { type WitnessContext } from '@midnight-ntwrk/compact-runtime';
import { type Ledger } from '../../contract/src/managed/zerowatch/contract/index.js';

// Private state for each operator agent.
// The alert fields (protocol, anomalyClass, timeBucket) are set locally from
// the NIDS output — they never leave this process.
export type ZeroWatchPrivateState = {
  readonly operatorKey: Uint8Array;   // 32-byte random private key
  readonly alert: {
    readonly protocol: string;        // e.g. "MODBUS"
    readonly anomalyClass: string;    // e.g. "FUNCTION_CODE_SCAN"
    readonly timeBucket: bigint;      // floor(unixMs / 15min)
  };
};

export const createPrivateState = (
  operatorKey: Uint8Array,
  protocol: string,
  anomalyClass: string,
  timeBucket: bigint,
): ZeroWatchPrivateState => ({
  operatorKey,
  alert: { protocol, anomalyClass, timeBucket },
});

// Returns the current 15-minute time bucket. Two alerts within the same
// 15-minute window will produce the same bucket value and thus the same hash.
export const currentTimeBucket = (): bigint =>
  BigInt(Math.floor(Date.now() / (15 * 60 * 1000)));

// Witness implementations. Each function takes a WitnessContext (giving access
// to ledger + private state) and returns [newPrivateState, returnValue].
// Private state is unchanged by both — we never mutate it from witnesses.
export const witnesses = {
  // Computes the canonical SHA-256 alert hash from private fields.
  // Two operators that observed the same (protocol, anomalyClass, timeBucket)
  // will produce identical hashes — that's the match condition.
  computeAlertHash: ({
    privateState,
  }: WitnessContext<Ledger, ZeroWatchPrivateState>): [ZeroWatchPrivateState, Uint8Array] => {
    const { protocol, anomalyClass, timeBucket } = privateState.alert;
    const preimage = `${protocol}|${anomalyClass}|${timeBucket}`;
    const hash = createHash('sha256').update(preimage, 'utf8').digest();
    return [privateState, hash];
  },

  // Returns the operator's private key. The Compact circuit hashes this via
  // persistentHash() to produce a public operatorId — the raw key never
  // touches the ledger.
  localOperatorKey: ({
    privateState,
  }: WitnessContext<Ledger, ZeroWatchPrivateState>): [ZeroWatchPrivateState, Uint8Array] => {
    return [privateState, privateState.operatorKey];
  },
};
