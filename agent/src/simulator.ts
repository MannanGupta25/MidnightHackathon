import {
  type CircuitContext,
  QueryContext,
  sampleContractAddress,
  createConstructorContext,
  CostModel,
} from '@midnight-ntwrk/compact-runtime';
import {
  Contract,
  type Ledger,
  ledger,
} from '../../contract/src/managed/zerowatch/contract/index.js';
import { type ZeroWatchPrivateState, witnesses } from './witnesses.js';

// Runs the ZeroWatch contract entirely in-process using compact-runtime's
// local execution engine. No blockchain connection needed — suitable for
// offline demo and unit testing.
export class ZeroWatchSimulator {
  readonly contract: Contract<ZeroWatchPrivateState>;
  circuitContext: CircuitContext<ZeroWatchPrivateState>;

  constructor(initialPrivateState: ZeroWatchPrivateState) {
    this.contract = new Contract<ZeroWatchPrivateState>(witnesses);
    const { currentPrivateState, currentContractState, currentZswapLocalState } =
      this.contract.initialState(
        createConstructorContext(initialPrivateState, '0'.repeat(64)),
      );
    this.circuitContext = {
      currentPrivateState,
      currentZswapLocalState,
      costModel: CostModel.initialCostModel(),
      currentQueryContext: new QueryContext(
        currentContractState.data,
        sampleContractAddress(),
      ),
    };
  }

  // Switch to a different operator's private state before calling submitAlert.
  // Simulates a second independent operator posting to the same shared contract.
  switchOperator(privateState: ZeroWatchPrivateState): void {
    this.circuitContext = {
      ...this.circuitContext,
      currentPrivateState: privateState,
    };
  }

  getLedger(): Ledger {
    return ledger(this.circuitContext.currentQueryContext.state);
  }

  submitAlert(): Ledger {
    const result = this.contract.impureCircuits.submitAlert(this.circuitContext);
    this.circuitContext = result.context;
    return this.getLedger();
  }
}
