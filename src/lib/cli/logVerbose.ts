import { verbosityState } from '../state/verbosity';

export function logVerbose(level: number, message: string): void {
  if (verbosityState.level >= level) {
    console.log(message);
  }
}
