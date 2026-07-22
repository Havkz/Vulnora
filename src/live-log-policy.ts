/** Orchestrator owns policy decisions; actual execution failures stay on RESULT. */
export function shouldPrintOrchestrationEvent(action: string): boolean {
  return ['SKIPPED', 'USED', 'DEFERRED', 'STOPPED', 'REPEATED', 'BLOCKED'].includes(action);
}
