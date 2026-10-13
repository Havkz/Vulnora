import type { MissionControl } from '../mission/index.js';
import type { ToolOrchestrator } from '../orchestrator/tool-orchestrator.js';
import type { OpsecController } from '../opsec/index.js';
import type { PackBoard } from '../pack/board.js';
import type { OperatorAgent } from '../operators/index.js';
import type { CoverageCapability, CoverageSnapshot } from '../orchestrator/coverage.js';
import { KillChainPhase, type Credential, type Finding, type ScanProgressEvent, type Target } from '../types/index.js';
import { restoreAgentCheckpoint } from '../agent/checkpoint.js';
import { validateProjectTarget } from './targets.js';

export interface EngineCheckpoint {
  version: 1;
  limits: { maxOperators: number; taskTimeoutMs: number };
  mission: ReturnType<MissionControl['exportCheckpoint']>;
  targets: Target[];
  vault: { findings: Finding[]; credentials: Credential[] };
  orchestrator: ReturnType<ToolOrchestrator['exportCheckpoint']>;
  opsec: ReturnType<OpsecController['exportCheckpoint']>;
  board: ReturnType<PackBoard['exportCheckpoint']>;
  operators: ReturnType<OperatorAgent['exportCheckpoint']>[];
  command: {
    tickCount: number; taskSeeded: boolean; phaseStatuses: [string, string][];
    coverageRecoveryAttempts: [string, number][]; coverageTerminalized: [string, CoverageCapability[]][];
    coverageSnapshots: [string, CoverageSnapshot][]; progressEvents: ScanProgressEvent[];
    whiteboxSource: string; spawnedFollowups: string[]; leadsPosted: number; followupsSpawned: number;
  };
}

const phases = Object.values(KillChainPhase);
const severities = ['critical', 'high', 'medium', 'low', 'info'];
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every(item => typeof item === 'string');
const count = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0;
const entries = (value: unknown): value is [string, unknown][] => Array.isArray(value) && value.every(item => Array.isArray(item) && item.length === 2 && typeof item[0] === 'string');
const objects = (value: unknown): value is Record<string, unknown>[] => Array.isArray(value) && value.every(record);
const uniqueIds = (items: { id: string }[]): boolean => items.every(item => typeof item.id === 'string' && !!item.id) && new Set(items.map(item => item.id)).size === items.length;

/** Validate every executable input before any subsystem is mutated. */
export function validateEngineCheckpoint(value: unknown): asserts value is EngineCheckpoint {
  const fail = (): never => { throw new Error('Invalid scanner checkpoint; saved project was retained and no scan started.'); };
  if (!record(value) || value.version !== 1) return fail();
  const saved = value as unknown as EngineCheckpoint;
  if (!record(saved.limits) || !count(saved.limits.maxOperators) || saved.limits.maxOperators < 1
    || !count(saved.limits.taskTimeoutMs) || saved.limits.taskTimeoutMs < 1) return fail();
  if (!record(saved.mission) || !objects(saved.mission.missions) || !objects(saved.mission.tasks)
    || !uniqueIds(saved.mission.missions) || !uniqueIds(saved.mission.tasks) || !objects(saved.targets) || !uniqueIds(saved.targets)) return fail();
  const missionIds = new Set(saved.mission.missions.map(mission => mission.id));
  if (saved.mission.activeMissionId !== null && (typeof saved.mission.activeMissionId !== 'string' || !missionIds.has(saved.mission.activeMissionId))) return fail();
  for (const mission of saved.mission.missions) {
    if (typeof mission.name !== 'string' || !strings(mission.objectives) || !strings(mission.phases) || !mission.phases.length
      || !mission.phases.every(phase => phases.includes(phase)) || !mission.phases.includes(mission.currentPhase)
      || !['planning', 'active', 'paused', 'completed', 'aborted'].includes(mission.status)
      || !Number.isFinite(mission.progress) || mission.progress < 0 || mission.progress > 100 || !record(mission.rules)) return fail();
    for (const key of ['scope', 'excludedTargets', 'allowedTechniques', 'forbiddenTechniques', 'requireManualApproval'] as const) if (!strings(mission.rules[key])) return fail();
    if (!count(mission.rules.maxDetectionEvents) || mission.rules.maxDetectionEvents < 1) return fail();
  }
  for (const target of saved.targets) {
    if (typeof target.name !== 'string' || typeof target.address !== 'string' || !Number.isFinite(target.discoveredAt)
      || !['web_application', 'api', 'network', 'host', 'database', 'cloud', 'mobile', 'iot', 'container'].includes(target.type)
      || !['external', 'dmz', 'internal', 'restricted', 'airgapped'].includes(target.zone)
      || !['discovered', 'scanning', 'vulnerable', 'exploited', 'owned', 'exfiltrated'].includes(target.status)
      || (target.port !== undefined && (!count(target.port) || target.port < 1 || target.port > 65535))
      || (target.services !== undefined && !objects(target.services)) || (target.vulnerabilities !== undefined && !objects(target.vulnerabilities))) return fail();
    validateProjectTarget(target.address);
    for (const service of target.services || []) {
      if (typeof service.name !== 'string' || typeof service.protocol !== 'string'
        || !count(service.port) || service.port < 1 || service.port > 65535) return fail();
    }
    for (const vulnerability of target.vulnerabilities || []) {
      if (typeof vulnerability.name !== 'string' || !severities.includes(vulnerability.severity)) return fail();
    }
  }
  for (const task of saved.mission.tasks) {
    if (!missionIds.has(task.missionId) || typeof task.name !== 'string' || typeof task.description !== 'string'
      || !phases.includes(task.phase) || !['recon', 'scanner', 'exploiter', 'infiltrator', 'exfiltrator', 'ghost', 'coordinator', 'analyst'].includes(task.operatorType)
      || !['pending', 'assigned', 'in_progress', 'completed', 'failed', 'skipped'].includes(task.status)
      || !strings(task.dependencies) || !Number.isFinite(task.priority) || !Number.isFinite(task.createdAt)
      || (task.executionPlan !== undefined && (!record(task.executionPlan) || typeof task.executionPlan.toolName !== 'string' || !record(task.executionPlan.parameters)))) return fail();
    if (task.result !== undefined && (!record(task.result) || typeof task.result.success !== 'boolean')) return fail();
    if (task.checkpoint !== undefined) {
      const target = saved.targets.find(item => task.description.includes(item.address)) || saved.targets[0];
      restoreAgentCheckpoint(task.checkpoint, task, target);
    }
  }
  if (!record(saved.vault) || !objects(saved.vault.findings) || !uniqueIds(saved.vault.findings)
    || !objects(saved.vault.credentials) || !uniqueIds(saved.vault.credentials)) return fail();
  for (const finding of saved.vault.findings) {
    if (typeof finding.title !== 'string' || typeof finding.description !== 'string' || typeof finding.targetId !== 'string'
      || typeof finding.operatorId !== 'string' || !phases.includes(finding.phase) || !severities.includes(finding.severity)
      || !Number.isFinite(finding.discoveredAt) || !objects(finding.evidence)
      || !finding.evidence.every(evidence => typeof evidence.content === 'string' && Number.isFinite(evidence.timestamp))) return fail();
  }
  if (!saved.vault.credentials.every(credential => typeof credential.secret === 'string' && typeof credential.source === 'string' && Number.isFinite(credential.discoveredAt))) return fail();
  const orchestrator = saved.orchestrator;
  if (!record(orchestrator) || !objects(orchestrator.records) || !uniqueIds(orchestrator.records)
    || !objects(orchestrator.events) || !objects(orchestrator.conflicts) || !record(orchestrator.metrics)
    || !strings(orchestrator.metrics.incompleteAreas) || !record(orchestrator.metrics.budgetCostSources)
    || !entries(orchestrator.budgets) || !entries(orchestrator.network) || !entries(orchestrator.wildcardDns) || !entries(orchestrator.lastHostRequest)) return fail();
  for (const evidence of orchestrator.records) {
    if (typeof evidence.toolName !== 'string' || typeof evidence.target !== 'string' || typeof evidence.rawOutput !== 'string'
      || !/^[a-f\d]{64}$/.test(evidence.normalizedSignature) || !/^[a-f\d]{64}$/.test(evidence.equivalentSignature)
      || !record(evidence.requestParameters) || !record(evidence.result) || typeof evidence.result.success !== 'boolean'
      || !Number.isFinite(evidence.timestamp) || !['success', 'failed', 'skipped', 'deferred'].includes(evidence.status)
      || !record(evidence.networkContext)) return fail();
  }
  for (const [key, metric] of Object.entries(orchestrator.metrics)) {
    if (key !== 'incompleteAreas' && key !== 'budgetCostSources' && !count(metric)) return fail();
  }
  for (const [, budget] of orchestrator.budgets) {
    if (!record(budget) || !record(budget.limits) || !record(budget.used)
      || !count(budget.limits.total_request_budget) || !count(budget.used.total_request_budget)
      || !Object.values(budget.limits).every(count) || !Object.values(budget.used).every(count)) return fail();
  }
  for (const [, network] of orchestrator.network) {
    if (!record(network) || !['clear', 'defensive', 'probable_edge_block'].includes(network.blockState)
      || !count(network.consecutiveTimeouts) || !count(network.blockingResponses) || !count(network.healthChecks) || !objects(network.recent)) return fail();
  }
  for (const [, wildcard] of orchestrator.wildcardDns) if (!record(wildcard) || typeof wildcard.detected !== 'boolean' || !strings(wildcard.addresses) || !Number.isFinite(wildcard.checkedAt)) return fail();
  if (!orchestrator.lastHostRequest.every(([, at]) => Number.isFinite(at))) return fail();
  const opsec = saved.opsec;
  if (!record(opsec) || !record(opsec.config) || !['silent', 'covert', 'loud'].includes(opsec.config.level)
    || !count(opsec.config.maxDetectionEvents) || opsec.config.maxDetectionEvents < 1
    || !count(opsec.config.cooldownAfterDetection) || !Array.isArray(opsec.config.jitterRange) || opsec.config.jitterRange.length !== 2
    || !opsec.config.jitterRange.every(count) || opsec.config.jitterRange[0] > opsec.config.jitterRange[1]
    || !objects(opsec.detections) || !objects(opsec.iocs) || !count(opsec.cooldownUntil)) return fail();
  for (const key of ['cleanupOnComplete', 'avoidDetection', 'trafficBlending', 'loggingSanitization'] as const) if (typeof opsec.config[key] !== 'boolean') return fail();
  const board = saved.board;
  if (!record(board) || !objects(board.leads) || !uniqueIds(board.leads) || !objects(board.log) || !objects(board.agents)) return fail();
  for (const lead of board.leads) {
    if (typeof lead.dedupKey !== 'string' || typeof lead.title !== 'string' || !record(lead.where)
      || !['open', 'claimed', 'confirmed', 'refuted', 'dead'].includes(lead.status) || !objects(lead.endorsements)
      || !objects(lead.refutations) || !count(lead.version) || !count(lead.smoke)) return fail();
  }
  const command = saved.command;
  if (!record(command) || !count(command.tickCount) || typeof command.taskSeeded !== 'boolean' || typeof command.whiteboxSource !== 'string'
    || !count(command.leadsPosted) || !count(command.followupsSpawned) || !strings(command.spawnedFollowups) || !objects(command.progressEvents)
    || !entries(command.phaseStatuses) || !command.phaseStatuses.every(([, status]) => typeof status === 'string')
    || !entries(command.coverageRecoveryAttempts) || !command.coverageRecoveryAttempts.every(([, attempts]) => count(attempts))
    || !entries(command.coverageTerminalized) || !command.coverageTerminalized.every(([, capabilities]) => strings(capabilities))
    || !entries(command.coverageSnapshots)) return fail();
  if (!objects(saved.operators) || !uniqueIds(saved.operators)
    || saved.operators.length > saved.limits.maxOperators
    || new Set(saved.operators.map(operator => operator.callsign)).size !== saved.operators.length) return fail();
  for (const operator of saved.operators) {
    if (typeof operator.callsign !== 'string' || !['recon', 'scanner', 'exploiter', 'infiltrator', 'exfiltrator', 'ghost', 'coordinator', 'analyst'].includes(operator.archetype)
      || !record(operator.config) || !record(operator.state) || !objects(operator.findings) || !objects(operator.credentials)
      || !Number.isFinite(operator.config.maxDetectionRisk) || operator.config.maxDetectionRisk < 0 || operator.config.maxDetectionRisk > 1
      || !count(operator.config.cooldownMs) || !count(operator.config.maxRetries)
      || !strings(operator.config.preferredTechniques) || !strings(operator.config.avoidTechniques) || !strings(operator.config.toolPreferences)
      || !count(operator.state.completedTasks) || !count(operator.state.failedTasks) || !count(operator.state.findingsCount) || !count(operator.state.credentialsCount)
      || !Number.isFinite(operator.state.detectionRisk) || operator.state.detectionRisk < 0 || operator.state.detectionRisk > 1) return fail();
  }
}
