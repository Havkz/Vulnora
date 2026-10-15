import process from 'node:process';
import { VulnoraCommand, KillChainPhase } from '../../index.ts';
import { ProjectStore } from '../../projects/store.ts';
import { acquireProjectLease } from '../../projects/lease.ts';

const [origin, directory, mode] = process.argv.slice(2);
const store = new ProjectStore(directory);
const project = await store.create('Crash recovery', origin);
await acquireProjectLease(directory, project.id);
let announced = false;
const command = new VulnoraCommand({ name: project.name, llm: { provider: 'mock', model: 'fixture' },
  ...(mode === 'discovery' ? { scanningBehavior: 'auto' } : {}),
  operators: { defaultConfig: { cooldownMs: 0 } },
  hooks: { onStateCheckpoint: async () => {
    const checkpoint = command.exportCheckpoint();
    project.checkpoint = checkpoint; project.status = 'running';
    await store.save(project);
    if (mode === 'write' && !announced && checkpoint.orchestrator.records.some(record => record.executionStatus === 'executed' && record.requestParameters.method === 'POST')
      && checkpoint.mission.tasks.some(task => task.checkpoint?.activeAttempt)) {
      announced = true; process.stdout.write(`READY ${project.id}\n`);
      await new Promise(() => {});
    }
    if (!announced && checkpoint.mission.tasks.some(task => task.name === 'first' && task.status === 'completed')
      && checkpoint.mission.tasks.some(task => task.name === 'second' && task.checkpoint?.activeCall)) {
      announced = true; process.stdout.write(`READY ${project.id}\n`);
    }
    if (mode === 'decomposed' && !announced && checkpoint.mission.tasks.some(task =>
      task.decomposition?.tasks[0]?.status === 'completed' && task.decomposition?.tasks[1]?.checkpoint?.activeCall)) {
      announced = true; process.stdout.write(`READY ${project.id}\n`);
    }
  } } });
command.targetEnv.addTarget({ name: 'Fixture', type: 'web_application', zone: 'external', address: origin });
const mission = command.mission.createMission({ name: project.name, objectives: ['Fixture'], phases: [KillChainPhase.RECON] });
command.mission.startMission(mission.id);
if (mode === 'decomposed') {
  const parent = command.mission.createTask({ missionId: mission.id, name: 'Split request', description: `Read ${origin}`,
    phase: KillChainPhase.RECON, operatorType: 'recon' });
  command.llm.prompt = async () => JSON.stringify([{ name: 'first', description: 'Read first fixture' }, { name: 'second', description: 'Read second fixture' }]);
  const operator = command.spawnOperator('Decomposition fixture', 'recon');
  const execute = operator.executeTask.bind(operator);
  operator.executeTask = async (task, target, signal) => {
    if (task.id === parent.id) throw new Error('Split fixture operation');
    return execute(task, target, signal);
  };
  operator.on('task:decomposed', ({ subtasks }) => {
    for (const subtask of subtasks) subtask.executionPlan = { toolName: 'http_request', parameters: { url: `${origin}/${subtask.name}` } };
  });
}
for (const name of mode === 'decomposed' ? [] : mode === 'write' ? ['second'] : ['first', 'second']) {
  const task = command.mission.createTask({ missionId: mission.id, name, description: `Read ${origin}`, phase: KillChainPhase.RECON, operatorType: 'recon' });
  task.executionPlan = mode === 'discovery' && name === 'second'
    ? { toolName: 'api_endpoint_discovery', parameters: { url: origin, wordlist: 'rest' } }
    : { toolName: 'http_request', parameters: { url: `${origin}/${name}`, ...(mode === 'write' ? { method: 'POST', body: 'fixture-only-write' } : {}) } };
}
command.start();
await command.tick();
