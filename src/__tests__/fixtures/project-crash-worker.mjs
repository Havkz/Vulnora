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
  } } });
command.targetEnv.addTarget({ name: 'Fixture', type: 'web_application', zone: 'external', address: origin });
const mission = command.mission.createMission({ name: project.name, objectives: ['Fixture'], phases: [KillChainPhase.RECON] });
command.mission.startMission(mission.id);
for (const name of mode === 'write' ? ['second'] : ['first', 'second']) {
  const task = command.mission.createTask({ missionId: mission.id, name, description: `Read ${origin}`, phase: KillChainPhase.RECON, operatorType: 'recon' });
  task.executionPlan = { toolName: 'http_request', parameters: { url: `${origin}/${name}`, ...(mode === 'write' ? { method: 'POST', body: 'fixture-only-write' } : {}) } };
}
command.start();
await command.tick();
