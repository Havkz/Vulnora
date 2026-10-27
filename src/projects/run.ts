import type { ProjectLogEvent, ProjectSession } from './session.js';

export type ProjectRunResult = 'completed' | 'incomplete' | 'paused' | 'interrupted';

/** Headless lifecycle over the same leased, checkpointed session as the TUI. */
export async function runProject(session: ProjectSession, signal: AbortSignal,
  onLog: (event: ProjectLogEvent) => void): Promise<ProjectRunResult> {
  let settle: (result: ProjectRunResult) => void;
  let fail: (error: Error) => void;
  const finished = new Promise<ProjectRunResult>((resolve, reject) => { settle = resolve; fail = reject; });
  // A journal failure can arrive while start() is still writing its first checkpoint.
  void finished.catch(() => {});
  const stopped = () => {
    const mission = session.command.mission.getAllMissions().at(-1);
    settle(session.project.status !== 'completed' ? 'paused'
      : mission?.completionStatus === 'COMPLETED' || mission?.completionStatus === 'COMPLETED_WITH_WARNINGS' ? 'completed' : 'incomplete');
  };
  const paused = () => settle(signal.aborted ? 'interrupted' : 'paused');
  const aborted = () => settle('interrupted');
  const error = (cause: Error) => fail(cause);
  session.on('log', onLog);
  session.on('error', error);
  session.command.on('command:stopped', stopped);
  session.command.on('command:paused', paused);
  signal.addEventListener('abort', aborted, { once: true });
  try {
    if (signal.aborted) return 'interrupted';
    if (session.project.status === 'completed') stopped();
    else {
      await session.start();
      if (signal.aborted) aborted();
    }
    const result = await finished;
    if (session.project.status === 'completed') await session.results();
    return result;
  } finally {
    signal.removeEventListener('abort', aborted);
    session.command.off('command:stopped', stopped);
    session.command.off('command:paused', paused);
    try { await session.close(); }
    finally { session.off('log', onLog); session.off('error', error); }
  }
}
