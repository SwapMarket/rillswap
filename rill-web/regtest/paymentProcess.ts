import type { ChildProcess } from "node:child_process";

/** Stop an owned detached payer group, even if its leader exits before its descendants. */
export async function stopPaymentProcess(child: ChildProcess, graceMs = 5000): Promise<void> {
  if (!child.pid) return;
  const group = -child.pid;
  const signal = (value: NodeJS.Signals | 0): boolean => {
    try { process.kill(group, value); return true; }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ESRCH") return false; throw error; }
  };
  const reaped = child.exitCode !== null || child.signalCode !== null
    ? Promise.resolve() : new Promise<void>((done) => child.once("close", () => done()));
  signal("SIGTERM");
  const deadline = performance.now() + graceMs;
  while (signal(0) && performance.now() < deadline) await new Promise((done) => setTimeout(done, 25));
  if (signal(0)) signal("SIGKILL");
  await reaped;
}
