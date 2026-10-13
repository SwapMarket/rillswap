import { test, expect } from "bun:test";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { stopPaymentProcess } from "../regtest/paymentProcess";

test.skipIf(process.platform !== "linux")("payer cleanup escalates surviving descendants after their leader exits", async () => {
  const childCode = "process.on('SIGTERM',()=>{});console.log('ready');setInterval(()=>{},1000)";
  const leader = spawn(process.execPath, ["-e", `
    const {spawn}=require('node:child_process');
    const child=spawn(process.execPath,['-e',${JSON.stringify(childCode)}],{stdio:['ignore','pipe','ignore']});
    child.stdout.once('data',()=>console.log(child.pid));
    process.on('SIGTERM',()=>process.exit(0));setInterval(()=>{},1000);
  `], { detached: true, stdio: ["ignore", "pipe", "ignore"] });
  try {
    const pid = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Payer fixture did not become ready")), 3000);
      leader.stdout!.once("data", (data) => { clearTimeout(timer); resolve(Number(String(data).trim())); });
      leader.once("error", (error) => { clearTimeout(timer); reject(error); });
    });
    expect(pid).toBeGreaterThan(0);
    const started = performance.now();
    await stopPaymentProcess(leader, 100);
    expect(leader.exitCode).toBe(0);
    expect(performance.now() - started).toBeGreaterThanOrEqual(100);
    // A reparented zombie is terminated too (it cannot retain pipes or send RPCs).
    const stopped = () => {
      try { return readFileSync(`/proc/${pid}/stat`, "utf8").split(") ")[1]?.startsWith("Z") === true; }
      catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return true; throw error; }
    };
    for (let tries = 0; !stopped() && tries < 100; tries++) await Bun.sleep(10);
    expect(stopped()).toBe(true);
  } finally { await stopPaymentProcess(leader, 0); }
});
