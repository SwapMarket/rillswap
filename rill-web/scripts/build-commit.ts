import { execFileSync } from "node:child_process";

/** Source archives can supply a revision; builds without Git remain usable. */
export function buildCommit(override = process.env.RILLSWAP_BUILD_COMMIT): string | null {
  let commit = override;
  if (commit === undefined) {
    try {
      commit = execFileSync("git", ["rev-parse", "--verify", "HEAD"], {
        cwd: new URL("..", import.meta.url), encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
      }).trim();
    } catch { return null; }
  }
  return /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(commit) ? commit.toLowerCase() : null;
}
