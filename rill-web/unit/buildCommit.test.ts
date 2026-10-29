import { expect, spyOn, test } from "bun:test";
import * as childProcess from "node:child_process";
import { buildCommit } from "../scripts/build-commit";

const COMMIT = "0123456789abcdef0123456789abcdef01234567";

test("an explicit full revision takes precedence without requiring Git", () => {
  const git = spyOn(childProcess, "execFileSync").mockImplementation(() => { throw new Error("Git unavailable"); });
  try {
    expect(buildCommit(COMMIT.toUpperCase())).toBe(COMMIT);
    expect(buildCommit("a".repeat(64))).toBe("a".repeat(64));
    expect(git).not.toHaveBeenCalled();
  } finally { git.mockRestore(); }
});

test("missing, abbreviated, and malformed explicit revisions are not published", () => {
  for (const value of ["", "0123456", "g".repeat(40), `${COMMIT}\n`, `<script>${COMMIT}</script>`]) {
    expect(buildCommit(value)).toBeNull();
  }
});

test("Git provides the checkout revision when no override is set", () => {
  const git = spyOn(childProcess, "execFileSync").mockReturnValue(`${COMMIT}\n`);
  const override = process.env.RILLSWAP_BUILD_COMMIT;
  delete process.env.RILLSWAP_BUILD_COMMIT;
  try {
    expect(buildCommit()).toBe(COMMIT);
    expect(git).toHaveBeenCalledWith("git", ["rev-parse", "--verify", "HEAD"], expect.objectContaining({ cwd: new URL("../", import.meta.url) }));
  } finally {
    git.mockRestore();
    if (override !== undefined) process.env.RILLSWAP_BUILD_COMMIT = override;
  }
});

test("builds without a Git executable or checkout omit the revision", () => {
  const git = spyOn(childProcess, "execFileSync").mockImplementation(() => { throw new Error("Git unavailable"); });
  const override = process.env.RILLSWAP_BUILD_COMMIT;
  delete process.env.RILLSWAP_BUILD_COMMIT;
  try { expect(buildCommit()).toBeNull(); } finally {
    git.mockRestore();
    if (override !== undefined) process.env.RILLSWAP_BUILD_COMMIT = override;
  }
});
