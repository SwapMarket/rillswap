import { cpSync, mkdirSync, rmSync } from "node:fs";
rmSync("tmp/pages-preview", { recursive: true, force: true });
mkdirSync("tmp/pages-preview", { recursive: true });
cpSync("tmp/pages", "tmp/pages-preview", { recursive: true });
cpSync("tmp/pages", "tmp/pages-preview/repository", { recursive: true });
