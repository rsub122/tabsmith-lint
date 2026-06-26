import { describe, it, expect } from "vitest";
import { run } from "../src/cli.js";
import { fixtureDir } from "./helpers.js";

describe("U1: CLI arg parsing + exit codes", () => {
  it("no directory argument → usage error, exit 3", () => {
    const r = run([]);
    expect(r.exitCode).toBe(3);
    expect(r.stderr).toMatch(/Usage/);
  });

  it("nonexistent directory → error, exit 3", () => {
    const r = run([fixtureDir("does-not-exist")]);
    expect(r.exitCode).toBe(3);
    expect(r.stderr).toMatch(/error/i);
  });

  it("--browser firefox → rejected, exit 3", () => {
    const r = run([fixtureDir("pass-basic-mv3"), "--browser", "firefox"]);
    expect(r.exitCode).toBe(3);
    expect(r.stderr).toMatch(/only --browser chrome/i);
  });

  it("invalid --format → exit 3", () => {
    const r = run([fixtureDir("pass-basic-mv3"), "--format", "yaml"]);
    expect(r.exitCode).toBe(3);
  });

  it("--version prints a semver and exits 0", () => {
    const r = run(["--version"]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("--format json produces parseable JSON for a clean extension", () => {
    const r = run([fixtureDir("pass-basic-mv3"), "--format", "json"]);
    expect(r.exitCode).toBe(0);
    const parsed = JSON.parse(r.stdout!);
    expect(parsed.tool).toBe("tabsmith-lint");
    expect(parsed.browsers.chrome.verdict).toBe("pass");
  });
});
