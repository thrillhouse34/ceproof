"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.vcsDetector = void 0;
/**
 * Detects version-control (git) facts about the scanned project: whether
 * it's inside a git working tree, and if so, its current tag/describe,
 * commit, branch, and dirty-state.
 *
 * This is the one and only place in this codebase that shells out to a
 * subprocess (via child_process.execFileSync). That makes it doctrinally
 * sensitive:
 *  - Args are always passed as an array (never a shell string), so there is
 *    no shell interpolation and no injection surface via projectPath.
 *  - Every git invocation is wrapped in try/catch. Git not being installed
 *    (ENOENT), the target not being a git repo, a detached/unborn HEAD, or
 *    any other failure must never throw out of `run()` — it must degrade to
 *    a smaller-but-honest fact set, per the "honest UNKNOWNs" / never-fail
 *    doctrine in ./types.ts.
 *  - Every invocation carries a timeout so a hung/misbehaving git process
 *    can never hang the scan.
 */
const child_process_1 = require("child_process");
const GIT_TIMEOUT_MS = 5000;
/**
 * Runs a single git subcommand against `cwd`, returning its trimmed stdout,
 * or `undefined` if the command fails for any reason (not a git repo, git
 * not installed, timeout, non-zero exit, etc). Never throws.
 */
function tryGit(cwd, args) {
    try {
        const out = (0, child_process_1.execFileSync)('git', args, {
            cwd,
            timeout: GIT_TIMEOUT_MS,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore'],
        });
        return out.trim();
    }
    catch {
        return undefined;
    }
}
function run(projectPath) {
    const insideWorkTree = tryGit(projectPath, ['rev-parse', '--is-inside-work-tree']);
    if (insideWorkTree !== 'true') {
        return { isGitRepo: false };
    }
    const facts = { isGitRepo: true };
    const tag = tryGit(projectPath, ['describe', '--tags', '--always']);
    if (tag !== undefined && tag !== '') {
        facts.tag = tag;
        // `--always` makes the call above fall back to a bare commit hash when
        // no tag is reachable, so its success alone doesn't tell us whether
        // `tag` is a real release version. Ask again without `--always`: that
        // variant fails outright when there's no reachable tag, which is
        // exactly the signal consumers need to avoid treating a commit hash as
        // a human-meaningful version.
        const strictTag = tryGit(projectPath, ['describe', '--tags']);
        facts.tagIsRealTag = strictTag !== undefined && strictTag !== '';
    }
    const commit = tryGit(projectPath, ['rev-parse', 'HEAD']);
    if (commit !== undefined && commit !== '') {
        facts.commit = commit;
    }
    const branch = tryGit(projectPath, ['rev-parse', '--abbrev-ref', 'HEAD']);
    if (branch !== undefined && branch !== '') {
        facts.branch = branch;
    }
    const status = tryGit(projectPath, ['status', '--porcelain']);
    if (status !== undefined) {
        facts.dirty = status.length > 0;
    }
    return facts;
}
exports.vcsDetector = { id: 'vcs', run };
//# sourceMappingURL=vcs.js.map