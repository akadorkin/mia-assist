import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { Ctx } from '../src/core/ctx.js';
import { gitCommit } from '../src/scenarios/common.js';

test('gitCommit: commits staged work; a retry with nothing staged succeeds', () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-gc-'));
    const run = (argv: string[]) => execFileSync(argv[0], argv.slice(1), { cwd: repo, encoding: 'utf8' });
    run(['git', 'init', '-q']);
    fs.writeFileSync(path.join(repo, 'a'), 'x');
    run(['git', 'add', 'a']);
    const ctx = { config: { gitAuthor: { name: 'mia', email: 'mia@test' } } } as unknown as Ctx;
    run(gitCommit(ctx, "msg with 'quotes' $(no)"));
    assert.equal(run(['git', 'log', '--format=%s']).trim(), "msg with 'quotes' $(no)");
    run(gitCommit(ctx, 'again')); // would throw «nothing to commit» before
    assert.equal(run(['git', 'rev-list', '--count', 'HEAD']).trim(), '1');
    fs.rmSync(repo, { recursive: true, force: true });
});
