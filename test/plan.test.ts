import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { Ctx } from '../src/core/ctx.js';
import { Host, Inventory } from '../src/core/inventory.js';
import { HostStep, runSteps } from '../src/core/plan.js';
import { ExecOptions, ExecResult } from '../src/core/ssh.js';

function setup(readonly = false) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-test-'));
    const config = loadConfig({ MIA_STATE_DIR: dir, MIA_INVENTORY: path.join(dir, 'none.yaml'), MIA_READONLY: String(readonly) });
    const ctx = new Ctx(config);
    const calls: string[] = [];
    const failOn = new Set<string>();
    (ctx as unknown as { transport: unknown }).transport = {
        exec: async (h: Host, script: string, _o?: ExecOptions): Promise<ExecResult> => {
            calls.push(h.name);
            const ok = !failOn.has(h.name);
            return { host: h.name, ok, code: ok ? 0 : 1, stdout: `ran ${script}`, stderr: ok ? '' : 'boom', ms: 1, error: ok ? undefined : 'exit 1: boom' };
        },
    };
    const inv = new Inventory('f', { hosts: { a: {}, b: {}, c: {}, d: {} } });
    return { ctx, calls, failOn, hosts: inv.resolve('all') };
}

const steps = (hosts: Host[], extra: Partial<HostStep> = {}): HostStep[] => hosts.map((h) => ({ host: h, action: 'do it', script: 'echo hi', ...extra }));

test('dry run: planHash, rollout, nothing executed', async () => {
    const { ctx, calls, hosts } = setup();
    const r = (await runSteps(ctx, 't', { x: 1 }, { apply: false, defaultBatch: 1 }, async () => steps(hosts))) as Record<string, unknown>;
    assert.equal(r.mode, 'dry-run');
    assert.match(r.planHash as string, /^[0-9a-f]{12}$/);
    assert.deepEqual(r.rollout, { batch: 1, stopOnFailure: true });
    assert.equal(calls.length, 0);
});

test('apply needs the same planHash; a changed fingerprint aborts', async () => {
    const { ctx, calls, hosts } = setup();
    const dry = (await runSteps(ctx, 't', { x: 1 }, { apply: false, defaultBatch: 1 }, async () => steps(hosts, { fingerprint: 'v1' }))) as { planHash: string };
    await assert.rejects(runSteps(ctx, 't', { x: 1 }, { apply: true, defaultBatch: 1 }, async () => steps(hosts)), /needs planHash/);
    const moved = (await runSteps(ctx, 't', { x: 1 }, { apply: true, planHash: dry.planHash, defaultBatch: 1 }, async () => steps(hosts, { fingerprint: 'v2' }))) as { mode: string };
    assert.equal(moved.mode, 'aborted');
    const otherArgs = (await runSteps(ctx, 't', { x: 2 }, { apply: true, planHash: dry.planHash, defaultBatch: 1 }, async () => steps(hosts, { fingerprint: 'v1' }))) as { mode: string };
    assert.equal(otherArgs.mode, 'aborted');
    assert.equal(calls.length, 0);
    const ok = (await runSteps(ctx, 't', { x: 1, apply: true, planHash: dry.planHash }, { apply: true, planHash: dry.planHash, defaultBatch: 1 }, async () => steps(hosts, { fingerprint: 'v1' }))) as { mode: string };
    assert.equal(ok.mode, 'applied');
    assert.deepEqual(calls, ['a', 'b', 'c', 'd']);
    assert.equal(ctx.state.journal().length, 4);
});

test('rolling apply stops at the first failure; continueOnError goes on', async () => {
    const { ctx, calls, failOn, hosts } = setup();
    failOn.add('b');
    const dry = (await runSteps(ctx, 't', {}, { apply: false, defaultBatch: 1 }, async () => steps(hosts))) as { planHash: string };
    const r = (await runSteps(ctx, 't', {}, { apply: true, planHash: dry.planHash, defaultBatch: 1 }, async () => steps(hosts))) as Record<string, unknown>;
    assert.equal(r.mode, 'stopped');
    assert.deepEqual(r.notRun, ['c', 'd']);
    assert.deepEqual(calls, ['a', 'b']);
    const journal = ctx.state.journal();
    assert.equal(journal[0].host, 'b');
    assert.equal(journal[0].ok, false);

    calls.length = 0;
    const again = (await runSteps(ctx, 't', {}, { apply: true, planHash: dry.planHash, defaultBatch: 1, continueOnError: true }, async () => steps(hosts))) as Record<string, unknown>;
    assert.equal(again.mode, 'aborted', 'planHash is one-time: a retry needs a new dry run');
    assert.equal(calls.length, 0);
    const dry2 = (await runSteps(ctx, 't', {}, { apply: false, defaultBatch: 1 }, async () => steps(hosts))) as { planHash: string };
    const r2 = (await runSteps(ctx, 't', {}, { apply: true, planHash: dry2.planHash, defaultBatch: 1, continueOnError: true }, async () => steps(hosts))) as Record<string, unknown>;
    assert.equal(r2.mode, 'applied-with-errors');
    assert.deepEqual(calls, ['a', 'b', 'c', 'd']);
});

test('two applies of one plan at once: only one runs (AUD-16)', async () => {
    const { ctx, calls, hosts } = setup();
    const dry = (await runSteps(ctx, 't', {}, { apply: false, defaultBatch: 4 }, async () => steps(hosts))) as { planHash: string };
    const both = await Promise.all([1, 2].map(() => runSteps(ctx, 't', {}, { apply: true, planHash: dry.planHash, defaultBatch: 4 }, async () => steps(hosts)) as Promise<{ mode: string }>));
    assert.deepEqual(both.map((r) => r.mode).sort(), ['aborted', 'applied']);
    assert.equal(calls.length, 4);
});

test('failed verification counts as failure and stops the rollout', async () => {
    const { ctx, calls, hosts } = setup();
    const mk = () => steps(hosts, { verify: async () => 'container exited' });
    const dry = (await runSteps(ctx, 't', {}, { apply: false, defaultBatch: 2 }, async () => mk())) as { planHash: string };
    const r = (await runSteps(ctx, 't', {}, { apply: true, planHash: dry.planHash, defaultBatch: 2 }, async () => mk())) as Record<string, unknown>;
    assert.equal(r.mode, 'stopped');
    assert.deepEqual(calls, ['a', 'b'], 'the first batch of 2 ran, the next did not');
    assert.match(JSON.stringify(r.results), /container exited/);
});

test('blockers and noop hosts', async () => {
    const { ctx, calls, hosts } = setup();
    const mk = () => hosts.map((h, i) => ({ host: h, action: 'x', script: 'x', ...(i === 0 ? { blockers: ['nope'] } : i === 1 ? { noop: 'already fine' } : {}) }));
    const dry = (await runSteps(ctx, 't', {}, { apply: false, defaultBatch: 1 }, async () => mk())) as Record<string, unknown>;
    assert.deepEqual(dry.blocked, ['a: nope']);
    assert.equal(dry.toRun, 3);
    const r = (await runSteps(ctx, 't', {}, { apply: true, planHash: dry.planHash as string, defaultBatch: 1 }, async () => mk())) as Record<string, unknown>;
    assert.equal(r.mode, 'aborted');
    assert.equal(calls.length, 0);
});

test('read-only mode refuses apply', async () => {
    const { ctx, hosts } = setup(true);
    const dry = (await runSteps(ctx, 't', {}, { apply: false, defaultBatch: 1 }, async () => steps(hosts))) as { planHash: string };
    await assert.rejects(runSteps(ctx, 't', {}, { apply: true, planHash: dry.planHash, defaultBatch: 1 }, async () => steps(hosts)), /read-only/);
});
