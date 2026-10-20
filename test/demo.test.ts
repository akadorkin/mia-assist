import assert from 'node:assert/strict';
import { test } from 'node:test';

test('demo fleet: status with real findings, «Выполнить» changes only the pretend state, no ssh anywhere', async () => {
    const { demoEnv, DemoTransport } = await import('../src/demo.js');
    const { loadConfig } = await import('../src/config.js');
    const { createServer } = await import('../src/server.js');
    const { callTool } = await import('../src/ui.js');
    const env = demoEnv();
    assert.match(env.MIA_SSH_BIN!, /nonexistent/, 'a stray real ssh call could not reach anything');
    const config = { ...loadConfig(env), demo: true };
    assert.equal(config.panel, undefined, 'no panel, no keys');
    const { ctx } = createServer(config, new DemoTransport(config));
    const status = await callTool('fleet_status', { target: 'all', tailnet: true });
    const rows = (status.data as { rows: Array<Record<string, unknown>> }).rows;
    const row = (h: string) => rows.find((r) => r.host === h)!;
    assert.equal(row('nl-1').state, 'ok');
    assert.match(String(row('nl-2').issues), /reboot\.required/);
    assert.match(String(row('de-1').issues), /cert\.expiring/);
    assert.match(String(row('pl-1').issues), /disk\.full.*f2b\.inactive|f2b\.inactive.*disk\.full/);
    assert.equal(row('ru-1').state, 'UNREACHABLE');
    assert.ok(rows.some((r) => r.host === 'spare-vps' && r.state === 'offline'), 'a pretend tailnet too');
    assert.ok(!rows.some((r) => r.host === 'macbook'), 'a personal device is never «not in fleet.yaml»');

    const dry = await callTool('apt_upgrade', { target: 'nl-2,rpi', apply: false });
    const plan = dry.data as { planHash: string; toRun: number };
    assert.equal(plan.toRun, 2);
    const done = await callTool('apt_upgrade', { target: 'nl-2,rpi', apply: true, planHash: plan.planHash });
    assert.equal((done.data as { mode: string }).mode, 'applied');
    const after = (await callTool('fleet_status', { target: 'nl-2,rpi', tailnet: false })).data as { rows: Array<Record<string, unknown>> };
    assert.deepEqual(
        after.rows.map((r) => [r.host, r.updates]),
        [
            ['nl-2', '0'],
            ['rpi', '0'],
        ],
        'the update emptied the pretend lists',
    );
    assert.ok(after.rows.find((r) => r.host === 'rpi')!.reboot, 'and the kernel now wants a reboot');
    assert.ok(ctx.state.journal().some((j) => j.tool === 'apt_upgrade'), 'journaled like the real thing, in the demo state dir');
    assert.match(ctx.config.stateDir, /mia-demo-/);
});
