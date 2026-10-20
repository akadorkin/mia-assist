import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SCENARIOS } from '../src/scenarios/index.js';
import { updateQueue, updateTarget } from '../src/scenarios/fleet-update.js';

// security updates one host at a time, hands-off never, no automatic reboots

test('fleet_update: hands-off is always out', () => {
    assert.equal(updateTarget('all', []), 'all,!hands-off');
    assert.equal(updateTarget('role:remnanode', ['nas']), 'role:remnanode,!hands-off,!nas');
    assert.equal(updateTarget('all,!hands-off', []), 'all,!hands-off');
});

test('fleet_update: queue has only hosts with updates, canary first', () => {
    const plan = [
        { host: 'pl2', now: { upgradable: 14, security: 0 } },
        { host: 'node-x', now: { upgradable: 50, security: 3 } },
        { host: 'node-a', now: { upgradable: 2, security: 2 } },
        { host: 'node-z', now: { upgradable: 0, security: 0 } },
    ];
    assert.deepEqual(updateQueue(plan, true), ['node-a', 'node-x']);
    assert.deepEqual(updateQueue(plan, true, 'node-x'), ['node-x', 'node-a']);
    assert.deepEqual(updateQueue(plan, false, 'pl2'), ['pl2', 'node-a', 'node-x']);
});

test('fleet_update: one upgrade step per host, each checked back; no reboot tool anywhere', () => {
    const def = SCENARIOS.get('fleet_update')!;
    const p = { target: 'all', securityOnly: true, includeKernel: false, skipDocker: true };
    assert.deepEqual(def.steps(p, {}).map((s) => s.id), ['plan', 'panel-nodes', 'reboot', 'snapshot']);
    const steps = def.steps(p, { queue: ['node-x', 'node-a'] });
    assert.deepEqual(steps.map((s) => s.id), ['plan', 'panel-nodes', 'upgrade-node-x', 'back-node-x', 'panel-node-x', 'upgrade-node-a', 'back-node-a', 'panel-node-a', 'reboot', 'snapshot']);
    const up = steps.find((s) => s.id === 'upgrade-node-a')!;
    assert.deepEqual(up.args!({ params: p, vars: {} }), { target: 'node-a', securityOnly: true, includeKernel: false, skipDocker: true });
    assert.ok(!steps.some((s) => s.tool === 'host_reboot'));
    assert.equal(steps.find((s) => s.id === 'reboot')!.kind, 'manual');
});
