import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Inventory } from '../src/core/inventory.js';

const inv = new Inventory('fleet.yaml', {
    defaults: { user: 'ops' },
    policy: { certWarnDays: 30 },
    groups: { eu: ['nl-1', 'de-1'] },
    hosts: {
        'nl-1': { roles: ['remnanode'], tags: ['prod'], domain: 'nl1.example.com', title: '🐧 penguin' },
        'de-1': { roles: ['remnanode'], tags: ['prod'], policy: { skip: ['tune'] } },
        'us-1': { roles: ['remnanode'], tags: ['test'], disabled: true },
        panel: { address: 'panel-host', roles: ['panel'], services: [{ name: 'bot', compose: '/opt/bot/docker-compose.yml' }] },
        laptop: { transport: 'local' },
        rooty: { user: 'root' },
    },
});

test('roles imply their base roles and services', () => {
    const nl = inv.get('nl-1');
    assert.deepEqual(nl.roles, ['edge', 'remnanode']);
    assert.ok(nl.services.some((s) => s.name === 'remnanode' && s.compose === '/opt/remnanode/docker-compose.yml'));
    assert.ok(nl.services.some((s) => s.name === 'tailscaled'));
    assert.equal(nl.logs['remnanode.log'], '/var/log/remnanode/*.log');
    assert.equal(nl.logs['install-docker'], '/var/log/install-docker.log');
    assert.ok(nl.services.some((s) => s.name === 'beszel-agent'));
    assert.deepEqual(nl.policy.mgmtPorts, [22, 2222, 9100, 45876, 5201, 2112, 2113]);
    assert.equal(nl.policy.securityUpdates, true);
    assert.equal(nl.policy.autoReboot, false);
    assert.deepEqual(inv.get('panel').roles, ['docker', 'panel']);
    assert.ok(inv.get('panel').services.some((s) => s.name === 'bot'));
});

test('policy merges global, defaults and host skips', () => {
    assert.equal(inv.get('nl-1').policy.certWarnDays, 30);
    assert.deepEqual(inv.get('nl-1').policy.publicPorts, ['80/tcp', '80/udp', '443/tcp', '443/udp']);
    assert.deepEqual(inv.get('de-1').policy.skip, ['tune']);
});

test('sudo defaults: on for non-root ssh users, off for root and local', () => {
    assert.equal(inv.get('nl-1').sudo, true);
    assert.equal(inv.get('rooty').sudo, false);
    assert.equal(inv.get('laptop').sudo, false);
    assert.equal(inv.get('panel').address, 'panel-host');
    assert.equal(inv.get('nl-1').address, 'nl-1');
});

test('target resolution', () => {
    const names = (t: string) => inv.resolve(t).map((h) => h.name);
    assert.deepEqual(names('all'), ['nl-1', 'de-1', 'panel', 'laptop', 'rooty']);
    assert.deepEqual(names('role:remnanode'), ['nl-1', 'de-1']);
    assert.deepEqual(names('eu'), ['nl-1', 'de-1']);
    assert.deepEqual(names('@eu,!de-1'), ['nl-1']);
    assert.deepEqual(names('tag:prod'), ['nl-1', 'de-1']);
    assert.deepEqual(names('*-1'), ['nl-1', 'de-1']);
    assert.deepEqual(names('us-1'), ['us-1'], 'disabled hosts are reachable by name');
    assert.deepEqual(names('all,!role:remnanode'), ['panel', 'laptop', 'rooty']);
});

test('target errors are explicit', () => {
    assert.throws(() => inv.resolve('nl1'), /unknown target "nl1".*did you mean nl-1/);
    assert.throws(() => inv.resolve('role:vpn'), /unknown role/);
    assert.throws(() => inv.resolve('tag:nope'), /no enabled host has tag/);
    assert.throws(() => inv.resolve('nl-1,!nl-1'), /matches no host/);
    assert.throws(() => inv.resolve(''), /empty target/);
});

test('invalid inventories are rejected with the path of the problem', () => {
    assert.throws(() => new Inventory('f', { hosts: { a: { roles: ['vpn'] } } }), /hosts\.a\.roles\.0/);
    assert.throws(() => new Inventory('f', { hosts: { a: {} }, groups: { g: ['b'] } }), /unknown host "b"/);
    assert.throws(() => new Inventory('f', { hosts: { a: {} }, groups: { a: ['a'] } }), /same name as a host/);
    assert.throws(() => new Inventory('f', { hosts: { a: { services: [{ name: 'x' }] } } }), /compose, container or unit/);
});

test('missing inventory file gives an empty inventory', () => {
    const empty = Inventory.load('/nonexistent/fleet.yaml');
    assert.equal(empty.hosts.size, 0);
    assert.throws(() => empty.resolve('all'), /matches no host/);
});

test('a host is reached by its animal as well as its key', () => {
    assert.equal(inv.get('nl-1').title, '🐧 penguin');
    assert.deepEqual(inv.resolve('penguin').map((h) => h.name), ['nl-1']);
    assert.deepEqual(inv.resolve('eu,!penguin').map((h) => h.name), ['de-1']);
});
