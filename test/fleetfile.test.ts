import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { planFleet, writeFleet } from '../src/core/fleetfile.js';

const FLEET = `# the owner's fleet
defaults:
  user: root

groups:
  proxies: [pl2, de3]   # public nodes
  home: [rpi]

hosts:
  pl2:
    address: node-pl2          # tailnet name
    roles: [remnanode]
    tags: [prod]
  de3:
    address: node-de3
    roles: [remnanode]
  rpi:
    address: rpi
    roles: [docker]
`;

function tmp(text = FLEET) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-fleet-'));
    const file = path.join(dir, 'fleet.yaml');
    fs.writeFileSync(file, text);
    return { dir, file, state: path.join(dir, 'state') };
}

test('fleet.yaml: add a host with groups, layout and comments kept, nothing written by the plan', () => {
    const { file } = tmp();
    const plan = planFleet(file, [{ op: 'add', name: 'pl3', set: { address: 'node-pl3', roles: ['remnanode'], tags: ['prod'], domain: 'pl3.example.com' } }, { op: 'update', name: 'pl3', groups: ['proxies', 'new-pool'] }]);
    assert.equal(fs.readFileSync(file, 'utf8'), FLEET, 'a plan does not write');
    assert.match(plan.after, /^  pl3:\n    address: node-pl3\n    roles: \[remnanode\]\n    tags: \[prod\]\n    domain: pl3\.example\.com$/m);
    assert.match(plan.after, /proxies: \[pl2, de3, pl3\]   # public nodes/, 'flow list extended in place, comment kept');
    assert.match(plan.after, /new-pool: \[pl3\]/);
    assert.match(plan.after, /address: node-pl2          # tailnet name/);
    assert.ok(plan.diff.some((l) => l.startsWith('+') && l.includes('pl3:')));
    assert.deepEqual(plan.summary, ['hosts.pl3 добавлен: address node-pl3, roles [remnanode], tags [prod], domain pl3.example.com', 'hosts.pl3: в группу proxies; новая группа new-pool']);
});

test('fleet.yaml: change, switch off and on, remove; group membership follows', () => {
    const { file } = tmp();
    let p = planFleet(file, [{ op: 'update', name: 'de3', set: { address: 'node-de3-new', tags: ['prod', 'eu'] }, groups: [] }]);
    assert.match(p.after, /    address: node-de3-new\n    roles: \[remnanode\]\n    tags: \[prod, eu\]/);
    assert.match(p.after, /proxies: \[pl2\] {8}# public nodes/, 'the comment keeps its column');
    assert.deepEqual(p.summary, ['hosts.de3: address: node-de3 → node-de3-new; tags: — → [prod, eu]; из группы proxies']);
    p = planFleet(file, [{ op: 'disable', name: 'rpi' }]);
    assert.match(p.after, /    roles: \[docker\]\n    disabled: true/);
    assert.deepEqual(p.summary, ['hosts.rpi: отключён']);
    const off = tmp(p.after);
    assert.deepEqual(planFleet(off.file, [{ op: 'enable', name: 'rpi' }]).after, FLEET);
    p = planFleet(file, [{ op: 'remove', name: 'pl2' }]);
    assert.doesNotMatch(p.after, /pl2/);
    assert.match(p.summary[0], /удалён, убран из групп: proxies/);
    assert.equal(planFleet(file, [{ op: 'update', name: 'de3', set: { address: 'node-de3' } }]).diff.filter((l) => /^[-+]/.test(l)).length, 0, 'nothing to change');
});

test('fleet.yaml: refuses what mia could not load, a duplicate, an unknown host; empty file works', () => {
    const { file } = tmp();
    assert.throws(() => planFleet(file, [{ op: 'add', name: 'pl2' }]), /уже есть/);
    assert.throws(() => planFleet(file, [{ op: 'update', name: 'nope', set: { user: 'x' } }]), /нет в fleet\.yaml/);
    assert.throws(() => planFleet(file, [{ op: 'add', name: 'x', set: { roles: ['router'] } }]), /not a valid inventory/);
    assert.throws(() => planFleet(file, [{ op: 'add', name: 'proxies' }]), /имя группы/);
    assert.throws(() => planFleet(file, [{ op: 'add', name: 'bad name' }]), /только буквы/);
    const empty = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mia-fleet-')), 'sub', 'fleet.yaml');
    const p = planFleet(empty, [{ op: 'add', name: 'rpi', set: { address: 'rpi', roles: ['docker'] } }]);
    assert.equal(p.after, 'hosts:\n  rpi:\n    address: rpi\n    roles: [docker]\n');
    writeFleet(p, path.join(path.dirname(empty), 'state'));
    assert.equal(fs.readFileSync(empty, 'utf8'), p.after);
});

test('fleet.yaml: write backs up into the state dir and refuses a file changed since the plan', () => {
    const { dir, file, state } = tmp();
    const p = planFleet(file, [{ op: 'disable', name: 'de3' }]);
    const { backup } = writeFleet(p, state);
    assert.equal(fs.readFileSync(backup!, 'utf8'), FLEET);
    assert.ok(backup!.startsWith(path.join(state, 'backups')));
    assert.deepEqual(fs.readdirSync(dir).sort(), ['fleet.yaml', 'state'], 'nothing next to fleet.yaml');
    const stale = planFleet(file, [{ op: 'enable', name: 'de3' }]);
    fs.appendFileSync(file, '# edited by hand\n');
    assert.throws(() => writeFleet(stale, state), /изменился после показа плана/);
    assert.notEqual(planFleet(file, [{ op: 'enable', name: 'de3' }]).hash, stale.hash);
});

test('fleet_host_edit: dry run shows the diff, apply needs the planHash, writes, journals', async () => {
    const { dir, file } = tmp();
    const { loadConfig } = await import('../src/config.js');
    const { Ctx } = await import('../src/core/ctx.js');
    const { registry, instrument } = await import('../src/tools/helpers.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const { registerInventoryTools } = await import('../src/tools/inventory.js');
    const ctx = new Ctx(loadConfig({ MIA_STATE_DIR: path.join(dir, 'state'), MIA_INVENTORY: file }));
    const server = new McpServer({ name: 't', version: '0' });
    instrument(server, ctx.out);
    registerInventoryTools(server, ctx);
    const call = async (a: Record<string, unknown>) => JSON.parse((await registry.get('fleet_host_edit')!.handler(a)).content[0].text);
    const args = { op: 'add', name: 'pl3', address: 'node-pl3', roles: 'remnanode', tags: 'prod', groups: 'proxies' };
    const dry = await call({ ...args, apply: false });
    assert.equal(dry.mode, 'dry-run');
    assert.ok(dry.plan[0].after.some((l: string) => l.includes('pl3:')));
    assert.equal(fs.readFileSync(file, 'utf8'), FLEET);
    assert.equal((await call({ ...args, apply: true, planHash: 'nope' })).mode, 'aborted');
    const done = await call({ ...args, apply: true, planHash: dry.planHash });
    assert.equal(done.mode, 'applied');
    assert.equal(ctx.inventory().get('pl3').address, 'node-pl3');
    assert.deepEqual(ctx.inventory().get('pl3').groups, ['proxies']);
    assert.equal(ctx.state.journal().filter((j) => j.tool === 'fleet_host_edit').length, 1);
    assert.equal((await call({ ...args, op: 'update', groups: undefined, apply: false })).toRun, 0, 'nothing to do the second time');
    await assert.rejects(async () => {
        const r = await registry.get('fleet_host_edit')!.handler({ op: 'update', name: 'pl3', unset: 'password', apply: false });
        if (r.isError) throw new Error(r.content[0].text);
    }, /unknown fields password/);
});

test('fleet.yaml surgery on a commented file: only the lines that mean the change', () => {
    const file = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'fleet.example.yaml');
    const changed = (edits: Parameters<typeof planFleet>[1]) => planFleet(file, edits).diff.filter((l) => /^[-+]/.test(l));
    const add = changed([{ op: 'add', name: 'pl3', set: { address: 'node-pl3', roles: ['remnanode'] }, groups: ['eu'] }]);
    assert.deepEqual(add.map((l) => l.replace(/^\+\s*\d+: /, '+ ')), ['-   eu: [nl-1, de-1]', '+   eu: [nl-1, de-1, pl3]', '+   pl3:', '+     address: node-pl3', '+     roles: [remnanode]', '+ '], 'blank line before the new host, trailing comment block untouched');
    assert.deepEqual(
        changed([{ op: 'update', name: 'nl-1', set: { tags: ['prod', 'eu'] } }]).map((l) => l.replace(/^\+\s*\d+: /, '+ ')),
        ['-     tags: [prod]', '+     tags: [prod, eu]'],
        '«bootstrap:   # comment» stays on its line',
    );
    assert.deepEqual(changed([{ op: 'disable', name: 'de-1' }]).length, 1);
    const rm = changed([{ op: 'remove', name: 'nl-1' }]);
    assert.ok(rm.includes('-   # A node built with vps-edge-run.sh --remnanode=1 --tailscale=1'), 'the comment right above goes with the host');
    assert.ok(!rm.some((l) => l.startsWith('+') && !l.includes('eu: [de-1]')));
});
