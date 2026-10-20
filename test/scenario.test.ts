import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { z } from 'zod';
import { loadConfig, parseRepos } from '../src/config.js';
import { Ctx } from '../src/core/ctx.js';
import { PanelBridge, ScenarioDef, ScenarioEngine } from '../src/core/scenario.js';
import { registry } from '../src/tools/helpers.js';
import { repoRunner } from '../src/tools/repo.js';
import { MANIFEST, parseManifest, setEnvLines } from '../src/tools/copy.js';
import { SCENARIOS } from '../src/scenarios/index.js';
import { ruleOps } from '../src/scenarios/xray-rules.js';

const FLEET = `# fleet
defaults:
  user: ops
groups:
  eu: [pl2, de3]   # exits
  ingress: [ingress1]
hosts:
  pl2:
    address: node-pl2
    roles: [remnanode]
    tags: [prod, eu]
    domain: pl2.example.org
    panelNode: pl-acme-pl2
    services:
      - {name: haproxy, unit: haproxy}
  de3:
    address: node-de3   # keep this comment
    roles: [remnanode]
  ingress1:
    address: node-ingress1
    roles: [remnanode]
    tags: [prod, ingress]
`;

function setup(fleet = FLEET) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-scn-'));
    const inv = path.join(dir, 'fleet.yaml');
    fs.writeFileSync(inv, fleet);
    const ctx = new Ctx(loadConfig({ MIA_STATE_DIR: path.join(dir, 'state'), MIA_INVENTORY: inv }));
    return { ctx, dir, inv };
}

/** Panel fake speaking the mcp-remnawave protocols. */
function fakePanel(handlers: Record<string, (a: Record<string, unknown>) => unknown>) {
    const calls: Array<[string, Record<string, unknown>]> = [];
    const bridge: PanelBridge = {
        call: async (name, args) => {
            calls.push([name, args]);
            const h = handlers[name];
            if (!h) return { ok: false, data: `unknown tool ${name}`, text: `unknown tool ${name}` };
            const data = h(args);
            return { ok: true, data, text: JSON.stringify(data) };
        },
    };
    return { bridge, calls };
}

// a mia write tool with the dry-run / planHash protocol, counting real runs
let applied = 0;
let hashVersion = 'h1';
registry.set('fake_write', {
    description: 'test',
    readonly: false,
    schema: { target: z.string(), apply: z.boolean().default(false), planHash: z.string().optional() },
    handler: async (a) => {
        const text = (d: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(d) }] });
        if (!a.apply) return text({ mode: 'dry-run', planHash: hashVersion, toRun: a.target === 'none' ? 0 : 1, plan: [{ host: a.target, will: 'x' }] });
        if (a.planHash !== hashVersion) return text({ mode: 'aborted', reason: 'changed', planHash: hashVersion });
        applied++;
        return text({ mode: 'applied', results: [{ host: a.target, ok: true }] });
    },
});

const demo: ScenarioDef = {
    name: 'demo',
    title: 'demo',
    description: 'demo',
    params: { host: z.string(), extra: z.boolean().default(false) },
    steps: (p, v) => [
        { id: 'look', title: 'look', kind: 'check', run: async () => ({ n: 3 }), expect: (d) => (d.n === 3 ? true : 'bad'), save: (d, r) => (r.vars.n = d.n) },
        { id: 'noop', title: 'already fine', kind: 'mia', tool: 'fake_write', args: () => ({ target: 'none' }) },
        { id: 'change', title: 'change', kind: 'mia', tool: 'fake_write', args: () => ({ target: p.host }) },
        { id: 'hands', title: 'by hand', kind: 'manual', instruction: (r) => `do ${r.vars.n} things` },
        { id: 'panel', title: 'panel', kind: 'panel', tool: 'hosts_bulk_edit', args: () => ({ filter: { node: 'x' } }) },
        { id: 'del', title: 'delete', kind: 'panel', tool: 'nodes_delete', protocol: 'confirmName', args: () => ({ node: 'x' }), confirm: () => 'node-x' },
        { id: 'skipme', title: 'n/a', kind: 'manual', when: () => p.extra, instruction: () => 'never' },
        ...(v.n === 3 ? [{ id: 'dyn', title: 'dynamic', kind: 'check' as const, run: async () => 'ok' }] : []),
        {
            id: 'inv',
            title: 'inventory',
            kind: 'inventory',
            edit: (doc) => {
                doc.setIn(['hosts', 'de3', 'disabled'], true);
                return 'de3 disabled';
            },
        },
    ],
};

test('engine: checks pass by themselves, changes wait for a decision, state survives a restart', async () => {
    const { ctx, inv } = setup();
    applied = 0;
    hashVersion = 'h1';
    const { bridge, calls } = fakePanel({
        hosts_bulk_edit: (a) => (a.apply ? (a.planHash === 'p1' ? { mode: 'applied' } : { mode: 'aborted' }) : { mode: 'dry-run', planHash: 'p1', changed: 2, report: [] }),
        nodes_delete: (a) => (a.confirmName === 'node-x' ? { deleted: true } : { deleted: false, impact: { hostsBound: 4 } }),
    });
    const eng = new ScenarioEngine(ctx, new Map([['demo', demo]]), bridge);
    let adv = await eng.start('demo', { host: 'pl2' });
    assert.deepEqual(
        adv.passed.map((p) => [p.id, p.status]),
        [
            ['look', 'passed'],
            ['noop', 'passed'],
        ],
    );
    assert.equal(adv.step?.id, 'change');
    assert.deepEqual(adv.step?.choices, ['apply', 'skip']);
    assert.equal(applied, 0, 'nothing runs before apply');

    // the plan changed between preview and apply: re-planned, not applied
    hashVersion = 'h2';
    adv = await (new ScenarioEngine(ctx, new Map([['demo', demo]]), bridge)).decide(adv.step!.run, 'apply');
    assert.equal(adv.outcome?.status, 'replanned');
    assert.equal(applied, 0);
    const run = adv.step!.run;
    adv = await eng.decide(run, 'apply');
    assert.equal(adv.outcome?.status, 'applied');
    assert.equal(applied, 1);
    assert.equal(adv.step?.id, 'hands');
    assert.equal(adv.step?.preview, 'do 3 things');
    await assert.rejects(eng.decide(run, "apply"), /руками/);
    adv = await eng.decide(run, 'done');
    assert.equal(adv.step?.id, 'panel');
    assert.equal((adv.step?.preview as { changed: number }).changed, 2);
    adv = await eng.decide(run, 'apply');
    assert.equal(adv.outcome?.status, 'applied');
    assert.deepEqual(calls.at(-2), ['hosts_bulk_edit', { filter: { node: 'x' }, apply: true, planHash: 'p1' }]);
    assert.equal(adv.step?.id, 'del');
    assert.deepEqual(calls.at(-1), ['nodes_delete', { node: 'x' }], 'destructive: preview without confirmName');
    adv = await eng.decide(run, 'apply');
    assert.deepEqual(calls.at(-1), ['nodes_delete', { node: 'x', confirmName: 'node-x' }]);
    assert.deepEqual(
        adv.passed.map((p) => [p.id, p.status]),
        [
            ['skipme', 'n/a'],
            ['dyn', 'passed'],
        ],
    );
    assert.equal(adv.step?.id, 'inv');
    const diff = (adv.step?.preview as { diff: string[] }).diff;
    assert.ok(diff.some((l) => l.includes('disabled: true')));
    assert.ok(!fs.readFileSync(inv, 'utf8').includes('disabled'), 'preview does not write');
    // another session edits fleet.yaml while the owner reads the diff: the new diff is shown, nothing written
    fs.appendFileSync(inv, '# another session\n');
    adv = await eng.decide(run, 'apply');
    assert.equal(adv.step?.id, 'inv');
    assert.ok(!fs.readFileSync(inv, 'utf8').includes('disabled'), 'a diff nobody saw is not applied');
    adv = await eng.decide(run, 'apply');
    assert.equal(adv.finished, true);
    const after = fs.readFileSync(inv, 'utf8');
    assert.match(after, /disabled: true/);
    assert.match(after, /# keep this comment/);
    assert.ok(fs.readdirSync(path.join(ctx.config.stateDir, 'backups')).some((f) => f.startsWith('fleet.yaml.')), 'backup in the state dir');
    assert.ok(!fs.readdirSync(path.dirname(inv)).some((f) => f.includes('.bak')), 'nothing left next to fleet.yaml (a git checkout)');
    assert.equal(ctx.state.journal().filter((j) => j.tool === 'scenario:demo').length, 4);
    assert.deepEqual(eng.runs()[0].finished, true);
});

test('engine: panel steps without mcp-remnawave ask to configure it; skip moves on', async () => {
    const { ctx } = setup();
    const def: ScenarioDef = {
        name: 'p',
        title: 'p',
        description: 'p',
        params: {},
        steps: () => [
            { id: 'a', title: 'a', kind: 'check', panel: true, tool: 'nodes_list' },
            { id: 'b', title: 'b', kind: 'manual', instruction: () => 'b' },
        ],
    };
    const eng = new ScenarioEngine(ctx, new Map([['p', def]]));
    let adv = await eng.start('p', {});
    assert.match(adv.step?.problem ?? '', /MIA_REMNAWAVE_MCP/);
    assert.deepEqual(adv.step?.choices, ['retry', 'skip']);
    adv = await eng.decide(adv.step!.run, 'skip');
    assert.equal(adv.step?.id, 'b');
    await assert.rejects(eng.start('p', { bogus: 1 }), /bogus/);
});

test('xray_rules: ops from the short parameters', () => {
    assert.deepEqual(ruleOps({ rule: 'outboundTag=RU-GOS', addDomains: 'domain:gov.example, domain:esia.gov.example' }), [
        { op: 'array_add', path: '/routing/rules[outboundTag=RU-GOS]/domain', values: ['domain:gov.example', 'domain:esia.gov.example'] },
    ]);
    assert.deepEqual(ruleOps({ rule: 'ruleTag=yt', outbound: 'YouTube', newRule: '{"outboundTag":"direct","domain":["geosite:google-gemini"]}' }), [
        { op: 'replace', path: '/routing/rules[ruleTag=yt]/outboundTag', value: 'YouTube' },
        { op: 'insert', path: '/routing/rules[ruleTag=yt]', position: 'before', value: { outboundTag: 'direct', domain: ['geosite:google-gemini'] } },
    ]);
    assert.throws(() => ruleOps({ addDomains: 'x' }), /нужно rule/);
    assert.throws(() => ruleOps({}), /менять нечего/);
});

test('xray_rules: one profile at a time, nodes must reconnect before the next', async () => {
    const { ctx } = setup();
    let patched: string[] = [];
    const { bridge } = fakePanel({
        config_profiles_list: () => [
            { name: 'profile-eu', nodes: ['de3'] },
            { name: 'profile-ru', nodes: ['ingress1'] },
        ],
        config_profile_patch: (a) => {
            if (!a.apply) return { mode: 'dry-run', planHash: `h-${a.profile}`, changed: 1, report: [{ ops: a.ops }] };
            patched.push(a.profile as string);
            return { mode: 'applied', planHash: `h-${a.profile}` };
        },
        nodes_list: () => ({ total: 0, nodes: [] }),
    });
    const eng = new ScenarioEngine(ctx, SCENARIOS, bridge, 0);
    let adv = await eng.start('xray_rules', { profiles: 'profile-ru,profile-eu', rule: 'outboundTag=RU-GOS', addDomains: 'domain:gov.example' });
    assert.equal(adv.step?.id, 'patch:profile-ru');
    assert.equal(adv.step?.total, 5);
    adv = await eng.decide(adv.step!.run, 'apply');
    assert.deepEqual(patched, ['profile-ru']);
    assert.deepEqual(
        adv.passed.map((p) => p.id),
        ['nodes:profile-ru'],
    );
    assert.equal(adv.step?.id, 'patch:profile-eu');
    patched = [];
    adv = await eng.decide(adv.step!.run, 'skip');
    assert.equal(adv.finished, true);
    assert.deepEqual(patched, []);
});

/** Walk a run answering: problems → skip, manual → done, changes → apply; returns the ids seen. */
async function walkAll(eng: ScenarioEngine, adv: Awaited<ReturnType<ScenarioEngine['start']>>, answers: Record<string, 'apply' | 'skip' | 'done'> = {}) {
    const seen: string[] = [];
    for (let i = 0; i < 60 && adv.step; i++) {
        const s = adv.step;
        seen.push(`${s.id}${s.problem ? '!' : ''}`);
        const d = answers[s.id] ?? (s.problem ? 'skip' : s.kind === 'manual' ? 'done' : 'apply');
        adv = await eng.decide(s.run, d);
    }
    return { seen, adv };
}

test('repo_script: files are recreated in a temp dir, args passed, dir removed', () => {
    const script = repoRunner(
        [
            { rel: 'deploy/run.sh', body: Buffer.from('#!/bin/bash\nset -e\necho "args:$*"\ncat ../lists/white.txt\necho "$FOO"\npwd > /tmp/mia-repo-test-pwd\n') },
            { rel: 'lists/white.txt', body: Buffer.from("1.2.3.4 'quoted' $HOME\n") },
        ],
        'deploy/run.sh',
        ['--mode', "it's"],
    );
    const out = execFileSync('bash', ['-s'], { input: `export FOO=bar\n${script}`, encoding: 'utf8' });
    assert.equal(out, "args:--mode it's\n1.2.3.4 'quoted' $HOME\nbar\n");
    const dir = fs.readFileSync('/tmp/mia-repo-test-pwd', 'utf8').trim();
    assert.match(dir, /\/tmp\/mia-repo\.\w+\/deploy$/);
    assert.equal(fs.existsSync(path.dirname(dir)), false);
    fs.rmSync('/tmp/mia-repo-test-pwd');
});

test('MIA_REPOS parsing', () => {
    const r = parseRepos('ops=~/src/ops-scripts, haproxy=/srv/haproxy-configs');
    assert.equal(r.ops, path.join(os.homedir(), 'src/ops-scripts'));
    assert.equal(r.haproxy, '/srv/haproxy-configs');
    assert.throws(() => parseRepos('nope'), /name=path/);
});

test('RemnawaveBridge talks to an MCP server over stdio and reads spilled results back', async () => {
    const { RemnawaveBridge } = await import('../src/core/remnawave.js');
    const fixture = path.join(import.meta.dirname, 'fixtures', 'fake-remnawave.ts');
    const bridge = RemnawaveBridge.from(JSON.stringify([process.execPath, '--import', 'tsx', fixture]))!;
    try {
        assert.ok((await bridge.tools()).includes('config_profile_patch'));
        const dry = await bridge.call('config_profile_patch', { profile: 'p', ops: [{ op: 'remove', path: '/x' }] });
        assert.equal(dry.ok, true);
        assert.equal((dry.data as { planHash: string }).planHash, 'abc123');
        const err = await bridge.call('boom', {});
        assert.equal(err.ok, false);
        const { ctx } = setup();
        const eng = new ScenarioEngine(ctx, SCENARIOS, bridge, 0);
        let adv = await eng.start('xray_rules', { profiles: 'profile-ru', rule: 'outboundTag=RU-GOS', removeDomains: 'domain:old.example' });
        assert.equal(adv.step?.id, 'patch:profile-ru');
        adv = await eng.decide(adv.step!.run, 'apply');
        assert.equal(adv.outcome?.status, 'applied');
        assert.equal(adv.finished, true);
    } finally {
        await bridge.close();
    }
});

test('host_copy helpers: env lines, manifest', { skip: process.platform === 'darwin' && 'GNU coreutils (stat -c, install -D) — the scripts run on Linux hosts' }, () => {
    assert.equal(setEnvLines('A=1\nLOG_NODE_NAME=de-acme-de2\nexport B=2\n', { LOG_NODE_NAME: 'pl-acme-pl3', B: '3', C: 'x' }), 'A=1\nLOG_NODE_NAME=pl-acme-pl3\nexport B=3\nC=x\n');
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-man-'));
    fs.writeFileSync(path.join(d, 'f'), 'hello');
    fs.mkdirSync(path.join(d, 'dir'));
    fs.writeFileSync(path.join(d, 'dir', 'x'), 'x');
    const out = execFileSync('bash', ['-c', `set -- ${d}/f ${d}/dir ${d}/none\n${MANIFEST}`], { encoding: 'utf8' });
    const rows = parseManifest(out);
    assert.deepEqual(
        rows.map((r) => [r.kind, r.size ?? r.files ?? null]),
        [
            ['file', 5],
            ['dir', 1],
            ['missing', null],
        ],
    );
    assert.match(rows[0].sha!, /^[0-9a-f]{16}$/);
});

test('repo_script installTo: the script is installed, the old copy kept, the installed one runs', { skip: process.platform === 'darwin' && 'GNU coreutils (stat -c, install -D) — the scripts run on Linux hosts' }, () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-inst-'));
    const dest = path.join(d, 'bin', 'ufw-blacklist.sh');
    fs.mkdirSync(path.dirname(dest));
    fs.writeFileSync(dest, 'echo old\n');
    const script = repoRunner([{ rel: 'deploy/ufw-blacklist.sh', body: Buffer.from('echo "new from $0"\nread -r x && echo "stdin leaked: $x" || true\n') }], 'deploy/ufw-blacklist.sh', [], dest);
    const out = execFileSync('bash', ['-s'], { input: `${script}\necho after`, encoding: 'utf8' });
    assert.match(out, new RegExp(`installed ${dest}\\nnew from ${dest}\\nafter`));
    assert.doesNotMatch(out, /stdin leaked/);
    assert.equal(fs.readFileSync(dest, 'utf8').includes('new from'), true);
    assert.equal(fs.readdirSync(path.dirname(dest)).filter((f) => f.startsWith('ufw-blacklist.sh.bak-')).length, 1);
});

test('a failed gate cannot be skipped past: only its rollback runs, then the run ends (AUD-16)', async () => {
    const { ctx } = setup();
    let reachable = false;
    const def: ScenarioDef = {
        name: 'g',
        title: 'g',
        description: 'g',
        params: {},
        steps: () => [
            { id: 'move', title: 'move', kind: 'manual', instruction: () => 'move' },
            { id: 'ru', title: 'ru', kind: 'check', gate: true, run: async () => reachable, expect: (d) => (d ? true : 'blocked-ru') },
            { id: 'undo', title: 'undo', kind: 'manual', onGateFail: 'ru', instruction: () => 'undo' },
            { id: 'drop-old', title: 'drop old', kind: 'manual', instruction: () => 'drop' },
        ],
    };
    const eng = new ScenarioEngine(ctx, new Map([['g', def]]), undefined, 0);
    let { seen, adv } = await walkAll(eng, await eng.start('g', {}));
    assert.deepEqual(seen, ['move', 'ru!', 'undo']);
    assert.equal(adv.finished, true);
    assert.deepEqual(adv.log!.map((l) => `${l.id}:${l.status}`), ['move:done', 'ru:skipped', 'undo:done', 'drop-old:n/a']);
    // провал → «проверить снова», а уже доступно: ворота пройдены, отката нет
    reachable = false;
    let a = await eng.start('g', {});
    a = await eng.decide(a.step!.run, 'done');
    assert.equal(a.step!.id, 'ru');
    reachable = true;
    a = await eng.decide(a.step!.run, 'retry');
    assert.deepEqual(a.passed.map((p) => `${p.id}:${p.status}`), ['ru:passed', 'undo:n/a']);
    assert.equal(a.step!.id, 'drop-old');
    ({ seen, adv } = await walkAll(eng, await eng.start('g', {})));
    assert.deepEqual(seen, ['move', 'drop-old'], 'a passing gate: no rollback, the run goes on');
});
