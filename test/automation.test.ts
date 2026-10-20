import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { runApiSteps } from '../src/core/plan.js';
import { cfRecords, zoneFor } from '../src/core/cloudflare.js';
import { Ctx } from '../src/core/ctx.js';
import { giteaRegistrationToken, giteaRunners } from '../src/core/gitea.js';
import { editText } from '../src/core/textedit.js';

test('registry files: clone / replace / remove entries in lines, IP lists, JSON and YAML', () => {
    const bash = `WHITELIST=(\n  "1.1.1.1"   # de2\n  "2.2.2.2"   # pl2\n)\nIPS="1.1.1.1 2.2.2.2 3.3.3.3"\npy = ['1.1.1.1', '2.2.2.2']\n# 2.2.2.2 old comment`;
    const c = editText(bash, 'lines', { op: 'clone', match: '2.2.2.2', replace: { '2.2.2.2': '9.9.9.9', pl2: 'pl3' } });
    assert.equal(c.changed, 3);
    assert.match(c.text, /"2\.2\.2\.2" {3}# pl2\n {2}"9\.9\.9\.9" {3}# pl3/);
    assert.match(c.text, /IPS="1\.1\.1\.1 2\.2\.2\.2 9\.9\.9\.9 3\.3\.3\.3"/);
    assert.match(c.text, /py = \['1\.1\.1\.1', '2\.2\.2\.2', '9\.9\.9\.9'\]/);
    assert.match(c.text, /# 2\.2\.2\.2 old comment$/);
    assert.equal(editText(c.text, 'lines', { op: 'clone', match: '2.2.2.2', replace: { '2.2.2.2': '9.9.9.9', pl2: 'pl3' } }).changed, 0, 'idempotent');
    const r = editText(c.text, 'lines', { op: 'remove', match: '9.9.9.9' });
    assert.equal(r.text, bash);

    const json = JSON.stringify({ 'node-pl2:9100': { name: 'pl2', cluster: 'eu' }, 'node-de2:9100': { name: 'de2' } }, null, 2) + '\n';
    const j = editText(json, 'json', { op: 'clone', match: 'node-pl2', replace: { 'node-pl2': 'node-pl3', pl2: 'pl3' } });
    assert.deepEqual(Object.keys(JSON.parse(j.text)), ['node-pl2:9100', 'node-pl3:9100', 'node-de2:9100']);
    assert.equal(JSON.parse(j.text)['node-pl3:9100'].name, 'pl3');
    assert.equal(editText(j.text, 'json', { op: 'remove', match: 'node-pl3' }).text, json);

    const yaml = 'nodes:\n  - {country: PL, name: pl-acme-pl2, ip: 198.51.100.10}   # template\n  - {country: DE, name: de2, ip: 198.51.100.11}\n';
    const y = editText(yaml, 'yaml', { op: 'clone', match: 'pl-acme-pl2', replace: { 'pl-acme-pl2': 'pl-acme-pl3', '198.51.100.10': '198.51.100.12' } });
    assert.match(y.text, /name: pl-acme-pl2, ip: 198\.51\.100\.10\} # template\n {2}- \{country: PL, name: pl-acme-pl3, ip: 198\.51\.100\.12\}/);
    const rep = editText(yaml, 'yaml', { op: 'replace', match: 'pl-acme-pl2', replace: { '198.51.100.10': '198.51.100.99' } });
    assert.equal(rep.changed, 1);
    assert.match(rep.text, /name: pl-acme-pl2, ip: 198\.51\.100\.99\} # template\n {2}- \{country: DE/);
    assert.equal(editText(yaml, 'yaml', { op: 'remove', match: 'de2' }).text, 'nodes:\n  - {country: PL, name: pl-acme-pl2, ip: 198.51.100.10} # template\n');
});

function withFetch(handler: (url: string, init?: RequestInit) => unknown) {
    const orig = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
        calls.push(`${init?.method ?? 'GET'} ${url}`);
        const out = handler(url, init);
        if (out instanceof Response) return out;
        return new Response(JSON.stringify(out), { status: 200 });
    }) as typeof fetch;
    return { calls, restore: () => (globalThis.fetch = orig) };
}

test('Cloudflare: zone by suffix, records across zones, move plan with read-back', async () => {
    const zones = [
        { id: 'z1', name: 'example.com' },
        { id: 'z2', name: 'sub.example.com' },
        { id: 'z3', name: 'example.net' },
    ];
    assert.equal(zoneFor(zones, 'a.sub.example.com')?.id, 'z2');
    assert.equal(zoneFor(zones, 'b.example.com')?.id, 'z1');
    assert.equal(zoneFor(zones, 'x.org'), undefined);

    let content = '198.51.100.1';
    const f = withFetch((url, init) => {
        if (url.includes('/zones?')) return { success: true, result: zones.map((z) => ({ id: z.id, name: z.name })) };
        if (init?.method === 'PATCH') {
            content = JSON.parse(String(init.body)).content;
            return { success: true, result: { id: 'r1', name: 'ingress2.example.com', type: 'A', content, ttl: 1 } };
        }
        if (url.includes('/zones/z1/dns_records')) {
            const q = new URL(url).searchParams;
            const rec = { id: 'r1', name: 'ingress2.example.com', type: 'A', content, ttl: 1 };
            return { success: true, result: (q.get('content') && q.get('content') !== content) || (q.get('name') && q.get('name') !== rec.name) ? [] : [rec] };
        }
        return { success: true, result: [] };
    });
    try {
        const recs = await cfRecords('t', { content: '198.51.100.1' });
        assert.deepEqual(recs.map((r) => `${r.zone} ${r.name} ${r.content}`), ['example.com ingress2.example.com 198.51.100.1']);
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-cf-'));
        const ctx = new Ctx(loadConfig({ MIA_STATE_DIR: dir, MIA_INVENTORY: path.join(dir, 'none.yaml'), CLOUDFLARE_API_TOKEN: 'cf-test-token-000000' }));
        const { registry, instrument } = await import('../src/tools/helpers.js');
        const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
        const { registerDnsTools } = await import('../src/tools/dns.js');
        const server = new McpServer({ name: 't', version: '0' });
        instrument(server, ctx.out);
        registerDnsTools(server, ctx);
        const call = async (a: Record<string, unknown>) => JSON.parse((await registry.get('dns_change')!.handler(a)).content[0].text);
        const dry = await call({ move: { from: '198.51.100.1', to: '198.51.100.2' }, apply: false });
        assert.equal(dry.mode, 'dry-run');
        assert.equal(dry.toRun, 1);
        assert.equal(dry.plan[0].will, '198.51.100.1 → 198.51.100.2');
        assert.equal(content, '198.51.100.1', 'dry run changes nothing');
        const done = await call({ move: { from: '198.51.100.1', to: '198.51.100.2' }, apply: true, planHash: dry.planHash });
        assert.equal(done.mode, 'applied');
        assert.equal(content, '198.51.100.2');
        const again = await call({ move: { from: '198.51.100.1', to: '198.51.100.2' }, apply: false });
        assert.equal(again.toRun, 0, 'nothing left on the old IP');
        assert.equal(ctx.state.journal()[0].tool, 'dns_change');
    } finally {
        f.restore();
    }
});

test('Gitea: runners from whichever API the version has; registration token fallbacks', async () => {
    const g = { url: 'https://git.example.com', token: 'gitea-test-token' };
    const f = withFetch((url, init) => {
        if (url.includes('/admin/actions/runners?')) return new Response('not found', { status: 404 });
        if (url.includes('/user/actions/runners?')) return { runners: [{ id: 7, name: 'node-pl2', status: 'online', busy: false, labels: [{ name: 'node-pl2:host' }] }], total_count: 1 };
        if (url.endsWith('/admin/runners/registration-token')) return new Response('forbidden', { status: 403 });
        if (url.endsWith('/admin/actions/runners/registration-token')) return new Response('nope', { status: 404 });
        if (url.endsWith('/user/actions/runners/registration-token') && (init?.method ?? 'GET') === 'GET') return { token: 'reg-token-123' };
        return new Response('?', { status: 500 });
    });
    try {
        const r = await giteaRunners(g);
        assert.equal(r.scope, '/user/actions/runners');
        assert.deepEqual(r.runners, [{ id: 7, name: 'node-pl2', status: 'online', busy: false, labels: ['node-pl2:host'] }]);
        assert.equal(await giteaRegistrationToken(g), 'reg-token-123');
        assert.ok(f.calls.every((c) => c.includes('https://git.example.com/api/v1/')));
    } finally {
        f.restore();
    }
});

test('runApiSteps: dry run, planHash, blockers, verify failure stops', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-api-'));
    const ctx = new Ctx(loadConfig({ MIA_STATE_DIR: dir, MIA_INVENTORY: path.join(dir, 'none.yaml') }));
    let applied: string[] = [];
    const build = async () => [
        { target: 'a', action: 'x', before: 1, after: 2, apply: async () => void applied.push('a') },
        { target: 'b', action: 'y', apply: async () => void applied.push('b'), verify: async () => 'still wrong' },
        { target: 'c', action: 'z', apply: async () => void applied.push('c') },
    ];
    const dry = (await runApiSteps(ctx, 't', {}, { apply: false }, build)) as { planHash: string; toRun: number };
    assert.equal(dry.toRun, 3);
    assert.equal(applied.length, 0);
    await assert.rejects(runApiSteps(ctx, 't', {}, { apply: true }, build), /planHash/);
    const res = (await runApiSteps(ctx, 't', {}, { apply: true, planHash: dry.planHash }, build)) as { mode: string; notRun: string[] };
    assert.equal(res.mode, 'stopped');
    assert.deepEqual(applied, ['a', 'b']);
    assert.deepEqual(res.notRun, ['c']);
    applied = [];
    const blocked = await runApiSteps(ctx, 't', {}, { apply: false }, async () => [{ target: 'x', action: 'y', blockers: ['no'], apply: async () => void applied.push('x') }]);
    assert.deepEqual((blocked as { blocked: string[] }).blocked, ['x: no']);
});
