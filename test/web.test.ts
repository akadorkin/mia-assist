import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

/** A request that sets its own Host (fetch would not let a test lie about it). */
function req(url: string, opts: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<{ status: number; headers: http.IncomingHttpHeaders; text: string }> {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const r = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method: opts.method ?? 'GET', headers: { host: u.host, ...(opts.headers ?? {}) } }, (res) => {
            let text = '';
            res.on('data', (d) => (text += d));
            res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, text }));
        });
        r.on('error', reject);
        if (opts.body) r.write(opts.body);
        r.end();
    });
}

test('mia web: token link → cookie, API needs the cookie (and X-Mia to start work), foreign Host refused; status and a plan run as jobs with progress', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-web-'));
    const inv = path.join(dir, 'fleet.yaml');
    fs.writeFileSync(inv, 'hosts:\n  alpha:\n    transport: local\n    sudo: false\n');
    const { loadConfig } = await import('../src/config.js');
    const { createServer } = await import('../src/server.js');
    const { startWeb } = await import('../src/web/server.js');
    const config = loadConfig({ MIA_STATE_DIR: path.join(dir, 'state'), MIA_INVENTORY: inv, MIA_TAILSCALE_BIN: '/nonexistent' });
    const { ctx } = createServer(config);
    const web = await startWeb({ ctx, config });
    try {
        const base = new URL(web.url);
        const origin = `${base.protocol}//${base.host}`;
        assert.equal(base.hostname, '127.0.0.1', 'this machine only');

        assert.equal((await req(`${origin}/`)).status, 401, 'no link, no page');
        const login = await req(web.url);
        assert.equal(login.status, 302);
        const cookie = String(login.headers['set-cookie']).split(';')[0];
        assert.match(String(login.headers['set-cookie']), /HttpOnly; SameSite=Strict/);
        const page = await req(`${origin}/`, { headers: { cookie } });
        assert.equal(page.status, 200);
        assert.match(page.text, /<title>mia — флот<\/title>/);
        assert.match(String(page.headers['content-security-policy']), /frame-ancestors 'none'/);

        assert.equal((await req(`${origin}/api/state`)).status, 403, 'API without the cookie');
        assert.equal((await req(`${origin}/api/state`, { headers: { cookie, host: 'evil.example:80' } })).status, 421, 'DNS rebinding: foreign Host');
        const state = JSON.parse((await req(`${origin}/api/state`, { headers: { cookie } })).text);
        assert.deepEqual(state.hosts.map((h: { name: string }) => h.name), ['alpha']);
        const status = state.tools.find((t: { name: string }) => t.name === 'fleet_status');
        assert.equal(status.title, 'Статус всего флота (инвентарь + весь tailnet)');
        assert.deepEqual(status.fields.find((f: { name: string }) => f.name === 'target'), { name: 'target', kind: 'string', default: 'all', required: false, hint: 'на каких хостах: all, имя, nl-*, группа, role:remnanode, tag:prod; через запятую, !x — исключить', hidden: false });
        const apt = state.tools.find((t: { name: string }) => t.name === 'apt_upgrade');
        assert.equal(apt.planned, true);
        assert.equal(apt.fields.find((f: { name: string }) => f.name === 'securityOnly').hint, 'только security-обновления');
        assert.ok(state.quick.some((q: { tool: string }) => q.tool === 'apt_upgrade'));

        const start = (tool: string, args: Record<string, unknown>, headers: Record<string, string> = { cookie, 'x-mia': '1', 'content-type': 'application/json' }) => req(`${origin}/api/jobs`, { method: 'POST', headers, body: JSON.stringify({ tool, args }) });
        assert.equal((await start('fleet_status', {}, { cookie, 'content-type': 'application/json' })).status, 403, 'starting work needs X-Mia (no cross-site form can send it)');
        assert.equal((await start('no_such_tool', {})).status, 400);
        const events = async (id: string) => {
            const sse = await req(`${origin}/api/jobs/${id}/events`, { headers: { cookie } });
            const parsed = [...sse.text.matchAll(/event: (\w+)\ndata: (.*)\n\n/g)].map((m) => [m[1], JSON.parse(m[2])] as const);
            return { progress: parsed.filter(([e]) => e === 'progress').map(([, d]) => d), done: parsed.find(([e]) => e === 'done')![1] };
        };
        const st = await events(JSON.parse((await start('fleet_status', { target: 'all', tailnet: false })).text).id);
        assert.ok(st.done.ok);
        assert.equal(st.done.data.rows[0].host, 'alpha');
        assert.ok(st.progress.some((p: { kind: string; host?: string; state?: string }) => p.kind === 'host' && p.host === 'alpha' && p.state === 'ok'), 'the page sees each host answer');
        assert.ok(Array.isArray(st.done.next), '«Дальше» comes with the result');

        const plan = await events(JSON.parse((await start('host_exec', { target: 'alpha', command: 'echo hi', apply: false })).text).id);
        assert.equal(plan.done.data.mode, 'dry-run');
        assert.equal(plan.done.risk, null);
        assert.deepEqual(plan.done.next, [], 'no «Дальше» under a plan');
        // AUD-16: обрыв связи — переподключение с Last-Event-ID отдаёт только пропущенное; идущие задачи видны в state
        const stId = JSON.parse((await start('fleet_status', { target: 'all', tailnet: false })).text).id;
        const all = (await req(`${origin}/api/jobs/${stId}/events`, { headers: { cookie } })).text;
        const ids = [...all.matchAll(/^id: (\d+)$/gm)].map((m) => Number(m[1]));
        assert.deepEqual(ids, ids.map((_, i) => i), 'events are numbered');
        const rest = (await req(`${origin}/api/jobs/${stId}/events`, { headers: { cookie, 'last-event-id': String(ids.length - 2) } })).text;
        assert.deepEqual([...rest.matchAll(/^id: (\d+)$/gm)].map((m) => Number(m[1])), [ids.length - 1]);
        assert.match(rest, /event: done/);
        assert.deepEqual(JSON.parse((await req(`${origin}/api/state`, { headers: { cookie } })).text).running, [], 'finished jobs are not «running»');
        const reboot = await events(JSON.parse((await start('host_reboot', { target: 'alpha', apply: false })).text).id);
        assert.deepEqual(reboot.done.risk, { text: 'Перезагрузить сервер: alpha', answer: 'alpha' }, 'the page asks to type the name before a reboot');
        const journal = path.join(dir, 'state', 'journal.jsonl');
        assert.ok(!fs.existsSync(journal) || !fs.readFileSync(journal, 'utf8').includes('host_reboot'), 'dry runs change nothing');
    } finally {
        await web.close();
    }
});

test('mia web behind a proxy (dash.example.com/mia/): listed Host without a token, X-Mia still needed to start work, framed by its own origin only', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-web-proxy-'));
    const inv = path.join(dir, 'fleet.yaml');
    fs.writeFileSync(inv, 'hosts:\n  alpha:\n    transport: local\n    sudo: false\n');
    const { loadConfig } = await import('../src/config.js');
    const { createServer } = await import('../src/server.js');
    const { startWeb } = await import('../src/web/server.js');
    const config = loadConfig({ MIA_STATE_DIR: path.join(dir, 'state'), MIA_INVENTORY: inv, MIA_TAILSCALE_BIN: '/nonexistent' });
    const { ctx } = createServer(config);
    const web = await startWeb({ ctx, config }, { port: 0, proxyHosts: ['dash.example.com'] });
    try {
        const port = new URL(web.url).port;
        const at = (p: string, opts: { method?: string; headers?: Record<string, string>; body?: string } = {}) =>
            req(`http://127.0.0.1:${port}${p}`, { ...opts, headers: { host: 'dash.example.com', ...(opts.headers ?? {}) } });
        assert.equal(new URL(web.url).hostname, '127.0.0.1', 'still this machine only');
        const page = await at('/');
        assert.equal(page.status, 200, 'the proxy decides who comes in: no token');
        assert.match(String(page.headers['content-security-policy']), /frame-ancestors 'self'/);
        assert.doesNotMatch(page.text, /fetch\('\/api/, 'paths are relative: the page lives under /mia/');
        assert.equal((await at('/api/state')).status, 200);
        const start = { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tool: 'fleet_hosts', args: {} }) };
        assert.equal((await at('/api/jobs', start)).status, 403, 'starting work still needs X-Mia (no cross-site POST)');
        assert.equal((await at('/api/jobs', { ...start, headers: { ...start.headers, 'x-mia': '1' } })).status, 200);
        assert.equal((await req(`http://127.0.0.1:${port}/api/state`, { headers: { host: 'evil.example' } })).status, 421, 'only the listed Host names');
    } finally {
        await web.close();
    }
});
