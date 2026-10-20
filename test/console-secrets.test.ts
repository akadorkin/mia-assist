import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { z } from 'zod';
import { loadConfig } from '../src/config.js';
import { convert } from '../src/console.js';
import { redactText } from '../src/core/output.js';
import { tailscalePeers } from '../src/core/panel.js';
import { loadSecrets, parseEnvFile, writeSecret } from '../src/core/secrets.js';
import { keyDaysLeft } from '../src/core/tailscale.js';

/** The prompts print; the test runner shares stdout with its own protocol, so keep it quiet. */
async function quietly<T>(fn: () => Promise<T>): Promise<T> {
    const log = console.log;
    console.log = () => undefined;
    try {
        return await fn();
    } finally {
        console.log = log;
    }
}
import { parseArgs, table } from '../src/ui.js';

// a fake Tailscale API key, split so secret scanners do not flag the fixture
const TSKEY = ['tskey', 'api', 'kAAAA', 'BBBBBBBBBBBBBBBB'].join('-');

test('secrets file: set keeps other lines, mode 600, quotes when needed; env wins over the file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-sec-'));
    const env: NodeJS.ProcessEnv = { MIA_SECRETS_FILE: path.join(dir, 'mia', 'secrets.env') };
    writeSecret('TAILSCALE_API_KEY', TSKEY, env);
    writeSecret('BESZEL_PASSWORD', "it's a pass", env);
    writeSecret('GITEA_URL', 'https://git.example.com', env);
    writeSecret('GITEA_URL', 'https://git2.example.com', env);
    const file = env.MIA_SECRETS_FILE!;
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    const text = fs.readFileSync(file, 'utf8');
    assert.equal(text.match(/GITEA_URL=/g)?.length, 1);
    assert.match(text, /BESZEL_PASSWORD="it's a pass"/);
    assert.deepEqual([...parseEnvFile(text)].map(([k, v]) => `${k}=${v}`), [`TAILSCALE_API_KEY=${TSKEY}`, `BESZEL_PASSWORD=it's a pass`, 'GITEA_URL=https://git2.example.com']);

    const run: NodeJS.ProcessEnv = { ...env, GITEA_URL: 'https://from-env.example.com' };
    const st = loadSecrets(run);
    assert.equal(run.GITEA_URL, 'https://from-env.example.com', 'the environment wins');
    assert.equal(run.BESZEL_PASSWORD, "it's a pass");
    assert.equal(st.states.find((s) => s.name === 'TAILSCALE_API_KEY')?.source, 'file');
    assert.equal(st.states.find((s) => s.name === 'CLOUDFLARE_API_TOKEN')?.source, 'missing');
    assert.equal(st.warning, undefined);
    // every configured secret value is masked wherever it shows up
    assert.equal(redactText(`key is ${TSKEY} and "it's a pass"!`), 'key is «redacted» and "«redacted»"!');
    writeSecret('GITEA_URL', undefined, env);
    assert.doesNotMatch(fs.readFileSync(file, 'utf8'), /GITEA_URL/);
    fs.chmodSync(file, 0o644);
    assert.match(loadSecrets({ ...env }).warning ?? '', /chmod 600/);
});

test('Tailscale API: every device with online state, key expiry and updates', async () => {
    const config = loadConfig({ TAILSCALE_API_KEY: ['tskey', 'api', 'test', '0000000000000000'].join('-'), MIA_STATE_DIR: os.tmpdir() });
    const orig = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
        calls.push(`${init?.method ?? 'GET'} ${url} ${(init?.headers as Record<string, string>)?.Authorization?.slice(0, 13)}`);
        const soon = new Date(Date.now() + 5 * 86_400_000).toISOString();
        return new Response(
            JSON.stringify({
                devices: [
                    { id: '1', name: 'node-pl2.tailnet.example', hostname: 'node-pl2', addresses: ['198.51.100.10', 'fd7a::10'], os: 'linux', connectedToControl: true, expires: soon, updateAvailable: true, clientVersion: '1.90.1-t123' },
                    { id: '2', name: 'iphone.tailnet.example', hostname: 'iPhone', addresses: ['198.51.100.11'], os: 'iOS', connectedToControl: false, lastSeen: '2026-09-20T10:00:00Z', keyExpiryDisabled: true },
                ],
            }),
            { status: 200 },
        );
    }) as typeof fetch;
    try {
        const peers = await tailscalePeers(config);
        assert.equal(calls[0], 'GET https://api.tailscale.com/api/v2/tailnet/-/devices?fields=all Bearer tskey-');
        assert.deepEqual(
            peers.map((p) => [p.dnsName, p.online, p.keyDaysLeft, p.updateAvailable ?? false, p.clientVersion]),
            [
                ['node-pl2.tailnet.example', true, 4, true, '1.90.1'],
                ['iphone.tailnet.example', false, undefined, false, undefined],
            ],
        );
    } finally {
        globalThis.fetch = orig;
    }
    assert.equal(keyDaysLeft({ expires: '0001-01-01T00:00:00Z' }), undefined);
    const now = Date.now();
    assert.equal(keyDaysLeft({ expires: new Date(now - 2 * 86_400_000).toISOString() }, now), -2);
});

test('console answers: enum by number, yes/no in both layouts, lists, numbers, JSON', () => {
    assert.equal(convert('2', z.enum(['restart', 'update'])), 'update');
    assert.throws(() => convert('9', z.enum(['a', 'b'])), /одно из/);
    assert.equal(convert('да', z.boolean()), true);
    assert.equal(convert('l', z.boolean()), true);
    assert.equal(convert('нет', z.boolean()), false);
    assert.equal(convert('42', z.number()), 42);
    assert.deepEqual(convert('a, b,c', z.array(z.string())), ['a', 'b', 'c']);
    assert.deepEqual(convert('{"LOG_NODE_NAME":"x"}', z.record(z.string())), { LOG_NODE_NAME: 'x' });
    assert.equal(convert('pl3', z.string()), 'pl3');
});

test('console tables: Russian headers and states, width ignores colour codes', () => {
    const t = table([
        { host: 'pl2', state: 'ok', up: '3d' },
        { host: 'de3', state: 'UNREACHABLE', error: 'tailnet: offline' },
    ]);
    const lines = t.split('\n').map((l) => l.replace(/\x1b\[[0-9;]*m/g, ''));
    assert.match(lines[0], /^хост\s+│ состояние\s+│ аптайм\s+│ ошибка$/);
    assert.match(lines[3], /^de3\s+│ НЕДОСТУПЕН\s+│/);
    assert.equal(parseArgs(['planHash=0123', 'batch=2'], { planHash: z.string(), batch: z.number() }).planHash, '0123');
});

test('status table: one line per host split by │, common issues once, tailnet devices apart, ssh reasons', async () => {
    const { statusTable, collapseIssues } = await import('../src/status-view.js');
    const { sshReason } = await import('../src/core/ssh.js');
    assert.deepEqual(collapseIssues('fw.public_port apt.security fw.public_port svc.down'), ['svc.down', 'apt.security', 'fw.public_port×2']);
    const common = 'apt.security updates.security_off';
    const host = (name: string, issues: string) => ({ host: name, state: 'warn', up: '4d', load: 0.5, cpu: 4, mem: '20%', disk: '5%', updates: '3', node: 'running', cert: '60d', ts: 'Running', panel: 'connected 3u', issues });
    const data = {
        rows: [
            { host: 'pl9', state: 'warn', up: '4d', load: 1.99, cpu: 16, mem: '7%', disk: '2%', updates: '9/1sec', reboot: true, node: 'running', cert: '84d', ts: 'Running', tsKey: '12d', panel: 'connected 40u', issues: `reboot.required fw.public_port fw.public_port geo.stale f2b.inactive fw.public_port svc.down units.failed ${common}` },
            host('de3', common),
            host('de2', common),
            host('fi1', `${common} f2b.jail_missing`),
            { host: 'promethium', state: 'UNREACHABLE', error: 'ssh: таймаут подключения — connect to host node-promethium port 22: Operation timed out' },
            { host: 'compute-vm-2-4-20-ssd-1758201234567', state: 'not in fleet.yaml', ts: 'online linux', os: 'linux', error: 'ssh: нет доступа (ключ не подошёл) — Permission denied (publickey)' },
            { host: 'node-fibonacci', state: 'offline', ts: 'offline since 2026-08-20 linux', os: 'linux' },
        ],
        summary: { hosts: 5, ok: 0, warn: 4, crit: 0, unreachable: 1, tailnetOnly: 2 },
    };
    const wide = statusTable(data, 240).split('\n');
    assert.match(wide[0], /│ аптайм │/);
    assert.match(wide.find((l) => l.startsWith('pl9'))!, /│ нужен │ .*│ 84 дн │ ✓ ключ 12 дн │ ✓ 40 /);
    const out = statusTable(data, 110);
    const lines = out.split('\n');
    assert.match(lines[0], /^хост\s+│ состояние\s+│ нагрузка │/, 'narrow terminal: uptime hidden first');
    assert.match(lines[1], /^─+┼─+┼/);
    assert.ok(lines.every((l) => l.length <= 110), 'fits the terminal');
    const pl9 = lines.find((l) => l.startsWith('pl9'))!;
    assert.match(pl9, /9 \(1\)/);
    assert.match(pl9, /svc\.down, .*\+\d/, 'critical first, the rest cut with +N');
    assert.doesNotMatch(pl9, /apt\.security/, 'common issues are not repeated on the line');
    assert.equal(lines.filter((l) => l.startsWith('pl9')).length, 1, 'one line per host');
    assert.match(lines.find((l) => l.startsWith('de3'))!, /только общие/);
    assert.match(out, /promethium\s+│ ✖ недоступен .*ssh: таймаут подключения/);
    assert.doesNotMatch(out, /Operation timed out/, 'the table keeps the Russian reason only');
    assert.match(out, /Общее для большинства/);
    assert.match(out, /apt\.security\s+ждут security-обновления\s+у всех$/m);
    assert.match(out, /всего 5  ·  ok 0  ·  внимание 4/);
    assert.match(out, /f2b\.jail_missing — не хватает/);
    assert.match(out, /Устройства tailnet, которых нет в fleet\.yaml \(2\)/);
    assert.match(out, /compute-vm-2-4-20-ssd-17582… │ ● в сети/);
    assert.match(out, /node-fibonacci\s+│ ○ не в сети \d+ дн/);
    assert.ok(lines.findIndex((l) => l.startsWith('compute-vm')) > lines.findIndex((l) => l.startsWith('pl9')), 'tailnet devices come after the fleet');
    assert.equal(sshReason('ssh: connect to host x port 22: Connection refused'), 'порт закрыт (sshd не слушает) — connect to host x port 22: Connection refused');
    assert.match(sshReason('Permission denied (publickey)'), /^нет доступа/);
});

test('arrow menus: cursor wraps, digits pick, search in either layout, Esc clears then goes back, long lists scroll', async () => {
    const { Picker } = await import('../src/select.js');
    const plain = (lines: string[]) => lines.map((l) => l.replace(/\x1b\[[0-9;]*m/g, ''));
    const menu = new Picker('Что делаем?', [{ label: 'Статус всего флота' }, { label: 'Проверки и диагностика', hint: '12' }, { label: 'Выход' }]);
    assert.equal(menu.key(undefined, { name: 'up' }), undefined);
    assert.match(plain(menu.render(80, 20)).find((l) => l.startsWith('❯'))!, /Выход/, 'up from the first item wraps to the last');
    menu.key(undefined, { name: 'down' });
    menu.key(undefined, { name: 'down' });
    assert.deepEqual(menu.key('\r', { name: 'return' }), { kind: 'select', index: 1 });
    assert.deepEqual(menu.key('3', { name: '3' }), { kind: 'select', index: 2 }, 'short menus keep the numbers');
    const ten = new Picker('Что делаем?', Array.from({ length: 10 }, (_, i) => ({ label: i === 9 ? 'Выход' : `пункт ${i + 1}` })));
    assert.deepEqual(ten.key('0', { name: '0' }), { kind: 'select', index: 9 }, 'the main menu: 0 is the tenth item (Выход)');
    assert.deepEqual(ten.key('8', { name: '8' }), { kind: 'select', index: 7 });
    const withRecent = new Picker('mia', [{ label: '↺ Статус' }, ...Array.from({ length: 10 }, (_, i) => ({ label: `раздел ${i + 1}` }))], { numberFrom: 1 });
    assert.deepEqual(withRecent.key('1', { name: '1' }), { kind: 'select', index: 1 }, 'recent runs on top do not shift the section numbers');
    assert.match(plain(withRecent.render()).join('\n'), /❯ {3}↺ Статус\n {2}1 раздел 1/);
    assert.deepEqual(menu.key(undefined, { name: 'c', ctrl: true }), { kind: 'cancel' });
    assert.deepEqual(menu.key('q', { name: 'q' }), { kind: 'back' });

    const tools = new Picker(
        'Инструмент',
        ['dns_change', 'dns_records', 'fleet_status', 'host_exec', 'tailnet_devices'].map((n) => ({ label: n, hint: n === 'dns_change' ? 'Поменять DNS-запись' : undefined })),
    );
    for (const ch of 'вты') tools.key(ch, { name: ch });
    assert.deepEqual(tools.visible(), [0, 1], 'typed in the Russian layout: "вты" is "dns"');
    tools.key(undefined, { name: 'down' });
    assert.deepEqual(tools.key(undefined, { name: 'return' }), { kind: 'select', index: 1 });
    assert.equal(tools.key(undefined, { name: 'escape' }), undefined, 'Esc clears the search first');
    assert.equal(tools.filter, '');
    for (const ch of 'поменять') tools.key(ch, { name: ch });
    assert.deepEqual(tools.visible(), [0], 'hints are searched too');
    assert.match(plain(tools.render()).join('\n'), /поиск: поменять  \(1 из 5/);
    tools.key(undefined, { name: 'escape' });
    assert.deepEqual(tools.key(undefined, { name: 'escape' }), { kind: 'back' });

    const long = new Picker('Инструмент', Array.from({ length: 60 }, (_, i) => ({ label: `tool_${i}`, hint: 'x'.repeat(200) })), { initial: 40 });
    const lines = plain(long.render(90, 20));
    assert.ok(lines.length <= 20, 'fits the screen');
    assert.ok(lines.every((l) => l.length <= 89), 'no line wraps');
    assert.match(lines.find((l) => l.startsWith('❯'))!, /tool_40/);
    assert.ok(lines.some((l) => /↑ ещё \d+/.test(l)) && lines.some((l) => /↓ ещё \d+/.test(l)));
    assert.equal(long.key('5', { name: '5' }), undefined, 'in long lists digits search');

    const roles = new Picker('Роли', [{ label: 'edge' }, { label: 'remnanode' }, { label: 'panel' }, { label: 'docker' }], { multi: true, checked: [3] });
    roles.key(undefined, { name: 'down' });
    roles.key(' ', { name: 'space' });
    assert.match(plain(roles.render()).join('\n'), /❯ ◉ remnanode[\s\S]*◉ docker/);
    assert.equal(roles.key('2', { name: '2' }), undefined, 'no digit shortcuts when ticking');
    roles.key(undefined, { name: 'escape' });
    roles.key(undefined, { name: 'down' });
    roles.key(' ', { name: 'space' });
    assert.deepEqual(roles.key('\r', { name: 'return' }), { kind: 'many', indexes: [3] }, 'Space unticks, Enter takes the ticked ones');
    assert.deepEqual(long.visible(), [5, 15, 25, 35, 45, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59]);
});

test('setup: settings are validated, network errors say why', async () => {
    const { SECRETS } = await import('../src/core/secrets.js');
    const { why } = await import('../src/secrets-cli.js');
    const v = (name: string, value: string) => SECRETS.find((s) => s.name === name)!.validate?.(value);
    assert.match(v('REMNAWAVE_BASE_URL', 'panel.example.com')!, /https:\/\//);
    assert.equal(v('REMNAWAVE_BASE_URL', 'https://panel.example.com'), undefined);
    assert.match(v('TAILSCALE_AUTH_KEY', 'tskey-api-x')!, /tskey-auth-/);
    assert.match(v('MIA_REPOS', 'vpn ~/vpn')!, /имя=путь/);
    assert.equal(v('MIA_REPOS', 'ops=~/ops-scripts,haproxy=~/haproxy-configs'), undefined);
    assert.match(v('MIA_INVENTORY', '~/mia-inventory')!, /yaml/);
    const e = Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND', hostname: 'panel.example.test' } });
    assert.equal(why(e), 'не подключиться: имя не резолвится (panel.example.test)');
    const { loadConfig } = await import('../src/config.js');
    assert.equal(loadConfig({ MIA_INVENTORY: '~/inv/fleet.yaml', HOME: '/h' }).inventoryFile.endsWith('/inv/fleet.yaml'), true, '~ from secrets.env is expanded');
});

test('irreversible plans ask to type the count or the name; Enter cancels', () => quietly(async () => {
    const { riskOf, typedConfirm } = await import('../src/ui.js');
    const reboot = { plan: [{ host: 'nl-1', will: 'shutdown -r +1' }, { host: 'nl-2', will: 'shutdown -r +1' }, { host: 'nl-3', skip: 'excluded' }, { host: 'de-1', will: 'shutdown -r +1' }] };
    assert.deepEqual(riskOf('host_reboot', reboot), { text: 'Перезагрузить 3 сервера: nl-1, nl-2, de-1', answer: '3' });
    assert.deepEqual(riskOf('host_reboot', { plan: [{ host: 'pl2', will: 'shutdown -r +1' }] }), { text: 'Перезагрузить сервер: pl2', answer: 'pl2' });
    assert.deepEqual(riskOf('tailnet_device_remove', { plan: [{ target: 'tailnet node-yt1.tailnet.example', will: 'delete the device from the tailnet' }] })?.answer, 'node-yt1');
    const dns = { plan: [{ target: 'A pl3.example.com', will: 'delete (203.0.113.7)' }, { target: 'A xhttp.pl3.example.com', will: 'delete (203.0.113.7)' }, { target: 'A a.example.com', will: '1.1.1.1 → 2.2.2.2' }] };
    assert.deepEqual(riskOf('dns_change', dns), { text: 'Удалить 2 DNS-записи: pl3.example.com, xhttp.pl3.example.com', answer: '2' });
    assert.equal(riskOf('dns_change', { plan: [{ target: 'A a.example.com', will: '1.1.1.1 → 2.2.2.2' }] }), undefined, 'moving a record is Enter as usual');
    assert.equal(riskOf('host_reboot', { plan: [{ host: 'x', will: 'reboot', blockers: ['no'] }] }), undefined);
    assert.equal(riskOf('apt_upgrade', reboot), undefined);
    const say = (answer: string) => async () => answer;
    const r = { text: 'Перезагрузить 3 сервера', answer: '3' };
    assert.equal(await typedConfirm(say('3'), r), true);
    assert.equal(await typedConfirm(say(''), r), false, 'Enter does not run it');
    assert.equal(await typedConfirm(say('да'), r), false);
    assert.equal(await typedConfirm(say('PL2'), { text: 'x', answer: 'pl2' }), true, 'case does not matter');
}));

test('live progress: ssh calls report per host inside the scope only; the block counts and folds', async () => {
    const { withProgress, report } = await import('../src/core/progress.js');
    const { LiveHosts } = await import('../src/tui.js');
    const { Transport } = await import('../src/core/ssh.js');
    const { adhocHost } = await import('../src/core/inventory.js');
    const { loadConfig } = await import('../src/config.js');
    const t = new Transport(loadConfig({}));
    const local = { ...adhocHost('me', 'localhost'), transport: 'local' as const, sudo: false };
    const events: string[] = [];
    await withProgress(
        (e) => events.push(e.kind === 'host' ? `${e.host}:${e.state}` : `hosts:${e.hosts.join(',')}`),
        async () => {
            report({ kind: 'hosts', phase: 'probe', hosts: ['me'] });
            await t.exec(local, 'true');
            await t.exec(local, 'exit 3');
        },
    );
    assert.deepEqual(events, ['hosts:me', 'me:run', 'me:ok', 'me:run', 'me:fail']);
    await t.exec(local, 'true'); // outside any scope: nobody hears, nothing breaks
    assert.equal(events.length, 5);

    const plain = (l: string[]) => l.map((x) => x.replace(/\x1b\[[0-9;]*m/g, ''));
    const live = new LiveHosts();
    live.on({ kind: 'hosts', phase: 'apply', hosts: ['nl-1', 'nl-2', 'nl-3'] }, 0);
    live.on({ kind: 'host', host: 'nl-1', state: 'run' }, 0);
    live.on({ kind: 'host', host: 'nl-1', state: 'ok', ms: 8100 }, 8100);
    live.on({ kind: 'host', host: 'nl-2', state: 'run' }, 1000);
    live.on({ kind: 'host', host: 'nl-3', state: 'fail', note: 'ssh: таймаут подключения — connect to host x' }, 2000);
    assert.deepEqual(live.counts(), { total: 3, done: 2, failed: 1 });
    const lines = plain(live.lines(100, 20, 6000));
    assert.match(lines[0], /✔ nl-1\s+8\.1s/);
    assert.match(lines[1], /nl-2\s+00:05/);
    assert.match(lines[2], /✖ nl-3\s+ssh: таймаут подключения$/);
    const many = new LiveHosts();
    many.on({ kind: 'hosts', phase: 'probe', hosts: Array.from({ length: 27 }, (_, i) => `h${i}`) });
    many.on({ kind: 'host', host: 'h3', state: 'run' });
    many.on({ kind: 'host', host: 'h4', state: 'fail', note: 'ssh: нет доступа' });
    const folded = plain(many.lines(100, 20));
    assert.equal(folded.length, 2, '27 hosts: who runs now and what failed, not 27 lines');
    assert.match(folded[0], /сейчас: h3/);
    assert.match(folded[1], /✖ h4\s+ssh: нет доступа/);
    many.on({ kind: 'hosts', phase: 'apply', hosts: ['h4'] });
    assert.deepEqual(many.counts(), { total: 1, done: 0, failed: 0 }, 'a new phase starts a fresh list');
});

test('short path: Enter takes the highlighted host, typed text can be the value, → edits, «п» asks for parameters', () => quietly(async () => {
    const { Picker } = await import('../src/select.js');
    const { decidePlan } = await import('../src/ui.js');
    const where = new Picker('Где?', [{ label: 'все серверы' }, { label: 'все ноды' }, { label: 'de3' }], { multi: true, enterPicksCurrent: true, freeText: 'как выражение' });
    assert.deepEqual(where.key('\r', { name: 'return' }), { kind: 'many', indexes: [0] }, 'one Enter = the highlighted line');
    where.key(undefined, { name: 'down' });
    where.key(' ', { name: 'space' });
    where.key(undefined, { name: 'down' });
    where.key(' ', { name: 'space' });
    assert.deepEqual(where.key('\r', { name: 'return' }), { kind: 'many', indexes: [1, 2] }, 'Space ticks several');
    const typed = new Picker('Где?', [{ label: 'de3' }], { multi: true, enterPicksCurrent: true, freeText: 'как выражение' });
    for (const ch of 'nl-*') typed.key(ch, { name: ch });
    assert.match(typed.render().join('\n').replace(/\x1b\[[0-9;]*m/g, ''), /✎ как выражение: nl-\*/);
    assert.deepEqual(typed.key('\r', { name: 'return' }), { kind: 'text', text: 'nl-*' });
    const menu = new Picker('mia', [{ label: '↺ Логи' }, { label: 'Статус' }], { filter: 'стат' });
    assert.deepEqual(menu.visible(), [1], 'mia статус opens the search filled in');
    assert.deepEqual(menu.key(undefined, { name: 'right' }), { kind: 'select', index: 1, alt: true }, '→ = open with the parameters');
    const say = (...answers: string[]) => async () => answers.shift() ?? '';
    assert.equal(await decidePlan(say('')), 'yes', 'Enter runs an ordinary plan');
    assert.equal(await decidePlan(say('н')), 'no');
    assert.equal(await decidePlan(say('п')), 'params');
    assert.equal(await decidePlan(say('g')), 'params', 'either layout');
    assert.equal(await decidePlan(say('y', '')), 'yes', 'a lone y is asked again');
    const risk = { text: 'Перезагрузить 3 сервера', answer: '3' };
    assert.equal(await decidePlan(say(''), risk), 'no', 'irreversible: Enter cancels');
    assert.equal(await decidePlan(say('3'), risk), 'yes');
    assert.equal(await decidePlan(say('п'), risk), 'params');
}));

test('one host that does not answer: blocks by default, «skipUnreachable» runs the rest', async () => {
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const { loadConfig } = await import('../src/config.js');
    const { Ctx } = await import('../src/core/ctx.js');
    const { runSteps } = await import('../src/core/plan.js');
    const { adhocHost } = await import('../src/core/inventory.js');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-skip-'));
    const ctx = new Ctx(loadConfig({ MIA_STATE_DIR: dir, MIA_INVENTORY: path.join(dir, 'none.yaml') }));
    const me = { ...adhocHost('alpha', 'localhost'), transport: 'local' as const, sudo: false };
    const dead = adhocHost('promethium', 'node-promethium');
    const build = async () => [
        { host: me, action: 'echo', script: 'echo done' },
        { host: dead, action: '-', script: '', blockers: ['unreachable: ssh: таймаут подключения — connect to host node-promethium port 22'] },
    ];
    const blocked = (await runSteps(ctx, 't', { target: 'all' }, { apply: false, defaultBatch: 1 }, build)) as { blocked?: string[] };
    assert.deepEqual(blocked.blocked, ['promethium: unreachable: ssh: таймаут подключения — connect to host node-promethium port 22']);
    const args = { target: 'all', skipUnreachable: true };
    const dry = (await runSteps(ctx, 't', args, { apply: false, defaultBatch: 1, skipUnreachable: true }, build)) as { planHash: string; toRun: number; blocked?: string[]; plan: Array<{ host: string; skip?: string }> };
    assert.equal(dry.blocked, undefined);
    assert.equal(dry.toRun, 1);
    assert.equal(dry.plan[1].skip, 'не отвечает — пропущен (ssh: таймаут подключения)');
    const done = (await runSteps(ctx, 't', { ...args, apply: true, planHash: dry.planHash }, { apply: true, planHash: dry.planHash, defaultBatch: 1, skipUnreachable: true }, build)) as unknown as { mode: string; results: Array<{ host: string; ok: boolean }> };
    assert.equal(done.mode, 'applied');
    assert.deepEqual(done.results.map((r) => [r.host, r.ok]), [['alpha', true]]);
});

test('«Дальше»: fixes for what a status or an audit found, on exactly those hosts; after a run — failed, not run, reboot', async () => {
    const { nextActions } = await import('../src/next.js');
    const all = () => true;
    const status = {
        rows: [
            { host: 'pl2', state: 'warn', updates: '12/3sec', reboot: true, issues: 'apt.security reboot.required geo.stale' },
            { host: 'de3', state: 'crit', updates: '0', issues: 'fw.public_mgmt node.pending_recreate' },
            { host: 'fi1', state: 'warn', updates: '4', issues: 'apt.updates f2b.inactive' },
            { host: 'promethium', state: 'UNREACHABLE', error: 'ssh: таймаут' },
            { host: 'Bohr', state: 'not in fleet.yaml' },
        ],
    };
    const next = nextActions('fleet_status', { target: 'all' }, status, all);
    const by = (tool: string) => next.find((n) => n.tool === tool);
    assert.equal(by('apt_upgrade')?.preset?.target, 'pl2,fi1');
    assert.equal(by('apt_upgrade')?.label, 'обновить пакеты: 2 сервера');
    assert.equal(by('host_reboot')?.preset?.target, 'pl2');
    assert.equal(by('remnanode_update')?.preset?.target, 'de3');
    assert.equal(by('geo_update')?.preset?.target, 'pl2');
    assert.deepEqual(by('service_action')?.preset, { service: 'fail2ban', action: 'restart', target: 'fi1' });
    assert.equal(by('fleet_audit')?.preset?.target, 'de3', 'crit hosts get an audit');
    assert.equal(by('tailnet_devices')?.preset?.filter, 'promethium');
    assert.ok(next.some((n) => n.setup === 'host-tailnet'));
    assert.equal(next[0].tool, 'apt_upgrade', 'updates first');
    assert.ok(!nextActions('fleet_status', {}, status, (t) => t !== 'apt_upgrade').some((n) => n.tool === 'apt_upgrade'), 'read-only mode: no write tools offered');

    const audit = { byCode: { 'cert.expiring': 'pl9, de2', 'disk.full': 'rpi' } };
    assert.deepEqual(
        nextActions('fleet_audit', {}, audit, all).map((n) => [n.tool, n.preset?.target]),
        [
            ['cert_renew', 'pl9,de2'],
            ['disk_cleanup', 'rpi'],
        ],
    );

    const ran = { mode: 'stopped', results: [{ host: 'pl2', ok: true, output: 'done\nREBOOT_REQUIRED' }, { host: 'de3', ok: false, error: 'код выхода 100' }], notRun: ['fi1', 'fi2'] };
    const after = nextActions('apt_upgrade', { target: 'pl2,de3,fi1,fi2', securityOnly: true }, ran, all);
    assert.deepEqual(
        after.map((n) => [n.tool, n.preset?.target]),
        [
            ['apt_upgrade', 'de3'],
            ['apt_upgrade', 'fi1,fi2'],
            ['host_reboot', 'pl2'],
        ],
    );
    assert.equal(after[0].preset?.securityOnly, true, 'the retry keeps the parameters');
});

test('speed: probed facts serve plans for a while, a change forgets them; ssh reuses one connection', async () => {
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const { loadConfig } = await import('../src/config.js');
    const { Ctx } = await import('../src/core/ctx.js');
    const { adhocHost } = await import('../src/core/inventory.js');
    // /tmp, not os.tmpdir(): on macOS the latter is too long for an ssh control socket (then there is no reuse to test)
    const dir = fs.mkdtempSync(path.join(process.platform === 'darwin' ? '/tmp' : os.tmpdir(), 'mia-cache-'));
    const ctx = new Ctx(loadConfig({ MIA_STATE_DIR: dir, MIA_INVENTORY: path.join(dir, 'none.yaml') }));
    let probes = 0;
    const exec = ctx.transport.exec.bind(ctx.transport);
    ctx.transport.exec = (async (...a: Parameters<typeof exec>) => {
        probes++;
        return exec(...a);
    }) as typeof exec;
    const me = { ...adhocHost('me', 'localhost'), transport: 'local' as const, sudo: false };
    await ctx.facts(me);
    await ctx.facts(me);
    assert.equal(probes, 1, 'the plan right after the status does not probe again');
    await ctx.facts(me, 'quick', { fresh: true });
    assert.equal(probes, 2, 'status / audit always probe');
    ctx.forget('me');
    await ctx.facts(me);
    assert.equal(probes, 3, 'after a change the host is probed again');
    const none = new Ctx(loadConfig({ MIA_STATE_DIR: dir, MIA_FACTS_TTL: '0' }));
    assert.equal(none.config.factsTtlMs, 0, 'MIA_FACTS_TTL=0 switches the memory off');

    const args = ctx.transport.sshArgs(adhocHost('pl2', 'node-pl2', 'root'));
    const i = args.indexOf('ControlMaster=auto');
    assert.ok(i > 0, 'one connection per host');
    assert.match(args.find((a) => a.startsWith('ControlPath='))!, /\/%C$/);
    assert.ok(args.find((a) => a.startsWith('ControlPath='))!.length < 104 - 40, 'the socket path fits macOS');
    assert.ok(!new Ctx(loadConfig({ MIA_STATE_DIR: dir, MIA_SSH_REUSE: '0' })).transport.sshArgs(adhocHost('x', 'x')).includes('ControlMaster=auto'));
});

test('redact: WireGuard keys, PEM private keys, shadow hashes, private_key (AUD-05)', () => {
    const wg = '[Interface]\nPrivate' + 'Key = yAnzAAAA' + 'BBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJ0=\nAddress = 10.8.1.1/24\n[Peer]\nPublicKey = pubKEYstays0000000000000000000000000000000=\nPresharedKey = psk000000000000000000000000000000000000000=';
    const r = redactText(wg);
    assert.ok(!r.includes('yAnzAAAA') && !r.includes('psk0000'), r);
    assert.ok(r.includes('pubKEYstays') && r.includes('Address = 10.8.1.1/24'), r);
    const pem = ['-----BEGIN', 'OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END', 'OPENSSH PRIVATE KEY-----'].join(' ');
    const rp = redactText(pem);
    assert.ok(!rp.includes('b3BlbnNzaC1rZXktdjEAAAAA') && rp.includes('-----END OPENSSH PRIVATE KEY-----'), rp);
    assert.ok(!redactText('root:$6$salt$hashhashhash:19000:0:99999:7:::').includes('hashhash'));
    assert.ok(!redactText('{"private_' + 'key": "abcdef' + '123456"}').includes('abcdef' + '123456'));
});
