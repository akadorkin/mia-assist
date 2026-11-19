import assert from 'node:assert/strict';
import { test } from 'node:test';
import { adhocHost } from '../src/core/inventory.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../src/config.js';
import { Ctx } from '../src/core/ctx.js';
import { ExecOptions } from '../src/core/ssh.js';
import { commandReboots, rebootBlocker, ufwDangerousPorts, ufwFromIsWorld, ufwProbePorts, ufwStillReachable } from '../src/tools/actions.js';

test('ufw_rule: 0.0.0.0/0 and ::/0 are the whole internet, like no from', () => {
    for (const f of [undefined, '0.0.0.0/0', '::/0', '0::/0', '0.0.0.0/1', '128.0.0.0/1', '::/1']) assert.equal(ufwFromIsWorld(f), true, String(f));
    for (const f of ['10.0.0.0/8', '1.2.3.4', '1.2.3.4/32', '2001:db8::/32', 'fd7a:115c:a1e0::/48']) assert.equal(ufwFromIsWorld(f), false, f);
});

test('ufw_rule: a port range is checked whole, not by its first number', () => {
    assert.deepEqual(ufwDangerousPorts('20:30'), [22]);
    assert.deepEqual(ufwDangerousPorts('9000:9200'), [9100]);
    assert.deepEqual(ufwDangerousPorts('1:65535'), [22, 2222, 5443, 5444, 9100]);
    assert.deepEqual(ufwDangerousPorts('30:20'), [22]);
    assert.deepEqual(ufwDangerousPorts('443'), []);
    assert.deepEqual(ufwDangerousPorts('8443:8450'), []);
    assert.deepEqual(ufwDangerousPorts('45876', [45876]), [45876], 'host mgmtPorts count too');
});

test('reboot guard: hands-off never, others allowed; reboot commands detected', () => {
    const ho = adhocHost('meet', 'meet');
    ho.groups.push('hands-off');
    assert.ok(rebootBlocker(ho));
    assert.equal(rebootBlocker(adhocHost('exit-1', 'exit-1')), undefined);
    for (const c of ['reboot', 'sudo shutdown -r now', 'systemctl reboot', 'init 6', 'apt-get upgrade -y && reboot', '/sbin/poweroff']) assert.equal(commandReboots(c), true, c);
    for (const c of ['cat /var/run/reboot-required', 'systemctl restart xray', 'ls /etc/reboot-reminder.d', 'uptime']) assert.equal(commandReboots(c), false, c);
});

test('ufw_rule: after each host a fresh ssh (no ControlMaster) and the ports that answered before; a lost one stops the rollout', async () => {
    assert.deepEqual(ufwProbePorts('allow', '8443', 'tcp'), [2222]);
    assert.deepEqual(ufwProbePorts('deny', '443', 'tcp'), [2222, 443]);
    assert.deepEqual(ufwProbePorts('delete-allow', '443', 'both'), [2222, 443]);
    assert.deepEqual(ufwProbePorts('deny', '443', 'udp'), [2222], 'udp cannot be probed by connect');
    assert.deepEqual(ufwProbePorts('deny', '20:30', 'tcp'), [2222], 'ranges: only 2222');

    const ctx = new Ctx(loadConfig({ MIA_STATE_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'mia-ufw-')) }));
    const fresh = ctx.transport.sshArgs(adhocHost('in1', 'node-in1'), undefined, true);
    assert.ok(fresh.includes('ControlPath=none') && !fresh.includes('ControlMaster=auto'), 'a new login, not the shared socket');
    let sshOk = true;
    const seen: ExecOptions[] = [];
    ctx.transport.exec = async (h, _s, o = {}) => (seen.push(o), { host: h.name, ok: sshOk, code: sshOk ? 0 : 255, stdout: '', stderr: '', ms: 1, error: sshOk ? undefined : 'ssh: таймаут' });
    const h = adhocHost('in1', 'node-in1');
    const open = new Set([2222]);
    const probe = async (_a: string, p: number) => open.has(p);
    assert.equal(await ufwStillReachable(ctx, h, [2222], probe), true);
    assert.equal(seen[0].fresh, true);
    assert.match(String(await ufwStillReachable(ctx, h, [2222, 443], probe)), /port 443 .*rollout stopped/);
    sshOk = false;
    assert.match(String(await ufwStillReachable(ctx, h, [], probe)), /new ssh login fails/);
});

test('repo_script: git fetch; a checkout behind its upstream is fast-forwarded, a diverged one is refused', async () => {
    const { execFileSync } = await import('node:child_process');
    const { repoBehind } = await import('../src/tools/repo.js');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-behind-'));
    const git = (cwd: string, ...a: string[]) => execFileSync('git', ['-C', cwd, '-c', 'user.name=t', '-c', 'user.email=t@t', ...a], { encoding: 'utf8', stdio: 'pipe' });
    execFileSync('git', ['init', '-q', '--bare', path.join(dir, 'origin.git')]);
    const [a, b] = [path.join(dir, 'a'), path.join(dir, 'b')];
    execFileSync('git', ['clone', '-q', path.join(dir, 'origin.git'), a], { stdio: 'pipe' });
    git(a, 'commit', '-q', '--allow-empty', '-m', '1');
    git(a, 'push', '-q', 'origin', 'HEAD');
    execFileSync('git', ['clone', '-q', path.join(dir, 'origin.git'), b], { stdio: 'pipe' });
    assert.deepEqual(repoBehind(b), { behind: 0 });
    git(a, 'commit', '-q', '--allow-empty', '-m', '2');
    git(a, 'push', '-q', 'origin', 'HEAD');
    // a commit pushed by another session in the middle of a runbook is fast-forwarded, not a blocker
    assert.deepEqual(repoBehind(b), { behind: 0 }, 'fetch sees the new origin commit and the checkout follows it');
    assert.equal(git(b, 'log', '-1', '--format=%s').trim(), '2');
    // a checkout that diverged (its own commit + a new one on origin) cannot follow: still refused
    git(b, 'commit', '-q', '--allow-empty', '-m', 'local');
    git(a, 'commit', '-q', '--allow-empty', '-m', '3');
    git(a, 'push', '-q', 'origin', 'HEAD');
    assert.deepEqual(repoBehind(b), { behind: 1 }, 'diverged: an old copy would roll out');
    execFileSync('git', ['init', '-q', path.join(dir, 'solo')]);
    assert.deepEqual(repoBehind(path.join(dir, 'solo')), {}, 'no upstream: nothing to compare');
});

test('tailnet_device_remove: name or 100.x still used (panel node, config_search, haproxy-configs) is a blocker; disabled nodes and look-alike names are not', async () => {
    const { execFileSync } = await import('node:child_process');
    const { tailnetUsers } = await import('../src/tools/tailnet.js');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-tsusers-'));
    const repo = path.join(dir, 'haproxy');
    fs.mkdirSync(path.join(repo, 'nodes/node-in1'), { recursive: true });
    fs.writeFileSync(path.join(repo, 'nodes/node-in1/haproxy.cfg'), 'backend b\n    server pl2 198.51.100.2:443 check\n    server pl1 198.51.100.23:443 check\n    # server old 198.51.100.9:443\n');
    execFileSync('git', ['init', '-q', repo]);
    execFileSync('git', ['-C', repo, 'add', '.']);
    const ctx = new Ctx(loadConfig({ MIA_STATE_DIR: dir, MIA_REPOS: `haproxy=${repo}` }));
    const nodes = [
        { uuid: '1', name: 'NL-1', address: 'node-pl2.tailnet.example', port: 2222 },
        { uuid: '2', name: 'OLD', address: '198.51.100.9', isDisabled: true },
        { uuid: '3', name: 'PL-1', address: 'node-pl1', port: 2222 },
    ];
    ctx.panelNodes = async () => nodes;
    const queries: string[] = [];
    const bridge = { call: async (_n: string, a: Record<string, unknown>) => (queries.push(String(a.query)), { ok: true, data: { hits: [{ in: 'profile EU', path: '/outbounds' }] }, text: '' }) };
    const pl2 = await tailnetUsers(ctx, bridge, { dnsName: 'node-pl2.tailnet.example.', ips: ['198.51.100.2', 'fd7a::1'] });
    assert.deepEqual(pl2.unchecked, []);
    assert.ok(pl2.users.includes('panel node NL-1 (node-pl2.tailnet.example:2222)'));
    assert.ok(!pl2.users.some((u) => u.includes('PL-1')), 'node-pl1 is not node-pl2');
    assert.ok(pl2.users.includes('panel profile EU'));
    assert.ok(new RegExp(queries[0]).test('198.51.100.2') && !new RegExp(queries[0]).test('198.51.100.23'), 'config_search on whole words');
    assert.deepEqual(pl2.users.filter((u) => u.startsWith('haproxy-configs')).length, 1, 'only 198.51.100.2, not 198.51.100.23');
    const old = await tailnetUsers(ctx, undefined, { dnsName: 'node-old.tailnet.example', ips: ['198.51.100.9'] });
    assert.deepEqual(old.users, [], 'a disabled panel node and a commented haproxy line do not hold the device');
    assert.match(old.unchecked.join(), /config_search needs MIA_REMNAWAVE_MCP/);
});
