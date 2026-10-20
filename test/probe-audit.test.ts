import assert from 'node:assert/strict';
import { test } from 'node:test';
import { audit, expandPort, publicAllows, statusRow } from '../src/core/audit.js';
import { Inventory } from '../src/core/inventory.js';
import { parseListen, parseProbe, parseUfw } from '../src/core/probe.js';
import { UFW_BASELINE, execOk, healthyNodeRecords, probeOutput } from './fixtures.js';

const inv = new Inventory('f', {
    hosts: {
        'nl-1': { roles: ['remnanode'], domain: 'nl1.example.com' },
        quiet: { roles: ['remnanode'], policy: { skip: ['tune', 'cert.expiring'] } },
        box: { roles: ['docker'], services: [{ name: 'bot', compose: '/opt/bot/docker-compose.yml' }] },
    },
});
const nl = inv.get('nl-1');
const facts = (over: Record<string, string> = {}) => parseProbe('nl-1', execOk(probeOutput(healthyNodeRecords(over))), 'quick');
const codes = (over: Record<string, string> = {}, host = nl) => audit(host, facts(over)).map((f) => `${f.sev}:${f.code}`);

test('ufw parser: rules, interfaces, v6, comments, defaults', () => {
    const u = parseUfw(UFW_BASELINE);
    assert.equal(u.active, true);
    assert.equal(u.defaultIn, 'deny');
    assert.equal(u.defaultRouted, 'allow');
    const ts = u.rules.find((r) => r.iface === 'tailscale0' && !r.v6)!;
    assert.equal(ts.port, 'Anywhere');
    assert.equal(ts.action, 'ALLOW IN');
    const ban = u.rules.find((r) => r.comment === 'banned')!;
    assert.equal(ban.port, 'Anywhere');
    assert.equal(ban.from, '203.0.113.7');
    assert.ok(u.rules.some((r) => r.v6 && r.port === '443/tcp'));
    const pub = publicAllows(u.rules).map((r) => r.port);
    assert.deepEqual([...new Set(pub)], ['80/tcp', '80/udp', '443/tcp', '443/udp']);
});

test('port spec expansion', () => {
    assert.deepEqual(expandPort('443'), ['443/tcp', '443/udp']);
    assert.deepEqual(expandPort('80/tcp'), ['80/tcp']);
    assert.deepEqual(expandPort('Anywhere'), ['any']);
});

test('ss parser: v4/v6/wildcard/zone ids, one row per socket', () => {
    const l = parseListen('tcp LISTEN 0 4096 [::]:443 [::]:* users:(("xray",pid=1,fd=3))\nudp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\ntcp LISTEN 0 4096 *:2222 *:*');
    assert.deepEqual(
        l.map((s) => [s.proto, s.addr, s.port, s.process]),
        [
            ['tcp', '::', 443, 'xray'],
            ['udp', '127.0.0.53', 53, undefined],
            ['tcp', '*', 2222, undefined],
        ],
    );
});

test('a baseline remnanode audits clean', () => {
    assert.deepEqual(codes(), []);
    const f = facts();
    assert.equal(f.mem?.usedPct, 25);
    assert.equal(f.certs[0].daysLeft, 60);
    assert.equal(f.tailscale?.dnsName, 'nl-1.tailnet.example');
    const row = statusRow(nl, f, []);
    assert.equal(row.state, 'ok');
    assert.equal(row.node, 'running');
    assert.equal(row.cert, '60d');
});

test('firewall: public management ports are crit, other public ports only listed, ufw off exposes mgmt ports', () => {
    const extra = UFW_BASELINE.replace('22/tcp on eth0             DENY IN     Anywhere', '22/tcp on eth0             ALLOW IN    Anywhere').replace(
        '9100/tcp on eth0           DENY IN     Anywhere',
        '8443/tcp on eth0           ALLOW IN    Anywhere',
    );
    const c = codes({ ufw: extra });
    assert.ok(c.includes('info:fw.mgmt_guarded'), 'MGMT-PORTS in front of ufw lets only the tailnet and home reach 22');
    assert.ok(!c.includes('crit:fw.public_mgmt'));
    assert.ok(codes({ ufw: extra, mgmt_list: '2222 9100' }).includes('crit:fw.public_mgmt'), 'a port MGMT-PORTS does not guard is exposed');
    assert.ok(codes({ ufw: extra, mgmt_jump: '0' }).includes('crit:fw.public_mgmt'), 'a chain INPUT never jumps to guards nothing');
    assert.ok(c.includes('info:fw.public_port'));
    assert.ok(!c.includes('warn:fw.public_port'));

    const off = codes({ ufw: 'Status: inactive' });
    assert.ok(off.includes('crit:fw.inactive'));
    assert.ok(!off.includes('crit:fw.exposed'), 'MGMT-PORTS guards the management ports');
    const exposed = audit(nl, facts({ ufw: 'Status: inactive', mgmt_chain: '', mgmt_jump: '' })).find((f) => f.code === 'fw.exposed')!;
    assert.match(exposed.msg, /2222\/tcp/);
    assert.match(exposed.msg, /22\/tcp\(sshd\)/);
    assert.match(exposed.msg, /9100\/tcp/);
    assert.doesNotMatch(exposed.msg, /443\/tcp/, 'inbound ports are not management ports');
    assert.doesNotMatch(exposed.msg, /53\//, 'loopback is not exposed');
});

test('current fleet baseline: MGMT-PORTS, ipset blacklists, beszel, automatic updates off', () => {
    assert.ok(codes({ mgmt_chain: '', mgmt_jump: '' }).includes('warn:mgmt.missing'));
    assert.ok(codes({ mgmt_jump: '0' }).includes('warn:mgmt.unhooked'));
    assert.ok(codes({ blacklist_cron: '' }).includes('warn:blacklist.cron'));
    assert.ok(codes({ ipsets: '' }).includes('warn:blacklist.missing'));
    assert.ok(codes({ ipsets: 'whitelist 10\nblacklist_ru 0' }).includes('warn:blacklist.empty'));
    assert.ok(codes({ rugov_chain: 'yes' }).includes('info:blacklist.legacy'));
    assert.ok(codes({ units: healthyNodeRecords().units.replace('beszel-agent|active', 'beszel-agent|inactive') }).includes('warn:beszel.inactive'));
    assert.ok(codes({ units: healthyNodeRecords().units.replace('ipset-load|active|enabled', 'ipset-load|inactive|disabled') }).includes('warn:blacklist.boot'));
    assert.ok(codes({ apt_auto: 'APT::Periodic::Unattended-Upgrade "0"' }).includes('warn:updates.security_off'));
    assert.ok(codes({ uu_installed: '0' }).includes('warn:updates.security_off'));
    assert.ok(codes({ units: healthyNodeRecords().units.replace('apt-daily-upgrade.timer|active|enabled', 'apt-daily-upgrade.timer|inactive|disabled') }).includes('warn:updates.security_off'));
    assert.ok(codes({ apt_auto: 'APT::Periodic::Unattended-Upgrade "1"\nUnattended-Upgrade::Automatic-Reboot "true"' }).includes('warn:updates.auto_reboot'));
    assert.ok(codes({ apt_origins: '${distro_id}:${distro_codename}-security\n${distro_id}:${distro_codename}-updates' }).includes('info:updates.not_security_only'));
    assert.ok(!codes({ uu_installed: '' }).some((c) => c.includes('updates.')), 'non-apt hosts (openSUSE nas) are not judged');
});

test('remnanode failures', () => {
    assert.ok(codes({ docker_ps: 'remnanode\tremnawave/node:latest\texited\tExited (1) 2 minutes ago' }).includes('crit:node.container'));
    assert.ok(codes({ remnanode_compose: 'image=remnawave/node:latest\nnode_port=2222\nsecret_key=missing\ngeo_volumes=2\ncert_volume=1' }).includes('crit:node.secret'));
    assert.ok(codes({ certs: `remnanode\t${1_790_000_000 + 5 * 86400}\tCN = nl1\tDNS:nl1.example.com` }).includes('crit:cert.expiring'));
    assert.ok(codes({ certs: `remnanode\t${1_790_000_000 + 15 * 86400}\tCN = nl1\tDNS:nl1.example.com` }).includes('warn:cert.expiring'));
    assert.ok(codes({ certs: `remnanode\t${1_790_000_000 + 60 * 86400}\tCN = x\tDNS:other.example.com` }).includes('warn:cert.domain'));
    assert.ok(codes({ certs: '' }).includes('info:cert.missing'), 'REALITY-only nodes may have no certificate');
    const oldGeo = `/opt/remnanode/roscomvpn-geoip.dat ${1_790_000_000 - 5 * 86400} 1`;
    assert.ok(codes({ geo_files: oldGeo }).includes('warn:geo.stale'));
    // the updater leaves unchanged files alone: its last successful run is what counts
    const ran = new Date((1_790_000_000 - 3600) * 1000).toISOString().replace('T', ' ').slice(0, 19);
    assert.ok(!codes({ geo_files: oldGeo, geo_service: `Result=success\nExecMainStatus=0\nExecMainExitTimestamp=Tue ${ran} UTC` }).includes('warn:geo.stale'));
    assert.ok(!codes({ geo_files: oldGeo, geo_service2: `Result=success\nExecMainExitTimestamp=Tue ${ran} UTC` }).includes('warn:geo.stale'));
    assert.ok(codes({ geo_files: oldGeo, geo_service: `Result=exit-code\nExecMainExitTimestamp=Tue ${ran} UTC` }).some((x) => x.endsWith('geo.stale') || x.endsWith('geo.failed')));
    assert.ok(codes({ listen: '' }).includes('warn:node.port'));
    assert.ok(codes({ docker_images_used: 'remnawave/node:latest\tsha256:bbb\tremnawave/node@sha256:eee\t2026-09-20' }).includes('info:node.pending_recreate'));
});

test('edge hardening and health', () => {
    assert.ok(codes({ sshd: 'passwordauthentication yes\npermitrootlogin yes' }).includes('crit:ssh.password'));
    assert.ok(codes({ sshd: 'passwordauthentication no\npermitrootlogin yes' }).includes('warn:ssh.root_login'));
    assert.ok(codes({ tailscale: JSON.stringify({ BackendState: 'NeedsLogin', Self: {} }) }).includes('crit:ts.down'));
    assert.ok(codes({ fail2ban: 'sshd 0 1' }).includes('warn:f2b.jail_missing'));
    assert.ok(codes({ sysctl: 'net.ipv4.tcp_congestion_control = cubic\nnet.netfilter.nf_conntrack_max = 1000\nnet.netfilter.nf_conntrack_count = 900' }).includes('warn:conntrack.high'));
    assert.ok(codes({ df: '/dev/vda1 ext4 41000000 40600000 400000 99% /' }).includes('crit:disk.full'));
    assert.ok(codes({ apt_upgradable: 'openssl/noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]' }).includes('warn:apt.security'));
    assert.ok(codes({ reboot_required_flag: 'yes', reboot_required: 'linux-image-6.8.0-47-generic' }).includes('warn:reboot.required'));
    assert.ok(codes({ timedate: 'NTPSynchronized=no' }).includes('warn:time.unsynced'));
    assert.ok(codes({ failed_units: 'foo.service' }).includes('warn:units.failed'));
});

test('policy.skip mutes by code and prefix', () => {
    const q = inv.get('quiet');
    const f = facts({ sysctl: 'net.ipv4.tcp_congestion_control = cubic', certs: `remnanode\t${1_790_000_000 + 10 * 86400}\tCN = x\tDNS:x` });
    const c = audit(q, f).map((x) => x.code);
    assert.ok(!c.includes('tune.bbr'));
    assert.ok(!c.includes('cert.expiring'));
});

test('panel state and unreachable hosts', () => {
    const f = facts();
    const node = { uuid: 'u', name: 'NL-1', address: 'nl1.example.com', isConnected: false, isDisabled: false, lastStatusMessage: 'timeout' };
    assert.ok(audit(nl, f, node).some((x) => x.code === 'panel.disconnected' && /timeout/.test(x.msg)));
    assert.ok(audit(nl, f, null).some((x) => x.code === 'panel.missing'));
    const down = parseProbe('nl-1', { host: 'nl-1', ok: false, code: 255, stdout: '', stderr: 'ssh: connect to host nl-1 port 22: Connection timed out', ms: 10000, unreachable: true, error: 'ssh failed: timed out' }, 'quick');
    assert.equal(down.reachable, false);
    assert.deepEqual(
        audit(nl, down, node).map((x) => x.code),
        ['reach', 'panel.disconnected'],
    );
    assert.equal(statusRow(nl, down, [], node).state, 'UNREACHABLE');
});

test('inventory services: compose down is crit, oneshot "present" services are not', () => {
    const box = inv.get('box');
    const f = parseProbe('box', execOk(probeOutput({ services: 'bot\tcompose=bot:exited worker:running\ndocker\t unit=active/enabled' })), 'quick');
    assert.ok(audit(box, f).some((x) => x.code === 'svc.down' && /bot:exited/.test(x.msg)));
    const ok = parseProbe('box', execOk(probeOutput({ services: 'bot\tcompose=bot:running worker:running\ndocker\t unit=active/enabled' })), 'quick');
    assert.deepEqual(audit(box, ok).filter((x) => x.code.startsWith('svc')), []);
    const missing = parseProbe('box', execOk(probeOutput({ services: 'bot\tcompose=missing-file\ndocker\t unit=absent' })), 'quick');
    assert.deepEqual(
        audit(box, missing).filter((x) => x.code.startsWith('svc')).map((x) => x.code),
        ['svc.missing', 'svc.missing'],
    );
});

test('firewall as the fleet runs it (2026-10-01): internal interfaces, ADMIN-PORTS, "ALLOW Anywhere on eth0" ingresses', () => {
    const withLine = (line: string) => UFW_BASELINE.replace('Anywhere on tailscale0     ALLOW IN    Anywhere', `Anywhere on tailscale0     ALLOW IN    Anywhere\n${line}`);
    // containers → host on docker0 is not "open to the internet"
    const docker = codes({ ufw: withLine('Anywhere on docker0        ALLOW IN    Anywhere') });
    assert.ok(!docker.includes('crit:fw.public_mgmt'), 'docker0 is an internal interface');
    assert.equal(publicAllows([{ to: 'Anywhere on amn0', port: 'Anywhere', iface: 'amn0', action: 'ALLOW IN', from: 'Anywhere', v6: false }]).length, 0);
    // ingress: every public port allowed by design; management ports guarded by MGMT-PORTS → informational
    const ingress = withLine('Anywhere on eth0           ALLOW IN    Anywhere');
    const c = codes({ ufw: ingress });
    assert.ok((c.includes('info:fw.mgmt_guarded') || c.includes('info:fw.mgmt_idle')) && !c.includes('crit:fw.public_mgmt'), 'nothing management-ish listens unguarded');
    // …but a management port that listens publicly and no chain guards is exposure
    const listen = healthyNodeRecords().listen + '\ntcp LISTEN 0 4096 0.0.0.0:5201 0.0.0.0:* users:(("iperf3",pid=9,fd=3))';
    const open = audit(nl, facts({ ufw: ingress, listen })).find((f) => f.code === 'fw.public_mgmt');
    assert.ok(open && /5201\/tcp\(iperf3\)/.test(open.msg), 'iperf3 on 0.0.0.0:5201 is reachable from anywhere');
    // ADMIN-PORTS (pl9) guards 22 ahead of ufw, like MGMT-PORTS
    const pl9 = UFW_BASELINE.replace('22/tcp on eth0             DENY IN     Anywhere', '22/tcp                     ALLOW IN    Anywhere');
    assert.ok(codes({ ufw: pl9, mgmt_list: '2222 9100' }).includes('crit:fw.public_mgmt'), 'without the guard 22 is open');
    assert.ok(!codes({ ufw: pl9, mgmt_list: '2222 9100', guard_ports: '22 2222' }).includes('crit:fw.public_mgmt'), 'ADMIN-PORTS guards 22');
});

test('noise the fleet produced on 2026-10-01: *.scope, wg-quick with the interface up, geo updater v2', () => {
    assert.ok(!codes({ failed_units: 'session-c43.scope' }).includes('warn:units.failed'), 'transient scopes are not services');
    assert.ok(codes({ failed_units: 'session-c43.scope\nfoo.service' }).includes('warn:units.failed'));
    // v2 rewrites only files xray uses and only when upstream changed: an old unused geosite is fine after a good run
    const now = facts().now!;
    const old = `/opt/remnanode/roscomvpn-geoip.dat ${now - 30 * 86400} 100000`;
    const run = (age: number, failed: string) =>
        `roscomvpn_geo_last_run_timestamp_seconds ${now - age}\nroscomvpn_geo_last_run_failed ${failed}\nroscomvpn_geo_file_used{file="roscomvpn-geoip.dat"} 1`;
    assert.ok(!codes({ geo_files: old, geo_metrics: run(3600, '0') }).some((x) => x.includes('geo.')), 'a recent good run means current data');
    assert.ok(codes({ geo_files: old, geo_metrics: run(3600, '1') }).includes('warn:geo.failed'));
    assert.ok(codes({ geo_files: old, geo_metrics: run(10 * 86400, '0') }).includes('warn:geo.stale'));
    // wg-quick@X inactive while the interface is up (brought up by something else) is not a dead service
    const wgInv = new Inventory('f', { hosts: { r: { roles: ['docker'], services: [{ name: 'wg1', unit: 'wg-quick@wg1' }] } } });
    const wgFacts = (ifaces: string) => parseProbe('r', execOk(probeOutput(healthyNodeRecords({ services: 'wg1\t unit=inactive/enabled', ifaces }))), 'quick');
    assert.ok(!audit(wgInv.get('r'), wgFacts('lo\neth0\nwg1')).some((x) => x.code === 'svc.down'));
    assert.ok(audit(wgInv.get('r'), wgFacts('lo\neth0')).some((x) => x.code === 'svc.down'));
});
