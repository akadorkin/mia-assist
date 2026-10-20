import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Config } from './config.js';
import { Host } from './core/inventory.js';
import { report } from './core/progress.js';
import { ExecOptions, ExecResult, Transport } from './core/ssh.js';

/**
 * `mia --demo` / `mia web --demo`: a made-up fleet to click through. Nothing leaves this machine — the
 * transport below answers instead of ssh, and «Выполнить» changes only this fleet's pretend state
 * (an update empties the list of updates, a reboot clears «нужен ребут» …). Keys, the panel and the
 * owner's fleet.yaml are not read.
 */

const FLEET = `# the demo fleet of mia --demo: nothing here exists
defaults:
  user: root

groups:
  eu: [nl-1, nl-2, de-1]
  ru: [ru-1]
  home: [rpi]

hosts:
  nl-1:
    address: node-nl-1
    roles: [remnanode]
    tags: [prod]
    domain: nl1.demo.example

  nl-2:
    address: node-nl-2
    roles: [remnanode]
    tags: [prod]
    domain: nl2.demo.example

  de-1:
    address: node-de-1
    roles: [remnanode]
    tags: [prod]
    domain: de1.demo.example

  ru-1:
    address: node-ru-1
    roles: [remnanode]
    tags: [prod]
    domain: ru1.demo.example

  pl-1:
    address: node-pl-1
    roles: [remnanode]
    tags: [prod]
    domain: pl1.demo.example

  bot:
    address: bot
    roles: [docker]
    tags: [prod]

  rpi:
    address: rpi
    roles: [docker]
    tags: [home]
`;

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');
const now = () => Math.floor(Date.now() / 1000);
const pkg = (name: string, sec: boolean) => `${name}/noble-updates${sec ? ',noble-security' : ''} 2.0.1 amd64 [upgradable from: 2.0.0]`;
const PKGS = ['openssl', 'libssl3', 'curl', 'libcurl4', 'openssh-server', 'openssh-client', 'linux-image-generic', 'tzdata', 'vim', 'git', 'python3', 'systemd', 'sudo', 'libc6', 'bash'];

/** What each demo host is going through; «Выполнить» edits this. */
interface Pretend {
    updates: number;
    security: number;
    reboot: boolean;
    uptime: number;
    certDays?: number;
    diskPct: number;
    f2b: boolean;
    down?: boolean;
}

function initial(): Map<string, Pretend> {
    const base = { updates: 0, security: 0, reboot: false, uptime: 12 * 86400, diskPct: 31, f2b: true };
    return new Map<string, Pretend>([
        ['nl-1', { ...base }],
        ['nl-2', { ...base, updates: 9, security: 4, reboot: true, uptime: 41 * 86400 }],
        ['de-1', { ...base, updates: 3, security: 1, certDays: 9 }],
        ['ru-1', { ...base, down: true }],
        ['pl-1', { ...base, diskPct: 99, f2b: false, updates: 2 }],
        ['bot', { ...base, updates: 5, security: 2 }],
        ['rpi', { ...base, updates: 14, security: 6, uptime: 90 * 86400 }],
    ]);
}

function records(h: Host, p: Pretend): Record<string, string> {
    const t = now();
    const node = h.roles.includes('remnanode');
    const upd = PKGS.slice(0, p.updates).map((n, i) => pkg(n, i < p.security));
    const units = ['ssh', 'docker', 'tailscaled', 'node_exporter', 'beszel-agent', 'ipset-load', 'ufw', 'cron', 'unattended-upgrades']
        .map((u) => `${u}|active|enabled`)
        .concat([`fail2ban|${p.f2b ? 'active' : 'inactive'}|enabled`, 'apt-daily-upgrade.timer|active|enabled', 'update-roscomvpn-geo.timer|active|enabled', 'update-roscomvpn-geo.service|inactive|static']);
    return {
        probe_version: '2',
        mode: 'quick',
        whoami: 'root',
        hostname: h.name,
        os: 'Ubuntu 24.04.3 LTS',
        kernel: '6.8.0-79-generic',
        arch: h.name === 'rpi' ? 'aarch64' : 'x86_64',
        now: String(t),
        uptime: String(p.uptime),
        loadavg: `${h.name === 'nl-2' ? '2.70' : '0.31'} 0.35 0.30 1/300 12345`,
        cpus: h.name === 'rpi' ? '4' : '2',
        meminfo: 'MemTotal:        4000000 kB\nMemAvailable:    2600000 kB\nSwapTotal:       0 kB\nSwapFree:        0 kB',
        ...(h.name === 'rpi' ? { temps: 'cpu-thermal 61500' } : {}),
        df: `/dev/vda1 ext4 41000000 ${Math.round(41000000 * p.diskPct / 100)} ${Math.round(41000000 * (100 - p.diskPct) / 100)} ${p.diskPct}% /`,
        apt_upgradable: upd.join('\n'),
        apt_last_update: String(t - 3600),
        ...(p.reboot ? { reboot_required: 'linux-image-6.8.0-84-generic', reboot_required_flag: 'yes' } : {}),
        units: units.join('\n'),
        failed_units: '',
        geo_service: `Result=success\nExecMainStatus=0\nExecMainExitTimestamp=Mon ${new Date((t - 7200) * 1000).toISOString().replace('T', ' ').slice(0, 19)} UTC`,
        timedate: 'NTPSynchronized=yes\nTimezone=Europe/Moscow',
        ufw: [
            'Status: active',
            'Default: deny (incoming), allow (outgoing), allow (routed)',
            '',
            'To                         Action      From',
            '--                         ------      ----',
            '443/tcp on eth0            ALLOW IN    Anywhere',
            '443/udp on eth0            ALLOW IN    Anywhere',
            '22/tcp on eth0             DENY IN     Anywhere',
            'Anywhere on tailscale0     ALLOW IN    Anywhere',
        ].join('\n'),
        listen: ['tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=1,fd=3))', 'tcp LISTEN 0 4096 *:2222 *:* users:(("node",pid=2,fd=5))', 'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=3,fd=3))'].join('\n'),
        sshd: 'port 22\npermitrootlogin no\npasswordauthentication no\npubkeyauthentication yes',
        fail2ban: p.f2b ? 'sshd 0 12\nsshd-fast 1 40\nrecidive 0 3' : '',
        sysctl: 'net.ipv4.tcp_congestion_control = bbr\nnet.core.default_qdisc = fq\nnet.ipv4.ip_forward = 1\nnet.netfilter.nf_conntrack_max = 262144\nnet.netfilter.nf_conntrack_count = 1200',
        ipsets: 'whitelist 1200\nblacklist_ru 1150\nblacklist_dangerous 340',
        blacklist_cron: '0 */2 * * * root /usr/local/bin/ufw-blacklist.sh',
        blacklist_script: String(t - 86400),
        mgmt_chain: '7',
        mgmt_jump: '1',
        mgmt_list: '22 2222 9100 45876',
        apt_auto: 'APT::Periodic::Update-Package-Lists "1"\nAPT::Periodic::Unattended-Upgrade "1"\nUnattended-Upgrade::Automatic-Reboot "false"',
        apt_origins: '${distro_id}:${distro_codename}-security',
        uu_installed: '1',
        tailscale: JSON.stringify({ BackendState: 'Running', Self: { DNSName: `${h.address}.tailnet.example.`, TailscaleIPs: ['198.51.100.9'], Online: true } }),
        docker_version: '28.3.0',
        compose_version: '2.39.1',
        ...(node
            ? {
                  docker_ps: 'remnanode\tremnawave/node:latest\trunning\tUp 3 days',
                  docker_inspect: '/remnanode\tsha256:aaa\tremnawave/node:latest\t2026-09-01T00:00:00Z\t0\t<nil>',
                  docker_images_used: 'remnawave/node:latest\tsha256:aaa\tremnawave/node@sha256:ddd\t2026-08-30',
                  remnanode_compose: 'image=remnawave/node:latest\nnode_port=2222\nsecret_key=present\ngeo_volumes=2\ncert_volume=1\nnetwork_host=1',
                  geo_files: `/opt/remnanode/roscomvpn-geoip.dat ${t - 7200} 100000\n/opt/remnanode/roscomvpn-geosite.dat ${t - 7200} 200000`,
                  certs: `remnanode\t${t + (p.certDays ?? 70) * 86400}\tCN = ${h.name}\tDNS:${h.name.replace('-', '')}.demo.example`,
                  services: 'remnanode\tcompose=remnanode:running container=running\ndocker\t unit=active/enabled',
              }
            : { docker_ps: 'app\tdemo/app:latest\trunning\tUp 3 days', services: 'docker\t unit=active/enabled' }),
        done: '1',
    };
}

const LOG = (host: string) =>
    Array.from({ length: 12 }, (_, i) => {
        const at = new Date(Date.now() - (12 - i) * 61_000).toISOString().slice(0, 19);
        return `${at} ${host} ${['xray: accepted tcp:1.1.1.1:443', 'xray: accepted udp:8.8.8.8:53', 'node: config applied', 'sshd: Accepted publickey for root'][i % 4]}`;
    }).join('\n');

/** The ssh of the demo: every script gets a plausible answer after a plausible pause. */
export class DemoTransport extends Transport {
    private fleet = initial();

    constructor(config: Config) {
        super(config);
    }

    override async exec(host: Host, script: string, opts: ExecOptions = {}): Promise<ExecResult> {
        report({ kind: 'host', host: host.name, state: 'run' });
        const started = Date.now();
        const p = this.fleet.get(host.name) ?? initial().get('nl-1')!;
        await new Promise((r) => setTimeout(r, p.down ? 1500 : 250 + Math.random() * 900));
        const res = (stdout: string, ok = true): ExecResult => ({ host: host.name, ok, code: ok ? 0 : 1, stdout, stderr: '', ms: Date.now() - started });
        let out: ExecResult;
        if (p.down) out = { host: host.name, ok: false, code: 255, stdout: '', stderr: '', ms: Date.now() - started, unreachable: true, error: `ssh: таймаут подключения — connect to host ${host.address} port 22: Operation timed out` };
        else if (script.includes('# mia probe:'))
            out = res(
                Object.entries(records(host, p))
                    .map(([k, v]) => `${k}\t${b64(v)}`)
                    .join('\n'),
            );
        else if (/apt-get .*(upgrade|install --only-upgrade)/.test(script)) {
            const kernel = p.updates > 0 && (host.name === 'bot' || host.name === 'rpi');
            p.updates = 0;
            p.security = 0;
            p.reboot = p.reboot || kernel;
            out = res(`демо: пакеты обновлены\n${p.reboot ? 'REBOOT_REQUIRED\n' : ''}`);
        } else if (/shutdown -r/.test(script)) {
            p.reboot = false;
            p.uptime = 40;
            out = res('демо: перезагрузка запланирована');
        } else if (/\/proc\/uptime/.test(script)) out = res(String(p.uptime));
        else if (/certbot/.test(script)) {
            p.certDays = 90;
            out = res(`демо: сертификат продлён\nnotAfter=${new Date(Date.now() + 90 * 86_400_000).toUTCString()}`);
        } else if (/journalctl|docker logs|tail -n/.test(script)) out = res(LOG(host.name));
        else if (opts.env?.COMPOSE || opts.env?.CONTAINER || opts.env?.UNIT) {
            if (opts.env.UNIT === 'fail2ban') p.f2b = true;
            out = res(opts.env.COMPOSE ? 'remnanode:running' : opts.env.UNIT ? 'active' : 'running');
        } else if (/fail2ban/.test(script) && /restart|start/.test(script)) {
            p.f2b = true;
            out = res('демо: fail2ban перезапущен');
        } else if (/journal|vacuum|apt-get clean|docker .*prune/.test(script)) {
            p.diskPct = 58;
            out = res('демо: место освобождено');
        } else out = res('демо: выполнено');
        report({ kind: 'host', host: host.name, state: out.ok ? 'ok' : 'fail', note: out.error, ms: out.ms });
        return out;
    }
}

/**
 * The environment of the demo: its own fleet.yaml, state dir and a pretend `tailscale status` in a
 * temp directory; no keys, no panel, no mcp-remnawave.
 */
export function demoEnv(): NodeJS.ProcessEnv {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mia-demo-'));
    fs.writeFileSync(path.join(dir, 'fleet.yaml'), FLEET);
    const peers: Array<[string, Record<string, unknown>]> = ['node-nl-1', 'node-nl-2', 'node-de-1', 'node-pl-1', 'bot', 'rpi'].map((n, i) => [`p${i}`, { HostName: n, DNSName: `${n}.tailnet.example.`, TailscaleIPs: [`100.64.0.${i + 10}`], Online: true, OS: 'linux' }]);
    peers.push(['p9', { HostName: 'node-ru-1', DNSName: 'node-ru-1.tailnet.example.', TailscaleIPs: ['198.51.100.30'], Online: false, LastSeen: new Date(Date.now() - 3 * 86_400_000).toISOString(), OS: 'linux' }]);
    peers.push(['p10', { HostName: 'macbook', DNSName: 'macbook.tailnet.example.', TailscaleIPs: ['198.51.100.40'], Online: true, OS: 'macOS' }]);
    peers.push(['p11', { HostName: 'spare-vps', DNSName: 'spare-vps.tailnet.example.', TailscaleIPs: ['198.51.100.41'], Online: false, LastSeen: '2026-09-30T10:00:00Z', OS: 'linux' }]);
    const status = JSON.stringify({ Self: { HostName: 'this-mac', DNSName: 'this-mac.tailnet.example.', TailscaleIPs: ['198.51.100.1'], Online: true, OS: 'macOS' }, Peer: Object.fromEntries(peers) });
    fs.writeFileSync(path.join(dir, 'status.json'), status);
    const ts = path.join(dir, 'tailscale');
    fs.writeFileSync(ts, `#!/bin/sh\ncat "${path.join(dir, 'status.json')}"\n`, { mode: 0o755 });
    return {
        MIA_INVENTORY: path.join(dir, 'fleet.yaml'),
        MIA_STATE_DIR: path.join(dir, 'state'),
        MIA_TAILSCALE_BIN: ts,
        MIA_TIME_SCALE: '0.05',
        MIA_SSH_REUSE: '0',
        // belt and braces: even a stray real ssh call could not reach anything
        MIA_SSH_BIN: '/nonexistent/mia-demo-has-no-ssh',
        MIA_SECRETS_FILE: path.join(dir, 'no-secrets.env'),
        HOME: process.env.HOME,
        PATH: process.env.PATH,
    };
}
