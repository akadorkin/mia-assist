import { Host } from './inventory.js';
import { script } from './scripts.js';
import { ExecResult, Transport } from './ssh.js';

export interface UfwRule {
    to: string;
    /** Port spec without iface/(v6): "80/tcp", "443", "Anywhere", "6881:6999/tcp". */
    port: string;
    iface?: string;
    action: string;
    from: string;
    v6: boolean;
    comment?: string;
}

export interface UfwState {
    active: boolean;
    defaultIn?: string;
    defaultOut?: string;
    defaultRouted?: string;
    rules: UfwRule[];
}

export interface ListenSocket {
    proto: string;
    addr: string;
    port: number;
    process?: string;
}

export interface Container {
    name: string;
    image: string;
    state: string;
    status: string;
    imageId?: string;
    startedAt?: string;
    restarts?: number;
    health?: string;
}

export interface Cert {
    name: string;
    notAfter?: number;
    daysLeft?: number;
    subject: string;
    sans: string[];
}

export interface HostFacts {
    host: string;
    reachable: boolean;
    error?: string;
    ms: number;
    mode: string;
    whoami?: string;
    hostname?: string;
    os?: string;
    kernel?: string;
    arch?: string;
    now?: number;
    uptimeS?: number;
    load?: [number, number, number];
    cpus?: number;
    mem?: { totalMiB: number; availMiB: number; usedPct: number; swapTotalMiB: number; swapUsedMiB: number };
    disks: Array<{ mount: string; fs: string; sizeGiB: number; usedPct: number }>;
    /** Sensor → °C (thermal zones and hwmon). */
    temps: Record<string, number>;
    rebootRequired: boolean;
    rebootPkgs: string[];
    apt?: { upgradable: Array<{ name: string; version: string; from?: string; security: boolean }>; lastUpdate?: number };
    units: Record<string, { active: string; enabled: string }>;
    failedUnits: string[];
    geoService?: Record<string, string>;
    /** update-roscomvpn-dat.service: some nodes update the .dat files with this one. */
    geoService2?: Record<string, string>;
    time?: { ntpSynced?: boolean; timezone?: string };
    ufw?: UfwState;
    listen: ListenSocket[];
    sshd: Record<string, string>;
    fail2ban?: Array<{ jail: string; banned: number; total: number }>;
    sysctl: Record<string, string>;
    tuningBackups: string[];
    resolv: string[];
    /** ipset name → entries (ufw-blacklist.sh sets: whitelist, blacklist_ru, blacklist_dangerous …). */
    ipsets: Record<string, number>;
    /** ufw-blacklist.sh: cron line(s) and script mtime. */
    blacklist: { cron?: string; scriptMtime?: number };
    /** MGMT-PORTS iptables chain: rules in it, INPUT jumps to it, ports from /etc/mgmt-ports.list. */
    mgmt: { rules?: number; jumps?: number; list?: string[] };
    /** Ports INPUT sends through MGMT-PORTS / ADMIN-PORTS (chains that end in DROP) — guarded before ufw. */
    guardPorts: string[];
    /** Network interfaces (ip -o link). */
    ifaces: string[];
    /** update-roscomvpn-geo.sh v2 state: last run (unix s), whether it failed, files xray actually uses. */
    geoState?: { lastRun?: number; failed?: boolean; used: Record<string, boolean> };
    /** Legacy rugov nftables chain from the old vps-edge-run.sh still present. */
    legacyRugov: boolean;
    /** apt-config: APT::Periodic::* and Unattended-Upgrade::Automatic-Reboot. */
    aptAuto: Record<string, string>;
    /** unattended-upgrades: installed?, allowed origins / patterns. undefined = not an apt system. */
    unattended?: { installed: boolean; origins: string[] };
    tailscale?: { backendState?: string; dnsName?: string; ips?: string[]; online?: boolean; version?: string };
    docker?: {
        version?: string;
        compose?: string;
        containers: Container[];
        images: Array<{ ref: string; id: string; digests: string[]; created?: string }>;
    };
    remnanode?: Record<string, string>;
    geoFiles: Array<{ path: string; mtime: number; size: number }>;
    certs: Cert[];
    remnanodeLogs: Array<{ file: string; size: number; mtime: number }>;
    services: Array<{ name: string; state: string; compose?: string; container?: string; unit?: string }>;
    // full mode
    packages?: Record<string, string>;
    snaps?: Record<string, string>;
    enabledUnits?: string[];
    dockerImages?: string[];
    nftChains?: string[];
    users?: string[];
    sudoGroup?: string[];
    authorizedKeys?: Array<{ home: string; fp: string; comment: string; type: string }>;
    crontabs?: string[];
    files?: Record<string, { sha: string; size: number; content?: string }>;
}

/** Paths tracked by snapshots on every host (globs allowed); services add their own files. */
export const TRACKED_FILES = [
    '/etc/ssh/sshd_config',
    '/etc/ssh/sshd_config.d/*.conf',
    '/etc/fail2ban/fail2ban.local',
    '/etc/fail2ban/jail.d/*.local',
    '/etc/fail2ban/jail.local',
    '/etc/sysctl.d/*.conf',
    '/etc/security/limits.d/*.conf',
    '/etc/systemd/system.conf.d/*.conf',
    '/etc/systemd/resolved.conf',
    '/etc/systemd/journald.conf.d/*.conf',
    '/etc/default/ufw',
    '/etc/ufw/user.rules',
    '/etc/ufw/user6.rules',
    '/etc/cron.d/*',
    '/etc/sudoers.d/*',
    '/etc/docker/daemon.json',
    '/etc/hosts',
    '/etc/logrotate.d/remnanode',
    '/etc/systemd/system/*.service',
    '/etc/systemd/system/*.timer',
    '/usr/local/sbin/update-roscomvpn-geo.sh',
    '/usr/local/bin/ufw-blacklist.sh',
    '/etc/ufw/before.rules',
    '/etc/mgmt-ports.list',
    '/etc/apt/apt.conf.d/20auto-upgrades',
    '/etc/apt/apt.conf.d/*unattended*',
];

export async function probeHost(transport: Transport, host: Host, mode: 'quick' | 'full' = 'quick', timeoutMs = 90_000): Promise<HostFacts> {
    const services = host.services.map((s) => [s.name, s.compose ?? '', s.container ?? '', s.unit ?? ''].join('|')).join('\n');
    const files = [...TRACKED_FILES, ...host.services.flatMap((s) => s.files ?? [])].join('\n');
    const res = await transport.exec(host, script('probe.sh'), {
        timeoutMs,
        env: { MIA_MODE: mode, MIA_SERVICES: services, MIA_FILES: files },
    });
    return parseProbe(host.name, res, mode);
}

export function decodeRecords(stdout: string): Map<string, string> {
    const rec = new Map<string, string>();
    for (const line of stdout.split('\n')) {
        const tab = line.indexOf('\t');
        if (tab <= 0) continue;
        const key = line.slice(0, tab);
        const b64 = line.slice(tab + 1).trim();
        rec.set(key, Buffer.from(b64, 'base64').toString('utf8'));
    }
    return rec;
}

const lines = (s?: string) => (s ?? '').split('\n').map((l) => l.trimEnd()).filter((l) => l.trim() !== '');
const num = (s?: string) => (s === undefined || s === '' || isNaN(Number(s)) ? undefined : Number(s));

export function parseProbe(host: string, res: ExecResult, mode: string): HostFacts {
    const r = decodeRecords(res.stdout);
    const base: HostFacts = {
        host,
        reachable: false,
        ms: res.ms,
        mode,
        disks: [],
        temps: {},
        rebootRequired: false,
        rebootPkgs: [],
        units: {},
        failedUnits: [],
        listen: [],
        sshd: {},
        sysctl: {},
        tuningBackups: [],
        resolv: [],
        ipsets: {},
        blacklist: {},
        mgmt: {},
        guardPorts: [],
        ifaces: [],
        legacyRugov: false,
        aptAuto: {},
        geoFiles: [],
        certs: [],
        remnanodeLogs: [],
        services: [],
    };
    if (!r.has('probe_version')) {
        base.error = res.error ?? (res.stderr.trim().split('\n').pop() || 'probe produced no output');
        return base;
    }
    const f: HostFacts = { ...base, reachable: true };
    if (!r.has('done')) f.error = `probe incomplete${res.error ? `: ${res.error}` : ''}`;

    f.whoami = r.get('whoami');
    f.hostname = r.get('hostname');
    f.os = r.get('os');
    f.kernel = r.get('kernel');
    f.arch = r.get('arch');
    f.now = num(r.get('now'));
    f.uptimeS = num(r.get('uptime')) !== undefined ? Math.round(num(r.get('uptime'))!) : undefined;
    const la = (r.get('loadavg') ?? '').split(' ').slice(0, 3).map(Number);
    if (la.length === 3 && la.every((x) => !isNaN(x))) f.load = la as [number, number, number];
    f.cpus = num(r.get('cpus'));

    const mi: Record<string, number> = {};
    for (const l of lines(r.get('meminfo'))) {
        const m = l.match(/^(\w+):\s+(\d+)/);
        if (m) mi[m[1]] = Number(m[2]);
    }
    if (mi.MemTotal) {
        f.mem = {
            totalMiB: Math.round(mi.MemTotal / 1024),
            availMiB: Math.round((mi.MemAvailable ?? 0) / 1024),
            usedPct: Math.round((1 - (mi.MemAvailable ?? 0) / mi.MemTotal) * 100),
            swapTotalMiB: Math.round((mi.SwapTotal ?? 0) / 1024),
            swapUsedMiB: Math.round(((mi.SwapTotal ?? 0) - (mi.SwapFree ?? 0)) / 1024),
        };
    }
    for (const l of lines(r.get('df'))) {
        const p = l.split(/\s+/);
        if (p.length < 7) continue;
        f.disks.push({ fs: p[1], sizeGiB: Math.round((Number(p[2]) / 1024 ** 2) * 10) / 10, usedPct: Number(p[5].replace('%', '')), mount: p.slice(6).join(' ') });
    }

    for (const l of lines(r.get('temps'))) {
        const i = l.lastIndexOf(' ');
        const name = l.slice(0, i).trim() || 'sensor';
        const milli = Number(l.slice(i + 1));
        // 0, 127/128 °C and above are "no reading" markers of some chips (a CPU at 127 °C would be off)
        if (!Number.isFinite(milli) || milli <= 0 || milli >= 120_000) continue;
        let key = name;
        for (let n = 2; key in f.temps; n++) key = `${name}#${n}`;
        f.temps[key] = Math.round(milli / 100) / 10;
    }
    f.rebootRequired = r.get('reboot_required_flag') === 'yes';
    f.rebootPkgs = (r.get('reboot_required') ?? '').split(/\s+/).filter(Boolean);
    if (r.has('apt_upgradable')) {
        f.apt = {
            upgradable: lines(r.get('apt_upgradable')).map((l) => {
                const m = l.match(/^([^/\s]+)\/(\S+)\s+(\S+)\s+\S+(?:\s+\[upgradable from: ([^\]]+)\])?/);
                return m ? { name: m[1], version: m[3], from: m[4], security: /-security/.test(m[2]) } : { name: l, version: '', security: false };
            }),
            lastUpdate: num(r.get('apt_last_update')),
        };
    }

    for (const l of lines(r.get('units'))) {
        const [u, active, enabled] = l.split('|');
        f.units[u] = { active: active || 'unknown', enabled: enabled || 'unknown' };
    }
    f.failedUnits = lines(r.get('failed_units'));
    if (r.get('geo_service')) f.geoService = kv(r.get('geo_service')!, '=');
    if (r.get('geo_service2')) f.geoService2 = kv(r.get('geo_service2')!, '=');
    if (r.get('timedate')) {
        const t = kv(r.get('timedate')!, '=');
        f.time = { ntpSynced: t.NTPSynchronized === undefined ? undefined : t.NTPSynchronized === 'yes', timezone: t.Timezone };
    }

    if (r.has('ufw')) f.ufw = parseUfw(r.get('ufw')!);
    f.listen = parseListen(r.get('listen'));
    for (const l of lines(r.get('sshd'))) {
        const [k, ...v] = l.split(' ');
        f.sshd[k.toLowerCase()] = v.join(' ');
    }
    if (r.has('fail2ban')) {
        f.fail2ban = lines(r.get('fail2ban')).map((l) => {
            const [jail, banned, total] = l.split(' ');
            return { jail, banned: Number(banned) || 0, total: Number(total) || 0 };
        });
    }
    for (const l of lines(r.get('sysctl'))) {
        const m = l.match(/^(\S+)\s*=\s*(.*)$/);
        if (m) f.sysctl[m[1]] = m[2].trim();
    }
    f.tuningBackups = lines(r.get('tuning_backups'));
    f.resolv = lines(r.get('resolv'));

    for (const l of lines(r.get('ipsets'))) {
        const [name, n] = l.split(' ');
        if (name) f.ipsets[name] = Number(n) || 0;
    }
    f.blacklist = { cron: r.get('blacklist_cron') || undefined, scriptMtime: num(r.get('blacklist_script')) };
    f.guardPorts = (r.get('guard_ports') ?? '').split(/\s+/).filter(Boolean);
    f.ifaces = lines(r.get('ifaces'));
    if (r.has('geo_metrics')) {
        const used: Record<string, boolean> = {};
        let lastRun: number | undefined;
        let failed: boolean | undefined;
        for (const l of lines(r.get('geo_metrics'))) {
            const m = l.match(/^roscomvpn_geo_(\w+?)(?:\{file="([^"]+)"\})?\s+(\S+)$/);
            if (!m) continue;
            if (m[1] === 'last_run_timestamp_seconds') lastRun = Number(m[3]);
            else if (m[1] === 'last_run_failed') failed = m[3] !== '0';
            else if (m[1] === 'file_used' && m[2]) used[m[2]] = m[3] !== '0';
        }
        f.geoState = { lastRun, failed, used };
    }
    f.mgmt = {
        rules: num(r.get('mgmt_chain')),
        jumps: num(r.get('mgmt_jump')),
        list: r.has('mgmt_list') ? (r.get('mgmt_list') ?? '').split(/\s+/).filter(Boolean) : undefined,
    };
    f.legacyRugov = r.get('rugov_chain') === 'yes';
    if (r.get('uu_installed')) f.unattended = { installed: r.get('uu_installed') === '1', origins: lines(r.get('apt_origins')) };
    for (const l of lines(r.get('apt_auto'))) {
        const m = l.match(/^(\S+)\s+"?([^"]*)"?$/);
        if (m) f.aptAuto[m[1]] = m[2];
    }

    if (r.get('tailscale')) {
        try {
            const ts = JSON.parse(r.get('tailscale')!) as { BackendState?: string; Version?: string; Self?: { DNSName?: string; TailscaleIPs?: string[]; Online?: boolean } };
            f.tailscale = {
                backendState: ts.BackendState,
                dnsName: ts.Self?.DNSName?.replace(/\.$/, ''),
                ips: ts.Self?.TailscaleIPs,
                online: ts.Self?.Online,
                version: (r.get('tailscale_version') || ts.Version)?.split('\n')[0],
            };
        } catch {
            f.tailscale = { backendState: 'unparsable', version: r.get('tailscale_version') };
        }
    } else if (r.has('tailscale_version')) {
        f.tailscale = { backendState: 'NoState', version: r.get('tailscale_version') };
    }

    if (r.has('docker_ps') || r.has('docker_version') || r.has('compose_version')) {
        const inspect = new Map<string, string[]>();
        for (const l of lines(r.get('docker_inspect'))) {
            const p = l.split('\t');
            inspect.set(p[0].replace(/^\//, ''), p);
        }
        f.docker = {
            version: r.get('docker_version') || undefined,
            compose: r.get('compose_version') || undefined,
            containers: lines(r.get('docker_ps')).map((l) => {
                const [name, image, state, status] = l.split('\t');
                const i = inspect.get(name);
                return {
                    name,
                    image,
                    state,
                    status,
                    imageId: i?.[1],
                    startedAt: i?.[3],
                    restarts: i ? Number(i[4]) : undefined,
                    health: i?.[5] && i[5] !== '<nil>' ? i[5] : undefined,
                };
            }),
            images: lines(r.get('docker_images_used')).map((l) => {
                const [ref, id, digests, created] = l.split('\t');
                return { ref, id, digests: (digests ?? '').split(',').filter(Boolean), created };
            }),
        };
    }
    if (r.has('remnanode_compose')) f.remnanode = kv(r.get('remnanode_compose')!, '=');
    f.geoFiles = lines(r.get('geo_files')).map((l) => {
        const [p, mtime, size] = l.split(' ');
        return { path: p, mtime: Number(mtime), size: Number(size) };
    });
    f.certs = lines(r.get('certs')).map((l) => {
        const [name, end, subject, sans] = l.split('\t');
        const notAfter = num(end);
        return {
            name,
            notAfter,
            daysLeft: notAfter && f.now ? Math.floor((notAfter - f.now) / 86400) : undefined,
            subject: subject ?? '',
            sans: (sans ?? '').split(',').map((s) => s.replace(/^DNS:/, '')).filter(Boolean),
        };
    });
    f.remnanodeLogs = lines(r.get('remnanode_logs')).map((l) => {
        const [file, size, mtime] = l.split(' ');
        return { file, size: Number(size), mtime: Number(mtime) };
    });
    f.services = lines(r.get('services')).map((l) => {
        const [name, state] = l.split('\t');
        const out: HostFacts['services'][number] = { name, state: (state ?? '').trim() };
        for (const part of out.state.split(/\s+/)) {
            const [k, v] = part.split('=');
            if (k === 'compose' || k === 'container' || k === 'unit') out[k] = v;
        }
        return out;
    });

    if (mode === 'full') {
        if (r.has('packages')) f.packages = Object.fromEntries(lines(r.get('packages')).map((l) => l.split('\t') as [string, string]));
        if (r.has('snaps')) f.snaps = Object.fromEntries(lines(r.get('snaps')).map((l) => l.split('\t') as [string, string]));
        if (r.has('enabled_units')) f.enabledUnits = lines(r.get('enabled_units'));
        if (r.has('docker_images')) f.dockerImages = lines(r.get('docker_images'));
        if (r.has('nft_chains')) f.nftChains = lines(r.get('nft_chains'));
        f.users = lines(r.get('users'));
        f.sudoGroup = (r.get('sudo_group') ?? '').split(',').filter(Boolean);
        f.authorizedKeys = lines(r.get('authorized_keys')).map((l) => {
            const [home, fp, comment, type] = l.split('\t');
            return { home, fp, comment: comment ?? '', type: (type ?? '').replace(/[()]/g, '') };
        });
        f.crontabs = lines(r.get('crontabs'));
        f.files = {};
        for (const [k, v] of r) {
            if (!k.startsWith('file:')) continue;
            const nl = v.indexOf('\n');
            const head = nl < 0 ? v : v.slice(0, nl);
            const body = nl < 0 ? '' : v.slice(nl + 1);
            const sha = head.match(/sha=(\w+)/)?.[1] ?? '';
            const size = Number(head.match(/size=(\d+)/)?.[1] ?? 0);
            f.files[k.slice(5)] = { sha, size, content: body.startsWith('(binary or large') ? undefined : body };
        }
    }
    return f;
}

function kv(s: string, sep: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const l of lines(s)) {
        const i = l.indexOf(sep);
        if (i > 0) out[l.slice(0, i).trim()] = l.slice(i + 1).trim();
    }
    return out;
}

export function parseUfw(text: string): UfwState {
    const st: UfwState = { active: /^Status:\s*active/m.test(text), rules: [] };
    const d = text.match(/^Default:\s*(\w+) \(incoming\),\s*(\w+) \(outgoing\)(?:,\s*(\w+) \(routed\))?/m);
    if (d) {
        st.defaultIn = d[1];
        st.defaultOut = d[2];
        st.defaultRouted = d[3];
    }
    let inTable = false;
    for (const raw of text.split('\n')) {
        const l = raw.trimEnd();
        if (/^--\s+/.test(l)) {
            inTable = true;
            continue;
        }
        if (!inTable || !l.trim()) continue;
        let line = l;
        let comment: string | undefined;
        const hash = line.indexOf(' # ');
        if (hash >= 0) {
            comment = line.slice(hash + 3).trim();
            line = line.slice(0, hash);
        }
        const cols = line.split(/\s{2,}/).map((c) => c.trim());
        if (cols.length < 3) continue;
        const [to, action, from] = cols;
        const v6 = /\(v6\)/.test(to) || /\(v6\)/.test(from);
        const onIdx = to.indexOf(' on ');
        const iface = onIdx >= 0 ? to.slice(onIdx + 4).trim() : undefined;
        const port = (onIdx >= 0 ? to.slice(0, onIdx) : to).replace(/\s*\(v6\)/, '').trim();
        st.rules.push({ to, port, iface, action, from: from.replace(/\s*\(v6\)/, '').trim(), v6, comment });
    }
    return st;
}

export function parseListen(text?: string): ListenSocket[] {
    const out: ListenSocket[] = [];
    for (const l of lines(text)) {
        const p = l.split(/\s+/);
        if (p.length < 5) continue;
        const local = p[4];
        const i = local.lastIndexOf(':');
        if (i < 0) continue;
        const addr = local.slice(0, i).replace(/^\[|\]$/g, '').replace(/%.*$/, '');
        const port = Number(local.slice(i + 1));
        if (!port) continue;
        const proc = l.match(/users:\(\("([^"]+)"/)?.[1];
        out.push({ proto: p[0], addr, port, process: proc });
    }
    // one row per proto/addr/port
    const seen = new Set<string>();
    return out.filter((s) => {
        const k = `${s.proto} ${s.addr} ${s.port}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
    });
}

/** True for addresses reachable from outside the box (not loopback). */
export function isWildcardOrPublic(addr: string): boolean {
    if (addr === '*' || addr === '0.0.0.0' || addr === '::') return true;
    if (/^127\./.test(addr) || addr === '::1' || addr === 'localhost') return false;
    // tailscale CGNAT range 100.64/10 and fd7a:115c:a1e0::/48 are private to the tailnet
    if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(addr) || /^fd7a:115c:a1e0:/i.test(addr)) return false;
    return true;
}
