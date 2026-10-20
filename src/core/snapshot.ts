import { publicAllows } from './audit.js';
import { HostFacts } from './probe.js';

/**
 * The part of a host's state that is configuration, not weather: what should only change
 * when somebody (or something) changes the host. Load, free memory, conntrack counts and
 * fail2ban bans are left out so a diff shows changes, not noise.
 */
export function snapshotState(f: HostFacts): Record<string, unknown> {
    const rules = f.ufw?.rules ?? [];
    // single-IP DENY/REJECT rules are fail2ban / manual bans: counted, not diffed
    const bans = rules.filter((r) => /DENY|REJECT/.test(r.action) && r.from !== 'Anywhere');
    const cfgRules = rules.filter((r) => !bans.includes(r));
    return {
        system: {
            hostname: f.hostname,
            os: f.os,
            kernel: f.kernel,
            arch: f.arch,
            timezone: f.time?.timezone,
            cpus: f.cpus,
            memTotalMiB: f.mem ? Math.round(f.mem.totalMiB / 64) * 64 : undefined,
            swapMiB: f.mem?.swapTotalMiB,
            disks: f.disks.map((d) => `${d.mount} ${d.fs} ${d.sizeGiB}GiB`),
        },
        packages: f.packages,
        snaps: f.snaps,
        units: {
            enabled: f.enabledUnits,
            state: Object.fromEntries(Object.entries(f.units).map(([u, s]) => [u, `${s.active}/${s.enabled}`])),
        },
        docker: f.docker
            ? {
                  version: f.docker.version,
                  compose: f.docker.compose,
                  containers: Object.fromEntries(f.docker.containers.map((c) => [c.name, `${c.image} ${c.state}${c.imageId ? ` ${c.imageId.slice(7, 19)}` : ''}`])),
                  images: f.dockerImages,
              }
            : undefined,
        firewall: {
            ufw: f.ufw ? { active: f.ufw.active, defaults: `${f.ufw.defaultIn}/${f.ufw.defaultOut}/${f.ufw.defaultRouted}`, rules: cfgRules.map((r) => `${r.to} ${r.action} ${r.from}${r.v6 ? ' v6' : ''}`) } : undefined,
            public: publicAllows(cfgRules).map((r) => `${r.port}${r.v6 ? ' v6' : ''}`),
            nftChains: f.nftChains,
            ipsets: Object.keys(f.ipsets).sort(),
            blacklist: f.blacklist.cron ? 'cron' : 'no-cron',
            mgmtPorts: f.mgmt.rules !== undefined ? { chain: true, jump: !!f.mgmt.jumps, list: f.mgmt.list } : 'no chain',
            ...(f.legacyRugov ? { legacyRugov: true } : {}),
        },
        listen: f.listen.map((s) => `${s.proto} ${s.addr}:${s.port}${s.process ? ` ${s.process}` : ''}`).sort(),
        ssh: f.sshd,
        access: {
            users: f.users,
            sudo: f.sudoGroup,
            authorizedKeys: f.authorizedKeys?.map((k) => `${k.home} ${k.type} ${k.fp} ${k.comment}`.trim()),
            crontabs: f.crontabs,
        },
        sysctl: Object.fromEntries(Object.entries(f.sysctl).filter(([k]) => k !== 'net.netfilter.nf_conntrack_count')),
        dns: f.resolv,
        tailscale: f.tailscale ? { dnsName: f.tailscale.dnsName, ips: f.tailscale.ips, version: f.tailscale.version } : undefined,
        remnanode: f.remnanode,
        certs: Object.fromEntries(f.certs.map((c) => [c.name, { notAfter: c.notAfter ? new Date(c.notAfter * 1000).toISOString().slice(0, 10) : undefined, sans: c.sans }])),
        tuning: { backups: f.tuningBackups },
        autoUpdates: { ...f.aptAuto, ...(f.unattended ? { installed: String(f.unattended.installed), origins: f.unattended.origins.join(' | ') } : {}) },
        files: f.files ? Object.fromEntries(Object.entries(f.files).map(([p, v]) => [p, v.content ?? `sha:${v.sha}`])) : undefined,
        counters: { ufwBans: bans.length },
    };
}

export interface Change {
    path: string;
    kind: 'added' | 'removed' | 'changed';
    before?: unknown;
    after?: unknown;
    /** For text (file) changes: lines gone / new. */
    linesRemoved?: string[];
    linesAdded?: string[];
}

const IGNORE = new Set(['counters']);

/** Structural diff: objects by key, arrays of scalars as sets, multi-line strings by line. */
export function diffState(a: unknown, b: unknown, path = ''): Change[] {
    if (IGNORE.has(path)) return [];
    if (a === undefined && b === undefined) return [];
    if (a === undefined) return [{ path, kind: 'added', after: summarize(b) }];
    if (b === undefined) return [{ path, kind: 'removed', before: summarize(a) }];
    if (Array.isArray(a) && Array.isArray(b)) {
        const sa = new Set(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))));
        const sb = new Set(b.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))));
        const out: Change[] = [];
        for (const x of sb) if (!sa.has(x)) out.push({ path, kind: 'added', after: x });
        for (const x of sa) if (!sb.has(x)) out.push({ path, kind: 'removed', before: x });
        return out;
    }
    if (isObj(a) && isObj(b)) {
        const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
        return keys.flatMap((k) => diffState(a[k], b[k], path ? `${path}.${k}` : k));
    }
    if (typeof a === 'string' && typeof b === 'string' && (a.includes('\n') || b.includes('\n'))) {
        if (a === b) return [];
        const la = a.split('\n');
        const lb = b.split('\n');
        const sa = new Set(la);
        const sb = new Set(lb);
        return [
            {
                path,
                kind: 'changed',
                linesRemoved: la.filter((l) => !sb.has(l)).slice(0, 40),
                linesAdded: lb.filter((l) => !sa.has(l)).slice(0, 40),
            },
        ];
    }
    if (JSON.stringify(a) === JSON.stringify(b)) return [];
    return [{ path, kind: 'changed', before: summarize(a), after: summarize(b) }];
}

function isObj(v: unknown): v is Record<string, unknown> {
    return !!v && typeof v === 'object' && !Array.isArray(v);
}

function summarize(v: unknown): unknown {
    if (typeof v === 'string' && v.length > 400) return v.slice(0, 400) + `… (${v.length} chars)`;
    if (Array.isArray(v) && v.length > 30) return [...v.slice(0, 30), `… ${v.length - 30} more`];
    if (isObj(v) && Object.keys(v).length > 30) return `{${Object.keys(v).length} keys}`;
    return v;
}

/** Group changes by top-level section; collapse package churn into one readable entry. */
export function groupChanges(changes: Change[], limit = 200): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    const bySection = new Map<string, Change[]>();
    for (const c of changes) {
        const sec = c.path.split('.')[0] || '(root)';
        if (!bySection.has(sec)) bySection.set(sec, []);
        bySection.get(sec)!.push(c);
    }
    for (const [sec, list] of bySection) {
        if (sec === 'packages') {
            const upgraded = list.filter((c) => c.kind === 'changed').map((c) => `${c.path.slice(9)} ${c.before} → ${c.after}`);
            const added = list.filter((c) => c.kind === 'added').map((c) => `${c.path.slice(9)} ${c.after}`);
            const removed = list.filter((c) => c.kind === 'removed').map((c) => `${c.path.slice(9)} ${c.before}`);
            out.packages = {
                upgraded: upgraded.length,
                installed: added.length,
                removed: removed.length,
                ...(added.length ? { installedList: added.slice(0, 50) } : {}),
                ...(removed.length ? { removedList: removed.slice(0, 50) } : {}),
                ...(upgraded.length ? { upgradedList: upgraded.slice(0, 50) } : {}),
            };
            continue;
        }
        out[sec] = list.slice(0, limit).map((c) => {
            const { path, ...rest } = c;
            return { path: path.slice(sec.length + 1) || sec, ...rest };
        });
    }
    return out;
}
