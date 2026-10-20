import fs from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/**
 * The fleet as the owner describes it: hosts, how to reach them, what runs there.
 * Lives in fleet.yaml outside the repo (it names real hosts); see fleet.example.yaml.
 */

export const ROLES = ['edge', 'remnanode', 'panel', 'docker'] as const;
export type Role = (typeof ROLES)[number];

const serviceSchema = z
    .object({
        name: z.string().regex(/^[\w.-]+$/, 'service name: letters, digits, . _ -'),
        /** docker compose file; the project is managed with `docker compose -f <file>`. */
        compose: z.string().optional(),
        /** compose service or plain container name (defaults to the service name for compose). */
        container: z.string().optional(),
        /** systemd unit. */
        unit: z.string().optional(),
        /** Log files (glob allowed) for host_logs. */
        logs: z.string().optional(),
        /** Files whose content is tracked by snapshots (secrets masked). */
        files: z.array(z.string()).optional(),
        /** running (default): alert when not up. present: only alert when missing (oneshot jobs, certbot). */
        expect: z.enum(['running', 'present']).optional(),
    })
    .refine((s) => s.compose || s.container || s.unit, { message: 'a service needs compose, container or unit' });

export type Service = z.infer<typeof serviceSchema>;

/** An application with an HTTP API mia talks to (through curl on the host). */
const appSchema = z.object({
    /** Base URL as seen FROM the host (default http://127.0.0.1:<default port>). */
    url: z.string().url().optional(),
    /** API key, or env:NAME to read it from the environment of the machine running mia. */
    apiKey: z.string().optional(),
    /** Docker container the app runs in: host paths are translated through its mounts, and it becomes a service. */
    container: z.string().optional(),
});

export type AppSpec = z.infer<typeof appSchema>;

export const policySchema = z
    .object({
        /** Ports that may be open to the internet (UFW allow from Anywhere, not on tailscale0). */
        publicPorts: z.array(z.string()),
        certWarnDays: z.number(),
        certCritDays: z.number(),
        diskWarnPct: z.number(),
        diskCritPct: z.number(),
        memWarnPct: z.number(),
        conntrackWarnPct: z.number(),
        geoMaxAgeHours: z.number(),
        /** CPU / board / drive sensors above this are reported. */
        tempWarnC: z.number(),
        /** Management ports: never public, only via tailnet / MGMT-PORTS (22 ssh, 2222 node API, 9100 node_exporter, 45876 beszel, 5201 iperf3, 2112/2113 xray probes). */
        mgmtPorts: z.array(z.number().int()),
        /** true (fleet policy 2026-09-28): security updates install automatically (unattended-upgrades). */
        securityUpdates: z.boolean(),
        /** false (fleet policy): no automatic reboots, the owner reboots by hand. */
        autoReboot: z.boolean(),
        /** fail2ban jails that must exist. */
        jails: z.array(z.string()),
        /** Checks switched off for this host / globally (by code, see audit.ts). */
        skip: z.array(z.string()),
    })
    .partial();

export type Policy = z.infer<typeof policySchema>;

const hostSchema = z.object({
    /** ssh target: MagicDNS name, Tailscale IP, public IP or an alias from ~/.ssh/config. Defaults to the host key. */
    address: z.string().optional(),
    user: z.string().optional(),
    port: z.number().int().optional(),
    /** Run remote commands through `sudo -n` (default true unless user is root). */
    sudo: z.boolean().optional(),
    /** `local` runs commands on this machine (the one the MCP runs on) without ssh. */
    transport: z.enum(['ssh', 'local']).optional(),
    roles: z.array(z.enum(ROLES)).optional(),
    tags: z.array(z.string()).optional(),
    /** Remnanode TLS domain (certbot). */
    domain: z.string().optional(),
    /** Node name in the Remnawave panel; default: matched by address / domain / name. */
    panelNode: z.string().optional(),
    /** Name for people: the node's animal, e.g. "🐧 penguin" (shown next to the key, accepted as a target). */
    title: z.string().optional(),
    provider: z.string().optional(),
    notes: z.string().optional(),
    services: z.array(serviceSchema).optional(),
    /** Applications with an API: Jellyfin, Tdarr. */
    apps: z.object({ jellyfin: appSchema.optional(), tdarr: appSchema.optional() }).optional(),
    policy: policySchema.optional(),
    /** How to reach a fresh server before Tailscale is up (node_bootstrap). */
    bootstrap: z
        .object({
            address: z.string(),
            user: z.string().default('root'),
            port: z.number().int().default(22),
            /** Private key for this first login (e.g. ~/.ssh/hz_provision, the fleet-provision key put on the VPS at purchase). */
            identityFile: z.string().optional(),
        })
        .optional(),
    /** Excluded from `all` and role/tag selectors (e.g. a host being rebuilt); still reachable by name. */
    disabled: z.boolean().optional(),
});

const inventorySchema = z.object({
    defaults: hostSchema.pick({ user: true, port: true, sudo: true, roles: true, tags: true }).partial().optional(),
    policy: policySchema.optional(),
    groups: z.record(z.array(z.string())).optional(),
    hosts: z.record(hostSchema),
});

export type HostSpec = z.infer<typeof hostSchema>;

export interface Host {
    name: string;
    address: string;
    user?: string;
    port?: number;
    sudo: boolean;
    transport: 'ssh' | 'local';
    roles: Role[];
    tags: string[];
    groups: string[];
    domain?: string;
    panelNode?: string;
    title?: string;
    provider?: string;
    notes?: string;
    services: Service[];
    apps: { jellyfin?: AppSpec; tdarr?: AppSpec };
    /** Named log files: role defaults (auth, syslog, apt …) and `<service>.log` for services with log files. */
    logs: Record<string, string>;
    policy: Required<Policy>;
    bootstrap?: { address: string; user: string; port: number; identityFile?: string };
    disabled: boolean;
}

export const DEFAULT_POLICY: Required<Policy> = {
    // vps-edge-run.sh opens each public port for tcp and udp
    publicPorts: ['80/tcp', '80/udp', '443/tcp', '443/udp'],
    certWarnDays: 21,
    certCritDays: 7,
    diskWarnPct: 99, // "the disk is out of space" = 99%
    diskCritPct: 99,
    memWarnPct: 90,
    conntrackWarnPct: 80,
    geoMaxAgeHours: 72,
    tempWarnC: 85,
    mgmtPorts: [22, 2222, 9100, 45876, 5201, 2112, 2113],
    securityUpdates: true,
    autoReboot: false,
    jails: ['sshd', 'sshd-fast', 'recidive'],
    skip: [],
};

/** Services every host of a role has, laid down by vps-edge-run.sh (remnanode) or the panel docs. */
export const ROLE_SERVICES: Record<Role, Service[]> = {
    edge: [
        { name: 'tailscaled', unit: 'tailscaled' },
        { name: 'fail2ban', unit: 'fail2ban', logs: '/var/log/fail2ban.log' },
        { name: 'node_exporter', unit: 'node_exporter' },
        { name: 'beszel-agent', unit: 'beszel-agent' },
        { name: 'ufw', unit: 'ufw' },
        { name: 'ipset-load', unit: 'ipset-load', expect: 'present' },
    ],
    remnanode: [
        {
            name: 'remnanode',
            compose: '/opt/remnanode/docker-compose.yml',
            container: 'remnanode',
            logs: '/var/log/remnanode/*.log',
            files: ['/opt/remnanode/docker-compose.yml'],
        },
        { name: 'certbot', compose: '/opt/certbot/docker-compose.yml', files: ['/opt/certbot/docker-compose.yml'], expect: 'present' },
        { name: 'geo-updater', unit: 'update-roscomvpn-geo.service', expect: 'present' },
        { name: 'docker', unit: 'docker' },
    ],
    panel: [
        {
            name: 'remnawave',
            compose: '/opt/remnawave/docker-compose.yml',
            container: 'remnawave',
            files: ['/opt/remnawave/docker-compose.yml'],
        },
        { name: 'docker', unit: 'docker' },
    ],
    docker: [{ name: 'docker', unit: 'docker' }],
};

/** Named log files per role, for host_logs (besides services' own logs). */
export const ROLE_LOGS: Record<Role, Record<string, string>> = {
    edge: {
        auth: '/var/log/auth.log',
        syslog: '/var/log/syslog',
        apt: '/var/log/apt/history.log',
    },
    remnanode: {
        'install-apt': '/var/log/initial-apt.log',
        'install-docker': '/var/log/install-docker.log',
        'install-tailscale': '/var/log/install-tailscale.log',
    },
    panel: {},
    docker: {},
};

export class Inventory {
    readonly hosts: Map<string, Host>;
    readonly groups: Map<string, string[]>;
    /** defaults.user: how to ssh into a machine that is not in the inventory (tailnet devices). */
    readonly defaultUser?: string;

    constructor(
        readonly file: string,
        raw: unknown,
    ) {
        const parsed = inventorySchema.safeParse(raw ?? { hosts: {} });
        if (!parsed.success) {
            const issues = parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`);
            throw new Error(`${file} is not a valid inventory:\n  - ${issues.join('\n  - ')}`);
        }
        const inv = parsed.data;
        const d = inv.defaults ?? {};
        this.defaultUser = d.user;
        const globalPolicy = { ...DEFAULT_POLICY, ...(inv.policy ?? {}) };

        this.groups = new Map(Object.entries(inv.groups ?? {}));
        this.hosts = new Map();

        for (const [name, h] of Object.entries(inv.hosts)) {
            if (!/^[\w.-]+$/.test(name)) throw new Error(`${file}: host name "${name}" — use letters, digits, . _ -`);
            const roles = new Set<Role>([...(d.roles ?? []), ...(h.roles ?? [])]);
            // a remnanode is always built by vps-edge-run.sh, so it carries the edge baseline too
            if (roles.has('remnanode')) roles.add('edge');
            if (roles.has('panel')) roles.add('docker');
            const user = h.user ?? d.user;
            const apps = h.apps ?? {};
            const appServices: Service[] = Object.entries(apps)
                .filter(([, a]) => a?.container)
                .map(([name, a]) => ({ name, container: a!.container! }));
            const services = mergeServices([...[...roles].flatMap((r) => ROLE_SERVICES[r]), ...appServices, ...(h.services ?? [])]);
            const policy = { ...globalPolicy, ...(h.policy ?? {}) };
            policy.skip = [...new Set([...(globalPolicy.skip ?? []), ...(h.policy?.skip ?? [])])];
            this.hosts.set(name, {
                name,
                address: h.address ?? name,
                user,
                port: h.port ?? d.port,
                sudo: h.sudo ?? d.sudo ?? (h.transport === 'local' ? false : user !== 'root'),
                transport: h.transport ?? 'ssh',
                roles: [...roles].sort(),
                tags: [...new Set([...(d.tags ?? []), ...(h.tags ?? [])])],
                groups: [],
                domain: h.domain,
                panelNode: h.panelNode,
                title: h.title,
                provider: h.provider,
                notes: h.notes,
                services,
                apps,
                logs: Object.assign(
                    {},
                    ...[...roles].map((r) => ROLE_LOGS[r]),
                    Object.fromEntries(services.filter((x) => x.logs).map((x) => [`${x.name}.log`, x.logs!])),
                ),
                policy,
                bootstrap: h.bootstrap,
                disabled: h.disabled ?? false,
            });
        }

        for (const [g, members] of this.groups) {
            if (this.hosts.has(g)) throw new Error(`${file}: group "${g}" has the same name as a host`);
            for (const m of members) {
                const host = this.hosts.get(m);
                if (!host) throw new Error(`${file}: group "${g}" lists unknown host "${m}"`);
                host.groups.push(g);
            }
        }
    }

    static load(file: string): Inventory {
        if (!fs.existsSync(file)) return new Inventory(file, { hosts: {} });
        const text = fs.readFileSync(file, 'utf8');
        let raw: unknown;
        try {
            raw = parseYaml(text);
        } catch (e) {
            throw new Error(`${file}: YAML error: ${e instanceof Error ? e.message : String(e)}`);
        }
        return new Inventory(file, raw);
    }

    get(name: string): Host {
        const h = this.hosts.get(name);
        if (!h) throw new Error(`unknown host "${name}"${suggest(name, [...this.hosts.keys()])}`);
        return h;
    }

    /**
     * Resolve a target expression to hosts, in inventory order.
     *   all | *            every enabled host
     *   nl-1               a host (disabled hosts only this way)
     *   nl-*               glob over host names
     *   eu | @eu           a group
     *   role:remnanode     by role;  tag:prod  by tag
     *   a,b,!c             union, then minus the ! parts
     */
    resolve(expr: string | string[]): Host[] {
        const parts = (Array.isArray(expr) ? expr : [expr])
            .flatMap((e) => e.split(','))
            .map((p) => p.trim())
            .filter(Boolean);
        if (!parts.length) throw new Error('empty target: give a host, group, role:<role>, tag:<tag> or all');

        const include = new Set<string>();
        const exclude = new Set<string>();
        for (const p of parts) {
            const neg = p.startsWith('!');
            const sel = neg ? p.slice(1) : p;
            const names = this.select(sel);
            for (const n of names) (neg ? exclude : include).add(n);
        }
        const hosts = [...this.hosts.values()].filter((h) => include.has(h.name) && !exclude.has(h.name));
        if (!hosts.length) throw new Error(`target "${parts.join(',')}" matches no host`);
        return hosts;
    }

    private select(sel: string): string[] {
        const enabled = [...this.hosts.values()].filter((h) => !h.disabled);
        if (sel === 'all' || sel === '*') return enabled.map((h) => h.name);
        if (sel.startsWith('role:')) {
            const r = sel.slice(5);
            if (!(ROLES as readonly string[]).includes(r)) throw new Error(`unknown role "${r}"; roles: ${ROLES.join(', ')}`);
            return enabled.filter((h) => h.roles.includes(r as Role)).map((h) => h.name);
        }
        if (sel.startsWith('tag:')) {
            const t = sel.slice(4);
            const found = enabled.filter((h) => h.tags.includes(t)).map((h) => h.name);
            if (!found.length) throw new Error(`no enabled host has tag "${t}"`);
            return found;
        }
        const g = sel.startsWith('@') ? sel.slice(1) : sel;
        if (this.groups.has(g)) return this.groups.get(g)!;
        if (this.hosts.has(sel)) return [sel];
        const byTitle = [...this.hosts.values()].filter((h) => titleWord(h.title) === sel.toLowerCase());
        if (byTitle.length === 1) return [byTitle[0].name];
        if (/[*?]/.test(sel)) {
            const re = new RegExp('^' + sel.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
            const found = enabled.filter((h) => re.test(h.name)).map((h) => h.name);
            if (!found.length) throw new Error(`"${sel}" matches no enabled host`);
            return found;
        }
        throw new Error(`unknown target "${sel}"${suggest(sel, [...this.hosts.keys(), ...this.groups.keys()])}`);
    }

    /** Find a service of a host by name (role services included). */
    service(host: Host, name: string): Service {
        const s = host.services.find((x) => x.name === name);
        if (!s) throw new Error(`host ${host.name} has no service "${name}"; it has: ${host.services.map((x) => x.name).join(', ') || 'none'}`);
        return s;
    }
}

/** A host that is not in the inventory (a fresh server being bootstrapped). */
export function adhocHost(name: string, address: string, user = 'root'): Host {
    return {
        name,
        address,
        user,
        sudo: user !== 'root',
        transport: 'ssh',
        roles: [],
        tags: [],
        groups: [],
        services: [],
        apps: {},
        logs: {},
        policy: { ...DEFAULT_POLICY },
        disabled: false,
    };
}

/** Later definitions of a service name override earlier ones (host services override role defaults). */
function mergeServices(list: Service[]): Service[] {
    const map = new Map<string, Service>();
    for (const s of list) map.set(s.name, { ...(map.get(s.name) ?? {}), ...s });
    return [...map.values()];
}

function suggest(name: string, known: string[]): string {
    const close = known.filter((k) => k.includes(name) || name.includes(k) || levenshtein(k, name) <= 2).slice(0, 5);
    return close.length ? `; did you mean ${close.join(', ')}?` : known.length ? `; known: ${known.slice(0, 15).join(', ')}` : '; the inventory is empty';
}

function levenshtein(a: string, b: string): number {
    const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++)
        for (let j = 1; j <= b.length; j++)
            dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return dp[a.length][b.length];
}

/** The word of a title without its emoji: "🐧 penguin" → "penguin". */
export function titleWord(title?: string): string | undefined {
    const w = title?.replace(/[^\p{L}\p{N}._-]+/gu, ' ').trim().toLowerCase();
    return w || undefined;
}
