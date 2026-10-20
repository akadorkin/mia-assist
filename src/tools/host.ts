import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { expandPort, publicAllows } from '../core/audit.js';
import { Ctx } from '../core/ctx.js';
import { Host } from '../core/inventory.js';
import { redactText } from '../core/output.js';
import { matchNode, nodeState } from '../core/panel.js';
import { HostFacts, isWildcardOrPublic } from '../core/probe.js';
import { audit } from '../core/audit.js';
import { pool } from '../core/ssh.js';
import { FETCH_CHECKED, run, urlSha256 } from './helpers.js';
import { targetParam } from './fleet.js';

const hostParam = z.string().describe('host name from the inventory (fleet_hosts)');

/** Run a read-only script, fail loudly on ssh / sudo problems. */
async function sh(ctx: Ctx, host: Host, script: string, env?: Record<string, string>, timeoutMs?: number): Promise<string> {
    const res = await ctx.transport.exec(host, script, { env, timeoutMs });
    if (res.unreachable || res.timedOut || (!res.ok && !res.stdout.trim())) throw new Error(`${host.name}: ${res.error ?? 'failed'}${res.stderr.trim() ? `\n${res.stderr.trim().slice(-500)}` : ''}`);
    return res.stdout;
}

const SECTIONS = ['system', 'updates', 'units', 'network', 'firewall', 'tailscale', 'docker', 'remnanode', 'services', 'tuning'] as const;

function sectionView(f: HostFacts, sec: (typeof SECTIONS)[number]): unknown {
    switch (sec) {
        case 'system':
            return { hostname: f.hostname, os: f.os, kernel: f.kernel, arch: f.arch, uptimeS: f.uptimeS, load: f.load, cpus: f.cpus, mem: f.mem, disks: f.disks, temps: f.temps, time: f.time, rebootRequired: f.rebootRequired, rebootPkgs: f.rebootPkgs };
        case 'updates':
            return f.apt ? { count: f.apt.upgradable.length, security: f.apt.upgradable.filter((u) => u.security).map((u) => u.name), list: f.apt.upgradable.map((u) => `${u.name} ${u.from ?? '?'} → ${u.version}`) } : undefined;
        case 'units':
            return { units: Object.fromEntries(Object.entries(f.units).map(([k, v]) => [k, `${v.active}/${v.enabled}`])), failed: f.failedUnits };
        case 'network':
            return { listen: f.listen.map((s) => `${s.proto} ${s.addr}:${s.port}${s.process ? ` ${s.process}` : ''}`), dns: f.resolv, sshd: f.sshd };
        case 'firewall':
            return { ufw: f.ufw, fail2ban: f.fail2ban, ipsets: f.ipsets, blacklist: f.blacklist, mgmtPorts: f.mgmt, legacyRugov: f.legacyRugov || undefined, autoUpdates: f.aptAuto };
        case 'tailscale':
            return f.tailscale;
        case 'docker':
            return f.docker;
        case 'remnanode':
            return { compose: f.remnanode, certs: f.certs, geoFiles: f.geoFiles, geoService: f.geoService, logs: f.remnanodeLogs };
        case 'services':
            return f.services;
        case 'tuning':
            return { sysctl: f.sysctl, backups: f.tuningBackups };
    }
}

export function registerHostTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'host_inspect',
        'Everything about one host in one call: system, pending updates, systemd units, listening sockets, firewall, Tailscale, docker, remnanode (compose, certificate, geo files), inventory services, tuning — plus audit findings and the matching panel node.',
        {
            host: hostParam,
            sections: z.array(z.enum(SECTIONS)).optional().describe(`subset of: ${SECTIONS.join(', ')} (default all)`),
        },
        ({ host, sections }) =>
            run(async () => {
                const h = ctx.inventory().get(host);
                const [f, nodes] = await Promise.all([ctx.facts(h, 'quick', { fresh: true }), ctx.panelNodes(true)]);
                if (!f.reachable) throw new Error(`${host} unreachable: ${f.error}`);
                const node = nodes ? (matchNode(h, nodes) ?? null) : undefined;
                const findings = audit(h, f, node);
                const secs = sections?.length ? sections : SECTIONS;
                return {
                    host: h.name,
                    address: h.address,
                    roles: h.roles,
                    probeMs: f.ms,
                    findings: findings.map((x) => `${x.sev.toUpperCase()} ${x.code}: ${x.msg}`),
                    panelNode: node ? { name: node.name, address: node.address, state: nodeState(node), usersOnline: node.usersOnline, xray: node.versions?.xray, node: node.versions?.node } : node === null ? 'no matching node' : undefined,
                    ...Object.fromEntries(secs.map((s) => [s, sectionView(f, s)])),
                };
            }),
    );

    server.tool(
        'host_logs',
        'Tail logs on a host. source: a service name (container stdout / systemd journal of the unit — e.g. remnanode, fail2ban, tailscaled), a log file name (remnanode.log = xray logs in /var/log/remnanode, auth, syslog, apt, install-*), or explicit unit:<unit>, container:<name>, file:<path or glob>, journal (whole journal).',
        {
            host: hostParam,
            source: z.string().describe('service name, log name, unit:<u>, container:<c>, file:<path>, journal'),
            lines: z.number().int().min(1).max(5000).default(200),
            grep: z.string().optional().describe('extended regex, case-insensitive; applied before taking the last N lines'),
            since: z.string().regex(/^\d+[smhd]$/, 'like 30m, 2h, 1d').optional().describe('only newer entries (journal/containers): 30m, 2h, 1d'),
        },
        ({ host, source, lines, grep, since }) =>
            run(async () => {
                const h = ctx.inventory().get(host);
                let kind: string;
                let src: string;
                let composeSvc = '';
                const [prefix, ...rest] = source.split(':');
                const arg = rest.join(':');
                if (source === 'journal') [kind, src] = ['journal', ''];
                else if (prefix === 'unit' && arg) [kind, src] = ['unit', arg];
                else if (prefix === 'container' && arg) [kind, src] = ['container', arg];
                else if (prefix === 'file' && arg) [kind, src] = ['file', arg];
                else if (h.logs[source]) [kind, src] = ['file', h.logs[source]];
                else {
                    const svc = h.services.find((s) => s.name === source);
                    if (!svc) {
                        throw new Error(
                            `unknown source "${source}" on ${host}. services: ${h.services.map((s) => s.name).join(', ')}; logs: ${Object.keys(h.logs).join(', ')}; or unit:/container:/file:/journal`,
                        );
                    }
                    if (svc.compose) {
                        kind = 'compose';
                        src = svc.compose;
                        composeSvc = svc.container ?? '';
                    } else if (svc.container) [kind, src] = ['container', svc.container];
                    else [kind, src] = ['unit', svc.unit!];
                }
                const sinceArg = since ? since : '';
                const out = await sh(
                    ctx,
                    h,
                    `
fetch=$LINES; [ -n "$GREP" ] && fetch=$(( LINES * 20 < 50000 ? LINES * 20 : 50000 ))
jsince=""; [ -n "$SINCE" ] && jsince="-$SINCE"
{
case "$KIND" in
  compose)   docker compose -f "$SRC" logs --no-color --tail "$fetch" \${SINCE:+--since "$SINCE"} $CSVC 2>&1 ;;
  container) docker logs --tail "$fetch" \${SINCE:+--since "$SINCE"} "$SRC" 2>&1 ;;
  unit)      journalctl -u "$SRC" -n "$fetch" --no-pager -o short-iso \${jsince:+--since "$jsince"} 2>&1 ;;
  journal)   journalctl -n "$fetch" --no-pager -o short-iso \${jsince:+--since "$jsince"} 2>&1 ;;
  file)      found=0; for f in $SRC; do [ -f "$f" ] || continue; found=1; echo "==> $f"; tail -n "$fetch" "$f"; done; [ $found = 1 ] || echo "(no file matches $SRC)" ;;
esac
} | { if [ -n "$GREP" ]; then grep -Ei -- "$GREP" | tail -n "$LINES"; else tail -n "$LINES"; fi; }
`,
                    { KIND: kind, SRC: src, CSVC: composeSvc, LINES: String(lines), GREP: grep ?? '', SINCE: sinceArg },
                );
                const text = redactText(out.replace(/\x1b\[[0-9;]*m/g, ''));
                return { host, source: `${kind} ${src}${composeSvc ? ` (${composeSvc})` : ''}`, lines: text.split('\n').length - 1, log: text };
            }),
    );

    server.tool(
        'host_ports',
        'What is reachable on a host and from where: every listening socket classified as local / tailnet-only / public-allowed / blocked by ufw / PUBLIC because ufw is off, with the process name. Plus the public UFW allows.',
        { host: hostParam },
        ({ host }) =>
            run(async () => {
                const h = ctx.inventory().get(host);
                // a check (runbooks poll it): always what is there now
                const f = await ctx.facts(h, 'quick', { fresh: true });
                if (!f.reachable) throw new Error(`${host} unreachable: ${f.error}`);
                const pub = f.ufw ? publicAllows(f.ufw.rules).flatMap((r) => expandPort(r.port)) : [];
                const tsAll = f.ufw?.rules.some((r) => r.iface === 'tailscale0' && /ALLOW IN/.test(r.action));
                const covers = (port: number, proto: string) => {
                    const pr = proto.startsWith('udp') ? 'udp' : 'tcp';
                    return pub.some((s) => {
                        if (s === 'any') return true;
                        const [p, sp] = s.split('/');
                        if (sp !== pr) return false;
                        if (p.includes(':')) {
                            const [a, b] = p.split(':').map(Number);
                            return port >= a && port <= b;
                        }
                        return Number(p) === port;
                    });
                };
                const sockets = f.listen.map((s) => {
                    let exposure: string;
                    if (!isWildcardOrPublic(s.addr)) exposure = /^127\.|^::1$/.test(s.addr) ? 'local' : 'tailnet';
                    else if (!f.ufw || !f.ufw.active) exposure = 'PUBLIC (ufw off)';
                    else if (covers(s.port, s.proto)) exposure = 'public (allowed)';
                    else if (tsAll) exposure = 'tailnet only (ufw)';
                    else exposure = 'blocked by ufw';
                    return { socket: `${s.proto} ${s.addr}:${s.port}`, process: s.process, exposure };
                });
                const order = ['PUBLIC (ufw off)', 'public (allowed)', 'tailnet only (ufw)', 'blocked by ufw', 'tailnet', 'local'];
                sockets.sort((a, b) => order.indexOf(a.exposure) - order.indexOf(b.exposure));
                return {
                    host,
                    ufw: f.ufw ? `${f.ufw.active ? 'active' : 'INACTIVE'} in:${f.ufw.defaultIn} out:${f.ufw.defaultOut}` : 'not installed',
                    publicAllows: [...new Set(pub)],
                    policyPublicPorts: h.policy.publicPorts,
                    sockets,
                };
            }),
    );

    server.tool(
        'host_firewall',
        'Firewall detail of a host: `ufw status numbered`, fail2ban jails with the banned IP lists, ipset blacklists (ufw-blacklist.sh) with entry counts, and the MGMT-PORTS iptables chain.',
        { host: hostParam },
        ({ host }) =>
            run(async () => {
                const h = ctx.inventory().get(host);
                const out = await sh(
                    ctx,
                    h,
                    `
echo "## ufw"; ufw status numbered 2>&1 | head -n 300
echo "## fail2ban"
for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do
  st="$(fail2ban-client status "$j" 2>/dev/null)"
  echo "$j current=$(printf '%s\\n' "$st" | sed -n 's/.*Currently banned:[[:space:]]*//p') total=$(printf '%s\\n' "$st" | sed -n 's/.*Total banned:[[:space:]]*//p')"
  echo "  banned: $(printf '%s\\n' "$st" | sed -n 's/.*Banned IP list:[[:space:]]*//p' | cut -c1-2000)"
done
echo "## blacklists"
ipset list -t 2>/dev/null | awk '/^Name:/{n=$2} /^Number of entries:/{print n, $4, "entries"}'
grep -Ev '^\\s*(#|$)' /etc/cron.d/ufw-blacklist 2>/dev/null | head -n 3
echo "## mgmt"
iptables -S MGMT-PORTS 2>&1 | head -n 40
iptables -S INPUT 2>/dev/null | grep -- '-j MGMT-PORTS'
echo "list: $(grep -Ev '^\\s*(#|$)' /etc/mgmt-ports.list 2>/dev/null | tr '\\n' ' ')"
`,
                );
                const parts: Record<string, string> = {};
                let cur = 'head';
                for (const l of out.split('\n')) {
                    const m = l.match(/^## (\w+)/);
                    if (m) cur = m[1];
                    else parts[cur] = (parts[cur] ? parts[cur] + '\n' : '') + l;
                }
                return { host, ufw: parts.ufw?.trim(), fail2ban: parts.fail2ban?.trim(), blacklists: parts.blacklists?.trim(), mgmtPorts: parts.mgmt?.trim() };
            }),
    );

    server.tool(
        'host_docker',
        'Docker on a host: containers (state, image, restarts), compose projects, disk usage of images/volumes/build cache.',
        { host: hostParam },
        ({ host }) =>
            run(async () => {
                const h = ctx.inventory().get(host);
                const out = await sh(
                    ctx,
                    h,
                    `
echo "## ps"; docker ps -a --format '{{.Names}}\\t{{.Image}}\\t{{.State}}\\t{{.Status}}\\t{{.Ports}}' 2>&1
echo "## compose"; docker compose ls -a 2>&1
echo "## df"; docker system df 2>&1
echo "## images"; docker images --format '{{.Repository}}:{{.Tag}}\\t{{.ID}}\\t{{.CreatedSince}}\\t{{.Size}}' 2>&1 | head -n 60
`,
                );
                const parts: Record<string, string[]> = {};
                let cur = 'head';
                for (const l of out.split('\n')) {
                    const m = l.match(/^## (\w+)/);
                    if (m) cur = m[1];
                    else if (l.trim()) (parts[cur] ??= []).push(l);
                }
                return { host, containers: parts.ps, compose: parts.compose, diskUsage: parts.df, images: parts.images };
            }),
    );

    server.tool(
        'host_file_read',
        'Read a file on a host (as root when sudo is configured) or list a directory. Secrets (SECRET_KEY, private keys, tokens, passwords) are masked.',
        {
            host: hostParam,
            path: z.string().regex(/^\/[^\0]*$/, 'absolute path').describe('absolute path'),
            maxBytes: z.number().int().min(1).max(1_000_000).default(65536),
        },
        ({ host, path, maxBytes }) =>
            run(async () => {
                const h = ctx.inventory().get(host);
                const out = await sh(
                    ctx,
                    h,
                    `
if [ -d "$P" ]; then echo "dir"; ls -la --time-style=long-iso "$P" 2>&1 | head -n 500
elif [ -f "$P" ]; then echo "file $(stat -c '%s %U:%G %a %y' "$P")"; head -c "$MAX" "$P"
else echo "missing"; fi
`,
                    { P: path, MAX: String(maxBytes) },
                );
                const nl = out.indexOf('\n');
                const head = nl < 0 ? out : out.slice(0, nl);
                const body = nl < 0 ? '' : out.slice(nl + 1);
                if (head === 'missing') throw new Error(`${path} does not exist on ${host}`);
                return { host, path, kind: head.split(' ')[0], meta: head.split(' ').slice(1).join(' ') || undefined, content: redactText(body) };
            }),
    );

    server.tool(
        'host_connections',
        'Established TCP connections per host on a local port (default 443), total and by remote address family — to watch traffic move from an old ingress to a new one, or drain before removing a node.',
        { target: targetParam, port: z.number().int().min(1).max(65535).default(443) },
        ({ target, port }) =>
            run(async () => {
                const hosts = ctx.inventory().resolve(target);
                const script = `ss -Htn state established "( sport = :$PORT )" | awk '{print $4}' | awk -F: 'BEGIN{t=0;ts=0} {t++; if ($0 ~ /^100\\./) ts++} END{print t, ts}'`;
                const res = await pool(hosts, ctx.config.concurrency, (h) => ctx.transport.exec(h, script, { env: { PORT: String(port) }, timeoutMs: 30_000 }));
                return {
                    port,
                    hosts: Object.fromEntries(
                        res.map((r) => {
                            if (!r.ok) return [r.host, { error: r.error }];
                            const [total, tailnet] = r.stdout.trim().split(/\s+/).map(Number);
                            return [r.host, { established: total, fromTailnet: tailnet, fromInternet: total - tailnet }];
                        }),
                    ),
                };
            }),
    );

    server.tool(
        'host_net_check',
        'Network checks run FROM hosts (in parallel): tcp connect, tls (TLS1.3 + h2 — what a REALITY dest needs), http timings, dns, ping, trace. Use to pick/verify a REALITY dest, check a node reaches the panel, or see if a destination is filtered from a location.',
        {
            target: targetParam,
            check: z.enum(['tcp', 'tls', 'http', 'dns', 'ping', 'trace']),
            to: z
                .string()
                .regex(/^[\w.:/?&=%-]+$/, 'host, host:port or URL')
                .describe('host / host:port (tcp, tls; default port 443) / URL (http) / name (dns)'),
            sni: z.string().regex(/^[\w.-]+$/).optional().describe('tls: server name to send (default: the host part of `to`), e.g. check a node by IP with its domain or a decoy SNI'),
        },
        ({ target, check, to, sni }) =>
            run(async () => {
                const hosts = ctx.inventory().resolve(target);
                let hostPart = to.replace(/^\w+:\/\//, '').split('/')[0];
                let port = '443';
                const m = hostPart.match(/^(.*):(\d+)$/);
                if (m) [hostPart, port] = [m[1], m[2]];
                const script = `
case "$CHECK" in
  tcp)   if timeout 6 bash -c "</dev/tcp/$H/$PORT" 2>/dev/null; then echo "open $H:$PORT"; else echo "CLOSED/filtered $H:$PORT"; fi ;;
  tls)   echo | timeout 10 openssl s_client -connect "$H:$PORT" -servername "$SNI" -alpn h2 2>&1 | grep -E '^(New|Protocol|    Protocol|    Cipher|ALPN|Verify return code)|subject=|verify error' | sort -u | head -n 12 ;;
  http)  curl -sS -o /dev/null -m 15 -w 'code=%{http_code} ip=%{remote_ip} dns=%{time_namelookup}s connect=%{time_connect}s tls=%{time_appconnect}s ttfb=%{time_starttransfer}s total=%{time_total}s\\n' "$URL" 2>&1 ;;
  dns)   (getent ahosts "$H" | awk '{print $1}' | sort -u) 2>&1; command -v dig >/dev/null && echo "via 1.1.1.1: $(dig +short @1.1.1.1 "$H" | tr '\\n' ' ')" ;;
  ping)  ping -c 4 -W 2 "$H" 2>&1 | tail -n 3 ;;
  trace) if command -v mtr >/dev/null; then mtr -rwn -c 3 "$H" 2>&1; else tracepath -n "$H" 2>&1 | head -n 30; fi ;;
esac
`;
                const url = /^\w+:\/\//.test(to) ? to : `https://${to}`;
                const res = await pool(hosts, ctx.config.concurrency, (h) =>
                    ctx.transport.exec(h, script, { env: { CHECK: check, H: hostPart, PORT: port, URL: url, SNI: sni ?? hostPart }, timeoutMs: 60_000, noSudo: true }),
                );
                return {
                    check,
                    to,
                    results: Object.fromEntries(res.map((r) => [r.host, r.unreachable ? `unreachable: ${r.error}` : r.stdout.trim() || r.error || '(no output)'])),
                };
            }),
    );

    server.tool(
        'host_services_discover',
        'What runs on a host that the inventory does not know yet: docker compose projects (with their files), standalone containers, non-stock systemd services, and known apps with an API (Jellyfin, Tdarr) — returned as ready `services:` / `apps:` YAML for fleet.yaml. Read-only; use it to describe a home server once.',
        { host: hostParam },
        ({ host }) =>
            run(async () => {
                const h = ctx.inventory().get(host);
                const out = await sh(
                    ctx,
                    h,
                    `
echo "## containers"
command -v docker >/dev/null && docker ps -a --no-trunc --format '{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.project.config_files"}}\t{{.Label "com.docker.compose.service"}}\t{{.Ports}}' 2>/dev/null
echo "## units"
systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}'
echo "## listen"
ss -H -lntp 2>/dev/null | awk '{print $4, $6}' | head -n 200
`,
                );
                const parts: Record<string, string[]> = {};
                let cur = '';
                for (const l of out.split('\n')) {
                    const m = l.match(/^## (\w+)/);
                    if (m) cur = m[1];
                    else if (l.trim()) (parts[cur] ??= []).push(l);
                }
                const known = new Set(h.services.flatMap((x) => [x.name, x.container, x.unit, x.compose].filter(Boolean) as string[]));
                const projects = new Map<string, { file: string; services: string[]; states: string[] }>();
                const standalone: Array<{ name: string; image: string; state: string }> = [];
                const apps: string[] = [];
                for (const l of parts.containers ?? []) {
                    const [name, image, state, project, files, service, ports] = l.split('\t');
                    if (project) {
                        const p = projects.get(project) ?? { file: (files ?? '').split(',')[0], services: [], states: [] };
                        p.services.push(service || name);
                        p.states.push(`${service || name}:${state}`);
                        projects.set(project, p);
                    } else standalone.push({ name, image, state });
                    const hostPort = (want: string) => (ports ?? '').match(new RegExp(`(?:0\\.0\\.0\\.0|\\[::\\]|\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)->${want}/tcp`))?.[1];
                    if (/jellyfin/i.test(image) && !h.apps.jellyfin) apps.push(`    jellyfin:`, `      url: http://127.0.0.1:${hostPort('8096') ?? '8096'}`, `      apiKey: env:JELLYFIN_API_KEY   # Dashboard → API Keys`, `      container: ${name}`);
                    if (/tdarr/i.test(image) && !/node/i.test(image) && !h.apps.tdarr) apps.push(`    tdarr:`, `      url: http://127.0.0.1:${hostPort('8265') ?? '8265'}`, `      # apiKey: env:TDARR_API_KEY    # only if Tdarr auth is on`, `      container: ${name}`);
                }
                const STOCK = /^(ssh|sshd|cron|dbus|systemd-|getty|serial-getty|polkit|rsyslog|snapd|networkd-dispatcher|unattended-upgrades|multipathd|udisks2|ModemManager|irqbalance|accounts-daemon|user@|containerd|docker|chrony|ntp|avahi-daemon|wpa_supplicant|NetworkManager|packagekit|fwupd|thermald|upower|rtkit|atd|cups|bluetooth|triggerhappy|dphys-swapfile|hciuart|rng-tools|lvm2|mdmonitor|smartmontools|qemu-guest-agent|open-vm-tools|cloud-|lxcfs|apparmor|blk-availability|console-setup|keyboard-setup|plymouth|setvtrgb|kmod|finalrd|e2scrub|fstrim|motd|apport|tailscaled|fail2ban|node_exporter|ufw)/;
                const units = (parts.units ?? []).map((u) => u.replace(/\.service$/, '')).filter((u) => !STOCK.test(u) && !known.has(u));
                const yaml: string[] = [];
                for (const [project, p] of projects) {
                    if (known.has(project) || known.has(p.file)) continue;
                    yaml.push(`      - name: ${project}`, `        compose: ${p.file || `/path/to/${project}/docker-compose.yml  # compose file not recorded in labels`}`);
                }
                for (const c of standalone) if (!known.has(c.name)) yaml.push(`      - name: ${c.name}`, `        container: ${c.name}`);
                for (const u of units) yaml.push(`      - name: ${u}`, `        unit: ${u}`);
                return {
                    host,
                    composeProjects: Object.fromEntries([...projects].map(([k, v]) => [k, { file: v.file, services: v.states.join(' ') }])),
                    containers: standalone.map((c) => `${c.name} (${c.image}) ${c.state}`),
                    customUnits: units,
                    listening: parts.listen,
                    ...(yaml.length || apps.length
                        ? {
                              addToFleetYaml: [`hosts:`, `  ${host}:`, ...(yaml.length ? ['    services:', ...yaml] : []), ...(apps.length ? ['    apps:', ...apps] : [])].join('\n'),
                          }
                        : { note: 'everything running here is already in the inventory' }),
                };
            }),
    );

    server.tool(
        'tuning_status',
        'Kernel/network tuning state from the owner\'s vps-network-tuning-script (`initial.sh status`): profile, BBR/fq, conntrack, NOFILE, swap, journald — plus available rollback backups.',
        { target: targetParam },
        ({ target }) =>
            run(async () => {
                const hosts = ctx.inventory().resolve(target);
                const sha = await urlSha256(ctx.config.tuningScriptUrl);
                const res = await pool(hosts, ctx.config.concurrency, (h) =>
                    ctx.transport.exec(h, `${FETCH_CHECKED} && bash /tmp/mia-tuning.sh status 2>&1 | sed 's/\\x1b\\[[0-9;]*m//g'; echo "backups: $(ls -1d /root/edge-tuning-backup-* 2>/dev/null | tr '\\n' ' ')"`, {
                        env: { URL: ctx.config.tuningScriptUrl, SHA: sha },
                        timeoutMs: 60_000,
                    }),
                );
                return Object.fromEntries(res.map((r) => [r.host, r.ok ? r.stdout.trim() : `${r.error}\n${r.stdout.trim().slice(-800)}`]));
            }),
    );
}
