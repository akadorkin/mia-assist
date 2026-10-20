import { tsCreateAuthKey } from '../core/tailscale.js';
import dns from 'node:dns/promises';
import crypto from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { Host, Service, adhocHost } from '../core/inventory.js';
import { matchNode, nodeState } from '../core/panel.js';
import { HostFacts } from '../core/probe.js';
import { HostStep, applyParams, rolloutParams, runSteps, waitFor } from '../core/plan.js';
import { pool, q } from '../core/ssh.js';
import { FETCH_CHECKED, run, urlSha256, writeTools } from './helpers.js';
import { targetParam } from './fleet.js';

type Facts = Map<string, HostFacts>;

async function factsOf(ctx: Ctx, hosts: Host[]): Promise<Facts> {
    const list = await pool(hosts, ctx.config.concurrency, (h) => ctx.facts(h));
    return new Map(list.map((f) => [f.host, f]));
}

/** Users online per host from the panel (for warnings before disruptive actions). */
async function usersOnline(ctx: Ctx, hosts: Host[]): Promise<Map<string, { node: string; users: number; state: string }>> {
    const nodes = await ctx.panelNodes(true);
    const out = new Map<string, { node: string; users: number; state: string }>();
    if (!nodes) return out;
    for (const h of hosts) {
        const n = matchNode(h, nodes);
        if (n) out.set(h.name, { node: n.name, users: n.usersOnline ?? 0, state: nodeState(n) });
    }
    return out;
}

function unreachableStep(h: Host, f: HostFacts | undefined): HostStep | undefined {
    if (f && f.reachable) return undefined;
    return { host: h, action: '-', script: '', blockers: [`unreachable: ${f?.error ?? 'not probed'}`] };
}

// ---------------------------------------------------------------- service helpers

function serviceScript(svc: Service, action: 'restart' | 'start' | 'stop' | 'update' | 'recreate'): { script: string; action: string } {
    if (svc.compose) {
        const f = q(svc.compose);
        const map = {
            restart: `docker compose -f ${f} restart`,
            start: `docker compose -f ${f} up -d`,
            stop: `docker compose -f ${f} stop`,
            update: `docker compose -f ${f} pull && docker compose -f ${f} up -d`,
            recreate: `docker compose -f ${f} up -d --force-recreate`,
        };
        return { script: `set -e\n${map[action]} 2>&1`, action: `${map[action]}` };
    }
    if (svc.unit) {
        if (action === 'update' || action === 'recreate') throw new Error(`${action} is for compose services; ${svc.name} is a systemd unit`);
        return { script: `systemctl ${action} ${q(svc.unit)} 2>&1`, action: `systemctl ${action} ${svc.unit}` };
    }
    if (action === 'update' || action === 'recreate') throw new Error(`${action} needs a compose file; ${svc.name} is a bare container`);
    return { script: `docker ${action} ${q(svc.container!)} 2>&1`, action: `docker ${action} ${svc.container}` };
}

const SERVICE_STATE_SCRIPT = `
if [ -n "$COMPOSE" ]; then docker compose -f "$COMPOSE" ps -a --format '{{.Service}}:{{.State}}' 2>/dev/null | tr '\\n' ' '; fi
if [ -n "$CONTAINER" ] && [ -z "$COMPOSE" ]; then docker inspect --format '{{.State.Status}}' "$CONTAINER" 2>/dev/null; fi
if [ -n "$UNIT" ]; then systemctl is-active "$UNIT" 2>/dev/null; fi
`;

/** true when the service is up (compose: every service running; unit: active; container: running). */
async function serviceUp(ctx: Ctx, host: Host, svc: Service): Promise<string | true> {
    const r = await ctx.transport.exec(host, SERVICE_STATE_SCRIPT, { env: { COMPOSE: svc.compose ?? '', CONTAINER: svc.container ?? '', UNIT: svc.unit ?? '' }, timeoutMs: 30_000 });
    const s = r.stdout.trim();
    if (!r.ok && !s) return r.error ?? 'state unknown';
    if (svc.compose) {
        const parts = s.split(/\s+/).filter(Boolean);
        if (!parts.length) return 'compose project not up';
        const down = parts.filter((p) => !p.endsWith(':running'));
        return down.length ? down.join(' ') : true;
    }
    if (svc.unit) return s === 'active' ? true : s;
    return s === 'running' ? true : s || 'absent';
}

/**
 * Up and still up a bit later: a container that crash-loops shows "running" for a few
 * seconds after every start, so one positive check proves nothing.
 */
/** A wait in real life, shorter on the demo fleet. */
const later = (ctx: Ctx, ms: number) => ms * ctx.config.timeScale;

async function serviceStable(ctx: Ctx, host: Host, svc: Service, timeoutMs = 90_000, settleMs = 15_000): Promise<string | true> {
    const up = await waitFor(() => serviceUp(ctx, host, svc), later(ctx, timeoutMs), later(ctx, 5000));
    if (up !== true) return up;
    await new Promise((r) => setTimeout(r, later(ctx, settleMs)));
    const again = await serviceUp(ctx, host, svc);
    return again === true ? true : `came up but went down again: ${again}`;
}

/** Digest of a Docker Hub tag (the manifest list digest, as in RepoDigests). */
async function hubDigest(ref: string): Promise<string | undefined> {
    const m = ref.match(/^(?:docker\.io\/)?([\w.-]+)\/([\w.-]+)(?::([\w.-]+))?$/);
    if (!m) return undefined;
    const [, ns, repo, tag = 'latest'] = m;
    try {
        const res = await fetch(`https://hub.docker.com/v2/repositories/${ns}/${repo}/tags/${tag}`, { signal: AbortSignal.timeout(10_000) });
        if (!res.ok) return undefined;
        const j = (await res.json()) as { digest?: string };
        return j.digest;
    } catch {
        return undefined;
    }
}

const REMNANODE: Service = { name: 'remnanode', compose: '/opt/remnanode/docker-compose.yml', container: 'remnanode' };

// ---------------------------------------------------------------- tools

export function registerActionTools(server: McpServer, ctx: Ctx) {
    if (ctx.config.readonly) return;

    writeTools(() => {
        server.tool(
            'service_action',
            'restart / start / stop / update (compose pull + up -d) / recreate a service on hosts — a compose project, systemd unit or container from the inventory (remnanode, certbot, remnawave, tailscaled, fail2ban, node_exporter, docker … or your own). Rolling by default (batch 1 for disruptive actions), verified: the service must be up again.',
            {
                target: targetParam,
                service: z.string().describe('service name (fleet_hosts details:true lists them)'),
                action: z.enum(['restart', 'start', 'stop', 'update', 'recreate']),
                ...rolloutParams,
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'service_action', args, { ...args, defaultBatch: args.action === 'start' ? 10 : 1 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const users = await usersOnline(ctx, hosts);
                        return hosts.map((h) => {
                            const svc = h.services.find((s) => s.name === args.service);
                            if (!svc) return { host: h, action: '-', script: '', noop: `no service ${args.service} here` };
                            const { script, action } = serviceScript(svc, args.action);
                            const u = users.get(h.name);
                            const disruptive = args.action !== 'start' && ['remnanode', 'docker', 'tailscaled'].includes(svc.name);
                            return {
                                host: h,
                                action,
                                script,
                                timeoutMs: args.action === 'update' ? 600_000 : 180_000,
                                warnings: disruptive && u?.users ? [`${u.users} user(s) online on ${u.node} will reconnect`] : undefined,
                                verify: args.action === 'stop' || svc.expect === 'present' ? undefined : () => serviceStable(ctx, h, svc),
                            };
                        });
                    }),
                ),
        );

        server.tool(
            'remnanode_update',
            'Update remnanode (remnawave/node image) on nodes: compares the running image with Docker Hub, then per node `docker compose pull && up -d`, waits for the container and (if the panel is configured) for the panel to see the node connected before moving on. Rolling, batch 1 by default; stops at the first node that does not come back.',
            {
                target: targetParam.default('role:remnanode'),
                force: z.boolean().default(false).describe('recreate even when the running image is already the latest'),
                prune: z.boolean().default(true).describe('remove dangling images afterwards'),
                ...rolloutParams,
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'remnanode_update', args, { ...args, defaultBatch: 1 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target).filter((h) => h.roles.includes('remnanode'));
                        if (!hosts.length) throw new Error('no remnanode hosts in the target');
                        const [facts, users] = await Promise.all([factsOf(ctx, hosts), usersOnline(ctx, hosts)]);
                        const digestCache = new Map<string, Promise<string | undefined>>();
                        return Promise.all(
                            hosts.map(async (h): Promise<HostStep> => {
                                const f = facts.get(h.name);
                                const bad = unreachableStep(h, f);
                                if (bad) return bad;
                                const c = f!.docker?.containers.find((x) => x.name === 'remnanode');
                                const ref = f!.remnanode?.image || c?.image || 'remnawave/node:latest';
                                if (!digestCache.has(ref)) digestCache.set(ref, hubDigest(ref));
                                const latest = await digestCache.get(ref)!;
                                const img = f!.docker?.images.find((i) => i.ref === c?.image);
                                const running = img?.digests.map((d) => d.split('@')[1]).filter(Boolean) ?? [];
                                const upToDate = !!latest && running.includes(latest) && img?.id === c?.imageId;
                                const u = users.get(h.name);
                                const step: HostStep = {
                                    host: h,
                                    action: `docker compose pull && up -d remnanode (${ref})${args.prune ? ' + image prune' : ''}`,
                                    script: `set -e\ncd /opt/remnanode\ndocker compose pull 2>&1\ndocker compose up -d 2>&1\n${args.prune ? 'docker image prune -f 2>&1 | tail -n 1\n' : ''}docker inspect --format 'running {{.Config.Image}} {{.Image}}' remnanode`,
                                    timeoutMs: 600_000,
                                    preview: {
                                        container: c ? `${c.state} ${c.status}` : 'absent',
                                        running: running[0]?.slice(0, 19) ?? c?.imageId?.slice(0, 19),
                                        hub: latest?.slice(0, 19) ?? 'unknown (Docker Hub not reachable from here)',
                                        panel: u ? `${u.node} ${u.state}, ${u.users} online` : undefined,
                                    },
                                    fingerprint: [c?.imageId, latest],
                                    warnings: [...(u?.users ? [`${u.users} user(s) on ${u.node} will reconnect`] : []), ...(!f!.remnanode ? ['no /opt/remnanode/docker-compose.yml'] : [])],
                                    blockers: !f!.remnanode ? ['remnanode compose missing: bootstrap the node first (node_bootstrap)'] : undefined,
                                    verify: async () => {
                                        const up = await serviceStable(ctx, h, REMNANODE);
                                        if (up !== true) return `remnanode: ${up}`;
                                        if (!ctx.panel || !u) return true;
                                        return waitFor(
                                            async () => {
                                                const nodes = await ctx.panelNodes(true);
                                                const n = nodes && matchNode(h, nodes);
                                                return !n ? 'node not found in panel' : n.isConnected ? true : `panel: ${nodeState(n)}${n.lastStatusMessage ? ` ${n.lastStatusMessage}` : ''}`;
                                            },
                                            later(ctx, 120_000),
                                            later(ctx, 10_000),
                                        );
                                    },
                                };
                                if (upToDate && !args.force) step.noop = `already on the latest image (${latest!.slice(0, 19)})`;
                                return step;
                            }),
                        );
                    }),
                ),
        );

        server.tool(
            'cert_renew',
            'Renew the remnanode TLS certificate with the docker certbot from vps-edge-run.sh (`cd /opt/certbot && docker compose run --rm certbot renew`). Skips certificates with more than `minDays` left unless force. Port 80 must be publicly open (it is in the baseline). Optionally restarts remnanode so xray loads the new certificate.',
            {
                target: targetParam.default('role:remnanode'),
                minDays: z.number().int().default(30).describe('renew only when fewer days left (certbot itself renews at <30)'),
                force: z.boolean().default(false).describe('--force-renewal regardless of days left'),
                restartNode: z.boolean().default(false).describe('restart remnanode after a renewal (users reconnect)'),
                ...rolloutParams,
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'cert_renew', args, { ...args, defaultBatch: args.restartNode ? 1 : 10 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const facts = await factsOf(ctx, hosts);
                        return hosts.map((h): HostStep => {
                            const f = facts.get(h.name);
                            const bad = unreachableStep(h, f);
                            if (bad) return bad;
                            const cert = f!.certs.find((c) => c.name === 'remnanode') ?? f!.certs[0];
                            const days = cert?.daysLeft;
                            const step: HostStep = {
                                host: h,
                                action: `certbot renew${args.force ? ' --force-renewal' : ''}${args.restartNode ? ' + restart remnanode' : ''}`,
                                script: `set -eo pipefail\ncd /opt/certbot\ndocker compose run --rm certbot renew${args.force ? ' --force-renewal' : ''} 2>&1 | tail -n 20\n${args.restartNode ? 'docker compose -f /opt/remnanode/docker-compose.yml restart 2>&1\n' : ''}openssl x509 -in /opt/certbot/certs/live/${cert?.name ?? 'remnanode'}/fullchain.pem -noout -enddate`,
                                timeoutMs: 300_000,
                                preview: { cert: cert ? `${cert.name} ${days}d left (${cert.sans.join(', ')})` : 'none' },
                                fingerprint: cert?.notAfter,
                                blockers: !cert ? ['no certificate under /opt/certbot/certs/live'] : undefined,
                            };
                            if (cert && !args.force && days !== undefined && days >= args.minDays) step.noop = `${days} days left (≥ ${args.minDays})`;
                            return step;
                        });
                    }),
                ),
        );

        server.tool(
            'geo_update',
            'Run the roscomvpn geoip/geosite updater now (update-roscomvpn-geo.service from vps-edge-run.sh) and check it succeeded.',
            { target: targetParam.default('role:remnanode'), ...rolloutParams, ...applyParams },
            (args) =>
                run(() =>
                    runSteps(ctx, 'geo_update', args, { ...args, defaultBatch: 10 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        return hosts.map((h) => ({
                            host: h,
                            action: 'systemctl start update-roscomvpn-geo.service',
                            script: `systemctl start update-roscomvpn-geo.service 2>&1; r=$?\nsystemctl show update-roscomvpn-geo.service -p Result --value\nstat -c '%n %y' /opt/remnanode/roscomvpn-*.dat 2>&1\nexit $r`,
                            timeoutMs: 300_000,
                        }));
                    }),
                ),
        );

        server.tool(
            'blacklist_update',
            'Refresh the ipset blacklists now with the fleet script /usr/local/bin/ufw-blacklist.sh (normally run by /etc/cron.d/ufw-blacklist every 2 h) and show the entry counts of the sets afterwards.',
            { target: targetParam.default('role:edge'), ...rolloutParams, ...applyParams },
            (args) =>
                run(() =>
                    runSteps(ctx, 'blacklist_update', args, { ...args, defaultBatch: 10 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const facts = await factsOf(ctx, hosts);
                        return hosts.map((h): HostStep => {
                            const f = facts.get(h.name);
                            const bad = unreachableStep(h, f);
                            if (bad) return bad;
                            return {
                                host: h,
                                action: '/usr/local/bin/ufw-blacklist.sh',
                                script: `set -eo pipefail\n/usr/local/bin/ufw-blacklist.sh 2>&1 | tail -n 5\nipset list -t | awk '/^Name:/{n=$2} /^Number of entries:/{print n, $4}'`,
                                preview: { ipsets: f!.ipsets, cron: f!.blacklist.cron ?? 'missing' },
                                blockers: f!.blacklist.scriptMtime === undefined ? ['no /usr/local/bin/ufw-blacklist.sh on this host'] : undefined,
                                timeoutMs: 300_000,
                            };
                        });
                    }),
                ),
        );

        server.tool(
            'updates_policy',
            'Bring hosts to the fleet update policy: security updates install automatically (unattended-upgrades, stock security-only origins), NO automatic reboots — reboots stay manual (host_reboot). Writes /etc/apt/apt.conf.d/20auto-upgrades and 99zz-mia-policy, enables apt-daily timers. apt-based hosts only.',
            { target: targetParam, ...rolloutParams, ...applyParams },
            (args) =>
                run(() =>
                    runSteps(ctx, 'updates_policy', args, { ...args, defaultBatch: 10 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const facts = await factsOf(ctx, hosts);
                        return hosts.map((h): HostStep => {
                            const f = facts.get(h.name);
                            const bad = unreachableStep(h, f);
                            if (bad) return bad;
                            const uu = f!.unattended;
                            const periodic = f!.aptAuto['APT::Periodic::Unattended-Upgrade'];
                            const reboot = f!.aptAuto['Unattended-Upgrade::Automatic-Reboot'];
                            const timer = f!.units['apt-daily-upgrade.timer'];
                            const ok = uu?.installed && periodic && periodic !== '0' && reboot !== 'true' && (!timer || timer.enabled === 'enabled' || timer.enabled === 'static');
                            const step: HostStep = {
                                host: h,
                                action: 'unattended security updates on, automatic reboot off',
                                script: [
                                    'set -e',
                                    'export DEBIAN_FRONTEND=noninteractive',
                                    "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed' || apt-get install -y -q unattended-upgrades 2>&1 | tail -n 2",
                                    "printf '%s\\n' 'APT::Periodic::Update-Package-Lists \"1\";' 'APT::Periodic::Unattended-Upgrade \"1\";' > /etc/apt/apt.conf.d/20auto-upgrades",
                                    // 99zz loads after the fleet's 99-fleet-no-auto-upgrades (2026-09-26, Unattended-Upgrade "0"):
                                    // the decisive values live here, not in 20auto-upgrades that it would override
                                    "printf '%s\\n' '// mia: fleet policy - security updates automatically, reboots only by hand' 'APT::Periodic::Update-Package-Lists \"1\";' 'APT::Periodic::Unattended-Upgrade \"1\";' 'Unattended-Upgrade::Automatic-Reboot \"false\";' > /etc/apt/apt.conf.d/99zz-mia-policy",
                                    'systemctl unmask apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true',
                                    'systemctl enable --now apt-daily.timer apt-daily-upgrade.timer 2>&1',
                                    'systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true',
                                    "apt-config dump | grep -E '^(APT::Periodic::Unattended-Upgrade|Unattended-Upgrade::Automatic-Reboot) '",
                                ].join('\n'),
                                preview: {
                                    installed: uu?.installed,
                                    unattended: periodic ?? 'unset',
                                    autoReboot: reboot ?? 'unset',
                                    timer: timer ? `${timer.active}/${timer.enabled}` : 'absent',
                                    origins: uu?.origins,
                                },
                                fingerprint: [uu?.installed, periodic, reboot, timer?.enabled],
                                blockers: !uu ? ['not an apt-based system (e.g. openSUSE nas): configure its own updater by hand'] : undefined,
                                warnings: uu?.origins.some((o) => /-(updates|proposed|backports)\b/.test(o)) ? ['unattended-upgrades is configured to install more than security updates (Allowed-Origins): left as is'] : undefined,
                                timeoutMs: 300_000,
                                verify: async (res) => (/Unattended-Upgrade "1"/.test(res.stdout) && /Automatic-Reboot "false"/.test(res.stdout) ? true : `unexpected apt-config after apply: ${res.stdout.trim().split('\n').slice(-2).join(' | ')}`),
                            };
                            if (ok) step.noop = 'already on the policy';
                            return step;
                        });
                    }),
                ),
        );

        server.tool(
            'fail2ban_unban',
            'Unban an IP in fail2ban (all jails, or one) on hosts — e.g. after locking yourself out or a false positive.',
            {
                target: targetParam,
                ip: z.string().regex(/^[\d.]+$|^[0-9a-fA-F:]+$/, 'IPv4 or IPv6'),
                jail: z.string().regex(/^[\w-]+$/).optional(),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'fail2ban_unban', args, { ...args, defaultBatch: 20 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        return hosts.map((h) => ({
                            host: h,
                            action: args.jail ? `fail2ban-client set ${args.jail} unbanip ${args.ip}` : `fail2ban-client unban ${args.ip}`,
                            script: args.jail ? `fail2ban-client set ${q(args.jail)} unbanip ${q(args.ip)} 2>&1` : `fail2ban-client unban ${q(args.ip)} 2>&1`,
                        }));
                    }),
                ),
        );

        server.tool(
            'ufw_rule',
            'Add or delete a UFW rule on hosts, e.g. open a new public port for an inbound (allow 8443/tcp on the internet interface) or close one. Public exposure of 22/2222/5443/5444/9100 is blocked unless allowDangerous. The rule list before the change is shown in the dry run.',
            {
                target: targetParam,
                op: z.enum(['allow', 'deny', 'delete-allow', 'delete-deny']),
                port: z.string().regex(/^\d{1,5}(:\d{1,5})?$/, 'port or range a:b'),
                proto: z.enum(['tcp', 'udp', 'both']).default('tcp'),
                iface: z.string().regex(/^[\w.-]+$/).optional().describe('interface, e.g. eth0 (public) or tailscale0; default: any'),
                from: z.string().regex(/^[\d./a-fA-F:]+$/).optional().describe('source IP/CIDR; default Anywhere'),
                allowDangerous: z.boolean().default(false),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'ufw_rule', args, { ...args, defaultBatch: 1 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const facts = await factsOf(ctx, hosts);
                        const verb = args.op.startsWith('delete') ? `delete ${args.op.split('-')[1]}` : args.op;
                        const protos = args.proto === 'both' ? ['tcp', 'udp'] : [args.proto];
                        const cmds = protos.map(
                            (p) => `ufw ${verb} ${args.iface ? `in on ${args.iface} ` : ''}${args.from ? `from ${args.from} ` : ''}to any port ${args.port} proto ${p}`,
                        );
                        const opensPublic = args.op === 'allow' && !args.from && args.iface !== 'tailscale0';
                        const dangerous = opensPublic && ['22', '2222', '5443', '5444', '9100'].includes(args.port.split(':')[0]);
                        return hosts.map((h): HostStep => {
                            const f = facts.get(h.name);
                            const bad = unreachableStep(h, f);
                            if (bad) return bad;
                            const policyOk = h.policy.publicPorts.some((p) => protos.every((pr) => p === `${args.port}/${pr}`));
                            return {
                                host: h,
                                action: cmds.join(' && '),
                                script: `set -e\n${cmds.join(' 2>&1\n')} 2>&1\nufw status numbered | head -n 60`,
                                preview: { ufw: f!.ufw?.active ? 'active' : 'INACTIVE', rules: f!.ufw?.rules.map((r) => `${r.to} ${r.action} ${r.from}`) },
                                fingerprint: f!.ufw?.rules.map((r) => `${r.to} ${r.action} ${r.from}`),
                                warnings: opensPublic && !policyOk ? [`${args.port}/${args.proto} is not in policy.publicPorts: fleet_audit will flag it until you add it to fleet.yaml`] : undefined,
                                blockers: dangerous && !args.allowDangerous ? [`opening ${args.port} to the internet breaks the baseline (Tailscale-only); pass allowDangerous:true if you really mean it`] : undefined,
                            };
                        });
                    }),
                ),
        );

        server.tool(
            'apt_upgrade',
            'Install pending apt updates on hosts (noninteractive, keeps existing config files). Shows what will be upgraded; warns when docker/containerd are in the list (remnanode restarts). Optional reboot afterwards when the kernel asks for it. Rolling, batch 1 by default.',
            {
                target: targetParam,
                securityOnly: z.boolean().default(false).describe('only packages from *-security'),
                distUpgrade: z.boolean().default(false).describe('apt-get dist-upgrade (may add/remove packages, e.g. new kernels)'),
                rebootIfRequired: z.boolean().default(false).describe('reboot afterwards when /var/run/reboot-required appears (waits for the host to return)'),
                includeKernel: z.boolean().default(false).describe('also kernel and GPU-driver packages (linux-image/modules/headers, nvidia) — they only take effect after a reboot'),
                skipDocker: z.boolean().default(false).describe('hold docker-ce/containerd back: their upgrade restarts every container (remnanode — clients reconnect); do them off-peak'),
                ...rolloutParams,
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'apt_upgrade', args, { ...args, defaultBatch: 1 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const [facts, users] = await Promise.all([factsOf(ctx, hosts), usersOnline(ctx, hosts)]);
                        return hosts.map((h): HostStep => {
                            const f = facts.get(h.name);
                            const bad = unreachableStep(h, f);
                            if (bad) return bad;
                            // Kernel / GPU driver: the new version only works after a reboot, and until then it breaks things —
                            // home 2026-10-01: one "security" metapackage linux-modules-nvidia-580-generic-hwe pulled the whole
                            // nvidia 580.178 userspace + a new kernel; the loaded 580.173 module no longer matched, GPU containers
                            // would not start. Reboots are manual in this fleet, so these go only with includeKernel.
                            const KERNEL = /^(linux-(image|modules|headers|generic|hwe|main-modules|objects|signatures|tools)|nvidia-|libnvidia-|xserver-xorg-video-nvidia)/;
                            const all = (f!.apt?.upgradable ?? []).filter((u) => !args.securityOnly || u.security);
                            const DOCKER = /^(docker-ce|docker-ce-cli|containerd\.io|docker-compose-plugin|docker-buildx-plugin|docker-ce-rootless-extras)$/;
                            const held = all.filter((u) => (!args.includeKernel && KERNEL.test(u.name)) || (args.skipDocker && DOCKER.test(u.name)));
                            const list = all.filter((u) => !held.includes(u));
                            const names = list.map((u) => u.name);
                            const touchesDocker = names.some((n) => /^(docker-ce|docker-ce-cli|containerd\.io|docker-compose-plugin)$/.test(n));
                            const u = users.get(h.name);
                            const opts = `-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold`;
                            // Ровно список из плана: обычный upgrade после свежего apt-get update ставил и то, что появилось
                            // позже (в т.ч. ядра/nvidia, которых нет в held), — план врал (AUD-05, 2026-10-20).
                            // shortcut: dist-upgrade по-прежнему берёт всё свежее, держит только held из плана; звать только руками.
                            const cmd = !args.distUpgrade
                                ? `apt-get ${opts} install --only-upgrade ${names.map(q).join(' ')}`
                                : held.length
                                  ? `apt-mark hold ${held.map((u) => q(u.name)).join(' ')} >/dev/null && { apt-get ${opts} ${args.distUpgrade ? 'dist-upgrade' : 'upgrade'}; rc=$?; apt-mark unhold ${held.map((u) => q(u.name)).join(' ')} >/dev/null; exit $rc; }`
                                  : `apt-get ${opts} ${args.distUpgrade ? 'dist-upgrade' : 'upgrade'}`;
                            const step: HostStep = {
                                host: h,
                                action: `apt-get update && ${args.distUpgrade ? 'dist-upgrade' : `upgrade ${names.length}${args.securityOnly ? ' security' : ''} package(s)`}${args.rebootIfRequired ? ' (+ reboot if required)' : ''}`,
                                script: `set -eo pipefail\nexport DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a\napt-get update -q 2>&1 | tail -n 2\n${cmd} 2>&1 | tail -n 25\n[ -f /var/run/reboot-required ] && echo REBOOT_REQUIRED || true`,
                                timeoutMs: 1_800_000,
                                preview: {
                                    upgradable: list.length,
                                    security: list.filter((x) => x.security).length,
                                    packages: list.slice(0, 60).map((x) => `${x.name} ${x.from ?? ''} → ${x.version}`),
                                    ...(held.length ? { heldBack: held.map((x) => x.name) } : {}),
                                },
                                fingerprint: names.sort(),
                                warnings: [
                                    ...(touchesDocker ? [`docker packages are upgraded: all containers restart${u?.users ? ` (${u.users} user(s) on ${u.node})` : ''}`] : []),
                                    ...(args.rebootIfRequired && u?.users ? [`may reboot with ${u.users} user(s) online`] : []),
                                ],
                                verify: async (res) => {
                                    if (!args.rebootIfRequired || !res.stdout.includes('REBOOT_REQUIRED')) return true;
                                    return rebootAndWait(ctx, h, 1);
                                },
                            };
                            if (!list.length && !args.distUpgrade) step.noop = held.length ? `only held-back packages pending (${held.map((x) => x.name).join(', ')})` : 'nothing to upgrade';
                            return step;
                        });
                    }),
                ),
        );

        server.tool(
            'host_reboot',
            'Reboot hosts (shutdown -r +delay) and wait for each to come back over ssh with remnanode running before the next one (rolling, batch 1). The dry run shows users online per node (panel) and whether a reboot is pending anyway.',
            {
                target: targetParam,
                delayMin: z.number().int().min(0).max(60).default(1),
                wait: z.boolean().default(true).describe('wait for the host to return (up to 10 min) before the next batch'),
                ...rolloutParams,
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'host_reboot', args, { ...args, defaultBatch: 1 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const [facts, users] = await Promise.all([factsOf(ctx, hosts), usersOnline(ctx, hosts)]);
                        return hosts.map((h): HostStep => {
                            const f = facts.get(h.name);
                            const bad = unreachableStep(h, f);
                            if (bad) return bad;
                            const u = users.get(h.name);
                            return {
                                host: h,
                                action: `shutdown -r +${args.delayMin}${args.wait ? ' and wait for it' : ''}`,
                                script: `shutdown -r +${args.delayMin} "mia: reboot" 2>&1 || shutdown -r now`,
                                preview: { uptime: f!.uptimeS ? `${Math.round(f!.uptimeS / 3600)}h` : undefined, rebootRequired: f!.rebootRequired, panel: u ? `${u.node} ${u.state}, ${u.users} online` : undefined },
                                warnings: u?.users ? [`${u.users} user(s) on ${u.node} will be disconnected`] : undefined,
                                verify: args.wait ? () => waitBack(ctx, h, args.delayMin) : undefined,
                            };
                        });
                    }),
                ),
        );

        server.tool(
            'host_exec',
            'Run an arbitrary shell command on hosts (bash, through sudo when configured). For anything the dedicated tools do not cover. Output tail per host; the journal keeps the command. Parallel by default (batch 10).',
            {
                target: targetParam,
                command: z.string().min(1),
                timeoutSec: z.number().int().min(1).max(3600).default(120),
                asUser: z.boolean().default(false).describe('run as the ssh user instead of root'),
                ...rolloutParams,
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'host_exec', args, { ...args, defaultBatch: 10 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const destructive = /\b(rm\s+-rf|mkfs|dd\s+if=|shutdown|reboot|poweroff|ufw\s+(disable|reset)|iptables\s+-F|userdel|passwd)\b/.test(args.command);
                        return hosts.map((h) => ({
                            host: h,
                            action: args.command.length > 200 ? args.command.slice(0, 200) + '…' : args.command,
                            script: args.asUser ? `sudo -u ${q(h.user ?? 'root')} bash -c ${q(args.command)} 2>&1` : `${args.command}\n`,
                            timeoutMs: args.timeoutSec * 1000,
                            warnings: destructive ? ['the command looks destructive — double-check the target list'] : undefined,
                        }));
                    }),
                ),
        );

        server.tool(
            'tuning_apply',
            'Apply or roll back the kernel/network tuning of vps-network-tuning-script (initial.sh apply|rollback): BBR+fq, conntrack, NOFILE, swap, journald limits. apply creates a backup in /root/edge-tuning-backup-*; rollback restores the latest (or backupDir).',
            {
                target: targetParam,
                op: z.enum(['apply', 'rollback']),
                backupDir: z.string().regex(/^\/root\/edge-tuning-backup-[\w-]+$/).optional(),
                ...rolloutParams,
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'tuning_apply', args, { ...args, defaultBatch: 1 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const [facts, sha] = await Promise.all([factsOf(ctx, hosts), urlSha256(ctx.config.tuningScriptUrl)]);
                        return hosts.map((h): HostStep => {
                            const f = facts.get(h.name);
                            const bad = unreachableStep(h, f);
                            if (bad) return bad;
                            return {
                                host: h,
                                fingerprint: sha,
                                action: `initial.sh ${args.op}${args.backupDir ? ` (${args.backupDir})` : ''}`,
                                script: `set -eo pipefail\n${FETCH_CHECKED}\n${args.backupDir ? `BACKUP_DIR=${q(args.backupDir)} ` : ''}bash /tmp/mia-tuning.sh ${args.op} 2>&1 | sed 's/\\x1b\\[[0-9;]*m//g' | tail -n 40\nsysctl net.ipv4.tcp_congestion_control net.core.default_qdisc`,
                                env: { URL: ctx.config.tuningScriptUrl, SHA: sha },
                                timeoutMs: 600_000,
                                preview: { script: `${ctx.config.tuningScriptUrl} (sha256 ${sha.slice(0, 12)})`, cc: f!.sysctl['net.ipv4.tcp_congestion_control'], qdisc: f!.sysctl['net.core.default_qdisc'], conntrackMax: f!.sysctl['net.netfilter.nf_conntrack_max'], backups: f!.tuningBackups },
                                blockers: args.op === 'rollback' && !f!.tuningBackups.length ? ['no /root/edge-tuning-backup-* to roll back to'] : undefined,
                            };
                        });
                    }),
                ),
        );

        server.tool(
            'disk_cleanup',
            'Free disk space on hosts: apt cache, journald vacuum to a size, unused docker images and build cache (never volumes), rotated logs. The dry run shows what takes space now.',
            {
                target: targetParam,
                journalSize: z.string().regex(/^\d+[MG]$/).default('300M'),
                dockerImages: z.boolean().default(true).describe('docker image prune -a (images not used by any container)'),
                ...rolloutParams,
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'disk_cleanup', args, { ...args, defaultBatch: 10 }, async () => {
                        const hosts = ctx.inventory().resolve(args.target);
                        const facts = await factsOf(ctx, hosts);
                        return hosts.map((h): HostStep => {
                            const f = facts.get(h.name);
                            const bad = unreachableStep(h, f);
                            if (bad) return bad;
                            return {
                                host: h,
                                action: `apt-get clean; journalctl --vacuum-size=${args.journalSize}; ${args.dockerImages ? 'docker image prune -af; ' : ''}docker builder prune -af; rm rotated *.gz logs`,
                                script: [
                                    'before=$(df -Pk / | awk \'NR==2{print $4}\')',
                                    'apt-get clean 2>&1',
                                    `journalctl --vacuum-size=${args.journalSize} 2>&1 | tail -n 1`,
                                    ...(args.dockerImages ? ['command -v docker >/dev/null && docker image prune -af 2>&1 | tail -n 1'] : []),
                                    'command -v docker >/dev/null && docker builder prune -af 2>&1 | tail -n 1',
                                    "find /var/log -type f -name '*.gz' -mtime +7 -delete 2>/dev/null",
                                    'after=$(df -Pk / | awk \'NR==2{print $4}\')',
                                    'echo "freed $(( (after - before) / 1024 )) MiB on /"',
                                ].join('\n'),
                                timeoutMs: 600_000,
                                preview: { disks: f!.disks.map((d) => `${d.mount} ${d.usedPct}% of ${d.sizeGiB}GiB`) },
                            };
                        });
                    }),
                ),
        );

        server.tool(
            'node_bootstrap',
            'Turn a fresh Ubuntu server into a node with vps-edge-run.sh (github.com/akadorkin/remnanode-install-script): user + sudo, Tailscale (--ssh, exit node), Docker, hardening (ssh, fail2ban, UFW tailscale-only), tuning, node_exporter, geo updater, certbot certificate for the domain, remnanode with the panel\'s SECRET_KEY. That is only the start of the current baseline: afterwards ops-scripts fleet-node-seal.sh (ipset blocklists, MGMT-PORTS, node_exporter, beszel-agent, log-upload) — the node_add runbook (scenario_start) runs the whole sequence; fleet_audit shows what is missing. Runs detached on the server over its public IP (the firewall reset cuts public ssh); poll with job_status. The server reboots 3 min after success. Needs the domain\'s A record pointing at the server.',
            {
                host: z.string().describe('inventory host (with bootstrap.address) or a new name'),
                address: z.string().optional().describe('public IP / ssh target of the fresh server (default: bootstrap.address from the inventory)'),
                sshUser: z.string().default('root').describe('initial ssh user (root on most VPS)'),
                sshPort: z.number().int().default(22),
                remnanode: z.boolean().default(true),
                domain: z.string().optional().describe('remnanode TLS domain (default: inventory domain)'),
                user: z.string().optional().describe('sudo user to create (default: inventory/defaults user)'),
                hostname: z.string().optional(),
                secretKey: z.string().optional().describe('remnanode SECRET_KEY; default: fetched from the panel (/api/keygen)'),
                tailscaleAuthKey: z.string().optional().describe('tskey-auth-… to join the tailnet unattended; else the log shows a login URL to open'),
                ...applyParams,
            },
            (args) =>
                run(async () => {
                    const inv = ctx.inventory();
                    const known = inv.hosts.get(args.host);
                    const address = args.address ?? known?.bootstrap?.address;
                    if (!address) throw new Error(`no address: pass address or set hosts.${args.host}.bootstrap.address in the inventory`);
                    const domain = args.domain ?? known?.domain;
                    const user = args.user ?? known?.user;
                    if (args.remnanode && !domain) throw new Error('remnanode needs a domain (certbot): pass domain or set it in the inventory');
                    const via = { address, user: args.sshUser, port: args.sshPort, ...(known?.bootstrap?.identityFile && address === known.bootstrap.address ? { identityFile: known.bootstrap.identityFile } : {}) };
                    const host: Host = known ?? adhocHost(args.host, args.host, args.sshUser);

                    return runSteps(ctx, 'node_bootstrap', { ...args, secretKey: args.secretKey ? 'given' : 'panel', tailscaleAuthKey: args.tailscaleAuthKey ? 'given' : undefined }, { ...args, defaultBatch: 1 }, async () => {
                        const blockers: string[] = [];
                        const warnings: string[] = [
                            'UFW is reset: public SSH closes, the host stays reachable over Tailscale only',
                            'the server reboots 3 minutes after a successful run',
                        ];
                        let secret = args.secretKey;
                        // a stored TAILSCALE_AUTH_KEY expires quietly: mint a one-time key on apply when the API is there
                        let tsKey = args.tailscaleAuthKey;
                        if (!tsKey && ctx.config.tailscaleApi) {
                            if (args.apply) tsKey = await tsCreateAuthKey(ctx.config.tailscaleApi, `mia bootstrap ${args.hostname ?? args.host}`);
                            else warnings.push('joins the tailnet with a one-time key from the Tailscale API (made on apply)');
                        }
                        if (args.remnanode && !secret) {
                            if (!ctx.panel) blockers.push('no secretKey given and the panel is not configured (REMNAWAVE_BASE_URL/REMNAWAVE_API_TOKEN)');
                            else secret = await ctx.panel.secretKey().catch((e: Error) => (blockers.push(`panel keygen: ${e.message}`), undefined));
                        }
                        let dnsInfo: string | undefined;
                        if (domain) {
                            const a = await dns.resolve4(domain).catch(() => [] as string[]);
                            dnsInfo = a.length ? a.join(',') : 'no A record';
                            if (/^\d+\.\d+\.\d+\.\d+$/.test(address) && !a.includes(address)) blockers.push(`${domain} resolves to ${dnsInfo}, not ${address}: certbot HTTP-01 would fail — fix the A record first`);
                        }
                        const reach = await ctx.transport.exec(host, 'echo ok; . /etc/os-release; echo "$PRETTY_NAME"; test -f /opt/remnanode/docker-compose.yml && echo HAS_REMNANODE || true', { via, timeoutMs: 30_000, noSudo: true });
                        if (!reach.ok) blockers.push(`cannot ssh ${args.sshUser}@${address}: ${reach.error}`);
                        else if (!/Ubuntu/.test(reach.stdout)) warnings.push(`not Ubuntu (${reach.stdout.split('\n')[1]}): the script targets Ubuntu 22.04/24.04`);
                        if (reach.stdout.includes('HAS_REMNANODE')) warnings.push('remnanode is already installed there: the run re-applies the baseline and keeps its SECRET_KEY unless you pass one');
                        if (!known) warnings.push(`"${args.host}" is not in the inventory: add it afterwards (fleet_discover prints YAML)`);

                        const flags = [
                            ...(user ? [`--user=${user}`] : []),
                            ...(args.hostname ? [`--hostname=${args.hostname}`] : []),
                            '--tailscale=1',
                            `--remnanode=${args.remnanode ? 1 : 0}`,
                            ...(domain && args.remnanode ? [`--domain=${domain}`] : []),
                            '--tailscale-only=1',
                            '--ports=skip',
                        ];
                        const id = `bootstrap-${args.host}-${new Date().toISOString().replace(/[-:]/g, '').slice(0, 15)}-${crypto.randomBytes(2).toString('hex')}`;
                        const log = `/var/log/mia-${id}.log`;
                        const rc = `/var/log/mia-${id}.rc`;
                        // the secret is written to a root-only file and read by the detached runner, so it is not in this ssh command line
                        const runner = [
                            'set -e',
                            'umask 077',
                            `curl -fsSL "$EDGE_URL" -o /root/vps-edge-run.sh`,
                            ...(tsKey
                                ? ['command -v tailscale >/dev/null || curl -fsSL https://tailscale.com/install.sh | sh', `tailscale up --ssh --advertise-exit-node --authkey="$TS_AUTHKEY"${args.hostname ? ` --hostname=${q(args.hostname)}` : ''}`]
                                : []),
                            ...(secret ? ['printf "%s" "$SECRET" > /root/.mia-secret'] : []),
                        ].join('\n');
                        const detached = `nohup setsid bash -c ${q(
                            `bash /root/vps-edge-run.sh ${flags.map(q).join(' ')}${secret ? ' --secret-key="$(cat /root/.mia-secret)"' : ''}; echo $? > ${rc}` +
                                // never leave the key in the log, whatever the script printed
                                (secret ? `; sed -i "s|$(sed 's/[][\\.*^$|]/\\\\&/g' /root/.mia-secret)|«redacted»|g" ${log}; rm -f /root/.mia-secret` : ''),
                        )} > ${log} 2>&1 < /dev/null &`;
                        return [
                            {
                                host,
                                via,
                                // no job id / log path here: the action is part of the planHash and must be the same on apply
                                action: `vps-edge-run.sh ${flags.join(' ')}${secret ? ' --secret-key=«panel»' : ''} (detached)`,
                                script: `${runner}\n${detached}\necho started ${id}`,
                                env: { EDGE_URL: ctx.config.edgeScriptUrl, SECRET: secret ?? '', TS_AUTHKEY: tsKey ?? '' },
                                timeoutMs: 300_000,
                                preview: { ssh: `${args.sshUser}@${address}:${args.sshPort}`, os: reach.stdout.split('\n')[1], domain, dns: dnsInfo, script: ctx.config.edgeScriptUrl, log: '/var/log/mia-bootstrap-<host>-<time>.log' },
                                fingerprint: [address, domain, dnsInfo, !!secret],
                                warnings,
                                blockers,
                                verify: async (res) => {
                                    if (!res.stdout.includes(`started ${id}`)) return 'runner did not start';
                                    ctx.state.saveJob({ id, host: args.host, kind: 'bootstrap', startedAt: new Date().toISOString(), log, rcFile: rc, via, note: domain });
                                    return true;
                                },
                            },
                        ];
                    }).then((r) => ({ ...r, ...(args.apply ? { next: 'Poll job_status (it tries Tailscale first, then the public address). Open the Tailscale login URL if one shows up.' } : {}) }));
                }),
        );
    });
}

/** After a reboot command: wait for ssh to drop and come back, then for remnanode (if any). */
async function waitBack(ctx: Ctx, h: Host, delayMin: number): Promise<string | true> {
    await new Promise((r) => setTimeout(r, later(ctx, delayMin * 60_000 + 20_000)));
    const back = await waitFor(
        async () => {
            const r = await ctx.transport.exec(h, 'cut -d. -f1 /proc/uptime', { timeoutMs: 20_000, noSudo: true });
            return r.ok && Number(r.stdout.trim()) < 1800 ? true : r.ok ? `uptime ${r.stdout.trim()}s (not rebooted yet)` : (r.error ?? 'down');
        },
        later(ctx, 600_000),
        later(ctx, 10_000),
    );
    if (back !== true) return `did not come back: ${back}`;
    if (!h.roles.includes('remnanode')) return true;
    const up = await serviceStable(ctx, h, REMNANODE, 120_000);
    return up === true ? true : `back, but remnanode: ${up}`;
}

async function rebootAndWait(ctx: Ctx, h: Host, delayMin: number): Promise<string | true> {
    await ctx.transport.exec(h, `shutdown -r +${delayMin} "mia: reboot after upgrade"`, { timeoutMs: 20_000 });
    return waitBack(ctx, h, delayMin);
}
