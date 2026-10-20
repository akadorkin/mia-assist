import dns from 'node:dns/promises';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Finding, Severity, audit, statusRow } from '../core/audit.js';
import { Ctx } from '../core/ctx.js';
import { Host, adhocHost } from '../core/inventory.js';
import { PanelNode, TailscalePeer, isPersonalDevice, matchNode, matchPeer, nodeState, tailscalePeers } from '../core/panel.js';
import { HostFacts, probeHost } from '../core/probe.js';
import { pool } from '../core/ssh.js';
import { report } from '../core/progress.js';
import { run } from './helpers.js';

export const targetParam = z
    .string()
    .default('all')
    .describe('hosts: all | <host> | <glob nl-*> | <group> | role:<edge|remnanode|panel|docker> | tag:<tag>; comma-separated, !x excludes');

export interface Probed {
    host: Host;
    facts: HostFacts;
    node?: PanelNode | null;
    findings: Finding[];
}

/** Probe hosts in parallel and audit them against the baseline (+ the panel's view when configured). */
export async function probeAll(ctx: Ctx, hosts: Host[], mode: 'quick' | 'full' = 'quick'): Promise<{ probed: Probed[]; panel: string }> {
    report({ kind: 'hosts', phase: 'probe', hosts: hosts.map((h) => h.name) });
    // status and audit are «check now»: always probed, and the plans right after reuse what they saw
    // the panel answers once; each host's status row goes out with its progress event as soon as it is probed,
    // so a table (the dashboard tab) fills in host by host instead of waiting for the slowest one
    const nodesP = ctx.panelNodes(true);
    const [facts, nodes] = await Promise.all([
        pool(hosts, ctx.config.concurrency, async (h) => {
            const f = await ctx.facts(h, mode, { fresh: true });
            const n = await nodesP;
            const node = n ? (matchNode(h, n) ?? null) : undefined;
            report({ kind: 'host', host: h.name, state: f.reachable ? 'ok' : 'fail', note: f.reachable ? undefined : f.error, row: statusRow(h, f, audit(h, f, node), node) });
            return f;
        }),
        nodesP,
    ]);
    const probed = hosts.map((host, i) => {
        const node = nodes ? (matchNode(host, nodes) ?? null) : undefined;
        return { host, facts: facts[i], node, findings: audit(host, facts[i], node) };
    });
    const panel = !ctx.panel ? 'not configured (REMNAWAVE_BASE_URL / REMNAWAVE_API_TOKEN — mia secrets set)' : nodes ? `ok, ${nodes.length} nodes` : `error: ${ctx.panelError}`;
    return { probed, panel };
}

const SEV_RANK: Record<Severity, number> = { crit: 0, warn: 1, info: 2 };

export function registerFleetTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'fleet_hosts',
        'The inventory (fleet.yaml): hosts with address, roles, tags, groups, services. No host is contacted. Start here to learn the names used by every other tool.',
        {
            target: targetParam,
            details: z.boolean().default(false).describe('include services, logs, policy and bootstrap settings'),
        },
        ({ target, details }) =>
            run(async () => {
                const inv = ctx.inventory();
                if (!inv.hosts.size) {
                    return {
                        inventory: inv.file,
                        hosts: 0,
                        hint: 'The inventory is empty or missing. Copy fleet.example.yaml to this path (or set MIA_INVENTORY), or run fleet_discover to get ready-made entries from Tailscale and the panel.',
                    };
                }
                const hosts = target === 'all' ? [...inv.hosts.values()] : inv.resolve(target);
                return {
                    inventory: inv.file,
                    hosts: hosts.length,
                    groups: Object.fromEntries(inv.groups),
                    list: hosts.map((h) => ({
                        name: h.name,
                        address: h.address,
                        user: h.user,
                        roles: h.roles.join(','),
                        tags: h.tags.length ? h.tags.join(',') : undefined,
                        groups: h.groups.length ? h.groups.join(',') : undefined,
                        domain: h.domain,
                        panelNode: h.panelNode,
                        title: h.title,
                        provider: h.provider,
                        transport: h.transport === 'local' ? 'local' : undefined,
                        disabled: h.disabled || undefined,
                        notes: h.notes,
                        ...(details
                            ? {
                                  services: h.services.map((s) => `${s.name}:${s.compose ? 'compose' : s.unit ? 'unit' : 'container'}${s.expect === 'present' ? '?' : ''}`).join(' '),
                                  logs: Object.keys(h.logs).join(' '),
                                  policy: h.policy,
                                  bootstrap: h.bootstrap,
                              }
                            : {}),
                    })),
                };
            }),
    );

    server.tool(
        'fleet_discover',
        'Cross-check the inventory with the tailnet (local `tailscale status`) and the Remnawave panel: nodes/peers missing from fleet.yaml (with ready YAML), inventory hosts that are offline or unknown to both, panel nodes and their state.',
        {},
        () =>
            run(async () => {
                const inv = ctx.inventory();
                const hosts = [...inv.hosts.values()];
                const [peers, nodes] = await Promise.all([tailscalePeers(ctx.config).catch((e: Error) => e), ctx.panelNodes(true)]);
                const peerList = peers instanceof Error ? [] : peers;

                const matchedPeers = new Set<string>();
                const matchedNodes = new Set<string>();
                const rows = hosts.map((h) => {
                    const p = matchPeer(h, peerList);
                    const n = nodes ? matchNode(h, nodes) : undefined;
                    if (p) matchedPeers.add(p.dnsName);
                    if (n) matchedNodes.add(n.uuid);
                    return {
                        host: h.name,
                        roles: h.roles.join(','),
                        tailnet: p ? `${p.online ? 'online' : `offline${p.lastSeen ? ` since ${p.lastSeen.slice(0, 16)}` : ''}`} ${p.dnsName}` : peers instanceof Error ? '?' : 'not in tailnet',
                        panel: n ? `${n.name}: ${nodeState(n)}${n.usersOnline !== undefined ? `, ${n.usersOnline} online` : ''}` : nodes ? (h.roles.includes('remnanode') ? 'no matching node' : '-') : '?',
                    };
                });

                const newPeers = peerList.filter((p) => !p.self && !isPersonalDevice(p) && !matchedPeers.has(p.dnsName));
                const newNodes = (nodes ?? []).filter((n) => !matchedNodes.has(n.uuid));

                // resolve panel node addresses to tailnet peers where the public IP matches nothing: best effort by hostname
                const yaml: string[] = [];
                for (const n of newNodes) {
                    const peer = peerList.find((p) => p.hostName.toLowerCase() === n.name.toLowerCase() || p.dnsName.split('.')[0].toLowerCase() === n.name.toLowerCase());
                    const key = (peer?.hostName ?? n.name).toLowerCase().replace(/[^\w.-]+/g, '-');
                    yaml.push(
                        `  ${key}:`,
                        `    address: ${peer ? peer.dnsName.split('.')[0] : `${key}  # tailnet name or ssh alias`}`,
                        `    roles: [remnanode]`,
                        ...(/^[\d.]+$/.test(n.address) ? [] : [`    domain: ${n.address}`]),
                        `    panelNode: ${JSON.stringify(n.name)}`,
                    );
                }
                for (const p of newPeers) {
                    if (newNodes.some((n) => n.name.toLowerCase() === p.hostName.toLowerCase())) continue;
                    yaml.push(`  ${p.hostName.toLowerCase().replace(/[^\w.-]+/g, '-')}:`, `    address: ${p.dnsName.split('.')[0]}`, `    roles: [edge]  # adjust: edge | remnanode | panel | docker`);
                }

                let domainChecks: Array<Record<string, unknown>> | undefined;
                if (nodes) {
                    domainChecks = await Promise.all(
                        nodes
                            .filter((n) => !/^[\d.:]+$/.test(n.address))
                            .map(async (n) => {
                                const a = await dns.resolve4(n.address).catch(() => [] as string[]);
                                return { node: n.name, address: n.address, resolves: a.length ? a.join(',') : 'NXDOMAIN / no A record' };
                            }),
                    );
                    domainChecks = domainChecks.filter((d) => d.resolves === 'NXDOMAIN / no A record');
                }

                return {
                    inventory: `${inv.file} (${hosts.length} hosts)`,
                    tailnet: peers instanceof Error ? `unavailable: ${peers.message}` : `${peerList.length} devices`,
                    panel: !ctx.panel ? 'not configured' : nodes ? `${nodes.length} nodes` : `error: ${ctx.panelError}`,
                    hosts: rows,
                    ...(newNodes.length ? { panelNodesNotInInventory: newNodes.map((n) => `${n.name} (${n.address}) ${nodeState(n)}`) } : {}),
                    ...(newPeers.length ? { tailnetDevicesNotInInventory: newPeers.map((p) => `${p.hostName} ${p.dnsName} ${p.online ? 'online' : 'offline'} ${p.os ?? ''}`.trim()) } : {}),
                    ...(domainChecks?.length ? { panelNodesWithoutDns: domainChecks } : {}),
                    ...(yaml.length ? { addToFleetYaml: ['hosts:', ...yaml].join('\n') } : {}),
                };
            }),
    );

    server.tool(
        'fleet_status',
        'One-screen health of the fleet: every host probed over ssh in parallel — uptime, load, memory, disk, pending updates/reboot, remnanode container, certificate days, Tailscale, panel state and users online — plus the codes of open issues (details: fleet_audit). With target all it also lists every tailnet device that is not in fleet.yaml: Linux machines are probed with the default ssh user, others shown with their online state.',
        {
            target: targetParam,
            tailnet: z.boolean().default(true).describe('with target all: add the tailnet devices that are not in fleet.yaml'),
        },
        ({ target, tailnet }) =>
            run(async () => {
                const inv = ctx.inventory();
                const hosts = inv.resolve(target);
                const wantTailnet = tailnet && (target === 'all' || target === '*');
                const peersP = wantTailnet || hosts.length ? tailscalePeers(ctx.config).catch((e: Error) => e) : Promise.resolve([] as TailscalePeer[]);
                const peersOrErr = await peersP;
                const peers = peersOrErr instanceof Error ? [] : peersOrErr;

                // tailnet devices that match no inventory host (disabled ones included: they are known)
                const known = [...inv.hosts.values()];
                const extras = wantTailnet ? peers.filter((p) => !p.self && !isPersonalDevice(p) && !known.some((h) => matchPeer(h, [p]))) : [];
                const probeable = extras.filter((p) => p.online && /linux/i.test(p.os ?? ''));
                const extraHosts = probeable.map((p) => adhocHost(p.hostName, p.dnsName || p.hostName, inv.defaultUser ?? 'root'));

                const [{ probed, panel }, extraFacts] = await Promise.all([
                    probeAll(ctx, hosts),
                    pool(extraHosts, ctx.config.concurrency, (h) => probeHost(ctx.transport, h, 'quick')),
                ]);
                const since = (p: TailscalePeer) => (p.lastSeen ? ` since ${p.lastSeen.slice(0, 10)}` : '');
                const rows = probed.map((p) => {
                    const row: Record<string, unknown> = statusRow(p.host, p.facts, p.findings, p.node);
                    const tp = matchPeer(p.host, peers);
                    if (tp?.keyDaysLeft !== undefined && tp.keyDaysLeft < 30) row.tsKey = tp.keyDaysLeft < 0 ? 'EXPIRED' : `${tp.keyDaysLeft}d`;
                    if (row.state === 'UNREACHABLE') {
                        const peer = matchPeer(p.host, peers);
                        if (peer && !peer.online) row.error = `в tailnet не в сети${peer.lastSeen ? ` с ${peer.lastSeen.slice(0, 10)}` : ''}`;
                        else if (!peer && peers.length) row.error = `${row.error ?? ''} (нет в tailnet)`.trim();
                    }
                    return row;
                });
                const extraRows = extras.map((p) => {
                    const i = probeable.indexOf(p);
                    const f = i >= 0 ? extraFacts[i] : undefined;
                    if (f?.reachable) return { ...statusRow(extraHosts[i], f, [], undefined), state: 'not in fleet.yaml', os: p.os };
                    return {
                        host: p.hostName,
                        state: p.online ? 'not in fleet.yaml' : 'offline',
                        ts: `${p.online ? 'online' : `offline${since(p)}`}${p.os ? ` ${p.os}` : ''}`,
                        os: p.os,
                        error: f?.error,
                    };
                });
                const all = [...rows, ...extraRows];
                const count = (s: string) => rows.filter((r) => r.state === s).length;
                return {
                    summary: {
                        hosts: rows.length,
                        ok: count('ok') + count('info'),
                        warn: count('warn'),
                        crit: count('crit'),
                        unreachable: count('UNREACHABLE'),
                        ...(wantTailnet ? { tailnetOnly: extraRows.length } : {}),
                    },
                    panel,
                    ...(wantTailnet ? { tailnet: peersOrErr instanceof Error ? `unavailable: ${peersOrErr.message}` : `${peers.filter((p) => !p.self).length} devices, ${peers.filter((p) => !p.self && p.online).length} online` } : {}),
                    rows: all,
                    ...(extraRows.length ? { hint: 'devices not in fleet.yaml: fleet_discover gives ready YAML entries for them (then they get the full audit)' } : {}),
                };
            }),
    );

    server.tool(
        'fleet_audit',
        'Audit hosts against the fleet baseline (as the nodes run now: vps-edge-run.sh bootstrap + ufw-blacklist.sh ipsets, MGMT-PORTS chain, beszel-agent, security updates automatic with manual reboots) and general health: firewall (ufw off, management ports public, other public ports listed), Tailscale, sshd hardening, fail2ban jails, node_exporter, beszel-agent, MGMT-PORTS, ipset blacklists, auto-updates, tuning (bbr/fq, conntrack), remnanode container/compose/SECRET_KEY, certificate expiry, geo updater, disks, memory, temperatures, pending security updates, reboot, failed units, NTP, inventory services, panel node state. Findings have stable codes (policy.skip in fleet.yaml mutes them).',
        {
            target: targetParam,
            minSeverity: z.enum(['crit', 'warn', 'info']).default('warn'),
            code: z.string().optional().describe('only findings whose code starts with this (e.g. "cert", "fw")'),
        },
        ({ target, minSeverity, code }) =>
            run(async () => {
                const hosts = ctx.inventory().resolve(target);
                const { probed, panel } = await probeAll(ctx, hosts);
                const byCode = new Map<string, string[]>();
                const perHost: Record<string, string[]> = {};
                for (const p of probed) {
                    const list = p.findings.filter((f) => SEV_RANK[f.sev] <= SEV_RANK[minSeverity] && (!code || f.code.startsWith(code)));
                    if (!list.length) continue;
                    perHost[p.host.name] = list.map((f) => `${f.sev.toUpperCase()} ${f.code}: ${f.msg}`);
                    for (const f of list) {
                        if (!byCode.has(f.code)) byCode.set(f.code, []);
                        byCode.get(f.code)!.push(p.host.name);
                    }
                }
                const clean = probed.filter((p) => !perHost[p.host.name]).map((p) => p.host.name);
                return {
                    hosts: probed.length,
                    panel,
                    clean: clean.length ? clean : undefined,
                    byCode: Object.fromEntries(
                        [...byCode].map(([c, h]) => [c, [...new Set(h)]] as const).sort((a, b) => b[1].length - a[1].length).map(([c, h]) => [c, h.join(', ')]),
                    ),
                    findings: perHost,
                };
            }),
    );
}
