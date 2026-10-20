import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { redact } from '../core/output.js';
import { probeHost } from '../core/probe.js';
import { diffState, groupChanges, snapshotState } from '../core/snapshot.js';
import { pool } from '../core/ssh.js';
import { run } from './helpers.js';
import { targetParam } from './fleet.js';

export function registerChangeTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'fleet_snapshot',
        'Record the configuration state of hosts (packages, enabled units, containers/images, ufw rules, listening ports, sshd, users/sudo/authorized keys, crontabs, sysctl, certificates, tracked config files …) to the local state dir, and report what changed since the previous snapshot. Run it on a schedule (e.g. daily cron `mia call fleet_snapshot`) to keep a change history.',
        {
            target: targetParam,
            reason: z.string().default('manual').describe('why (shown in history): manual, daily, before-upgrade …'),
        },
        ({ target, reason }) =>
            run(async () => {
                const hosts = ctx.inventory().resolve(target);
                const facts = await pool(hosts, ctx.config.concurrency, (h) => probeHost(ctx.transport, h, 'full', 180_000));
                return {
                    results: hosts.map((h, i) => {
                        const f = facts[i];
                        if (!f.reachable) return { host: h.name, saved: false, error: f.error };
                        const prev = ctx.state.listSnapshots(h.name)[0];
                        const state = snapshotState(f);
                        const meta = ctx.state.saveSnapshot(h.name, reason, state);
                        if (!prev) return { host: h.name, saved: meta.file, changes: 'first snapshot' };
                        const before = ctx.state.readSnapshot(prev.file);
                        const changes = diffState(before.state, ctx.state.readSnapshot(meta.file).state);
                        return {
                            host: h.name,
                            saved: meta.file,
                            since: before.takenAt,
                            changes: changes.length ? countBySection(changes.map((c) => c.path)) : 'none',
                        };
                    }),
                    next: 'fleet_changes shows the changes in detail.',
                };
            }),
    );

    server.tool(
        'fleet_changes',
        'What changed on hosts: diff of recorded snapshots (latest vs previous, or vs the first one after `since`), or of the latest snapshot vs the live host (live:true, catches changes made by hand since). Next to the diff: actions this server ran on those hosts in the same window (journal), so changes made outside mia stand out.',
        {
            target: targetParam,
            since: z.string().optional().describe('ISO date/time: compare the first snapshot at/after it with the latest'),
            live: z.boolean().default(false).describe('compare the latest snapshot with the host as it is now (probes the host)'),
            section: z.string().optional().describe('only this section: packages, units, docker, firewall, listen, ssh, access, sysctl, files, certs, remnanode, tailscale, system'),
        },
        ({ target, since, live, section }) =>
            run(async () => {
                const hosts = ctx.inventory().resolve(target);
                const liveFacts = live ? await pool(hosts, ctx.config.concurrency, (h) => probeHost(ctx.transport, h, 'full', 180_000)) : [];
                const out: Record<string, unknown> = {};
                hosts.forEach((h, i) => {
                    const snaps = ctx.state.listSnapshots(h.name);
                    if (!snaps.length) {
                        out[h.name] = 'no snapshot yet: run fleet_snapshot first';
                        return;
                    }
                    let fromMeta = snaps[1] ?? snaps[0];
                    let to: { label: string; state: Record<string, unknown> };
                    if (live) {
                        const f = liveFacts[i];
                        if (!f.reachable) {
                            out[h.name] = `unreachable: ${f.error}`;
                            return;
                        }
                        fromMeta = snaps[0];
                        // stored snapshots are redacted: redact the live side the same way so masked values compare equal
                        to = { label: 'live', state: redact(snapshotState(f)) };
                    } else {
                        if (since) {
                            // the oldest snapshot taken at/after `since`, compared with the latest
                            const after = snaps.filter((s) => s.takenAt >= since);
                            const first = after[after.length - 1];
                            if (!first || first.file === snaps[0].file) {
                                out[h.name] = `fewer than two snapshots since ${since} (latest: ${snaps[0].takenAt}); use live:true to compare with the host now`;
                                return;
                            }
                            fromMeta = first;
                        } else if (snaps.length < 2) {
                            out[h.name] = `only one snapshot (${snaps[0].takenAt}); take another or use live:true`;
                            return;
                        }
                        to = { label: snaps[0].takenAt, state: ctx.state.readSnapshot(snaps[0].file).state };
                    }
                    const from = ctx.state.readSnapshot(fromMeta.file);
                    let changes = diffState(from.state, to.state);
                    if (section) changes = changes.filter((c) => c.path === section || c.path.startsWith(section + '.'));
                    const journal = ctx.state.journal({ host: h.name, since: from.takenAt, limit: 30 }).map((j) => `${j.at.slice(0, 19)} ${j.tool}: ${j.action} → ${j.ok ? 'ok' : `FAILED ${j.result ?? ''}`}`);
                    out[h.name] = {
                        from: from.takenAt,
                        to: to.label,
                        changes: changes.length ? groupChanges(changes) : 'none',
                        ...(journal.length ? { miaActions: journal } : {}),
                    };
                });
                return out;
            }),
    );

    server.tool(
        'snapshots_list',
        'Recorded snapshots of a host (newest first), or the hosts that have any.',
        { host: z.string().optional() },
        ({ host }) =>
            run(async () => {
                if (!host) return { hosts: ctx.state.snapshotHosts().map((h) => ({ host: h, snapshots: ctx.state.listSnapshots(h).length, latest: ctx.state.listSnapshots(h)[0]?.takenAt })) };
                return ctx.state.listSnapshots(host).map((s) => ({ takenAt: s.takenAt, reason: s.reason, file: s.file }));
            }),
    );

    server.tool(
        'journal_list',
        'What this server did to hosts: every action with time, host, outcome and planHash (newest first).',
        {
            host: z.string().optional(),
            contains: z.string().optional(),
            since: z.string().optional().describe('ISO date/time'),
            limit: z.number().int().min(1).max(1000).default(50),
        },
        (p) => run(async () => ({ file: ctx.state.journalFile, entries: ctx.state.journal(p) })),
    );
}

function countBySection(paths: string[]): Record<string, number> {
    const out: Record<string, number> = {};
    for (const p of paths) {
        const s = p.split('.')[0];
        out[s] = (out[s] ?? 0) + 1;
    }
    return out;
}
