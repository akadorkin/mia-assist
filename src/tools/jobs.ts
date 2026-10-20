import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { Host, adhocHost } from '../core/inventory.js';
import { redactText } from '../core/output.js';
import { run } from './helpers.js';

export function registerJobTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'job_status',
        'State of a detached remote job (node_bootstrap): running or finished with exit code, the log tail, a Tailscale login URL if the node waits for authorization. Tries the host over Tailscale (inventory address) first, then the public bootstrap address. Without jobId: lists known jobs.',
        {
            jobId: z.string().optional(),
            lines: z.number().int().min(10).max(2000).default(60),
        },
        ({ jobId, lines }) =>
            run(async () => {
                const jobs = ctx.state.readJobs();
                if (!jobId) return Object.values(jobs).sort((a, b) => b.startedAt.localeCompare(a.startedAt)).map((j) => ({ id: j.id, host: j.host, kind: j.kind, startedAt: j.startedAt, note: j.note }));
                const job = jobs[jobId];
                if (!job) throw new Error(`unknown job ${jobId}; known: ${Object.keys(jobs).slice(-10).join(', ') || 'none'}`);
                const inv = ctx.inventory();
                const known = inv.hosts.get(job.host);
                const script = `if [ -f ${job.rcFile} ]; then echo "RC=$(cat ${job.rcFile})"; elif pgrep -f vps-edge-run.sh >/dev/null; then echo RUNNING; else echo "RC=unknown (runner gone)"; fi\ntail -n ${lines} ${job.log} 2>/dev/null | sed 's/\\x1b\\[[0-9;]*m//g'`;
                const attempts: Array<{ how: string; host: Host; via?: Job['via'] }> = [];
                if (known) attempts.push({ how: `tailscale/inventory (${known.address})`, host: known });
                if (job.via) {
                    const h = known ?? adhocHost(job.host, job.via.address, job.via.user);
                    attempts.push({ how: `public ${job.via.address}`, host: h, via: job.via });
                }
                const errors: string[] = [];
                for (const a of attempts) {
                    const res = await ctx.transport.exec(a.host, script, { via: a.via, timeoutMs: 30_000 });
                    if (!res.ok && !res.stdout.trim()) {
                        errors.push(`${a.how}: ${res.error}`);
                        continue;
                    }
                    const [head, ...rest] = res.stdout.split('\n');
                    const log = redactText(rest.join('\n'));
                    const url = log.match(/https:\/\/login\.tailscale\.com\/[\w/-]+/)?.[0];
                    const state = head.startsWith('RC=') ? (head === 'RC=0' ? 'finished OK (reboot in ~3 min)' : `finished, exit ${head.slice(3)}`) : 'running';
                    return {
                        job: job.id,
                        host: job.host,
                        via: a.how,
                        state,
                        ...(url && state === 'running' ? { tailscaleLogin: `open ${url} to authorize the node, the run continues after that` } : {}),
                        log,
                        ...(state.startsWith('finished OK')
                            ? {
                                  next: [
                                      known ? 'after the reboot: fleet_status / fleet_audit on the host' : 'add the host to fleet.yaml (address = its tailnet name), then fleet_audit',
                                      'create the node in the panel if not done (mcp-remnawave nodes_create, address = its tailnet name node-<name>.<magicdns-suffix>, port 2222) and bind its profile/inbounds',
                                      'fleet_snapshot to record its baseline',
                                  ],
                              }
                            : {}),
                    };
                }
                return { job: job.id, host: job.host, state: 'unknown — host not reachable', tried: errors, hint: 'during the reboot or before Tailscale is authorized the host can be unreachable for a few minutes' };
            }),
    );
}

type Job = ReturnType<Ctx['state']['readJobs']>[string];
