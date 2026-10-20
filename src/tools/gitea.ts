import fs from 'node:fs';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { HostStep, applyParams, runApiSteps, runSteps } from '../core/plan.js';
import { Ctx } from '../core/ctx.js';
import { giteaRegistrationToken, giteaRunnerDelete, giteaRunners } from '../core/gitea.js';
import { run, writeTools } from './helpers.js';
import { repoFile, repoRunner, repoState } from './repo.js';

function gitea(ctx: Ctx) {
    if (!ctx.config.gitea) throw new Error('needs GITEA_URL and GITEA_TOKEN (mia secrets set GITEA_TOKEN)');
    return ctx.config.gitea;
}

/** Remote tail that shows whether the runner runs and which labels it registered with. */
const RUNNER_CHECK = `echo '--- mia: runner'
systemctl is-active act_runner 2>&1 | head -n 1
for f in /etc/act_runner/.runner /var/lib/act_runner/.runner /opt/act_runner/.runner /home/*/.runner; do [ -f "$f" ] && grep -oE '"[a-z0-9.-]+:(host|docker[^"]*)"' "$f"; done 2>/dev/null | sort -u`;

export function registerGiteaTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'gitea_runners',
        'Gitea Actions runners (GITEA_URL + GITEA_TOKEN): name, online/offline, busy, labels — to spot stale registrations and runners that announce another node\'s label.',
        { filter: z.string().optional() },
        ({ filter }) =>
            run(async () => {
                const { scope, runners } = await giteaRunners(gitea(ctx));
                let rows = runners.map((r) => ({ name: r.name, id: r.id, status: r.status, busy: r.busy || undefined, labels: r.labels.join(',') }));
                if (filter) rows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(filter.toLowerCase()));
                const wrongLabel = runners.filter((r) => r.labels.some((l) => /^node-[\w-]+:host$/.test(l) && !l.startsWith(`${r.name}:`) && !l.startsWith(`node-${r.name}:`)));
                return { scope, runners: rows.length, offline: rows.filter((r) => r.status !== 'online' && r.status !== 'idle' && r.status !== 'active').length, ...(wrongLabel.length ? { labelMismatch: wrongLabel.map((r) => `${r.name}: ${r.labels.join(',')}`) } : {}), rows };
            }),
    );

    writeTools(() => {
        server.tool(
            'gitea_runner_remove',
            'Delete a runner registration in Gitea (a node taken out of service). Dry run shows the runner; a busy runner is refused.',
            { name: z.string().describe('runner name, e.g. node-pl9'), ...applyParams },
            (args) =>
                run(() =>
                    runApiSteps(ctx, 'gitea_runner_remove', args, args, async () => {
                        const g = gitea(ctx);
                        const { scope, runners } = await giteaRunners(g);
                        const hits = runners.filter((r) => r.name === args.name || r.name === `node-${args.name}`);
                        if (!hits.length) return [{ target: `runner ${args.name}`, action: '-', noop: 'no such runner in Gitea', apply: async () => undefined }];
                        return hits.map((r) => ({
                            target: `runner ${r.name} #${r.id}`,
                            action: 'delete the registration',
                            before: { status: r.status, labels: r.labels },
                            blockers: r.busy ? ['busy with a job right now'] : undefined,
                            apply: () => giteaRunnerDelete(g, scope, r.id),
                            verify: async () => ((await giteaRunners(g)).runners.some((x) => x.id === r.id) ? 'still registered' : true),
                        }));
                    }),
                ),
        );

        server.tool(
            'gitea_runner_register',
            'Register the Gitea Actions runner on a node with a runner bootstrap script from your own repo checkout (MIA_REPOS; default ops:deploy/bootstrap-node-runner.sh <name> <token>): a fresh registration token comes from the Gitea API at run time and reaches the script through an environment variable, never the plan or journal. Verified afterwards: act_runner active and the label is exactly node-<name>:host (copied configs announced other nodes\' labels before).',
            {
                host: z.string().describe('inventory host'),
                name: z.string().optional().describe('name for the script (default: the inventory name, e.g. pl3 → label node-pl3:host)'),
                repo: z.string().default('ops'),
                script: z.string().default('deploy/bootstrap-node-runner.sh'),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'gitea_runner_register', args, { ...args, defaultBatch: 1 }, async () => {
                        const g = gitea(ctx);
                        const h = ctx.inventory().get(args.host);
                        const name = args.name ?? h.name;
                        const label = `node-${name.replace(/^node-/, '')}:host`;
                        const root = ctx.config.repos[args.repo];
                        if (!root) throw new Error(`repo "${args.repo}" is not configured (MIA_REPOS)`);
                        const rel = path.relative(root, repoFile(root, args.script)).split(path.sep).join('/');
                        const body = fs.readFileSync(path.join(root, rel));
                        const existing = (await giteaRunners(g).catch(() => ({ runners: [] as Array<{ name: string; status: string; labels: string[] }> }))).runners.filter((r) => r.labels.includes(label) || r.name === `node-${name}` || r.name === name);
                        const token = await giteaRegistrationToken(g);
                        return [
                            {
                                host: h,
                                action: `${args.repo}:${rel} ${name} $RUNNER_TOKEN → label ${label}`,
                                script: `${repoRunner([{ rel, body }], rel, [name, { env: 'RUNNER_TOKEN' }])}\n${RUNNER_CHECK}`,
                                env: { RUNNER_TOKEN: token },
                                timeoutMs: 600_000,
                                preview: { repo: { path: root, ...repoState(root) }, label, alreadyInGitea: existing.map((r) => `${r.name} (${r.status}) ${r.labels.join(',')}`) },
                                warnings: existing.length ? ['a runner with this name/label is already registered: the old one should be removed (gitea_runner_remove)'] : undefined,
                                fingerprint: [rel, body.length],
                                verify: async (res) => {
                                    const tail = res.stdout.split('--- mia: runner').pop() ?? '';
                                    if (!/^active/m.test(tail)) return `act_runner is not active: ${tail.trim().split('\n')[0] ?? ''}`;
                                    const labels = [...tail.matchAll(/"([a-z0-9.-]+:[\w-]+)"/g)].map((m) => m[1]);
                                    if (!labels.includes(label)) return `registered labels ${labels.join(',') || 'none'} — expected ${label}`;
                                    const foreign = labels.filter((l) => /^node-/.test(l) && l !== label);
                                    return foreign.length ? `also announces ${foreign.join(',')}` : true;
                                },
                            } satisfies HostStep,
                        ];
                    }),
                ),
        );
    });
}
