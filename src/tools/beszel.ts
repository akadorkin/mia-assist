import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { applyParams, runApiSteps, waitFor } from '../core/plan.js';
import { beszelAddSystem, beszelSystems, beszelUpdate } from '../core/beszel.js';
import { matchPeer, tailscalePeers } from '../core/panel.js';
import { Ctx } from '../core/ctx.js';
import { run, writeTools } from './helpers.js';

function beszel(ctx: Ctx) {
    if (!ctx.config.beszel) throw new Error('needs BESZEL_URL, BESZEL_EMAIL, BESZEL_PASSWORD (mia secrets set …)');
    return ctx.config.beszel;
}

export function registerBeszelTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'beszel_systems',
        'Systems (cards) in the Beszel hub: name, host, status — to find duplicates a new agent created and cards of removed nodes.',
        { filter: z.string().optional() },
        ({ filter }) =>
            run(async () => {
                let rows = (await beszelSystems(beszel(ctx))).map((s) => ({ name: s.name, host: s.host, status: s.status, id: s.id }));
                if (filter) rows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(filter.toLowerCase()));
                const dup = rows.filter((r, i) => rows.findIndex((x) => x.host === r.host) !== i).map((r) => r.host);
                return { systems: rows.length, down: rows.filter((r) => r.status !== 'up').length, ...(dup.length ? { duplicateHosts: [...new Set(dup)] } : {}), rows };
            }),
    );

    writeTools(() => {
        server.tool(
            'beszel_system_add',
            'Add a machine to the Beszel hub: a card for its tailnet address and the agent token that belongs to that card, written to /etc/beszel-agent.token.env on the host (never shown), then beszel-agent is enabled and the card must turn «up». The agent binary and unit must already be on the host (e.g. copied from a template node with host_copy). A token copied from another machine does not work: the hub answers «fingerprint mismatch».',
            {
                host: z.string().describe('inventory host'),
                name: z.string().optional().describe('card name, e.g. "🇩🇪 Germany | de-1" (default: the inventory name)'),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runApiSteps(ctx, 'beszel_system_add', args, args, async () => {
                        const b = beszel(ctx);
                        const h = ctx.inventory().get(args.host);
                        const ip = matchPeer(h, await tailscalePeers(ctx.config).catch(() => []))?.ips.find((x) => x.includes('.'));
                        const name = args.name ?? h.name;
                        if (!ip) return [{ target: `beszel ${name}`, action: '-', blockers: [`${h.name} is not in the tailnet: the card needs its 100.x address`], apply: async () => undefined }];
                        const have = (await beszelSystems(b)).find((s) => s.host === ip);
                        if (have) return [{ target: `beszel ${have.name} (${ip})`, action: '-', noop: `already there, ${have.status}`, apply: async () => undefined }];
                        const unit = await ctx.transport.exec(h, 'test -x /opt/beszel-agent/beszel-agent && test -f /etc/systemd/system/beszel-agent.service && echo ok', { timeoutMs: 20_000 });
                        return [
                            {
                                target: `beszel ${name} (${ip})`,
                                action: `create the card, write its token to ${h.name}:/etc/beszel-agent.token.env, enable beszel-agent`,
                                blockers: unit.stdout.includes('ok') ? undefined : [`no beszel-agent binary / unit on ${h.name}: copy them from a node that has them first`],
                                apply: async () => {
                                    const { token } = await beszelAddSystem(b, { name, host: ip });
                                    const res = await ctx.transport.exec(h, 'umask 077; printf "TOKEN=%s\\n" "$BZ_TOKEN" > /etc/beszel-agent.token.env\nsystemctl daemon-reload; systemctl enable beszel-agent >/dev/null 2>&1; systemctl restart beszel-agent; sleep 1; systemctl is-active beszel-agent', { env: { BZ_TOKEN: token }, timeoutMs: 60_000 });
                                    if (!res.ok) throw new Error(`${h.name}: ${res.error ?? res.stdout.trim()}`);
                                    return 'card created, token on the host, agent started';
                                },
                                verify: () =>
                                    waitFor(async () => {
                                        const s = (await beszelSystems(b)).find((x) => x.host === ip);
                                        return s?.status === 'up' ? true : `card is ${s?.status ?? 'missing'}`;
                                    }, 60_000, 3000),
                            },
                        ];
                    }),
                ),
        );

        server.tool(
            'beszel_system_edit',
            'Rename or delete a Beszel card, found by exact name or host (tailnet name / IP). Delete only after the agent on that machine is stopped, or it recreates the card.',
            {
                find: z.string().describe('exact card name or host'),
                rename: z.string().optional().describe('new name, e.g. "🇵🇱 Poland | acme-pl3"'),
                remove: z.boolean().default(false),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runApiSteps(ctx, 'beszel_system_edit', args, args, async () => {
                        const b = beszel(ctx);
                        if (!args.rename && !args.remove) throw new Error('rename or remove');
                        const all = await beszelSystems(b);
                        const hits = all.filter((s) => s.name === args.find || s.host === args.find);
                        if (!hits.length) return [{ target: `beszel ${args.find}`, action: '-', noop: 'no such card', apply: async () => undefined }];
                        return hits.map((s) => ({
                            target: `beszel ${s.name} (${s.host})`,
                            action: args.remove ? 'delete the card (and its history)' : `rename → ${args.rename}`,
                            before: { name: s.name, status: s.status },
                            noop: !args.remove && s.name === args.rename ? 'already named so' : undefined,
                            warnings: args.remove && s.status === 'up' ? ['the agent still reports: stop it first (service_action beszel-agent stop) or the card comes back'] : undefined,
                            apply: () => beszelUpdate(b, s.id, args.remove ? null : { name: args.rename }),
                            verify: async () => {
                                const now = (await beszelSystems(b)).find((x) => x.id === s.id);
                                if (args.remove) return now ? 'still there' : true;
                                return now?.name === args.rename ? true : `named ${now?.name}`;
                            },
                        }));
                    }),
                ),
        );
    });
}
