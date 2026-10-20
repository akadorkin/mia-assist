import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { applyParams, runApiSteps } from '../core/plan.js';
import { beszelSystems, beszelUpdate } from '../core/beszel.js';
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
