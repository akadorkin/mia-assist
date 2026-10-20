import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { applyParams, runApiSteps } from '../core/plan.js';
import { Ctx } from '../core/ctx.js';
import { HOST_FIELDS, HostEdit, HostField, planFleet, readFleet, writeFleet } from '../core/fleetfile.js';
import { ROLES } from '../core/inventory.js';
import { list, listParam } from '../scenarios/common.js';
import { run, writeTools } from './helpers.js';

export function registerInventoryTools(server: McpServer, ctx: Ctx) {
    writeTools(() => {
        if (ctx.config.readonly) return;
        server.tool(
            'fleet_host_edit',
            "Edit a host in fleet.yaml (this machine's inventory, not the server): add, change fields, move between groups, switch off/on (disabled), remove. The dry run shows the diff of fleet.yaml (layout and comments kept) and refuses a result mia could not load; apply writes it with a backup in the state directory and refuses if the file changed since the plan.",
            {
                op: z.enum(['add', 'update', 'disable', 'enable', 'remove']).describe('add a host, update its fields, disable/enable it (disabled: true), remove it'),
                name: z.string().describe('host key in fleet.yaml, e.g. pl3'),
                address: z.string().optional().describe('ssh target: tailnet name (node-pl3), IP or ~/.ssh/config alias'),
                user: z.string().optional().describe('ssh user (default: defaults.user)'),
                port: z.number().int().optional().describe('ssh port'),
                sudo: z.boolean().optional().describe('run commands through sudo -n'),
                roles: listParam(`roles: ${ROLES.join(' | ')}`),
                tags: listParam('tags, e.g. prod'),
                groups: listParam('the groups the host is in after the edit (missing ones are created; omit to leave membership as is)'),
                domain: z.string().optional().describe('remnanode TLS domain'),
                panelNode: z.string().optional().describe('node name in the Remnawave panel'),
                title: z.string().optional().describe('name for people: the animal with its emoji, e.g. "🐧 penguin"'),
                provider: z.string().optional(),
                notes: z.string().optional(),
                unset: listParam(`fields to remove: ${HOST_FIELDS.join(', ')}`),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runApiSteps(ctx, 'fleet_host_edit', args, args, async () => {
                        const set: HostEdit['set'] = {};
                        for (const k of HOST_FIELDS) {
                            const v = (args as Record<string, unknown>)[k];
                            if (v === undefined) continue;
                            set[k] = k === 'roles' || k === 'tags' ? list(v) : (v as string);
                        }
                        const unset = list(args.unset) as HostField[];
                        const bad = unset.filter((k) => !(HOST_FIELDS as readonly string[]).includes(k));
                        if (bad.length) throw new Error(`unset: unknown fields ${bad.join(', ')}; allowed: ${HOST_FIELDS.join(', ')}`);
                        const file = ctx.config.inventoryFile;
                        const plan = planFleet(file, [{ op: args.op, name: args.name, set, unset, ...(args.groups !== undefined ? { groups: list(args.groups) } : {}) }]);
                        const changed = plan.diff.filter((l) => /^[-+]/.test(l));
                        return [
                            {
                                target: `fleet.yaml hosts.${args.name}`,
                                action: plan.summary.join('; '),
                                ...(changed.length ? { after: changed } : { noop: 'fleet.yaml already says so' }),
                                apply: async () => {
                                    const { backup } = writeFleet(plan, ctx.config.stateDir);
                                    ctx.inventory();
                                    return { file, ...(backup ? { backup } : {}) };
                                },
                                verify: async () => (readFleet(file) === plan.after ? true : 'fleet.yaml differs from the plan after writing'),
                            },
                        ];
                    }),
                ),
        );
    });
}
