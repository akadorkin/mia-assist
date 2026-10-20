import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { ApiStep, applyParams, runApiSteps } from '../core/plan.js';
import { cfCreate, cfDelete, cfRecords, cfUpdate, cfZones, zoneFor } from '../core/cloudflare.js';
import { Ctx } from '../core/ctx.js';
import { run, writeTools } from './helpers.js';

const ipv4 = z.string().regex(/^\d+\.\d+\.\d+\.\d+$/, 'IPv4');
const rowOf = (r: { zone: string; name: string; type: string; content: string; proxied: boolean; ttl: number }) => ({ name: r.name, type: r.type, content: r.content, proxied: r.proxied || undefined, ttl: r.ttl === 1 ? 'auto' : r.ttl, zone: r.zone });

function token(ctx: Ctx): string {
    if (!ctx.config.cloudflareToken) throw new Error('needs CLOUDFLARE_API_TOKEN (mia secrets set CLOUDFLARE_API_TOKEN)');
    return ctx.config.cloudflareToken;
}

export function registerDnsTools(server: McpServer, ctx: Ctx) {
    server.tool(
        'dns_records',
        'DNS records in Cloudflare (CLOUDFLARE_API_TOKEN): by name, or every record that points at an IP across all zones — e.g. everything still on an old ingress address.',
        { name: z.string().optional().describe('exact record name'), ip: z.string().optional().describe('every record with this content'), type: z.enum(['A', 'AAAA', 'CNAME', 'TXT', 'any']).default('any') },
        (args) =>
            run(async () => {
                if (!args.name && !args.ip) throw new Error('give name or ip');
                const recs = await cfRecords(token(ctx), { name: args.name, content: args.ip, type: args.type === 'any' ? undefined : args.type });
                return { records: recs.length, rows: recs.map(rowOf) };
            }),
    );

    writeTools(() => {
        server.tool(
            'dns_change',
            'Change A records in Cloudflare with a dry run: set (name → IP, created or updated; one A record per name), move (every A record on one IP to another — an ingress switch), remove (records by name, or every A record on an IP). The plan shows each record before and after; after apply every record is read back.',
            {
                set: z.array(z.object({ name: z.string(), ip: ipv4, proxied: z.boolean().optional() })).optional(),
                move: z.object({ from: ipv4, to: ipv4 }).optional(),
                remove: z.object({ names: z.array(z.string()).optional(), ip: ipv4.optional() }).optional(),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runApiSteps(ctx, 'dns_change', args, args, async () => {
                        const t = token(ctx);
                        if (!args.set?.length && !args.move && !args.remove) throw new Error('nothing to change: set, move or remove');
                        const zones = await cfZones(t);
                        const steps: ApiStep[] = [];
                        const readBack = (id: string, zoneName: string, name: string, want: string | null) => async () => {
                            const now = await cfRecords(t, { name, type: 'A' }, zones);
                            const r = now.find((x) => x.id === id || (want && x.content === want));
                            if (want === null) return now.some((x) => x.id === id) ? 'still there' : true;
                            return r?.content === want ? true : `reads ${r?.content ?? 'nothing'} in ${zoneName}`;
                        };
                        for (const s of args.set ?? []) {
                            const zone = zoneFor(zones, s.name);
                            if (!zone) {
                                steps.push({ target: `A ${s.name}`, action: '-', blockers: [`no zone for ${s.name} (${zones.map((z) => z.name).join(', ')})`], apply: async () => undefined });
                                continue;
                            }
                            const cur = await cfRecords(t, { name: s.name, type: 'A' }, zones);
                            if (cur.length > 1) {
                                steps.push({ target: `A ${s.name}`, action: '-', before: cur.map((r) => r.content), blockers: [`${cur.length} A records for one name — the fleet keeps exactly one (fi2 lesson); remove the extra ones first`], apply: async () => undefined });
                            } else if (!cur.length) {
                                steps.push({ target: `A ${s.name}`, action: `create → ${s.ip}${s.proxied ? ' (proxied)' : ''}`, before: 'no record', after: s.ip, apply: () => cfCreate(t, zone, { type: 'A', name: s.name, content: s.ip, proxied: s.proxied ?? false }).then((r) => r.id), verify: readBack('', zone.name, s.name, s.ip) });
                            } else {
                                const r = cur[0];
                                const same = r.content === s.ip && (s.proxied === undefined || s.proxied === r.proxied);
                                steps.push({ target: `A ${s.name}`, action: `${r.content} → ${s.ip}`, before: r.content, after: s.ip, noop: same ? 'already so' : undefined, apply: () => cfUpdate(t, r, { content: s.ip, ...(s.proxied !== undefined ? { proxied: s.proxied } : {}) }).then(() => undefined), verify: readBack(r.id, r.zone, r.name, s.ip) });
                            }
                        }
                        if (args.move) {
                            const recs = await cfRecords(t, { content: args.move.from, type: 'A' }, zones);
                            if (!recs.length) steps.push({ target: `A records on ${args.move.from}`, action: '-', noop: 'none left', apply: async () => undefined });
                            for (const r of recs) steps.push({ target: `A ${r.name}`, action: `${r.content} → ${args.move.to}`, before: r.content, after: args.move.to, apply: () => cfUpdate(t, r, { content: args.move!.to }).then(() => undefined), verify: readBack(r.id, r.zone, r.name, args.move.to) });
                        }
                        if (args.remove) {
                            const recs = [
                                ...(args.remove.ip ? await cfRecords(t, { content: args.remove.ip, type: 'A' }, zones) : []),
                                ...(await Promise.all((args.remove.names ?? []).map((n) => cfRecords(t, { name: n }, zones)))).flat(),
                            ].filter((r, i, all) => all.findIndex((x) => x.id === r.id) === i);
                            for (const r of recs) steps.push({ target: `${r.type} ${r.name}`, action: `delete (${r.content})`, before: r.content, warnings: r.type !== 'A' ? [`${r.type} record`] : undefined, apply: () => cfDelete(t, r), verify: readBack(r.id, r.zone, r.name, null) });
                            if (!recs.length) steps.push({ target: 'records to remove', action: '-', noop: 'none found', apply: async () => undefined });
                        }
                        return steps;
                    }),
                ),
        );
    });
}
