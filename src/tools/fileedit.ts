import crypto from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { Ctx } from '../core/ctx.js';
import { redactText } from '../core/output.js';
import { applyParams, runSteps } from '../core/plan.js';
import { lineDiff, preserveLayout } from '../core/scenario.js';
import { q } from '../core/ssh.js';
import { detectFormat, editText } from '../core/textedit.js';
import { run, writeTools } from './helpers.js';

const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 16);

export function registerFileEditTools(server: McpServer, ctx: Ctx) {
    writeTools(() => {
        server.tool(
            'host_file_edit',
            'Edit one of the fleet\'s registry files on a host the way it is done by hand: clone the entry of a template node for a new node (Prometheus overrides, log-collector inventory, reboot-reminder lists, IP lists) or remove the entries of a removed node (e.g. node_servers.keep.txt). Works on plain lines (an IP inside a one-line list is edited in place), JSON and YAML (comments kept). The dry run shows the diff; the file is backed up (.bak-mia-<time>), written in place (owner and mode kept), optionally a unit is reloaded.',
            {
                host: z.string(),
                path: z.string().regex(/^\/[\w@%+=:,./-]+$/),
                op: z.enum(['clone', 'replace', 'remove']).describe('clone — добавить копию записи; replace — поменять в самой записи; remove — убрать запись'),
                match: z.string().min(3).describe('text that identifies the entry (template node name / address, or the removed node)'),
                replace: z.record(z.string()).optional().describe('clone: text replacements, e.g. {"node-pl2":"node-pl3","pl2":"pl3"}'),
                format: z.enum(['auto', 'lines', 'json', 'yaml']).default('auto'),
                reload: z.string().regex(/^[\w@.-]+$/).optional().describe('unit to reload (or restart when it cannot reload) afterwards'),
                ...applyParams,
            },
            (args) =>
                run(() =>
                    runSteps(ctx, 'host_file_edit', args, { ...args, defaultBatch: 1 }, async () => {
                        const h = ctx.inventory().get(args.host);
                        if (args.op !== 'remove' && !Object.keys(args.replace ?? {}).length) throw new Error(`${args.op} needs replace`);
                        const cur = await ctx.transport.exec(h, `test -f ${q(args.path)} || { echo MISSING; exit 0; }\nbase64 -w0 < ${q(args.path)}`, { timeoutMs: 30_000 });
                        if (!cur.ok) return [{ host: h, action: '-', script: '', blockers: [`unreachable: ${cur.error}`] }];
                        if (cur.stdout.trim() === 'MISSING') return [{ host: h, action: '-', script: '', blockers: [`no ${args.path} on ${h.name}`] }];
                        const before = Buffer.from(cur.stdout.trim(), 'base64').toString('utf8');
                        const format = args.format === 'auto' ? detectFormat(args.path, before) : args.format;
                        const res = editText(before, format, args.op === 'remove' ? { op: 'remove', match: args.match } : { op: args.op, match: args.match, replace: args.replace! });
                        if (format === 'json') JSON.parse(res.text); // never write broken JSON
                        // YAML is re-serialised by the library: keep the owner's layout on every line that did not change
                        const after = format === 'yaml' ? preserveLayout(before, res.text) : res.text;
                        const payload = Buffer.from(after).toString('base64').replace(/(.{76})/g, '$1\n');
                        return [
                            {
                                host: h,
                                action: `${args.op} "${args.match}" in ${args.path} (${format})${args.reload ? `, reload ${args.reload}` : ''}`,
                                noop: res.changed === 0 ? (args.op === 'remove' ? 'nothing matches' : 'nothing to change or already there') : undefined,
                                script: [
                                    'set -eo pipefail',
                                    `cp -p ${q(args.path)} ${q(args.path)}.bak-mia-$(date +%Y%m%d-%H%M%S)`,
                                    `base64 -d > /tmp/mia-edit.$$ <<'MIA_B64'`,
                                    payload,
                                    'MIA_B64',
                                    // cat into the file keeps its owner, mode and inode (a symlink or a watched file stays what it was)
                                    `cat /tmp/mia-edit.$$ > ${q(args.path)} && rm -f /tmp/mia-edit.$$`,
                                    ...(args.reload ? [`systemctl reload ${q(args.reload)} 2>/dev/null || systemctl restart ${q(args.reload)}`, `systemctl is-active ${q(args.reload)}`] : []),
                                    `sha256sum ${q(args.path)} | cut -c1-16`,
                                ].join('\n'),
                                preview: { format, entries: res.changed, diff: lineDiff(redactText(before), redactText(after)), ...(res.notes.length ? { notes: res.notes } : {}) },
                                fingerprint: sha(before),
                                timeoutMs: 60_000,
                                verify: async (r) => (r.stdout.trim().split('\n').pop() === sha(after) ? true : 'file content differs from the plan after writing'),
                            },
                        ];
                    }),
                ),
        );
    });
}
